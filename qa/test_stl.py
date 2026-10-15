"""Permanent pure STL requirements; this module performs no file or network I/O."""

from __future__ import annotations

import hashlib
import math
import struct
from collections.abc import Callable

from qa.stl import make_cuboid_stl, parse_stl, validate_stl


# Fixture coordinates are millimetres; aliases describe immutable serialized geometry.
Point = tuple[float, float, float]
Triangle = tuple[Point, Point, Point]
Triangles = tuple[Triangle, ...]


def _cuboid(size: Point) -> Triangles:
    """Origin-based outward faces, specified independently of the future generator."""
    x, y, z = size
    points = ((0.0, 0.0, 0.0), (x, 0.0, 0.0), (x, y, 0.0), (0.0, y, 0.0),
              (0.0, 0.0, z), (x, 0.0, z), (x, y, z), (0.0, y, z))
    faces = ((0, 2, 1), (0, 3, 2), (4, 5, 6), (4, 6, 7),
             (0, 1, 5), (0, 5, 4), (1, 2, 6), (1, 6, 5),
             (2, 3, 7), (2, 7, 6), (3, 0, 4), (3, 4, 7))
    return tuple((points[a], points[b], points[c]) for a, b, c in faces)


def _tetrahedron(size: Point) -> Triangles:
    """The cuboid's bounds with one sixth its volume expose bounds-only checking."""
    x, y, z = size
    a, b, c, d = (0.0, 0.0, 0.0), (x, 0.0, 0.0), (0.0, y, 0.0), (0.0, 0.0, z)
    return ((a, c, b), (a, b, d), (b, c, d), (c, a, d))


def _binary(triangles: Triangles, header: bytes = b"Public mathematical specimen", attribute: int = 0) -> bytes:
    """Encode independently specified faces as complete little-endian STL records."""
    records = tuple(struct.pack("<12fH", 0.0, 0.0, 0.0, *a, *b, *c, attribute)
                    for a, b, c in triangles)
    return header.ljust(80, b"\0") + struct.pack("<I", len(records)) + b"".join(records)


def _ascii(triangles: Triangles) -> bytes:
    """Encode the text grammar independently of the implementation under test."""
    lines = ["solid public_specimen"]
    for triangle in triangles:
        lines.append("facet normal 0 0 0")
        lines.append("outer loop")
        lines.extend("vertex " + " ".join(format(number, ".9g") for number in vertex)
                     for vertex in triangle)
        lines.extend(("endloop", "endfacet"))
    lines.append("endsolid public_specimen")
    return ("\n".join(lines) + "\n").encode("ascii")


def _reject(code: str, operation: Callable[[], object]) -> None:
    """Require the public rejection code, rather than accepting an unrelated exception."""
    try:
        operation()
    except ValueError as error:
        assert error.args == (code,), (code, error.args)
        return
    raise AssertionError("Expected rejection: " + code)


def _number(summary: dict[str, object], key: str) -> float:
    """Read a numeric measurement without treating a protocol boolean as a geometry value."""
    value = summary[key]
    assert isinstance(value, (int, float)) and not isinstance(value, bool), key
    return float(value)


def test_complete_ascii_and_binary_geometry() -> None:
    """Every retained input/result size must preserve vertices and complete-file metrics."""
    cases = (((17.0, 11.0, 7.0), 1309.0), ((20.0, 11.0, 7.0), 1540.0),
             ((20.0, 10.0, 6.0), 1200.0), ((24.0, 10.0, 6.0), 1440.0))
    for size, volume in cases:
        triangles = _cuboid(size)
        for format_name, payload in (("binary", _binary(triangles)), ("ascii", _ascii(triangles))):
            assert parse_stl(payload) == triangles
            summary = validate_stl(payload, ((0.0, 0.0, 0.0), size), volume)
            assert set(summary) == {"format", "byte_count", "triangle_count", "bounds_mm",
                                    "signed_volume_mm3", "sha256"}
            assert summary["format"] == format_name
            assert summary["byte_count"] == len(payload)
            assert summary["triangle_count"] == 12
            assert summary["bounds_mm"] == ((0.0, 0.0, 0.0), size)
            assert math.isclose(_number(summary, "signed_volume_mm3"), volume, abs_tol=1e-6)
            assert summary["sha256"] == hashlib.sha256(payload).hexdigest()


def test_binary_header_and_attributes_are_not_format_shortcuts() -> None:
    """Legal binary metadata cannot make complete binary geometry look like ASCII."""
    triangles = _cuboid((17.0, 11.0, 7.0))
    payload = _binary(triangles, header=b"solid this is a binary header", attribute=0x8123)
    assert parse_stl(payload) == triangles
    assert validate_stl(payload, ((0.0, 0.0, 0.0), (17.0, 11.0, 7.0)), 1309.0)["format"] == "binary"


def test_complete_binary_consumption() -> None:
    """Plausible faces cannot conceal a missing record or unconsumed final byte."""
    payload = _binary(_cuboid((17.0, 11.0, 7.0)))
    for damaged in (payload[:-1], payload + b"\0", payload[:80] + struct.pack("<I", 13) + payload[84:]):
        _reject("STL_BINARY_LENGTH", lambda: parse_stl(damaged))
    _reject("STL_EMPTY", lambda: parse_stl(b""))
    _reject("STL_EMPTY", lambda: parse_stl(_binary(())))


def test_complete_ascii_grammar() -> None:
    """A readable prefix cannot hide incomplete facets or tokens after endsolid."""
    payload = _ascii(_cuboid((17.0, 11.0, 7.0)))
    variants = (payload + b"unexpected\n", payload.replace(b"outer loop", b"outer", 1),
                payload.replace(b"endfacet\n", b"", 1), payload.replace(b"vertex 0 0 0\n", b"", 1),
                payload.replace(b"endsolid public_specimen\n", b""),
                payload.replace(b"outer loop\n", b"outer loop\nvertex 9 9 9\n", 1))
    for damaged in variants:
        _reject("STL_ASCII_SYNTAX", lambda: parse_stl(damaged))
    _reject("STL_EMPTY", lambda: parse_stl(b"solid empty\nendsolid empty\n"))


def test_every_normal_and_coordinate_must_be_finite() -> None:
    """Late-record corruption must be rejected even when all earlier faces are finite."""
    triangles = _cuboid((17.0, 11.0, 7.0))
    for value in (math.nan, math.inf, -math.inf):
        for axis in range(3):
            for vertex_index, vertex in enumerate(triangles[-1]):
                point = (value if axis == 0 else vertex[0], value if axis == 1 else vertex[1],
                         value if axis == 2 else vertex[2])
                a, b, c = triangles[-1]
                damaged_triangle: Triangle = (point if vertex_index == 0 else a,
                                              point if vertex_index == 1 else b,
                                              point if vertex_index == 2 else c)
                damaged = triangles[:-1] + (damaged_triangle,)
                for payload in (_binary(damaged), _ascii(damaged)):
                    _reject("STL_NONFINITE", lambda: parse_stl(payload))
            binary = _binary(triangles)
            offset = 84 + (len(triangles) - 1) * 50 + axis * 4
            binary_normal = binary[:offset] + struct.pack("<f", value) + binary[offset + 4:]
            normal = (value if axis == 0 else 0.0, value if axis == 1 else 0.0, value if axis == 2 else 0.0)
            ascii_head, ascii_tail = _ascii(triangles).rsplit(b"facet normal 0 0 0", 1)
            normal_line = ("facet normal " + " ".join(format(number, ".9g") for number in normal)).encode("ascii")
            ascii_normal = ascii_head + normal_line + ascii_tail
            for payload in (binary_normal, ascii_normal):
                _reject("STL_NONFINITE", lambda: parse_stl(payload))


def test_degenerate_open_and_inconsistent_faces_are_rejected() -> None:
    """Correct bounds and vertex values do not make damaged topology acceptable."""
    triangles = _cuboid((17.0, 11.0, 7.0))
    bounds = ((0.0, 0.0, 0.0), (17.0, 11.0, 7.0))
    a, b, c = triangles[0]
    degenerate = ((a, a, c),) + triangles[1:]
    flipped = ((a, c, b),) + triangles[1:]
    for encoder in (_binary, _ascii):
        _reject("STL_DEGENERATE", lambda: validate_stl(encoder(degenerate), bounds, 1309.0))
        _reject("STL_TOPOLOGY", lambda: validate_stl(encoder(triangles[:-1]), bounds, 1309.0))
        _reject("STL_TOPOLOGY", lambda: validate_stl(encoder(flipped), bounds, 1309.0))


def test_bounds_and_volume_are_independent_requirements() -> None:
    """A translated box and a same-bounds tetrahedron fail different geometric contracts."""
    size = (17.0, 11.0, 7.0)
    triangles = _cuboid(size)
    shifted = tuple(((a[0] + 1, a[1], a[2]), (b[0] + 1, b[1], b[2]), (c[0] + 1, c[1], c[2]))
                    for a, b, c in triangles)
    bounds = ((0.0, 0.0, 0.0), size)
    for encoder in (_binary, _ascii):
        _reject("STL_BOUNDS", lambda: validate_stl(encoder(shifted), bounds, 1309.0))
        wrong_bounds = (((1.0, 0.0, 0.0), size), ((0.0, 1.0, 0.0), size), ((0.0, 0.0, 1.0), size),
                        ((0.0, 0.0, 0.0), (16.0, 11.0, 7.0)),
                        ((0.0, 0.0, 0.0), (17.0, 10.0, 7.0)),
                        ((0.0, 0.0, 0.0), (17.0, 11.0, 6.0)))
        for expected in wrong_bounds:
            _reject("STL_BOUNDS", lambda: validate_stl(encoder(triangles), expected, 1309.0))
        _reject("STL_VOLUME", lambda: validate_stl(encoder(_tetrahedron(size)), bounds, 1309.0))
        tetrahedron = validate_stl(encoder(_tetrahedron(size)), bounds, 1309.0 / 6.0)
        assert tetrahedron["triangle_count"] == 4
        assert math.isclose(_number(tetrahedron, "signed_volume_mm3"), 1309.0 / 6.0, abs_tol=1e-6)


def test_consistent_reverse_winding_retains_signed_volume() -> None:
    """Whole-surface orientation is retained rather than silently rewritten."""
    triangles = tuple((a, c, b) for a, b, c in _cuboid((17.0, 11.0, 7.0)))
    summary = validate_stl(_binary(triangles), ((0.0, 0.0, 0.0), (17.0, 11.0, 7.0)), 1309.0)
    assert math.isclose(_number(summary, "signed_volume_mm3"), -1309.0, abs_tol=1e-6)


def test_fresh_cuboid_generation_has_the_required_geometry() -> None:
    """Fresh public fixtures have measured shape, and invalid dimensions never become files."""
    for size, volume in (((17.0, 11.0, 7.0), 1309.0), ((20.0, 10.0, 6.0), 1200.0)):
        for format_name in ("binary", "ascii"):
            payload = make_cuboid_stl(size, format_name)
            assert isinstance(payload, bytes)
            summary = validate_stl(payload, ((0.0, 0.0, 0.0), size), volume)
            assert summary["format"] == format_name
            assert summary["triangle_count"] == 12
            assert math.isclose(abs(_number(summary, "signed_volume_mm3")), volume, abs_tol=1e-6)
    for size in ((0.0, 11.0, 7.0), (-17.0, 11.0, 7.0), (math.nan, 11.0, 7.0), (17.0, math.inf, 7.0)):
        _reject("CUBOID_DIMENSIONS", lambda: make_cuboid_stl(size, "binary"))
    _reject("STL_ENCODING", lambda: make_cuboid_stl((17.0, 11.0, 7.0), "json"))


def main() -> int:
    """Run every permanent pure case once; any exception makes the process fail."""
    tests = (test_complete_ascii_and_binary_geometry, test_binary_header_and_attributes_are_not_format_shortcuts,
             test_complete_binary_consumption, test_complete_ascii_grammar,
             test_every_normal_and_coordinate_must_be_finite,
             test_degenerate_open_and_inconsistent_faces_are_rejected,
             test_bounds_and_volume_are_independent_requirements,
             test_consistent_reverse_winding_retains_signed_volume,
             test_fresh_cuboid_generation_has_the_required_geometry)
    failures: list[str] = []
    for test in tests:
        try:
            test()
            print("PASS " + test.__name__)
        except Exception as error:
            failures.append(test.__name__)
            print("FAIL " + test.__name__ + ": " + repr(error))
    return min(1, len(failures))


if __name__ == "__main__":
    raise SystemExit(main())
