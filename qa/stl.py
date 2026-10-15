"""Pure, complete STL decoding and millimetre geometry measurements.

The serialized order and all input bytes remain authoritative. No function performs
I/O, repairs topology, welds nearby vertices, or modifies caller-owned geometry.
"""

from __future__ import annotations

import hashlib
import math
import re
import struct
from fractions import Fraction


# Immutable coordinates are millimetres; triangle order is the file's order.
Point = tuple[float, float, float]
Triangle = tuple[Point, Point, Point]
Bounds = tuple[Point, Point]
Triangles = tuple[Triangle, ...]
RationalPoint = tuple[Fraction, Fraction, Fraction]


def _encoding(content: bytes) -> str:
    if len(content) >= 84 and len(content) == 84 + struct.unpack_from("<I", content, 80)[0] * 50:
        return "binary"
    return "ascii" if content.lstrip().startswith(b"solid") else "binary"


def _finite_point(numbers: tuple[float, ...]) -> Point:
    if not all(math.isfinite(number) for number in numbers):
        raise ValueError("STL_NONFINITE")
    return numbers[0], numbers[1], numbers[2]


def _parse_binary(content: bytes) -> Triangles:
    """Decode every 50-byte record; metadata never replaces length validation."""
    if len(content) < 84:
        raise ValueError("STL_BINARY_LENGTH")
    triangle_count = struct.unpack_from("<I", content, 80)[0]
    if len(content) != 84 + triangle_count * 50:
        raise ValueError("STL_BINARY_LENGTH")
    if triangle_count == 0:
        raise ValueError("STL_EMPTY")
    triangles: list[Triangle] = []
    for normal_x, normal_y, normal_z, ax, ay, az, bx, by, bz, cx, cy, cz, attribute in struct.iter_unpack(
            "<12fH", memoryview(content)[84:]):
        _finite_point((normal_x, normal_y, normal_z))
        triangles.append((_finite_point((ax, ay, az)), _finite_point((bx, by, bz)), _finite_point((cx, cy, cz))))
    return tuple(triangles)


def _parse_ascii(content: bytes) -> Triangles:
    """Require complete ASCII facet grammar, including the final endsolid line."""
    try:
        text = content.decode("ascii")
    except UnicodeDecodeError:
        raise ValueError("STL_ASCII_SYNTAX") from None
    lines = text.strip().splitlines()
    if len(lines) < 2 or re.fullmatch(r"\s*solid(?:[ \t]+[^\r\n]*)?\s*", lines[0]) is None:
        raise ValueError("STL_ASCII_SYNTAX")
    if re.fullmatch(r"\s*endsolid(?:[ \t]+[^\r\n]*)?\s*", lines[-1]) is None:
        raise ValueError("STL_ASCII_SYNTAX")
    tokens = " ".join(lines[1:-1]).split()
    if not tokens:
        raise ValueError("STL_EMPTY")
    if len(tokens) % 21:
        raise ValueError("STL_ASCII_SYNTAX")
    triangles: list[Triangle] = []
    for offset in range(0, len(tokens), 21):
        facet = tokens[offset:offset + 21]
        if (facet[:2] != ["facet", "normal"] or facet[5:7] != ["outer", "loop"]
                or any(facet[index] != "vertex" for index in (7, 11, 15))
                or facet[19:] != ["endloop", "endfacet"]):
            raise ValueError("STL_ASCII_SYNTAX")
        try:
            normal = tuple(float(number) for number in facet[2:5])
            points = tuple(tuple(float(number) for number in facet[index + 1:index + 4])
                           for index in (7, 11, 15))
        except ValueError:
            raise ValueError("STL_ASCII_SYNTAX") from None
        _finite_point(normal)
        triangles.append((_finite_point(points[0]), _finite_point(points[1]), _finite_point(points[2])))
    return tuple(triangles)


def parse_stl(content: bytes) -> Triangles:
    """Consume binary/ASCII bytes and return finite vertices in serialized order.

    ValueError has one stable STL_* code. Zero normals and arbitrary binary
    header/attribute bytes are legal; trailing bytes or tokens are not.
    """
    if not content:
        raise ValueError("STL_EMPTY")
    return _parse_binary(content) if _encoding(content) == "binary" else _parse_ascii(content)


def _rational_point(point: Point) -> RationalPoint:
    return Fraction(point[0]), Fraction(point[1]), Fraction(point[2])


def _cross(first: RationalPoint, second: RationalPoint) -> RationalPoint:
    return (first[1] * second[2] - first[2] * second[1],
            first[2] * second[0] - first[0] * second[2],
            first[0] * second[1] - first[1] * second[0])


def _subtract(first: RationalPoint, second: RationalPoint) -> RationalPoint:
    return first[0] - second[0], first[1] - second[1], first[2] - second[2]


def _coordinate_extents(triangles: Triangles, axis: int) -> tuple[float, float]:
    coordinates = tuple(vertex[axis] for triangle in triangles for vertex in triangle)
    return min(coordinates), max(coordinates)


def validate_stl(content: bytes, expected_bounds_mm: Bounds, expected_volume_mm3: float, *,
                 abs_tol_mm: float = 0.0001, abs_tol_mm3: float = 0.001) -> dict[str, object]:
    """Measure a closed consistently oriented mesh without welding or repair.

    Exact rational predicates over the decoded finite coordinates decide area,
    directed-edge topology and signed volume. Absolute tolerances apply only to
    the declared bounds/volume comparison, not to topology. The six-field result
    includes SHA256 of the complete original serialization.
    """
    triangles = parse_stl(content)
    directed_edges: dict[tuple[Point, Point], int] = {}
    signed_volume_six = Fraction(0)
    for first, second, third in triangles:
        rational_first, rational_second, rational_third = (
            _rational_point(first), _rational_point(second), _rational_point(third))
        area = _cross(_subtract(rational_second, rational_first), _subtract(rational_third, rational_first))
        if area == (0, 0, 0):
            raise ValueError("STL_DEGENERATE")
        for start, end in ((first, second), (second, third), (third, first)):
            edge = (start, end)
            directed_edges[edge] = directed_edges.get(edge, 0) + 1
        volume_cross = _cross(rational_second, rational_third)
        signed_volume_six += sum(rational_first[axis] * volume_cross[axis] for axis in range(3))
    if any(count != 1 or directed_edges.get((end, start), 0) != 1
           for (start, end), count in directed_edges.items()):
        raise ValueError("STL_TOPOLOGY")
    x_extent, y_extent, z_extent = (_coordinate_extents(triangles, axis) for axis in range(3))
    minimum: Point = x_extent[0], y_extent[0], z_extent[0]
    maximum: Point = x_extent[1], y_extent[1], z_extent[1]
    bounds: Bounds = minimum, maximum
    if (not math.isfinite(abs_tol_mm) or abs_tol_mm < 0
            or any(not math.isfinite(expected_bounds_mm[side][axis])
                   or abs(bounds[side][axis] - expected_bounds_mm[side][axis]) > abs_tol_mm
                   for side in range(2) for axis in range(3))):
        raise ValueError("STL_BOUNDS")
    try:
        signed_volume_mm3 = float(signed_volume_six / 6)
    except OverflowError:
        raise ValueError("STL_VOLUME") from None
    if (not math.isfinite(expected_volume_mm3) or expected_volume_mm3 <= 0
            or not math.isfinite(abs_tol_mm3) or abs_tol_mm3 < 0
            or not math.isfinite(signed_volume_mm3)
            or abs(abs(signed_volume_mm3) - expected_volume_mm3) > abs_tol_mm3):
        raise ValueError("STL_VOLUME")
    return {"format": _encoding(content), "byte_count": len(content), "triangle_count": len(triangles),
            "bounds_mm": bounds, "signed_volume_mm3": signed_volume_mm3,
            "sha256": hashlib.sha256(content).hexdigest()}


def make_cuboid_stl(size_mm: Point, encoding: str) -> bytes:
    """Serialize a deterministic origin-based closed cuboid; sizes are millimetres.

    CUBOID_DIMENSIONS rejects nonfinite/nonpositive sides before serialization;
    STL_ENCODING rejects unsupported formats. This function never creates a file.
    """
    if not all(math.isfinite(side) and side > 0 for side in size_mm):
        raise ValueError("CUBOID_DIMENSIONS")
    if encoding not in ("binary", "ascii"):
        raise ValueError("STL_ENCODING")
    x, y, z = size_mm
    origin, x_tip, y_tip, far_xy = (0.0, 0.0, 0.0), (x, 0.0, 0.0), (0.0, y, 0.0), (x, y, 0.0)
    z_tip, far_xz, far_yz, far_xyz = (0.0, 0.0, z), (x, 0.0, z), (0.0, y, z), (x, y, z)
    triangles: Triangles = (
        (origin, far_xy, x_tip), (origin, y_tip, far_xy),
        (z_tip, far_xz, far_xyz), (z_tip, far_xyz, far_yz),
        (origin, x_tip, far_xz), (origin, far_xz, z_tip),
        (x_tip, far_xy, far_xyz), (x_tip, far_xyz, far_xz),
        (far_xy, y_tip, far_yz), (far_xy, far_yz, far_xyz),
        (y_tip, origin, z_tip), (y_tip, z_tip, far_yz))
    if encoding == "binary":
        try:
            serialized_sides = tuple(struct.unpack("<f", struct.pack("<f", side))[0] for side in size_mm)
            if not all(math.isfinite(side) and side > 0 for side in serialized_sides):
                raise ValueError("CUBOID_DIMENSIONS")
            records = b"".join(struct.pack("<12fH", 0.0, 0.0, 0.0, *first, *second, *third, 0)
                               for first, second, third in triangles)
        except (OverflowError, struct.error):
            raise ValueError("CUBOID_DIMENSIONS") from None
        return b"Public origin-based cuboid, millimetres".ljust(80, b"\0") + struct.pack("<I", 12) + records
    lines = ["solid cuboid_mm"]
    for triangle in triangles:
        lines.extend(("facet normal 0 0 0", "outer loop"))
        lines.extend("vertex " + " ".join(format(coordinate, ".17g") for coordinate in point)
                     for point in triangle)
        lines.extend(("endloop", "endfacet"))
    lines.append("endsolid cuboid_mm")
    return ("\n".join(lines) + "\n").encode("ascii")
