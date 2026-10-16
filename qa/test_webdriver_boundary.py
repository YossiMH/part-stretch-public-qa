"""Pure protocol/policy cases; literal messages are data, never a fake driver."""

from __future__ import annotations

import ast
import copy
import pathlib
import re
from collections.abc import Callable

from qa.webdriver import (admit_native_session, latest_stable_safari_version,
                          parse_webdriver_response, require_current_safari_version, write_next_action)


def _reject(code: str, operation: Callable[[], object]) -> None:
    """Require the public rejection code, rather than accepting an unrelated exception."""
    try:
        operation()
    except ValueError as error:
        assert error.args == (code,), (code, error.args)
        return
    raise AssertionError("Expected rejection: " + code)


def test_response_value_is_preserved_without_coercion() -> None:
    """Protocol values survive parsing without converting null or arrays to default objects."""
    body = b'{"value":{"sessionId":"synthetic-serialization-id","capabilities":{"browserName":"Safari","browserVersion":"27.0"}}}'
    value = parse_webdriver_response(200, body)
    assert value == {"sessionId": "synthetic-serialization-id",
                     "capabilities": {"browserName": "Safari", "browserVersion": "27.0"}}
    assert parse_webdriver_response(200, b'{"value":null}') is None
    assert parse_webdriver_response(200, b'{"value":{"ready":true}}') == {"ready": True}
    assert parse_webdriver_response(200, b'{"value":[0,"text",null]}') == [0, "text", None]


def test_page_error_text_remains_observation_data() -> None:
    """Page error text uses its own field, separate from a WebDriver refusal."""
    assert parse_webdriver_response(200, b'{"value":{"ui_error":"","editor":"absent"}}') == {
        "ui_error": "", "editor": "absent"}
    assert parse_webdriver_response(200, b'{"value":{"ui_error":"Invalid shrink","editor":"displayed"}}') == {
        "ui_error": "Invalid shrink", "editor": "displayed"}


def test_product_startup_requires_complete_document_and_both_handlers() -> None:
    """The observed preselection state cannot admit a file before handlers exist."""
    from qa.webdriver import product_startup_ready

    observed = {"document_ready": "interactive", "file_change_handler": "object", "browse_click_handler": "object"}
    assert product_startup_ready(observed) is False
    assert product_startup_ready({**observed, "document_ready": "complete"}) is False
    ready = {"document_ready": "complete", "file_change_handler": "function", "browse_click_handler": "function"}
    assert product_startup_ready(ready) is True
    assert product_startup_ready({**ready, "document_ready": "interactive"}) is False
    for handler in ("file_change_handler", "browse_click_handler"):
        assert product_startup_ready({**ready, handler: "object"}) is False
        assert product_startup_ready({key: value for key, value in ready.items() if key != handler}) is False
    assert product_startup_ready(None) is False


def test_model_readiness_rejects_the_observed_loading_geometry() -> None:
    """Reopening an edited STL can retain its old dimensions while loading."""
    from qa.native_safari import _matches_model

    observed = {"editor": "displayed", "units": "1", "dimensions": "20 × 11 × 7",
                "filename": "qa-native-guest.stl", "load_progress": "displayed", "load_error": ""}
    assert _matches_model(observed, (20.0, 11.0, 7.0)) is False
    settled = {**observed, "load_progress": "absent"}
    assert _matches_model(settled, (20.0, 11.0, 7.0)) is True
    assert _matches_model({**settled, "load_error": "Cannot load file"}, (20.0, 11.0, 7.0)) is False
    for field in ("load_progress", "load_error"):
        assert _matches_model({key: value for key, value in settled.items() if key != field},
                              (20.0, 11.0, 7.0)) is False
    assert observed["load_progress"] == "displayed"


def test_loaded_file_readiness_requires_its_exact_source_and_geometry() -> None:
    """Matching dimensions from the prior source cannot complete file adoption."""
    from qa.native_safari import _matches_model

    expected_filename = "qa-native-guest-edited.stl"
    observed = {"editor": "displayed", "units": "1", "dimensions": "20 × 11 × 7",
                "filename": "qa-native-guest.stl", "load_progress": "absent", "load_error": ""}
    assert _matches_model(observed, (20.0, 11.0, 7.0), expected_filename) is False
    adopted = {**observed, "filename": expected_filename}
    assert _matches_model(adopted, (20.0, 11.0, 7.0), expected_filename) is True
    for field, value in (("filename", ""), ("dimensions", "17 × 11 × 7"),
                         ("editor", "absent"), ("units", "25.4"), ("load_progress", "displayed")):
        assert _matches_model({**adopted, field: value}, (20.0, 11.0, 7.0), expected_filename) is False
    assert observed["filename"] == "qa-native-guest.stl"


def test_png_capture_dimensions_require_complete_ihdr() -> None:
    """Header dimensions describe the captured PNG, not a reported DOM rectangle."""
    from qa.native_safari import _png_dimensions

    header = (b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR" + (320).to_bytes(4, "big")
              + (240).to_bytes(4, "big") + b"\x08\x06\x00\x00\x00\x00\x00\x00\x00")
    assert _png_dimensions(header) == (320, 240)
    _reject("NATIVE_SCREENSHOT_NOT_PNG", lambda: _png_dimensions(b"not a PNG"))
    for damaged in (header[:-1], header[:8], header[:8] + b"\x00\x00\x00\x0c" + header[12:],
                    header[:12] + b"IDAT" + header[16:]):
        _reject("NATIVE_SCREENSHOT_HEADER", lambda: _png_dimensions(damaged))
    for width, height in ((0, 240), (320, 0), (0x80000000, 240), (320, 0x80000000)):
        damaged = header[:16] + width.to_bytes(4, "big") + height.to_bytes(4, "big") + header[24:]
        _reject("NATIVE_SCREENSHOT_DIMENSIONS", lambda: _png_dimensions(damaged))


def test_current_public_identity_requires_current_origin_release_and_bodies() -> None:
    """Current metadata cannot rescue a wrong origin or different served runtime bytes."""
    from qa.native_safari import _current_identity_matches

    observed = {"origin": "https://part-stretch-app.netlify.app",
                "release": "13aa60e02304d49b6e92bfc997ff027604b75c6f", "services": "required",
                "manifest_product_commit": "13aa60e02304d49b6e92bfc997ff027604b75c6f",
                "manifest_asset_source_commit": "13aa60e02304d49b6e92bfc997ff027604b75c6f",
                "body_sha256": {
                    "preview-release.json": "c878189c48e37d2f12893e2b4daebc32181cceda4ba5626ef2a8c894f76c7941",
                    "app.js": "00bda7479576df48f98b8183ed6bff1893216bf0c92fd3e3cbe5cfaaaf79ece6",
                    "viewer.js": "8a29738154aee3b2b193922b133ab79db91be8d227a9e7105c08a7f2e255dfc5"}}
    assert _current_identity_matches(observed) is True
    for field, wrong in (("origin", "https://part-stretch-free.pages.dev"),
                         ("release", "9b0731642df08c879cbea912b6ff7daf3401a164"),
                         ("services", "guest-beta"), ("manifest_product_commit", "79c9da3"),
                         ("manifest_asset_source_commit", "79c9da3")):
        assert _current_identity_matches({**observed, field: wrong}) is False
        assert _current_identity_matches({key: value for key, value in observed.items() if key != field}) is False
    body_hashes = observed["body_sha256"]
    for path in ("preview-release.json", "app.js", "viewer.js"):
        assert _current_identity_matches({**observed, "body_sha256": {**body_hashes, path: "0" * 64}}) is False
        assert _current_identity_matches({**observed, "body_sha256": {
            key: value for key, value in body_hashes.items() if key != path}}) is False
    assert _current_identity_matches({key: value for key, value in observed.items() if key != "body_sha256"}) is False
    assert _current_identity_matches(None) is False
    assert observed["release"] == "13aa60e02304d49b6e92bfc997ff027604b75c6f"


def test_camera_pair_requires_completed_same_canvas_images() -> None:
    """Only completed same-method/target/size captures can establish a changed pair."""
    from qa.native_safari import _camera_pair_changed

    before = {"capture_method": "element", "target": "#view", "outcome": "completed",
              "png_width": 656, "png_height": 451, "sha256": "0" * 64}
    after = {**before, "sha256": "1" * 64}
    original_before, original_after = dict(before), dict(after)
    assert _camera_pair_changed(before, after) is True
    assert _camera_pair_changed(before, before) is False
    for field, value in (("capture_method", "viewport"), ("target", "#editor"),
                         ("outcome", "unsupported"), ("outcome", "unknown"),
                         ("png_width", 657), ("png_height", 452), ("png_width", 0),
                         ("png_height", -1), ("png_width", True), ("png_height", "451"),
                         ("sha256", ""), ("sha256", "not-a-hash")):
        assert _camera_pair_changed(before, {**after, field: value}) is False
        assert _camera_pair_changed({**before, field: value}, after) is False
    for field in before:
        assert _camera_pair_changed(before, {key: value for key, value in after.items() if key != field}) is False
    for missing in (None, [], {}):
        assert _camera_pair_changed(before, missing) is False
        assert _camera_pair_changed(missing, after) is False
    assert before == original_before and after == original_after


def test_current_model_retains_its_original_dimensions_after_edit() -> None:
    """Edited dimensions cannot replace the separately observed original source size."""
    from qa.native_safari import _current_original_dimensions_match

    imported = {"dimensions": "17 x 11 x 7", "original_dimensions": "17 x 11 x 7"}
    edited = {**imported, "dimensions": "20 x 11 x 7"}
    assert _current_original_dimensions_match(imported) is True
    assert _current_original_dimensions_match(edited) is True
    for wrong in ("18 x 11 x 7", "20 x 11 x 7", "17 x 12 x 7", "17 x 11 x 8", "", None):
        assert _current_original_dimensions_match({**edited, "original_dimensions": wrong}) is False
    assert _current_original_dimensions_match({"dimensions": "20 x 11 x 7"}) is False
    assert imported["original_dimensions"] == "17 x 11 x 7"


def test_json_and_envelope_errors_cannot_become_success() -> None:
    """Malformed bytes, absent values and failed HTTP responses cannot admit a command."""
    for body in (b'not json', b'{"value":null} trailing', b'{"value":"\xff"}',
                 b'{"value":NaN}', b'{"value":[Infinity]}'):
        _reject("WEBDRIVER_JSON", lambda: parse_webdriver_response(200, body))
    for body in (b'[]', b'null', b'{}', b'{"result":null}', b'{"value":{"error":42}}', b'{"value":{"error":""}}'):
        _reject("WEBDRIVER_ENVELOPE", lambda: parse_webdriver_response(200, body))
    for status in (199, 302, 403, 500):
        _reject("WEBDRIVER_HTTP_STATUS", lambda: parse_webdriver_response(status, b'{"value":null}'))


def test_current_canvas_placement_scrolls_only_a_safe_reachable_gutter() -> None:
    """The recorded crop needs one page scroll; fit and target failures must not dispatch it."""
    from qa.native_safari import _current_canvas_placement

    clipped = {"rectangle": [32, 424.765625, 656, 451], "viewport": [1024, 716],
               "scroll_y": 0, "scroll_max_y": 500, "gutter_point": [16, 358], "gutter_target": "page-gutter"}
    assert _current_canvas_placement(clipped) == {"action": "wheel", "x": 16, "y": 358, "delta_y": 176}
    assert _current_canvas_placement({**clipped, "scroll_max_y": 160}) == {
        "action": "wheel", "x": 16, "y": 358, "delta_y": 160}
    assert _current_canvas_placement({**clipped, "rectangle": [32, 100, 656, 451],
                                      "gutter_target": "unsafe"}) == {"action": "none"}
    _reject("NATIVE_CURRENT_CANVAS_CANNOT_FIT", lambda: _current_canvas_placement(
        {**clipped, "rectangle": [32, 0, 656, 717]}))
    _reject("NATIVE_CURRENT_CANVAS_CANNOT_FIT", lambda: _current_canvas_placement({**clipped, "scroll_max_y": 80}))
    _reject("NATIVE_CURRENT_CANVAS_UNSAFE_GUTTER", lambda: _current_canvas_placement({**clipped, "gutter_target": "unsafe"}))
    _reject("NATIVE_CURRENT_CANVAS_UNSAFE_GUTTER", lambda: _current_canvas_placement({**clipped, "gutter_point": [100, 500]}))
    assert clipped["rectangle"] == [32, 424.765625, 656, 451]


def test_remote_error_code_is_retained_without_raw_message() -> None:
    """A diagnostic code is useful without exposing a raw session message or stack."""
    body = b'{"value":{"error":"invalid argument","message":"must-not-be-logged/session/private-path","stacktrace":"must-not-be-logged"}}'
    for status in (200, 400):
        _reject("WEBDRIVER_REMOTE_ERROR:invalid argument", lambda: parse_webdriver_response(status, body))
    _reject("WEBDRIVER_REMOTE_ERROR:session not created", lambda: parse_webdriver_response(
        500, b'{"value":{"error":"session not created","message":"must-not-be-logged"}}'))


def test_native_admission_requires_actual_host_and_session_fields() -> None:
    """Plausible Safari text cannot rescue another host/browser or an absent version."""
    capabilities = {"browserName": "Safari", "browserVersion": "27.0", "unrelated": "ignored"}
    original = dict(capabilities)
    assert admit_native_session("Darwin", capabilities) == {"browser_name": "safari", "browser_version": "27.0"}
    assert capabilities == original
    assert admit_native_session("Darwin", {"browserName": "safari", "browserVersion": "27.0.1"}) == {
        "browser_name": "safari", "browser_version": "27.0.1"}
    for host in ("Windows", "Linux", "", "darwin"):
        _reject("NATIVE_MACOS_REQUIRED", lambda: admit_native_session(host, capabilities))
    for name in ("chrome", "WebKit", "Safari Technology Preview", "", None):
        _reject("NATIVE_SAFARI_REQUIRED", lambda: admit_native_session(
            "Darwin", {"browserName": name, "browserVersion": "27.0", "userAgent": "Safari/27.0"}))
    for version in ("", " ", None, 27, True):
        _reject("NATIVE_SAFARI_VERSION_REQUIRED", lambda: admit_native_session(
            "Darwin", {"browserName": "Safari", "browserVersion": version}))
    for malformed in (None, [], {"value": capabilities}, {"error": "session not created"}):
        _reject("NATIVE_SAFARI_REQUIRED", lambda: admit_native_session("Darwin", malformed))


def test_current_safari_release_includes_whole_major_labels() -> None:
    """The current whole-major release cannot be replaced by an older decimal row."""
    observed = latest_stable_safari_version("Safari 26.6\nSafari 27")
    assert observed == "27", observed
    assert latest_stable_safari_version("Safari 26.6\nSafari 27.1") == "27.1"


def test_current_safari_version_normalizes_only_equivalent_trailing_zeros() -> None:
    """27 and 27.0 match; genuinely older/newer installed versions still fail."""
    assert require_current_safari_version("27.0", "27") is None
    assert require_current_safari_version("27", "27.0") is None
    for installed in ("26.6", "27.1"):
        _reject("NATIVE_SAFARI_NOT_CURRENT_STABLE:" + installed + ":27",
                lambda: require_current_safari_version(installed, "27"))


def test_only_known_unexecuted_writes_can_be_dispatched() -> None:
    """The decision returns an instruction and never invents completion or a retry."""
    assert write_next_action("operation-1", "", "not-dispatched") == "dispatch-once"
    assert write_next_action("operation-1", "operation-1", "confirmed-not-executed") == "dispatch-once"
    assert write_next_action("operation-1", "operation-1", "completed") == "retain-result"
    assert write_next_action("operation-1", "operation-1", "refused") == "stop-refused"
    for observed_id in ("", "operation-1"):
        assert write_next_action("operation-1", observed_id, "unknown") == "inspect-same-operation"


def test_foreign_or_missing_receipts_cannot_authorize_replay() -> None:
    """Only this operation's matching observations may authorize further effects."""
    for outcome in ("not-dispatched", "confirmed-not-executed", "completed", "unknown", "refused"):
        _reject("WRITE_ID_MISMATCH", lambda: write_next_action("operation-1", "operation-2", outcome))
    for outcome in ("confirmed-not-executed", "completed", "refused"):
        _reject("WRITE_OBSERVATION_REQUIRED", lambda: write_next_action("operation-1", "", outcome))
    _reject("WRITE_ID_REQUIRED", lambda: write_next_action("", "", "unknown"))
    _reject("WRITE_OUTCOME", lambda: write_next_action("operation-1", "operation-1", "not-dispatched"))
    for outcome in ("timeout", "failed", "", "retry"):
        _reject("WRITE_OUTCOME", lambda: write_next_action("operation-1", "operation-1", outcome))


def _draw_observation() -> dict[str, object]:
    """Compact telemetry input only; it neither draws pixels nor emulates a browser.

    Pixel coordinates use the default framebuffer's bottom-left origin. The
    three interior foreground pixels occupy (1,1), (2,2), (3,3); the other 22
    pixels match the opaque clear color. Bounds are inclusive pixel coordinates.
    """
    return {
        "observer": "completed", "native_click": "completed", "record_count": 1,
        "event": {"type": "click", "trust": "trusted", "target": "[data-view=fit]",
                  "order": "document-bubble-after-target", "click_started_ms": 100.0,
                  "event_timestamp_ms": 101.0, "observed_ms": 102.0, "click_completed_ms": 103.0},
        "visibility": {
            "document": "visible", "focus": "focused", "active_element": "button[data-view=fit]",
            "canvas": {"display": "block", "visibility": "visible", "opacity": 1.0,
                       "rectangle": [32.0, 100.0, 5.0, 5.0]},
            "overlay": {"display": "none", "visibility": "hidden", "opacity": 0.0,
                        "rectangle": [0.0, 0.0, 0.0, 0.0]},
            "viewport": [1024.0, 716.0], "scroll": [0.0, 176.0]},
        "gl": {
            "context": "webgl2", "context_status": "healthy", "framebuffer": "default",
            "context_attributes": {"alpha": False, "preserveDrawingBuffer": False},
            "drawing_buffer": [5, 5], "viewport": [0, 0, 5, 5], "program_link": "linked",
            "shader_logs": [{"type": "vertex", "status": "compiled", "log": ""},
                            {"type": "fragment", "status": "compiled", "log": ""}],
            "uniforms": {"eye": [0.0, 0.0, 30.0], "right": [1.0, 0.0, 0.0],
                         "up": [0.0, 1.0, 0.0], "forward": [0.0, 0.0, -1.0],
                         "scale": [1.0, 1.0], "planes": [0.1, 100.0]},
            "position_buffer_bytes": 432},
        "pixels": {
            "readback": "completed", "error": "", "width": 5, "height": 5, "byte_length": 100,
            "sentinel_rgba": [19, 37, 73, 109], "sentinel_unchanged_count": 0,
            "zero_pixel_count": 0, "opaque_pixel_count": 25, "clear_rgba": [215, 215, 215, 255],
            "clear_pixel_count": 22, "unique_color_count": 3, "foreground_count": 3,
            "foreground_bounds": [1, 1, 3, 3],
            "samples": [{"x": 0, "y": 0, "rgba": [215, 215, 215, 255]},
                        {"x": 4, "y": 0, "rgba": [215, 215, 215, 255]},
                        {"x": 0, "y": 4, "rgba": [215, 215, 215, 255]},
                        {"x": 4, "y": 4, "rgba": [215, 215, 215, 255]},
                        {"x": 2, "y": 2, "rgba": [224, 160, 91, 255]}]}}


def _require_draw_class(observation: object, expected: str) -> None:
    """Pixel telemetry cannot establish visible geometry, including on admission failure."""
    from qa.native_safari import _classify_draw_observation

    original = copy.deepcopy(observation)
    result = _classify_draw_observation(observation)
    assert result["pixel_class"] == expected, result
    assert result["native_visible_model"] == "UNESTABLISHED", result
    assert observation == original


def test_draw_pixels_distinguish_clear_flat_and_bounded_raster_content() -> None:
    """Varied bounded raster content says nothing about the native screenshot's model."""
    observation = _draw_observation()
    pixels = observation["pixels"]
    assert isinstance(pixels, dict)
    _require_draw_class(observation, "RASTER_CONTENT_OBSERVED")
    clear_samples = [{**sample, "rgba": [215, 215, 215, 255]} for sample in pixels["samples"]]
    clear = {**pixels, "clear_pixel_count": 25, "unique_color_count": 1,
             "foreground_count": 0, "foreground_bounds": [], "samples": clear_samples}
    _require_draw_class({**observation, "pixels": clear}, "CLEAR_ONLY")
    flat = {**pixels, "clear_pixel_count": 0, "unique_color_count": 1,
            "foreground_count": 25, "foreground_bounds": [0, 0, 4, 4],
            "samples": [{**sample, "rgba": [224, 160, 91, 255]} for sample in pixels["samples"]]}
    _require_draw_class({**observation, "pixels": flat}, "FLAT_UNCLASSIFIED")


def test_draw_pixels_reject_unchanged_sentinel_zero_and_failed_readback() -> None:
    """Silent readback failure cannot look like successful rasterization."""
    observation = _draw_observation()
    pixels = observation["pixels"]
    assert isinstance(pixels, dict)
    sentinel = {**pixels, "sentinel_unchanged_count": 25, "opaque_pixel_count": 0,
                "clear_pixel_count": 0, "unique_color_count": 1, "foreground_count": 25,
                "foreground_bounds": [0, 0, 4, 4],
                "samples": [{**sample, "rgba": [19, 37, 73, 109]} for sample in pixels["samples"]]}
    zero = {**sentinel, "sentinel_unchanged_count": 0, "zero_pixel_count": 25,
            "samples": [{**sample, "rgba": [0, 0, 0, 0]} for sample in pixels["samples"]]}
    for invalid in (sentinel, zero, {**pixels, "readback": "unknown"},
                    {**pixels, "error": "SecurityError"}, {**pixels, "opaque_pixel_count": 24},
                    {**pixels, "sentinel_unchanged_count": 1}):
        _require_draw_class({**observation, "pixels": invalid}, "UNKNOWN")


def test_draw_pixels_require_finite_bounded_consistent_summary() -> None:
    """Malformed dimensions, counts, bounds and samples cannot qualify raster content."""
    observation = _draw_observation()
    pixels = observation["pixels"]
    assert isinstance(pixels, dict)
    for field, value in (("width", 0), ("height", -1), ("width", True), ("height", "5"),
                         ("width", float("nan")), ("height", float("inf")),
                         ("byte_length", 99), ("byte_length", 2097153),
                         ("clear_pixel_count", 23), ("foreground_count", 26),
                         ("unique_color_count", 0), ("unique_color_count", 26),
                         ("foreground_bounds", [0, 1, 3, 3]),
                         ("foreground_bounds", [3, 1, 1, 3]),
                         ("foreground_bounds", [1, 1, 5, 3]),
                         ("clear_rgba", [215, 215, 215, 0])):
        _require_draw_class({**observation, "pixels": {**pixels, field: value}}, "UNKNOWN")
    graphics = observation["gl"]
    assert isinstance(graphics, dict)
    for width, height, expected in ((1024, 512, "RASTER_CONTENT_OBSERVED"), (1024, 513, "UNKNOWN")):
        bounded = {**pixels, "width": width, "height": height, "byte_length": width * height * 4,
                   "opaque_pixel_count": width * height, "clear_pixel_count": width * height - 3,
                   "samples": [{"x": x, "y": y, "rgba": [215, 215, 215, 255]}
                               for x, y in ((0, 0), (width - 1, 0), (0, height - 1),
                                            (width - 1, height - 1), (width // 2, height // 2))]}
        _require_draw_class({**observation, "pixels": bounded,
                             "gl": {**graphics, "drawing_buffer": [width, height],
                                    "viewport": [0, 0, width, height]}}, expected)
    samples = pixels["samples"]
    for damaged in (samples[:-1], [samples[0]] * 5,
                    [{**samples[0], "x": 5}, *samples[1:]],
                    [{**samples[0], "rgba": [224, 160, 91, 255]}, *samples[1:]],
                    [*samples[:-1], {**samples[-1], "rgba": [224, 160, 91, 254]}]):
        _require_draw_class({**observation, "pixels": {**pixels, "samples": damaged}}, "UNKNOWN")
    for field in pixels:
        _require_draw_class({**observation, "pixels": {
            key: value for key, value in pixels.items() if key != field}}, "UNKNOWN")


def test_draw_observer_requires_one_completed_trusted_ordered_fit_event() -> None:
    """Missing, duplicate, foreign or uncertain input records never authorize another click."""
    observation = _draw_observation()
    event = observation["event"]
    assert isinstance(event, dict)
    for field, value in (("observer", "absent"), ("observer", "unknown"),
                         ("native_click", "unknown"), ("record_count", 0),
                         ("record_count", 2), ("record_count", True)):
        _require_draw_class({**observation, field: value}, "UNKNOWN")
    for field, value in (("type", "pointerup"), ("trust", "untrusted"), ("target", "[data-view=top]"),
                         ("order", "unknown"), ("observed_ms", 99.0),
                         ("observed_ms", 100.5), ("observed_ms", 104.0),
                         ("event_timestamp_ms", 99.0), ("event_timestamp_ms", 104.0),
                         ("event_timestamp_ms", float("nan")),
                         ("click_completed_ms", float("inf"))):
        _require_draw_class({**observation, "event": {**event, field: value}}, "UNKNOWN")
    for field in observation:
        _require_draw_class({key: value for key, value in observation.items() if key != field}, "UNKNOWN")
    for field in event:
        _require_draw_class({**observation, "event": {
            key: value for key, value in event.items() if key != field}}, "UNKNOWN")
    for missing in (None, [], {}):
        _require_draw_class(missing, "UNKNOWN")


def test_draw_observation_requires_visible_admitted_canvas_and_existing_healthy_gl() -> None:
    """Environment and incomplete GL observations stay unknown without repairing the page."""
    observation = _draw_observation()
    visibility, graphics = observation["visibility"], observation["gl"]
    assert isinstance(visibility, dict) and isinstance(graphics, dict)
    canvas = visibility["canvas"]
    assert isinstance(canvas, dict)
    for field, value in (("document", "hidden"), ("focus", "unfocused"),
                         ("viewport", [0, 716]), ("scroll", [0, float("nan")])):
        _require_draw_class({**observation, "visibility": {**visibility, field: value}}, "UNKNOWN")
    for field, value in (("display", "none"), ("visibility", "hidden"), ("opacity", 0.0),
                         ("rectangle", [32, 100, 0, 5]), ("rectangle", [32, 714, 5, 5])):
        _require_draw_class({**observation, "visibility": {
            **visibility, "canvas": {**canvas, field: value}}}, "UNKNOWN")
    for field, value in (("context", "missing"), ("context_status", "lost"),
                         ("framebuffer", "non-default"), ("program_link", "failed"),
                         ("drawing_buffer", [5, 6]), ("viewport", [0, 0, 4, 5]),
                         ("position_buffer_bytes", 0), ("position_buffer_bytes", float("nan")),
                         ("context_attributes", {"alpha": True, "preserveDrawingBuffer": False})):
        _require_draw_class({**observation, "gl": {**graphics, field: value}}, "UNKNOWN")
    uniforms = graphics["uniforms"]
    assert isinstance(uniforms, dict)
    for field, value in (("eye", [0, 0, float("inf")]), ("right", [1, 0]),
                         ("scale", [1.0]), ("scale", [float("nan"), 1.0]),
                         ("scale", [1.0, float("inf")]), ("scale", 1.0),
                         ("scale", float("nan")), ("planes", [0.1, float("inf")])):
        _require_draw_class({**observation, "gl": {
            **graphics, "uniforms": {**uniforms, field: value}}}, "UNKNOWN")
    for section, record in (("visibility", visibility), ("gl", graphics)):
        for field in record:
            _require_draw_class({**observation, section: {
                key: value for key, value in record.items() if key != field}}, "UNKNOWN")


def test_diagnostic_captures_retain_originals_without_claiming_native_visible_model() -> None:
    """Two completed native originals remain pending actual viewing; unknown remains unknown."""
    from qa.native_safari import _diagnostic_capture_provenance

    canvas = {"name": "draw-canvas", "capture_method": "element", "target": "#view",
              "outcome": "completed", "command_outcome": "completed",
              "png_width": 656, "png_height": 451, "png_bytes": 12000, "sha256": "0" * 64}
    viewport = {**canvas, "capture_method": "viewport", "target": "viewport",
                "png_width": 1024, "png_height": 716, "sha256": "1" * 64, "name": "draw-viewport"}
    originals = [canvas, viewport]
    before = copy.deepcopy(originals)
    completed = _diagnostic_capture_provenance(originals)
    assert completed["capture_status"] == "COMPLETED_ORIGINALS"
    assert completed["native_visible_model"] == "UNESTABLISHED"
    assert completed["originals"] == originals
    for images in ([], [canvas], [canvas, canvas], [viewport, canvas, viewport],
                   [canvas, {**viewport, "outcome": "unknown"}],
                   [canvas, {**viewport, "command_outcome": "unknown"}],
                   [canvas, {"name": "draw-viewport", "capture_method": "viewport", "target": "viewport",
                             "outcome": "unknown", "command_outcome": "unknown"}],
                   [{**canvas, "outcome": "unsupported"}, viewport],
                   [{**canvas, "capture_method": "readPixels"}, viewport],
                   [{**canvas, "target": "#editor"}, viewport],
                   [canvas, {**viewport, "png_bytes": 262145}],
                   [canvas, {**viewport, "png_width": 0}],
                   [canvas, {**viewport, "sha256": ""}],
                   [canvas, {**viewport, "name": "draw-canvas"}],
                   [canvas, {key: value for key, value in viewport.items() if key != "outcome"}]):
        retained = copy.deepcopy(images)
        result = _diagnostic_capture_provenance(images)
        assert result["capture_status"] == "UNKNOWN", result
        assert result["native_visible_model"] == "UNESTABLISHED", result
        assert result["originals"] == images
        assert images == retained
    assert originals == before


def test_native_phase_contract_preserves_full_current_and_legacy_predecessors() -> None:
    """One phase contract owns handler, predecessors, result name and diagnostic limits."""
    from qa import native_safari

    current = native_safari._phase_contract("current")
    assert current["handler"] is native_safari._current_diagnostic
    assert current["previous_phases"] == ()
    assert current["result_name"] == "current-public-native-draw-diagnostic"
    assert current["image_limit"] == 2
    assert current["edit_policy"] == "forbidden"
    full = native_safari._phase_contract("full-current")
    assert full["handler"] is native_safari._current_product
    assert full["previous_phases"] == ()
    assert full["result_name"] == "current-public-native-import-edit-render"
    assert full["edit_policy"] == "existing-import-edit-camera"
    for phase, handler, predecessors in (("integration", native_safari._integration, ()),
                                         ("guest", native_safari._product, ("integration",)),
                                         ("controls", native_safari._product, ("integration", "guest"))):
        contract = native_safari._phase_contract(phase)
        assert contract["handler"] is handler
        assert contract["previous_phases"] == predecessors
    no_results = pathlib.Path(__file__).resolve().parent / "no-same-run-predecessor-needed"
    for phase in ("current", "full-current"):
        assert native_safari._prerequisites(no_results, "pure-phase-contract", phase, []) == 0
    _reject("NATIVE_PHASE_UNKNOWN", lambda: native_safari._phase_contract("future-current"))


def test_real_unchanged_yaml_selects_diagnostic_in_actual_parser_contract() -> None:
    """Read the real literal invoker; no YAML dependency or second phase table is needed."""
    from qa import native_safari

    workflow = (pathlib.Path(__file__).resolve().parents[1] / "codemagic.yaml").read_text(encoding="utf-8")
    loops = re.findall(r'^\s*for phase in (\([^\n]+\)):\s*$', workflow, re.MULTILINE)
    assert len(loops) == 1, loops
    selected = ast.literal_eval(loops[0])
    assert selected == ("current",), selected
    assert '"-m", "qa.native_safari", phase' in workflow
    assert '"--deadline-seconds", "55"' in workflow
    parser = native_safari._argument_parser()
    arguments = parser.parse_args([selected[0], "--output", ".qa-runs/pure-phase/current",
                                   "--run-id", "pure-phase", "--deadline-seconds", "55"])
    contract = native_safari._phase_contract(arguments.phase)
    assert arguments.phase == "current"
    assert contract["handler"] is native_safari._current_diagnostic
    assert contract["result_name"] == "current-public-native-draw-diagnostic"
    assert contract["image_limit"] == 2 and contract["edit_policy"] == "forbidden"
    for phase in ("integration", "guest", "controls", "full-current"):
        parsed = parser.parse_args([phase, "--output", ".qa-runs/pure-phase/" + phase,
                                    "--run-id", "pure-phase"])
        assert parsed.phase == phase
    help_text = parser.format_help()
    assert "full-current" in help_text and "current" in help_text


def main() -> int:
    """Execute pure cases without a browser or service; every unexpected result fails."""
    tests = (test_response_value_is_preserved_without_coercion,
             test_page_error_text_remains_observation_data,
             test_product_startup_requires_complete_document_and_both_handlers,
             test_model_readiness_rejects_the_observed_loading_geometry,
             test_loaded_file_readiness_requires_its_exact_source_and_geometry,
             test_current_public_identity_requires_current_origin_release_and_bodies,
             test_png_capture_dimensions_require_complete_ihdr,
             test_camera_pair_requires_completed_same_canvas_images,
             test_current_model_retains_its_original_dimensions_after_edit,
             test_json_and_envelope_errors_cannot_become_success,
             test_current_canvas_placement_scrolls_only_a_safe_reachable_gutter,
             test_remote_error_code_is_retained_without_raw_message,
             test_native_admission_requires_actual_host_and_session_fields,
             test_current_safari_release_includes_whole_major_labels,
             test_current_safari_version_normalizes_only_equivalent_trailing_zeros,
             test_only_known_unexecuted_writes_can_be_dispatched,
             test_foreign_or_missing_receipts_cannot_authorize_replay,
             test_draw_pixels_distinguish_clear_flat_and_bounded_raster_content,
             test_draw_pixels_reject_unchanged_sentinel_zero_and_failed_readback,
             test_draw_pixels_require_finite_bounded_consistent_summary,
             test_draw_observer_requires_one_completed_trusted_ordered_fit_event,
             test_draw_observation_requires_visible_admitted_canvas_and_existing_healthy_gl,
             test_diagnostic_captures_retain_originals_without_claiming_native_visible_model,
             test_native_phase_contract_preserves_full_current_and_legacy_predecessors,
             test_real_unchanged_yaml_selects_diagnostic_in_actual_parser_contract)
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
