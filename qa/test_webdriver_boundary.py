"""Pure protocol/policy cases; literal messages are data, never a fake driver."""

from __future__ import annotations

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


def test_json_and_envelope_errors_cannot_become_success() -> None:
    """Malformed bytes, absent values and failed HTTP responses cannot admit a command."""
    for body in (b'not json', b'{"value":null} trailing', b'{"value":"\xff"}',
                 b'{"value":NaN}', b'{"value":[Infinity]}'):
        _reject("WEBDRIVER_JSON", lambda: parse_webdriver_response(200, body))
    for body in (b'[]', b'null', b'{}', b'{"result":null}', b'{"value":{"error":42}}', b'{"value":{"error":""}}'):
        _reject("WEBDRIVER_ENVELOPE", lambda: parse_webdriver_response(200, body))
    for status in (199, 302, 403, 500):
        _reject("WEBDRIVER_HTTP_STATUS", lambda: parse_webdriver_response(status, b'{"value":null}'))


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


def main() -> int:
    """Execute pure cases without a browser or service; every unexpected result fails."""
    tests = (test_response_value_is_preserved_without_coercion,
             test_page_error_text_remains_observation_data,
             test_product_startup_requires_complete_document_and_both_handlers,
             test_model_readiness_rejects_the_observed_loading_geometry,
             test_loaded_file_readiness_requires_its_exact_source_and_geometry,
             test_png_capture_dimensions_require_complete_ihdr,
             test_camera_pair_requires_completed_same_canvas_images,
             test_json_and_envelope_errors_cannot_become_success,
             test_remote_error_code_is_retained_without_raw_message,
             test_native_admission_requires_actual_host_and_session_fields,
             test_current_safari_release_includes_whole_major_labels,
             test_current_safari_version_normalizes_only_equivalent_trailing_zeros,
             test_only_known_unexecuted_writes_can_be_dispatched,
             test_foreign_or_missing_receipts_cannot_authorize_replay)
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
