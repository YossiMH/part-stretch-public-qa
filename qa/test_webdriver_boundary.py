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
