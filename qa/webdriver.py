"""Pure WebDriver protocol admission and non-replay decisions.

Actual HTTP calls belong to the synchronous native runner. These functions never
send a command, inspect a host, log a response, or mutate caller-owned values.
"""

from __future__ import annotations

import json
import re


def _reject_nonfinite(token: str) -> object:
    raise ValueError("WEBDRIVER_JSON")


def parse_webdriver_response(http_status: int, body: bytes) -> object:
    """Decode a complete UTF-8 WebDriver envelope, preserving its valid value.

    Remote error codes survive without raw message/stack/session data. HTTP200
    cannot hide a remote error; non-2xx responses never count as success.
    """
    try:
        envelope = json.loads(body.decode("utf-8"), parse_constant=_reject_nonfinite)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ValueError("WEBDRIVER_JSON") from None
    if not isinstance(envelope, dict) or "value" not in envelope:
        raise ValueError("WEBDRIVER_ENVELOPE")
    value = envelope["value"]
    if isinstance(value, dict) and "error" in value:
        code = value["error"]
        if not isinstance(code, str) or not code.strip():
            raise ValueError("WEBDRIVER_ENVELOPE")
        raise ValueError("WEBDRIVER_REMOTE_ERROR:" + code)
    if not 200 <= http_status < 300:
        raise ValueError("WEBDRIVER_HTTP_STATUS")
    return value


def admit_native_session(host_system: str, capabilities: object) -> dict[str, str]:
    """Require Darwin and a real-session Safari identity supplied by the runner.

    This pure check cannot establish the provenance of its arguments. UA strings,
    preview names, other engines and absent versions cannot rescue admission.
    """
    if host_system != "Darwin":
        raise ValueError("NATIVE_MACOS_REQUIRED")
    if not isinstance(capabilities, dict):
        raise ValueError("NATIVE_SAFARI_REQUIRED")
    name, version = capabilities.get("browserName"), capabilities.get("browserVersion")
    if not isinstance(name, str) or name.lower() != "safari":
        raise ValueError("NATIVE_SAFARI_REQUIRED")
    if not isinstance(version, str) or not version.strip():
        raise ValueError("NATIVE_SAFARI_VERSION_REQUIRED")
    return {"browser_name": "safari", "browser_version": version}


def _version_tuple(text: str) -> tuple[int, ...]:
    components = tuple(int(number) for number in text.split("."))
    while len(components) > 1 and components[-1] == 0:
        components = components[:-1]
    return components


def latest_stable_safari_version(release_text: str) -> str:
    """Select a numeric stable Safari release from already-observed Apple text.

    This pure parser performs no retrieval and cannot establish source freshness.
    """
    versions = tuple(set(re.findall(r"\bSafari\s+(\d+(?:\.\d+){0,2})\b", release_text)))
    if not versions:
        raise ValueError("APPLE_STABLE_SAFARI_VERSION_UNOBSERVABLE")
    return max(versions, key=_version_tuple)


def require_current_safari_version(installed_version: str, stable_version: str) -> None:
    """Reject a numeric release mismatch without claiming exact build currency."""
    if _version_tuple(installed_version) != _version_tuple(stable_version):
        raise ValueError("NATIVE_SAFARI_NOT_CURRENT_STABLE:" + installed_version + ":" + stable_version)


def write_next_action(operation_id: str, observed_id: str, outcome: str) -> str:
    """Return the next instruction for one journaled write, without effects.

    Only undispatched or matching confirmed-unexecuted work permits dispatch.
    Missing/foreign receipts and unknown outcomes never authorize a replay.
    """
    if not operation_id:
        raise ValueError("WRITE_ID_REQUIRED")
    if observed_id and observed_id != operation_id:
        raise ValueError("WRITE_ID_MISMATCH")
    if outcome == "not-dispatched":
        if observed_id:
            raise ValueError("WRITE_OUTCOME")
        return "dispatch-once"
    if outcome == "unknown":
        return "inspect-same-operation"
    if outcome not in ("confirmed-not-executed", "completed", "refused"):
        raise ValueError("WRITE_OUTCOME")
    if not observed_id:
        raise ValueError("WRITE_OBSERVATION_REQUIRED")
    return {"confirmed-not-executed": "dispatch-once", "completed": "retain-result",
            "refused": "stop-refused"}[outcome]
