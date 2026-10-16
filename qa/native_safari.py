"""Bounded native Safari checks using real WebDriver controls and task-owned files.

Each CLI invocation owns its subprocesses, one Safari session and one new output
directory. Effects are synchronous and journaled before dispatch; an uncertain
response terminates the phase without replay. Only selected public observations
and actual PNG bytes reach stdout. Image viewing remains an executor activity.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import http.client
import json
import math
import os
import pathlib
import platform
import re
import signal
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from collections.abc import Callable
from datetime import datetime, timezone
from types import FrameType

from qa.stl import Point, make_cuboid_stl, validate_stl
from qa.webdriver import (admit_native_session, latest_stable_safari_version,
                          parse_webdriver_response, product_startup_ready, require_current_safari_version, write_next_action)


# Historical full guest checks retain their target; current is a separate limited
# check. Limits describe admitted work, not browser capability or visible pixels.
PUBLIC_URL = "https://part-stretch-free.pages.dev/"
PUBLIC_RELEASE = "9b0731642df08c879cbea912b6ff7daf3401a164"
# Bind current declarations and actual served bytes independently. The manifest
# declares 13aa; retained release records identify its runtime baseline as 79c9.
CURRENT_ORIGIN = "https://part-stretch-app.netlify.app"
CURRENT_RELEASE = "13aa60e02304d49b6e92bfc997ff027604b75c6f"
CURRENT_BODY_SHA256 = {
    "preview-release.json": "c878189c48e37d2f12893e2b4daebc32181cceda4ba5626ef2a8c894f76c7941",
    "app.js": "00bda7479576df48f98b8183ed6bff1893216bf0c92fd3e3cbe5cfaaaf79ece6",
    "viewer.js": "8a29738154aee3b2b193922b133ab79db91be8d227a9e7105c08a7f2e255dfc5"}
CURRENT_BODY_BYTE_LIMIT = 256 * 1024
APPLE_RELEASES_URL = "https://support.apple.com/en-us/100100"
PNG_BYTE_LIMIT = 256 * 1024
IMAGE_LOG_BYTE_LIMIT = 1024 * 1024
# One same-task default-framebuffer read, never a replacement native image.
DRAW_READBACK_BYTE_LIMIT = 2 * 1024 * 1024
SOURCE_PATHS = ("codemagic.yaml", "qa/test-plan.md", "qa/test_stl.py", "qa/test_webdriver_boundary.py",
                "qa/stl.py", "qa/webdriver.py", "qa/native_safari.py", "qa/file-controls.html")
ELEMENT_KEY = "element-6066-11e4-a52e-4f735466cecf"

# Session tuples contain loopback origin, session ID, local operation journal and
# monotonic body deadline and main-owned diagnostic cache. The cache records only
# observations and test progress; it never authorizes or retries browser effects.
Session = tuple[str, str, pathlib.Path, float, dict[str, object]]
Checks = list[dict[str, object]]
Images = list[dict[str, object]]


def _utc() -> str:
    """Timestamp external observations in UTC, independently of elapsed-time deadlines."""
    return datetime.now(timezone.utc).isoformat()


def _remaining(deadline: float, maximum_seconds: float = 4.0) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("NATIVE_PHASE_DEADLINE")
    return min(remaining, maximum_seconds)


def _object(value: object, code: str) -> dict[str, object]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise ValueError(code)
    return value


def _string(value: object, code: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(code)
    return value


def _number(value: object, code: str) -> float:
    if not isinstance(value, (float, int)) or isinstance(value, bool) or not math.isfinite(value):
        raise ValueError(code)
    return float(value)


def _json_file(path: pathlib.Path, value: object) -> None:
    """Persist one new task-owned JSON result exclusively, flushing before return."""
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        stream.write(json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n")
        stream.flush()
        os.fsync(stream.fileno())


def _journal(path: pathlib.Path, record: dict[str, object]) -> None:
    """Append the operation observation before another external effect can begin."""
    with path.open("a", encoding="utf-8", newline="\n") as stream:
        stream.write(json.dumps({"utc": _utc(), **record}, sort_keys=True, separators=(",", ":")) + "\n")
        stream.flush()
        os.fsync(stream.fileno())


def _request(origin: str, route: str, method: str, payload: object, deadline: float,
             journal: pathlib.Path, name: str, operation_id: str = "") -> object:
    """Dispatch exactly one bounded HTTP command; never log bodies/session URLs.

    A valid remote error is a retained refusal. Transport or malformed-response
    uncertainty retains the same ID and raises; no caller retries a write.
    """
    operation_id = operation_id or uuid.uuid4().hex
    if write_next_action(operation_id, "", "not-dispatched") != "dispatch-once":
        raise ValueError("WRITE_DISPATCH_NOT_AUTHORIZED")
    timeout = _remaining(deadline, 10.0)
    body = None if payload is None else json.dumps(payload, allow_nan=False).encode("utf-8")
    request = urllib.request.Request(origin + route, data=body, method=method,
                                     headers={"Content-Type": "application/json; charset=utf-8"})
    _journal(journal, {"operation_id": operation_id, "name": name, "method": method, "outcome": "unknown"})
    try:
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                status, content = response.status, response.read()
        except urllib.error.HTTPError as response:
            status, content = response.code, response.read()
        value = parse_webdriver_response(status, content)
        if method == "POST" and route == "/session":
            if not isinstance(value, dict) or not isinstance(value.get("sessionId"), str) or not value["sessionId"]:
                raise ValueError("NATIVE_SESSION_RECEIPT_INCOMPLETE")
    except ValueError as error:
        code = str(error)
        outcome = "refused" if code.startswith("WEBDRIVER_REMOTE_ERROR:") else "unknown"
        _journal(journal, {"operation_id": operation_id, "name": name, "outcome": outcome, "code": code})
        raise
    except (OSError, urllib.error.URLError, TimeoutError):
        _journal(journal, {"operation_id": operation_id, "name": name, "outcome": "unknown"})
        raise RuntimeError("NATIVE_COMMAND_OUTCOME_UNKNOWN:" + name) from None
    _journal(journal, {"operation_id": operation_id, "name": name, "outcome": "completed"})
    return value


def _command(session: Session, method: str, route: str, payload: object, name: str,
             operation_id: str = "") -> object:
    """Send one command on the owned session; _request owns the operation receipt."""
    session[4]["command"] = {"name": name, "method": method,
                             "route": re.sub(r"/element/[^/]+", "/element/{element}", route)}
    return _request(session[0], "/session/" + urllib.parse.quote(session[1], safe="") + route,
                    method, payload, session[3], session[2], name, operation_id)


def _read(session: Session, script: str, arguments: tuple[object, ...] = ()) -> object:
    """Execute supported read-only DOM/File/WebGL observation, awaiting its result."""
    return _command(session, "POST", "/execute/sync", {"script": script, "args": arguments}, "read-dom")


def _poll(deadline: float, observation: Callable[[], object], accepts: Callable[[object], bool], name: str) -> object:
    """Repeat read-only observations, not effects, until the phase's finite deadline."""
    while time.monotonic() < deadline:
        value = observation()
        if accepts(value):
            return value
        time.sleep(min(0.08, _remaining(deadline)))
    raise TimeoutError(name)


def _element(session: Session, selector: str) -> str:
    """Resolve a real DOM element without clicking it or changing page state."""
    value = _read(session, "return document.querySelector(arguments[0]);", (selector,))
    return _string(_object(value, "NATIVE_ELEMENT_MISSING:" + selector).get(ELEMENT_KEY), "NATIVE_ELEMENT_REFERENCE")


def _click(session: Session, selector: str) -> None:
    """Click once with ordinary WebDriver; unknown completion aborts the phase."""
    element = _element(session, selector)
    _command(session, "POST", "/element/" + element + "/click", {}, "click:" + selector)


def _visible(session: Session, selector: str) -> object:
    """Read rendered DOM presence without changing visibility or focus."""
    return _read(session, "const e=document.querySelector(arguments[0]); return e && e.getClientRects().length>0"
                 " && getComputedStyle(e).visibility!=='hidden';", (selector,))


def _wait_visible(session: Session, selector: str) -> None:
    """Wait only by reading the real control; never synthesize a missing control."""
    _poll(session[3], lambda: _visible(session, selector), lambda value: value is True,
          "NATIVE_CONTROL_NOT_VISIBLE:" + selector)


def _type(session: Session, selector: str, text: str) -> None:
    """Replace through Mac Command+A, then verify the typed value across normal Tab.

    Element Send Keys left the handler-free number unchanged in native integration.
    Use keyboard Actions with explicit key release; readbacks still require the edit.
    """
    element = _element(session, selector)
    _command(session, "POST", "/element/" + element + "/click", {}, "focus:" + selector)
    _layout(session, (selector,))
    _command(session, "POST", "/actions", {"actions": [{"type": "key", "id": "native-keyboard", "actions": [
        {"type": "keyDown", "value": "\ue03d"}, {"type": "keyDown", "value": "a"},
        {"type": "keyUp", "value": "a"}, {"type": "keyUp", "value": "\ue03d"}]}]}, "select-all:" + selector)
    for character in text:
        _command(session, "POST", "/actions", {"actions": [{"type": "key", "id": "native-keyboard", "actions": [
            {"type": "keyDown", "value": character}, {"type": "keyUp", "value": character}]}]}, "type:" + selector)
        if _read(session, "return document.activeElement===document.querySelector(arguments[0]);", (selector,)) is not True:
            raise ValueError("NATIVE_FIELD_LOST_FOCUS:" + selector)
    value_script = "return document.querySelector(arguments[0]).value;"
    if _read(session, value_script, (selector,)) != text:
        raise ValueError("NATIVE_FIELD_VALUE_BEFORE_TAB:" + selector)
    _command(session, "POST", "/actions", {"actions": [{"type": "key", "id": "native-keyboard", "actions": [
        {"type": "keyDown", "value": "\ue004"}, {"type": "keyUp", "value": "\ue004"}]}]}, "tab:" + selector)
    if _read(session, value_script, (selector,)) != text:
        raise ValueError("NATIVE_FIELD_VALUE_AFTER_TAB:" + selector)


def _select_file(session: Session, selector: str, path: pathlib.Path) -> dict[str, object]:
    """Select a real local path using WebDriver, then hash its actual selected File."""
    element = _element(session, selector)
    _command(session, "POST", "/element/" + element + "/value", {"text": str(path)}, "select-file:" + selector)
    value = _read(session, """
const file=document.querySelector(arguments[0]).files[0];
if (!file) return null;
return file.arrayBuffer().then(buffer=>crypto.subtle.digest('SHA-256',buffer)).then(digest=>({
 name:file.name,byte_count:file.size,sha256:Array.from(new Uint8Array(digest),v=>v.toString(16).padStart(2,'0')).join('')
}));
""", (selector,))
    selected = _object(value, "NATIVE_SELECTED_FILE_UNOBSERVABLE")
    payload = path.read_bytes()
    if (selected.get("name") != path.name or selected.get("byte_count") != len(payload)
            or selected.get("sha256") != hashlib.sha256(payload).hexdigest()):
        raise ValueError("NATIVE_SELECTED_FILE_BYTES_MISMATCH")
    return selected


def _supply_product_file(session: Session, path: pathlib.Path) -> dict[str, object]:
    """Supply one genuine path and retain its file bytes and normal command receipt.

    The product clears its input after adopting the File. Identity therefore uses
    full pre/post filesystem reads, this command's journal ID, and the caller's
    normal adopted filename/model/settings checks, not a retained FileList.
    """
    if not path.is_absolute() or path.is_symlink() or not path.is_file():
        raise ValueError("NATIVE_PRODUCT_FILE_PATH_INVALID")
    before = path.read_bytes()
    before_sha256 = hashlib.sha256(before).hexdigest()
    element = _element(session, "#file")
    operation_id = uuid.uuid4().hex
    supplied_file_cache: dict[str, object] = {
        "path": str(path), "name": path.name, "byte_count": len(before), "before_sha256": before_sha256,
        "command_receipt": {"operation_id": operation_id, "outcome": "unknown"}}
    session[4]["supplied_file_cache"] = supplied_file_cache
    command_started = time.monotonic()
    try:
        receipt = _command(session, "POST", "/element/" + element + "/value", {"text": str(path)},
                           "select-product-file", operation_id)
    finally:
        supplied_file_cache["command_elapsed_seconds"] = time.monotonic() - command_started
    if receipt is not None:
        raise ValueError("NATIVE_PRODUCT_FILE_COMMAND_RECEIPT_INVALID")
    supplied_file_cache["command_receipt"] = {"operation_id": operation_id, "outcome": "completed", "value": receipt}
    after = path.read_bytes()
    after_sha256 = hashlib.sha256(after).hexdigest()
    supplied_file_cache.update({"after_sha256": after_sha256, "sha256": after_sha256, "byte_count": len(after)})
    if before != after or before_sha256 != after_sha256:
        raise ValueError("NATIVE_PRODUCT_FILE_BYTES_CHANGED")
    return supplied_file_cache


def _snapshot(session: Session) -> dict[str, object]:
    """Read selected public controls only; never dump a page, app object or storage."""
    observed = _object(_read(session, """
const text=id=>document.getElementById(id)?.textContent.trim()||'';
const value=id=>document.getElementById(id)?.value??'';
const visible=id=>{const e=document.getElementById(id);return e&&e.getClientRects().length>0;};
return {release:document.querySelector('meta[name="part-stretch-release"]')?.content||'',
 services:document.querySelector('meta[name="part-stretch-services"]')?.content||'',
 filename:text('filename'),dimensions:text('dimensions'),original_dimensions:text('original-dimensions'),
 start:value('start'),end:value('end'),delta:value('delta'),target:value('target'),units:value('units'),
 axis:document.querySelector('#precision-controls [data-axis][aria-pressed="true"]')?.getAttribute('data-axis')||'',
 ui_error:visible('error-box')?text('error'):'',status:text('status'),view_note:text('view-note'),
 editor:visible('editor')?'displayed':'absent',anchor_picker:visible('anchor-picker')?'displayed':'absent',
 focused:document.activeElement?.id||'',viewport:[innerWidth,innerHeight],
 document_ready:document.readyState,selected_file_count:document.getElementById('file')?.files?.length??null,
 file_change_handler:typeof document.getElementById('file')?.onchange,
 browse_click_handler:typeof document.getElementById('browse')?.onclick,
 load_error:visible('load-error')?text('load-error').slice(0,512):'',
 load_progress:visible('load-progress')?'displayed':'absent'};
"""), "NATIVE_DOM_OBSERVATION")
    session[4]["selected_dom"] = {key: value[:512] if isinstance(value, str) else value
                                   for key, value in observed.items()}
    return observed


def _dimensions(text: object) -> Point:
    numbers = re.findall(r"[-+]?\d+(?:\.\d+)?", _string(text, "NATIVE_DIMENSIONS_UNOBSERVABLE"))
    if len(numbers) != 3:
        raise ValueError("NATIVE_DIMENSIONS_FORMAT")
    return float(numbers[0]), float(numbers[1]), float(numbers[2])


def _matches_model(observed: object, size_mm: Point, expected_filename: str = "") -> bool:
    """Match settled geometry, requiring the adopted source when one is specified."""
    snapshot = _object(observed, "NATIVE_DOM_OBSERVATION")
    try:
        size = _dimensions(snapshot.get("dimensions"))
    except ValueError:
        return False
    return (snapshot.get("editor") == "displayed" and snapshot.get("units") == "1"
            and snapshot.get("load_progress") == "absent" and snapshot.get("load_error") == ""
            and (not expected_filename or snapshot.get("filename") == expected_filename)
            and all(abs(size[axis] - size_mm[axis]) <= 0.0001 for axis in range(3)))


def _model(session: Session, size_mm: Point, expected_filename: str = "",
           expected_release: str = PUBLIC_RELEASE, expected_services: str = "guest-beta") -> dict[str, object]:
    """Wait for settled public geometry/source and reject its displayed error."""
    observed = _object(_poll(session[3], lambda: _snapshot(session),
                             lambda value: _matches_model(value, size_mm, expected_filename),
                             "NATIVE_MODEL_DIMENSIONS_DEADLINE"), "NATIVE_DOM_OBSERVATION")
    if observed.get("release") != expected_release or observed.get("services") != expected_services:
        raise ValueError("NATIVE_PUBLIC_RELEASE_MISMATCH")
    if observed.get("ui_error"):
        raise ValueError("NATIVE_VISIBLE_PRODUCT_ERROR")
    return observed


def _settings(observed: dict[str, object], end_mm: float, delta_mm: float) -> None:
    for field, expected in (("start", 5.0), ("end", end_mm), ("delta", delta_mm), ("target", end_mm - 5.0 + delta_mm)):
        try:
            actual = float(_string(observed.get(field), "NATIVE_SETTING_MISSING:" + field))
        except ValueError:
            raise ValueError("NATIVE_SETTING_MISMATCH:" + field) from None
        if not math.isfinite(actual) or abs(actual - expected) > 0.0001:
            raise ValueError("NATIVE_SETTING_MISMATCH:" + field)
    if observed.get("axis") != "0":
        raise ValueError("NATIVE_AXIS_MISMATCH")


def _webgl(session: Session) -> dict[str, object]:
    """Read the app-owned primary context only after _model confirmed adoption.

    No fallback/probe context is requested. The normal loaded-model path is the
    prerequisite for this one existing WebGL2 context/version observation.
    """
    observed = _object(_read(session, """
const canvas=document.getElementById('view');
const context=canvas.getContext('webgl2');
return context?{kind:'webgl2',version:context.getParameter(context.VERSION),
 width:canvas.width,height:canvas.height}:{kind:'unobservable'};
"""), "NATIVE_WEBGL_UNOBSERVABLE")
    if observed.get("kind") != "webgl2" or "WebGL 2" not in _string(observed.get("version"), "NATIVE_WEBGL_VERSION"):
        raise ValueError("NATIVE_WEBGL2_NOT_OBSERVED")
    return observed


def _png_dimensions(payload: bytes) -> tuple[int, int]:
    """Read PNG IHDR pixel dimensions without decoding or classifying image content."""
    if not payload.startswith(b"\x89PNG\r\n\x1a\n"):
        raise ValueError("NATIVE_SCREENSHOT_NOT_PNG")
    if len(payload) < 33 or payload[8:16] != b"\x00\x00\x00\rIHDR":
        raise ValueError("NATIVE_SCREENSHOT_HEADER")
    width, height = int.from_bytes(payload[16:20], "big"), int.from_bytes(payload[20:24], "big")
    if not 0 < width < 0x80000000 or not 0 < height < 0x80000000:
        raise ValueError("NATIVE_SCREENSHOT_DIMENSIONS")
    return width, height


def _camera_pair_changed(before: object, after: object) -> bool:
    """Require completed same-size native canvas captures with different byte hashes.

    Callers own actual method/element provenance. This predicate cannot establish
    visible model content or camera movement; both images still require viewing.
    """
    if not isinstance(before, dict) or not isinstance(after, dict):
        return False
    for image in (before, after):
        width, height, sha256 = image.get("png_width"), image.get("png_height"), image.get("sha256")
        if (image.get("capture_method") != "element" or image.get("target") != "#view"
                or image.get("outcome") != "completed"
                or not isinstance(width, int) or isinstance(width, bool) or width <= 0
                or not isinstance(height, int) or isinstance(height, bool) or height <= 0
                or not isinstance(sha256, str) or re.fullmatch(r"[0-9a-f]{64}", sha256) is None):
            return False
    return (before["png_width"] == after["png_width"] and before["png_height"] == after["png_height"]
            and before["sha256"] != after["sha256"])


def _capture(session: Session, output: pathlib.Path, name: str, images: Images,
             target: str = "viewport", element: str = "") -> dict[str, object]:
    """Retain unmodified native PNGs and capture outcomes, including failed attempts.

    Element targets use the standard endpoint; a supplied reference binds camera
    captures to the exact canvas used by Actions. Unsupported/uncertain commands
    fail without another method or replay. Headers expose dimensions, not pixels.
    """
    capture_method = "viewport" if target == "viewport" else "element"
    attempt: dict[str, object] = {"name": name, "capture_method": capture_method,
                                 "target": target, "outcome": "unknown", "command_outcome": "not-dispatched"}
    capture_cache = session[4].setdefault("capture_observations_cache", [])
    if not isinstance(capture_cache, list):
        raise ValueError("NATIVE_CAPTURE_CACHE_INVALID")
    capture_cache.append(attempt)
    try:
        route = "/screenshot"
        if capture_method == "element":
            element = element or _element(session, target)
            route = "/element/" + element + "/screenshot"
        attempt["command_outcome"] = "unknown"
        receipt = _command(session, "GET", route, None, "screenshot:" + name)
        attempt["command_outcome"] = "completed"
        encoded = _string(receipt, "NATIVE_SCREENSHOT_MISSING")
        try:
            payload = base64.b64decode(encoded, validate=True)
        except ValueError:
            raise ValueError("NATIVE_SCREENSHOT_ENCODING") from None
        path = output / (name + ".png")
        with path.open("xb") as stream:
            stream.write(payload)
        attempt.update({"png_bytes": len(payload), "sha256": hashlib.sha256(payload).hexdigest()})
        width, height = _png_dimensions(payload)
        record: dict[str, object] = {**attempt, "outcome": "completed", "png_width": width, "png_height": height}
        images.append(record)
        attempt.update(record)
        if len(payload) > PNG_BYTE_LIMIT:
            raise ValueError("NATIVE_IMAGE_COLLECTION_INCOMPLETE:PNG_LIMIT")
        return record
    except Exception as error:
        code = _failure_code(error)
        attempt["code"] = code
        if (attempt["command_outcome"] == "unknown"
                and code in ("WEBDRIVER_REMOTE_ERROR:unknown command", "WEBDRIVER_REMOTE_ERROR:unsupported operation")):
            attempt["outcome"] = "unsupported"
            attempt["command_outcome"] = "refused"
        else:
            attempt["outcome"] = "unknown" if code.startswith("NATIVE_COMMAND_OUTCOME_UNKNOWN:") else "error"
            if attempt["command_outcome"] == "unknown" and code.startswith("WEBDRIVER_REMOTE_ERROR:"):
                attempt["command_outcome"] = "refused"
        raise


def _new_fixture(output: pathlib.Path, run_id: str, phase: str, size_mm: Point) -> tuple[pathlib.Path, dict[str, object]]:
    """Create and fully validate a fresh task-named file, never a copied fixture."""
    path = output / ("qa-" + run_id + "-" + phase + ".stl")
    payload = make_cuboid_stl(size_mm, "binary")
    with path.open("xb") as stream:
        stream.write(payload)
    return path, validate_stl(payload, ((0.0, 0.0, 0.0), size_mm), math.prod(size_mm))


def _await_download(session: Session, directory: pathlib.Path, token: str, size_mm: Point) -> tuple[pathlib.Path, dict[str, object]]:
    """Read only new task-token files; full geometry and two identical reads decide completion."""
    last_error = "NATIVE_DOWNLOAD_NOT_OBSERVED"
    while time.monotonic() < session[3]:
        candidates = tuple(directory.glob("*" + token + "*.stl"))
        if len(candidates) > 1:
            raise ValueError("NATIVE_DOWNLOAD_IDENTITY_AMBIGUOUS")
        if candidates:
            path = candidates[0]
            if path.is_symlink() or not path.is_file():
                raise ValueError("NATIVE_DOWNLOAD_NOT_REGULAR_FILE")
            try:
                payload = path.read_bytes()
                summary = validate_stl(payload, ((0.0, 0.0, 0.0), size_mm), math.prod(size_mm))
                if path.read_bytes() == payload:
                    return path, summary
            except (ValueError, OSError) as error:
                last_error = str(error) if isinstance(error, ValueError) else "NATIVE_DOWNLOAD_READ_INCOMPLETE"
        time.sleep(min(0.08, _remaining(session[3])))
    raise TimeoutError("NATIVE_DOWNLOAD_VALIDATION_DEADLINE:" + last_error)


def _prepare_download(directory: pathlib.Path, token: str) -> None:
    """Refuse a pre-existing task-token result rather than replay an uncertain download."""
    if not directory.is_dir():
        raise ValueError("NATIVE_DOWNLOAD_DIRECTORY_UNAVAILABLE")
    if next(directory.glob("*" + token + "*"), None) is not None:
        raise ValueError("NATIVE_DOWNLOAD_IDENTITY_ALREADY_EXISTS")


def _edit(session: Session, size_mm: Point, end_mm: float, delta_mm: float,
          expected_release: str = PUBLIC_RELEASE, expected_services: str = "guest-beta") -> dict[str, object]:
    """Choose the numeric X band and fixed-start anchor through visible controls."""
    session[4]["stage"] = "edit-choose-region"
    _click(session, "#choose")
    session[4]["stage"] = "edit-choose-X-direction"
    _wait_visible(session, '#direction-picker [data-axis="0"]')
    _click(session, '#direction-picker [data-axis="0"]')
    session[4]["stage"] = "edit-enter-exact-positions"
    _wait_visible(session, "#choose-exact")
    _click(session, "#choose-exact")
    session[4]["stage"] = "edit-open-precision-controls"
    _wait_visible(session, "#delta")
    if _read(session, "return document.getElementById('precision-controls').open;") is not True:
        _click(session, "#precision-controls summary")
    session[4]["stage"] = "edit-start-boundary"
    _type(session, "#start", "5")
    session[4]["stage"] = "edit-end-boundary"
    _type(session, "#end", format(end_mm, ".9g"))
    session[4]["stage"] = "prepare-anchor-nonzero-delta"
    _type(session, "#delta", format(delta_mm, ".9g"))
    session[4]["stage"] = "edit-open-anchor-picker"
    _wait_visible(session, "#anchor")
    _click(session, "#anchor")
    session[4]["stage"] = "edit-fixed-start-anchor"
    _wait_visible(session, '[data-anchor="1"]')
    _click(session, '[data-anchor="1"]')
    session[4]["stage"] = "prepare-anchored-zero-delta"
    _type(session, "#delta", "0")
    original_operation = _model(session, size_mm, expected_release=expected_release, expected_services=expected_services)
    _settings(original_operation, end_mm, 0.0)
    session[4]["stage"] = "edit-requested-delta"
    _type(session, "#delta", format(delta_mm, ".9g"))
    return original_operation


def _resume(session: Session) -> str:
    """Use the visible normal recovery button after a real browser refresh."""
    _command(session, "POST", "/refresh", {}, "reload-interrupted-local-work")
    selector = _string(_poll(session[3], lambda: _read(session, """
return ['#resume-unpaid-edit','#resume-checkout'].find(selector=>{
 const element=document.querySelector(selector);return element&&element.getClientRects().length>0;
})||'';
"""), lambda value: isinstance(value, str) and len(value) > 0, "NATIVE_RESUME_NOT_AVAILABLE"), "NATIVE_RESUME_NOT_AVAILABLE")
    _click(session, selector)
    return selector


def _layout(session: Session, selectors: tuple[str, ...]) -> dict[str, object]:
    """Observe visible control geometry and hit-testing at the actual viewport."""
    observed = _object(_read(session, """
return {viewport:[innerWidth,innerHeight],controls:arguments[0].map(selector=>{
 const element=document.querySelector(selector);if(!element)return {selector,result:'missing'};
 const rectangle=element.getBoundingClientRect(),x=rectangle.left+rectangle.width/2,y=rectangle.top+rectangle.height/2;
 const hit=document.elementFromPoint(x,y);
 return {selector,rectangle:[rectangle.left,rectangle.top,rectangle.width,rectangle.height],
 result:rectangle.width>0&&rectangle.height>0&&rectangle.left>=0&&rectangle.top>=0&&rectangle.right<=innerWidth&&
 rectangle.bottom<=innerHeight&&hit&&(hit===element||element.contains(hit))?'usable':'clipped-or-covered'};
})};
""", (selectors,)), "NATIVE_LAYOUT_UNOBSERVABLE")
    controls = observed.get("controls")
    if not isinstance(controls, list) or any(_object(control, "NATIVE_LAYOUT_UNOBSERVABLE").get("result") != "usable" for control in controls):
        raise ValueError("NATIVE_LAYOUT_CLIPPED_OR_COVERED")
    return observed


def _view_controls(session: Session, output: pathlib.Path, images: Images) -> dict[str, object]:
    """Exercise normal camera Actions on the same real canvas captured before/after.

    Native element images are canonical; viewport originals remain diagnostic.
    Element scrolling occurs outside the viewport pair. Actual viewing must still
    distinguish model motion from blank images, metadata or focus decoration.
    """
    _click(session, "#view")
    element = _element(session, "#view")
    canvas_identity_script = ("return arguments[0]===document.getElementById('view')"
                              "&&arguments[0].tagName==='CANVAS'?'same-view-canvas':'other';")
    if _read(session, canvas_identity_script, ({ELEMENT_KEY: element},)) != "same-view-canvas":
        raise ValueError("NATIVE_VIEW_CANVAS_IDENTITY_MISMATCH")
    session[4]["stage"] = "view-camera-before"
    before = _capture(session, output, "view-before-canvas", images, "#view", element)
    before_layout = _layout(session, ("#view",))
    _capture(session, output, "view-before", images)
    session[4]["stage"] = "view-camera-actions"
    for modifier, offset in (("", 45), ("\ue008", -35)):
        pointer_actions: list[dict[str, object]] = [
            {"type": "pointerMove", "duration": 0, "origin": {ELEMENT_KEY: element}, "x": 0, "y": 0},
            {"type": "pointerDown", "button": 0},
            {"type": "pointerMove", "duration": 120, "origin": "pointer", "x": offset, "y": 20},
            {"type": "pointerUp", "button": 0}]
        actions: list[dict[str, object]] = [{"type": "pointer", "id": "native-pointer", "parameters": {"pointerType": "mouse"},
                                           "actions": pointer_actions}]
        if modifier:
            actions.append({"type": "key", "id": "native-keyboard", "actions": [
                {"type": "keyDown", "value": modifier}, {"type": "pause", "duration": 0},
                {"type": "pause", "duration": 120}, {"type": "keyUp", "value": modifier}]})
        _command(session, "POST", "/actions", {"actions": actions}, "view-pan" if modifier else "view-orbit")
    _command(session, "POST", "/actions", {"actions": [{"type": "wheel", "id": "native-wheel", "actions": [
        {"type": "scroll", "duration": 120, "origin": {ELEMENT_KEY: element}, "x": 0, "y": 0,
         "deltaX": 0, "deltaY": -120}]}]}, "view-wheel-zoom")
    _capture(session, output, "view-after", images)
    session[4]["stage"] = "view-camera-after"
    if _read(session, canvas_identity_script, ({ELEMENT_KEY: element},)) != "same-view-canvas":
        raise ValueError("NATIVE_VIEW_CANVAS_IDENTITY_MISMATCH")
    after = _capture(session, output, "view-after-canvas", images, "#view", element)
    if not _camera_pair_changed(before, after):
        raise ValueError("NATIVE_VIEW_CHANGE_NOT_OBSERVED")
    focused = _read(session, "return document.activeElement?.id||'';")
    if focused != "view":
        raise ValueError("NATIVE_VIEW_KEYBOARD_FOCUS_LOST")
    return {"actions": ["orbit-drag", "shift-drag-pan", "wheel-zoom"], "focused": focused,
            "camera_images": {"before": before, "after": after}, "before_layout": before_layout,
            "layout": _layout(session, ("#view",))}


def _integration(session: Session, output: pathlib.Path, run_id: str, origin: str, checks: Checks, images: Images) -> None:
    """Use the real served file input/download page before any product journey."""
    fixture, summary = _new_fixture(output, run_id, "integration", (17.0, 11.0, 7.0))
    transport = output / "transport"
    transport.mkdir()
    with (transport / fixture.name).open("xb") as stream:
        stream.write(fixture.read_bytes())
    page = pathlib.Path(__file__).with_name("file-controls.html").read_text(encoding="utf-8")
    page = page.replace('href="fixture.stl"', 'href="' + fixture.name + '"')
    with (transport / "index.html").open("x", encoding="utf-8", newline="\n") as stream:
        stream.write(page)
    _poll(min(session[3], time.monotonic() + 4.0), lambda: _static_status(origin, session[3]),
          lambda value: value == 200, "NATIVE_STATIC_SERVER_STARTUP_DEADLINE")
    _command(session, "POST", "/url", {"url": origin + "/"}, "open-file-control-page")
    page_observation = _snapshot(session)
    session[4]["preselection_dom_cache"] = session[4]["selected_dom"]
    if session[4].get("selected_dom") != page_observation:
        raise ValueError("NATIVE_OBSERVATION_CACHE_MISMATCH")
    if (page_observation.get("file_change_handler") != "undefined"
            or page_observation.get("browse_click_handler") != "undefined"
            or session[4].get("preselection_dom_cache") != page_observation
            or product_startup_ready(page_observation)):
        raise ValueError("NATIVE_PRESELECTION_OBSERVATION_MISMATCH")
    if page_observation.get("ui_error") != "" or page_observation.get("editor") != "absent":
        raise ValueError("NATIVE_FILE_CONTROL_OBSERVATION_MISMATCH")
    checks.append({"name": "page-observation-protocol-boundary", "dom": page_observation})
    selected = _select_file(session, "#fixture", fixture)
    checks.append({"name": "ordinary-file-selection", "selected": selected, "stl": summary})
    downloads = pathlib.Path.home() / "Downloads"
    _prepare_download(downloads, run_id + "-integration")
    _click(session, "#fixture-download")
    downloaded, downloaded_summary = _await_download(session, downloads, run_id + "-integration", (17.0, 11.0, 7.0))
    if downloaded_summary["sha256"] != summary["sha256"] or downloaded.read_bytes() != fixture.read_bytes():
        raise ValueError("NATIVE_INTEGRATION_DOWNLOAD_BYTES_MISMATCH")
    checks.append({"name": "ordinary-download-complete-bytes", "filename": downloaded.name, "stl": downloaded_summary})
    session[4]["stage"] = "handler-free-number-replacement"
    _type(session, "#start", "5")
    number_observation = _object(_snapshot(session), "NATIVE_DOM_OBSERVATION")
    if number_observation.get("focused") != "number-next":
        raise ValueError("NATIVE_NUMBER_TAB_FOCUS_MISMATCH")
    checks.append({"name": "handler-free-number-replacement", "dom": number_observation})
    _capture(session, output, "integration-file-controls", images)
    heading = _object(_read(session, """
const e=document.querySelector('h1');if(!e)return {};
const r=e.getBoundingClientRect();return {text:e.textContent.trim(),rectangle:[r.left,r.top,r.width,r.height],
 visibility:getComputedStyle(e).visibility,viewport:[innerWidth,innerHeight]};
"""), "NATIVE_INTEGRATION_HEADING_UNOBSERVABLE")
    if heading.get("text") != "Native file controls":
        raise ValueError("NATIVE_INTEGRATION_HEADING_MISMATCH")
    checks.append({"name": "native-capture-static-target", "dom": heading})
    _capture(session, output, "integration-heading-element", images, "h1")


def _product(session: Session, output: pathlib.Path, run_id: str, phase: str, checks: Checks, images: Images) -> None:
    """Run the actual public guest or independent controls case through normal UI."""
    size: Point = (17.0, 11.0, 7.0) if phase == "guest" else (20.0, 10.0, 6.0)
    result_size: Point = (20.0, 11.0, 7.0) if phase == "guest" else (24.0, 10.0, 6.0)
    end_mm, delta_mm = (12.0, 3.0) if phase == "guest" else (15.0, 4.0)
    fixture, summary = _new_fixture(output, run_id, phase, size)
    session[4]["stage"] = "first-public-navigation"
    _command(session, "POST", "/url", {"url": PUBLIC_URL}, "open-public-guest")
    session[4]["stage"] = "public-startup-wait"
    startup = _object(_poll(session[3], lambda: _snapshot(session), product_startup_ready,
                            "NATIVE_PUBLIC_STARTUP_DEADLINE"), "NATIVE_DOM_OBSERVATION")
    session[4]["preselection_dom_cache"] = session[4]["selected_dom"]
    checks.append({"name": "normal-page-startup-before-file-selection", "dom": startup})
    session[4]["stage"] = "first-product-file-selection"
    supplied = _supply_product_file(session, fixture)
    session[4]["stage"] = "first-model-dimensions-wait"
    imported = _model(session, size, fixture.name)
    if imported.get("filename") != fixture.name or supplied.get("sha256") != summary["sha256"]:
        raise ValueError("NATIVE_IMPORTED_FILE_IDENTITY_MISMATCH")
    checks.append({"name": "normal-import", "supplied_file": supplied, "stl": summary, "dom": imported, "webgl": _webgl(session)})
    session[4]["stage"] = "first-import-verified"
    _capture(session, output, "imported-model", images)
    _capture(session, output, "imported-model-editor", images, "#editor")
    original_operation = _edit(session, size, end_mm, delta_mm)
    edited = _model(session, result_size)
    _settings(edited, end_mm, delta_mm)
    if edited.get("focused") != "target":
        raise ValueError("NATIVE_TAB_ORDER_DID_NOT_REACH_TARGET")
    checks.append({"name": "normal-fixed-start-X-edit", "anchor_control": "data-anchor=1", "dom": edited,
                   "original_operation": original_operation, "layout": _layout(session, ("#delta", "#target"))})
    _capture(session, output, "edited-model", images)
    _capture(session, output, "edited-model-editor", images, "#editor")
    if phase == "guest":
        resume_control = _resume(session)
        resumed = _model(session, result_size)
        _settings(resumed, end_mm, delta_mm)
        checks.append({"name": "reload-resume-interrupted-local-work", "control": resume_control, "dom": resumed})
        downloads = pathlib.Path.home() / "Downloads"
        _prepare_download(downloads, run_id + "-guest")
        _click(session, "#download")
        downloaded, downloaded_summary = _await_download(session, downloads, run_id + "-guest", result_size)
        checks.append({"name": "one-product-download-complete-stl", "filename": downloaded.name, "stl": downloaded_summary})
        session[4]["stage"] = "exact-downloaded-file-selection"
        reopened = _supply_product_file(session, downloaded)
        session[4]["stage"] = "exact-downloaded-file-adoption-wait"
        reopened_model = _model(session, result_size, downloaded.name)
        if (reopened.get("sha256") != downloaded_summary["sha256"]
                or reopened_model.get("filename") != downloaded.name):
            raise ValueError("NATIVE_EXACT_DOWNLOADED_FILE_REOPEN_MISMATCH")
        checks.append({"name": "exact-downloaded-file-reopen", "supplied_file": reopened, "dom": reopened_model, "webgl": _webgl(session)})
        session[4]["stage"] = "exact-downloaded-file-reopen-verified"
        _capture(session, output, "reopened-model", images)
        _capture(session, output, "reopened-model-editor", images, "#editor")
    else:
        _type(session, "#delta", "-11")
        rejected = _object(_poll(session[3], lambda: _snapshot(session),
                                 lambda value: len(str(_object(value, "NATIVE_DOM_OBSERVATION").get("ui_error", ""))) > 0,
                                 "NATIVE_INVALID_SHRINK_NOT_REJECTED"), "NATIVE_DOM_OBSERVATION")
        if not _matches_model(rejected, result_size):
            raise ValueError("NATIVE_INVALID_SHRINK_CHANGED_MODEL")
        checks.append({"name": "invalid-shrink-retains-valid-model", "dom": rejected})
        for action_index in range(2):
            _click(session, "#undo")
            undo = _object(_poll(session[3], lambda: _snapshot(session), lambda value:
                (_matches_model(value, size) or _matches_model(value, result_size))
                and not _object(value, "NATIVE_DOM_OBSERVATION").get("ui_error"),
                "NATIVE_UNDO_DID_NOT_SETTLE"), "NATIVE_DOM_OBSERVATION")
            checks.append({"name": "normal-undo-" + str(action_index + 1), "dom": undo})
            if _matches_model(undo, size) and not undo.get("ui_error"):
                break
            if not _matches_model(undo, result_size) or undo.get("ui_error"):
                raise ValueError("NATIVE_UNDO_DID_NOT_RESTORE_VALID_OPERATION")
        restored = _model(session, size)
        _settings(restored, end_mm, 0.0)
        checks.append({"name": "undo-original-model-and-operation", "dom": restored})
        _capture(session, output, "undo-original-model", images)
        _capture(session, output, "undo-original-model-editor", images, "#editor")
    checks.append({"name": "view-and-focus-controls", **_view_controls(session, output, images)})
    checks.append({"name": "model-after-view-controls", "dom": _model(session, result_size if phase == "guest" else size)})


def _current_identity_matches(observed: object) -> bool:
    """Require current declarations and complete public body hashes as separate facts."""
    return (isinstance(observed, dict) and observed.get("origin") == CURRENT_ORIGIN
            and observed.get("release") == CURRENT_RELEASE and observed.get("services") == "required"
            and observed.get("manifest_product_commit") == CURRENT_RELEASE
            and observed.get("manifest_asset_source_commit") == CURRENT_RELEASE
            and observed.get("body_sha256") == CURRENT_BODY_SHA256)


def _current_page(session: Session) -> dict[str, object]:
    """Observe public UI only; never read auth storage or replace retained work."""
    observed = _object(_read(session, """
const visible=id=>{const element=document.getElementById(id);return element&&element.getClientRects().length>0;};
return {origin:location.origin,release:document.querySelector('meta[name="part-stretch-release"]')?.content||'',
 services:document.querySelector('meta[name="part-stretch-services"]')?.content||'',
 account_access:document.getElementById('unpaid-backup')?.dataset.access||'',
 sign_in:visible('sign-in')?'displayed':'absent',sign_out:visible('sign-out')?'displayed':'absent',
 recovery:['resume-local-job','unpaid-recovery'].filter(visible),
 open_dialog_count:document.querySelectorAll('dialog[open]').length};
"""), "NATIVE_CURRENT_PAGE_UNOBSERVABLE")
    session[4]["current_page_cache"] = observed
    if (observed.get("origin") != CURRENT_ORIGIN or observed.get("release") != CURRENT_RELEASE
            or observed.get("services") != "required"):
        raise ValueError("NATIVE_CURRENT_PUBLIC_DECLARATION_MISMATCH")
    return observed


def _current_empty_page(session: Session) -> dict[str, object]:
    """Wait for the visible guest decision, then refuse any prior model or recovery UI."""
    observed = _object(_poll(session[3], lambda: _current_page(session),
                             lambda value: _object(value, "NATIVE_CURRENT_PAGE_UNOBSERVABLE").get("account_access")
                             in ("guest", "account"), "NATIVE_CURRENT_ACCOUNT_UI_DEADLINE"),
                       "NATIVE_CURRENT_PAGE_UNOBSERVABLE")
    snapshot = _snapshot(session)
    if (observed.get("account_access") != "guest" or observed.get("sign_out") != "absent"
            or observed.get("sign_in") != "displayed" or observed.get("recovery") != []
            or observed.get("open_dialog_count") != 0 or snapshot.get("filename")
            or snapshot.get("editor") != "absent"):
        raise ValueError("NATIVE_CURRENT_RETAINED_OR_AUTH_UI_PRESENT")
    return observed


def _current_public_identity(session: Session, page: dict[str, object]) -> dict[str, object]:
    """Hash three bounded unauthenticated HTTPS bodies without following redirects.

    Only selected metadata and complete digests enter diagnostics. The synchronous
    connection is closed on every outcome; the phase alarm bounds DNS and total
    work. Temporarily shorten that same alarm to five seconds for each whole GET,
    then restore its remaining phase budget; the existing handler only raises.
    """
    bodies_cache: list[dict[str, object]] = []
    session[4]["current_public_bodies_cache"] = bodies_cache
    observed_hashes: dict[str, str] = {}
    manifest: dict[str, object] = {}
    for relative_path, expected_sha256 in CURRENT_BODY_SHA256.items():
        operation_id = uuid.uuid4().hex
        _journal(session[2], {"operation_id": operation_id, "name": "current-public-body:" + relative_path,
                             "method": "GET", "outcome": "unknown"})
        request_deadline = min(session[3], time.monotonic() + 5.0)
        connection = http.client.HTTPSConnection(urllib.parse.urlsplit(CURRENT_ORIGIN).netloc,
                                                  timeout=_remaining(request_deadline, 5.0))
        signal.setitimer(signal.ITIMER_REAL, _remaining(request_deadline, 5.0))
        try:
            connection.request("GET", "/" + relative_path, headers={"Accept": "*/*"})
            response = connection.getresponse()
            if response.status != 200:
                raise ValueError("NATIVE_CURRENT_PUBLIC_BODY_STATUS:" + str(response.status))
            content = response.read(CURRENT_BODY_BYTE_LIMIT + 1)
            if len(content) > CURRENT_BODY_BYTE_LIMIT:
                raise ValueError("NATIVE_CURRENT_PUBLIC_BODY_LIMIT")
            observed_sha256 = hashlib.sha256(content).hexdigest()
            bodies_cache.append({"path": relative_path, "status": response.status,
                                 "bytes": len(content), "sha256": observed_sha256})
            observed_hashes[relative_path] = observed_sha256
            if observed_sha256 != expected_sha256:
                raise ValueError("NATIVE_CURRENT_PUBLIC_BODY_MISMATCH:" + relative_path)
            if relative_path == "preview-release.json":
                manifest = _object(json.loads(content.decode("utf-8")), "NATIVE_CURRENT_MANIFEST_FORMAT")
        except TimeoutError:
            raise TimeoutError("NATIVE_CURRENT_PUBLIC_BODY_DEADLINE:" + relative_path) from None
        finally:
            connection.close()
            signal.setitimer(signal.ITIMER_REAL, max(0.001, session[3] - time.monotonic()))
        _journal(session[2], {"operation_id": operation_id, "name": "current-public-body:" + relative_path,
                             "outcome": "completed"})
    identity = {"origin": page.get("origin"), "release": page.get("release"), "services": page.get("services"),
                "manifest_product_commit": manifest.get("product_commit"),
                "manifest_asset_source_commit": manifest.get("asset_source_commit"), "body_sha256": observed_hashes}
    if not _current_identity_matches(identity):
        raise ValueError("NATIVE_CURRENT_PUBLIC_IDENTITY_MISMATCH")
    return identity


def _current_graphics(session: Session, stage: str, checks: Checks) -> None:
    """Observe the already-owned context and selected error UI at a named boundary.

    Normal model adoption is the prerequisite; this never creates a fallback
    context, listens for events, injects loss or calls application functions.
    """
    observed = _object(_read(session, """
const canvas=document.getElementById('view'),context=canvas.getContext('webgl2');
const rectangle=canvas.getBoundingClientRect();
return {kind:context?'webgl2':'unobservable',loss:context?(context.isContextLost()?'lost':'healthy'):'unobservable',
 version:context&&!context.isContextLost()?context.getParameter(context.VERSION):'',
 width:canvas.width,height:canvas.height,rectangle:[rectangle.left,rectangle.top,rectangle.width,rectangle.height]};
"""), "NATIVE_CURRENT_GRAPHICS_UNOBSERVABLE")
    snapshot = _snapshot(session)
    checks.append({"name": stage, "graphics": observed, "dom": snapshot})
    if (observed.get("kind") != "webgl2" or observed.get("loss") != "healthy"
            or "WebGL 2" not in str(observed.get("version"))):
        raise ValueError("NATIVE_CURRENT_GRAPHICS_NOT_HEALTHY:" + stage)
    if snapshot.get("ui_error"):
        raise ValueError("NATIVE_VISIBLE_PRODUCT_ERROR")


def _current_canvas_placement(value: object) -> dict[str, object]:
    """Choose no input or one reachable page-wheel input from CSS-pixel observations.

    A small margin is used only when scrolling is needed and fits. Gutter safety
    requires both the observed normal-page target and a point outside the canvas;
    this decision never dispatches input or mutates the supplied observations.
    """
    observed = _object(value, "NATIVE_CURRENT_CANVAS_PLACEMENT_OBSERVATION")
    rectangle, viewport = observed.get("rectangle"), observed.get("viewport")
    if not isinstance(rectangle, list) or len(rectangle) != 4 or not isinstance(viewport, list) or len(viewport) != 2:
        raise ValueError("NATIVE_CURRENT_CANVAS_PLACEMENT_OBSERVATION")
    left, top, width, height = (_number(item, "NATIVE_CURRENT_CANVAS_PLACEMENT_OBSERVATION") for item in rectangle)
    viewport_width, viewport_height = (_number(item, "NATIVE_CURRENT_CANVAS_PLACEMENT_OBSERVATION") for item in viewport)
    if width <= 0 or height <= 0 or left < 0 or left + width > viewport_width or height > viewport_height:
        raise ValueError("NATIVE_CURRENT_CANVAS_CANNOT_FIT")
    if 0 <= top and top + height <= viewport_height:
        return {"action": "none"}
    point = observed.get("gutter_point")
    if not isinstance(point, list) or len(point) != 2 or observed.get("gutter_target") != "page-gutter":
        raise ValueError("NATIVE_CURRENT_CANVAS_UNSAFE_GUTTER")
    point_x, point_y = (math.floor(_number(item, "NATIVE_CURRENT_CANVAS_UNSAFE_GUTTER")) for item in point)
    if (not 0 <= point_x < viewport_width or not 0 <= point_y < viewport_height
            or left <= point_x < left + width and top <= point_y < top + height):
        raise ValueError("NATIVE_CURRENT_CANVAS_UNSAFE_GUTTER")
    scroll_y = _number(observed.get("scroll_y"), "NATIVE_CURRENT_CANVAS_PLACEMENT_OBSERVATION")
    scroll_max_y = _number(observed.get("scroll_max_y"), "NATIVE_CURRENT_CANVAS_PLACEMENT_OBSERVATION")
    if not 0 <= scroll_y <= scroll_max_y:
        raise ValueError("NATIVE_CURRENT_CANVAS_CANNOT_FIT")
    minimum_delta_y = math.ceil(max(top + height - viewport_height, -scroll_y))
    maximum_delta_y = math.floor(min(top, scroll_max_y - scroll_y))
    if minimum_delta_y > maximum_delta_y:
        raise ValueError("NATIVE_CURRENT_CANVAS_CANNOT_FIT")
    margin = min(16.0, (viewport_height - height) / 2.0)
    requested_delta_y = math.floor(top - margin) if top < 0 else math.ceil(top + height - viewport_height + margin)
    delta_y = max(minimum_delta_y, min(maximum_delta_y, requested_delta_y))
    return {"action": "wheel", "x": point_x, "y": point_y, "delta_y": delta_y}


def _current_canvas_position_observation(session: Session) -> dict[str, object]:
    """Read real page geometry and hit-tested gutter without scrolling or touching app state."""
    observed = _object(_read(session, """
const canvas=document.getElementById('view'),rectangle=canvas.getBoundingClientRect();
const x=Math.floor(Math.min(16,Math.max(0,rectangle.left/2))),y=Math.floor(innerHeight/2);
const hit=document.elementFromPoint(x,y),scroller=document.scrollingElement;
return {rectangle:[rectangle.left,rectangle.top,rectangle.width,rectangle.height],viewport:[innerWidth,innerHeight],
 scroll_y:scroller?.scrollTop??null,scroll_max_y:scroller?Math.max(0,scroller.scrollHeight-scroller.clientHeight):null,
 gutter_point:[x,y],gutter_target:hit&&['HTML','BODY','MAIN'].includes(hit.tagName)
 &&!hit.closest('canvas,.viewport,button,input,select,textarea,a,summary,dialog,iframe,[contenteditable]')?'page-gutter':'unsafe'};
"""), "NATIVE_CURRENT_CANVAS_PLACEMENT_OBSERVATION")
    session[4]["current_canvas_placement_cache"] = observed
    return observed


def _current_position_canvas(session: Session, name: str, checks: Checks) -> None:
    """Own at most one ordinary page scroll and full-layout admission before capture.

    The gutter avoids the viewer's wheel-to-zoom handler. An unknown/refused input,
    absent movement or incomplete result fails without another scroll or image.
    """
    before = _current_canvas_position_observation(session)
    placement = _current_canvas_placement(before)
    checks.append({"name": "canvas-placement:" + name, "before": before, "decision": placement})
    if placement["action"] == "wheel":
        _command(session, "POST", "/actions", {"actions": [{"type": "wheel", "id": "native-page-wheel", "actions": [
            {"type": "scroll", "duration": 120, "origin": "viewport", "x": placement["x"], "y": placement["y"],
             "deltaX": 0, "deltaY": placement["delta_y"]}]}]}, "current-canvas-page-scroll")
        after = _current_canvas_position_observation(session)
        checks.append({"name": "canvas-after-page-scroll:" + name, "after": after})
        movement = _number(after.get("scroll_y"), "NATIVE_CURRENT_CANVAS_PLACEMENT_OBSERVATION") - _number(
            before.get("scroll_y"), "NATIVE_CURRENT_CANVAS_PLACEMENT_OBSERVATION")
        if movement * _number(placement["delta_y"], "NATIVE_CURRENT_CANVAS_PLACEMENT_OBSERVATION") <= 0:
            raise ValueError("NATIVE_CURRENT_CANVAS_SCROLL_NOT_OBSERVED")
    checks.append({"name": "canvas-layout-before-capture:" + name, "layout": _layout(session, ("#view",))})


def _current_stage_images(session: Session, output: pathlib.Path, stage: str, checks: Checks, images: Images) -> None:
    """Keep native stage originals and require a complete visible canvas target.

    Editor clipping remains recorded rather than repaired by alternate pixels.
    Position the separate canvas before its sole standard capture, then retain
    full layout and proportional-PNG checks after capture as well.
    Actual model visibility still requires executor and independent image views.
    """
    for suffix, target in (("", "viewport"), ("-editor", "#editor"), ("-canvas", "#view")):
        image_name = stage + suffix
        if target == "#view":
            _current_position_canvas(session, image_name, checks)
        _current_graphics(session, "before-capture:" + image_name, checks)
        descriptor = _capture(session, output, image_name, images, target)
        if target == "#view":
            layout = _layout(session, ("#view",))
            rectangle = _object(layout["controls"][0], "NATIVE_CURRENT_CANVAS_LAYOUT")["rectangle"]
            expected_height = _number(descriptor.get("png_width"), "NATIVE_SCREENSHOT_DIMENSIONS") * rectangle[3] / rectangle[2]
            if abs(_number(descriptor.get("png_height"), "NATIVE_SCREENSHOT_DIMENSIONS") - expected_height) > 2:
                raise ValueError("NATIVE_CURRENT_CANVAS_CAPTURE_CLIPPED")
            checks.append({"name": "complete-canvas-capture:" + image_name, "layout": layout, "image": descriptor})
        _current_graphics(session, "after-capture:" + image_name, checks)


def _current_original_dimensions_match(observed: object) -> bool:
    """Keep the current check's millimeter source size separate from its edited size."""
    if not isinstance(observed, dict):
        return False
    try:
        original_mm = _dimensions(observed.get("original_dimensions"))
    except ValueError:
        return False
    return all(abs(original_mm[axis] - expected) <= 0.0001
               for axis, expected in enumerate((17.0, 11.0, 7.0)))


def _current_product(session: Session, output: pathlib.Path, run_id: str, checks: Checks, images: Images) -> None:
    """Test current import/edit/render only; no entitlement, download or persisted-state shortcut."""
    session[4]["stage"] = "current-public-navigation"
    _command(session, "POST", "/url", {"url": CURRENT_ORIGIN + "/"}, "open-current-public")
    startup = _object(_poll(session[3], lambda: _snapshot(session), product_startup_ready,
                            "NATIVE_PUBLIC_STARTUP_DEADLINE"), "NATIVE_DOM_OBSERVATION")
    checks.append({"name": "current-startup-before-file-selection", "dom": startup})
    page = _current_empty_page(session)
    identity = _current_public_identity(session, page)
    checks.append({"name": "current-public-identity", "identity": identity})
    _current_empty_page(session)
    fixture, summary = _new_fixture(output, run_id, "current", (17.0, 11.0, 7.0))
    session[4]["stage"] = "current-once-only-file-selection"
    supplied = _supply_product_file(session, fixture)
    imported = _model(session, (17.0, 11.0, 7.0), fixture.name, CURRENT_RELEASE, "required")
    if not _current_original_dimensions_match(imported):
        raise ValueError("NATIVE_CURRENT_ORIGINAL_DIMENSIONS_MISMATCH:import")
    if supplied.get("sha256") != summary["sha256"]:
        raise ValueError("NATIVE_IMPORTED_FILE_IDENTITY_MISMATCH")
    checks.append({"name": "current-normal-import", "supplied_file": supplied, "stl": summary, "dom": imported})
    session[4]["stage"] = "current-import-images"
    _current_stage_images(session, output, "imported-model", checks, images)
    original_operation = _edit(session, (17.0, 11.0, 7.0), 12.0, 3.0, CURRENT_RELEASE, "required")
    edited = _model(session, (20.0, 11.0, 7.0), fixture.name, CURRENT_RELEASE, "required")
    if not _current_original_dimensions_match(edited):
        raise ValueError("NATIVE_CURRENT_ORIGINAL_DIMENSIONS_MISMATCH:edit")
    _settings(edited, 12.0, 3.0)
    if edited.get("focused") != "target":
        raise ValueError("NATIVE_TAB_ORDER_DID_NOT_REACH_TARGET")
    checks.append({"name": "current-fixed-start-X-edit", "dom": edited, "original_operation": original_operation,
                   "layout": _layout(session, ("#delta", "#target"))})
    session[4]["stage"] = "current-edit-images"
    _current_stage_images(session, output, "edited-model", checks, images)
    _current_graphics(session, "before-current-camera-controls", checks)
    checks.append({"name": "current-view-and-focus-controls", **_view_controls(session, output, images)})
    _current_graphics(session, "after-current-camera-controls", checks)
    final_model = _model(session, (20.0, 11.0, 7.0), fixture.name, CURRENT_RELEASE, "required")
    if not _current_original_dimensions_match(final_model):
        raise ValueError("NATIVE_CURRENT_ORIGINAL_DIMENSIONS_MISMATCH:final")
    _settings(final_model, 12.0, 3.0)
    if hashlib.sha256(fixture.read_bytes()).hexdigest() != summary["sha256"]:
        raise ValueError("NATIVE_PRODUCT_FILE_BYTES_CHANGED")
    checks.append({"name": "current-model-after-controls", "dom": final_model,
                   "result_name": "current-public-native-import-edit-render",
                   "remaining": "full-Safari-download-reopen-controls-and-stage-images"})


def _draw_vector(value: object, length: int) -> list[float]:
    if not isinstance(value, list) or len(value) != length:
        raise ValueError("NATIVE_DRAW_VECTOR")
    return [_number(component, "NATIVE_DRAW_VECTOR") for component in value]


def _draw_integer(value: object, minimum: int, maximum: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not minimum <= value <= maximum:
        raise ValueError("NATIVE_DRAW_INTEGER")
    return value


def _draw_style(value: object) -> dict[str, object]:
    style = _object(value, "NATIVE_DRAW_STYLE")
    for field in ("display", "visibility"):
        _string(style.get(field), "NATIVE_DRAW_STYLE")
    opacity = _number(style.get("opacity"), "NATIVE_DRAW_STYLE")
    rectangle = _draw_vector(style.get("rectangle"), 4)
    if not 0 <= opacity <= 1 or min(rectangle[2:]) < 0:
        raise ValueError("NATIVE_DRAW_STYLE")
    return style


def _draw_pixel_class(observation: dict[str, object]) -> str:
    """Validate compact bottom-left-origin RGBA telemetry without inferring visibility."""
    if (observation.get("observer") != "completed" or observation.get("native_click") != "completed"
            or _draw_integer(observation.get("record_count"), 1, 1) != 1):
        raise ValueError("NATIVE_DRAW_EVENT")
    event = _object(observation.get("event"), "NATIVE_DRAW_EVENT")
    if any(event.get(field) != expected for field, expected in (
            ("type", "click"), ("trust", "trusted"), ("target", "[data-view=fit]"),
            ("order", "document-bubble-after-target"))):
        raise ValueError("NATIVE_DRAW_EVENT")
    started, timestamp, observed, completed = (
        _number(event.get(field), "NATIVE_DRAW_EVENT") for field in
        ("click_started_ms", "event_timestamp_ms", "observed_ms", "click_completed_ms"))
    if not 0 <= started <= timestamp <= observed <= completed:
        raise ValueError("NATIVE_DRAW_EVENT")
    visibility = _object(observation.get("visibility"), "NATIVE_DRAW_VISIBILITY")
    if visibility.get("document") != "visible" or visibility.get("focus") != "focused":
        raise ValueError("NATIVE_DRAW_VISIBILITY")
    _string(visibility.get("active_element"), "NATIVE_DRAW_VISIBILITY")
    viewport_width, viewport_height = _draw_vector(visibility.get("viewport"), 2)
    _draw_vector(visibility.get("scroll"), 2)
    canvas = _draw_style(visibility.get("canvas"))
    _draw_style(visibility.get("overlay"))
    left, top, css_width, css_height = _draw_vector(canvas.get("rectangle"), 4)
    if (canvas.get("display") == "none" or canvas.get("visibility") != "visible"
            or canvas.get("opacity") != 1 or min(css_width, css_height) <= 0
            or min(left, top) < 0 or left + css_width > viewport_width
            or top + css_height > viewport_height):
        raise ValueError("NATIVE_DRAW_VISIBILITY")
    graphics = _object(observation.get("gl"), "NATIVE_DRAW_GL")
    if any(graphics.get(field) != expected for field, expected in (
            ("context", "webgl2"), ("context_status", "healthy"),
            ("framebuffer", "default"), ("program_link", "linked"))):
        raise ValueError("NATIVE_DRAW_GL")
    attributes = _object(graphics.get("context_attributes"), "NATIVE_DRAW_GL")
    if attributes.get("alpha") is not False or attributes.get("preserveDrawingBuffer") is not False:
        raise ValueError("NATIVE_DRAW_GL")
    shader_logs = graphics.get("shader_logs")
    if (not isinstance(shader_logs, list) or len(shader_logs) != 2
            or { _object(shader, "NATIVE_DRAW_GL").get("type") for shader in shader_logs }
            != {"vertex", "fragment"}):
        raise ValueError("NATIVE_DRAW_GL")
    for shader in shader_logs:
        if shader.get("status") != "compiled" or not isinstance(shader.get("log"), str):
            raise ValueError("NATIVE_DRAW_GL")
    uniforms = _object(graphics.get("uniforms"), "NATIVE_DRAW_GL")
    for name, length in (("eye", 3), ("right", 3), ("up", 3), ("forward", 3), ("scale", 2), ("planes", 2)):
        _draw_vector(uniforms.get(name), length)
    if min(_draw_vector(uniforms.get("scale"), 2)) <= 0:
        raise ValueError("NATIVE_DRAW_GL")
    buffer_bytes = _draw_integer(graphics.get("position_buffer_bytes"), 36, 0x7fffffff)
    if buffer_bytes % 36:
        raise ValueError("NATIVE_DRAW_GL")
    pixels = _object(observation.get("pixels"), "NATIVE_DRAW_PIXELS")
    if pixels.get("readback") != "completed" or pixels.get("error") != "":
        raise ValueError("NATIVE_DRAW_PIXELS")
    width = _draw_integer(pixels.get("width"), 1, DRAW_READBACK_BYTE_LIMIT // 4)
    height = _draw_integer(pixels.get("height"), 1, DRAW_READBACK_BYTE_LIMIT // 4)
    pixel_count = width * height
    if (_draw_integer(pixels.get("byte_length"), 4, DRAW_READBACK_BYTE_LIMIT) != pixel_count * 4
            or _draw_vector(graphics.get("drawing_buffer"), 2) != [width, height]
            or _draw_vector(graphics.get("viewport"), 4) != [0, 0, width, height]):
        raise ValueError("NATIVE_DRAW_PIXELS")
    sentinel = _draw_vector(pixels.get("sentinel_rgba"), 4)
    clear = _draw_vector(pixels.get("clear_rgba"), 4)
    if sentinel != [19, 37, 73, 109] or clear[3] != 255:
        raise ValueError("NATIVE_DRAW_PIXELS")
    for component in clear:
        if not component.is_integer() or not 0 <= component <= 255:
            raise ValueError("NATIVE_DRAW_PIXELS")
    for field in ("sentinel_unchanged_count", "zero_pixel_count"):
        if _draw_integer(pixels.get(field), 0, pixel_count) != 0:
            raise ValueError("NATIVE_DRAW_PIXELS")
    if _draw_integer(pixels.get("opaque_pixel_count"), 0, pixel_count) != pixel_count:
        raise ValueError("NATIVE_DRAW_PIXELS")
    clear_count = _draw_integer(pixels.get("clear_pixel_count"), 0, pixel_count)
    foreground_count = _draw_integer(pixels.get("foreground_count"), 0, pixel_count)
    unique_count = _draw_integer(pixels.get("unique_color_count"), 1, pixel_count)
    if clear_count + foreground_count != pixel_count:
        raise ValueError("NATIVE_DRAW_PIXELS")
    bounds = pixels.get("foreground_bounds")
    if foreground_count:
        min_x, min_y, max_x, max_y = _draw_vector(bounds, 4)
        if (any(not coordinate.is_integer() for coordinate in (min_x, min_y, max_x, max_y))
                or not 0 <= min_x <= max_x < width or not 0 <= min_y <= max_y < height
                or foreground_count > (max_x - min_x + 1) * (max_y - min_y + 1)):
            raise ValueError("NATIVE_DRAW_PIXELS")
    elif bounds != []:
        raise ValueError("NATIVE_DRAW_PIXELS")
    sample_positions = ((0, 0), (width - 1, 0), (0, height - 1), (width - 1, height - 1),
                        (width // 2, height // 2))
    samples = pixels.get("samples")
    if not isinstance(samples, list) or len(samples) != 5:
        raise ValueError("NATIVE_DRAW_PIXELS")
    sampled_colors: set[tuple[float, ...]] = set()
    for sample, (expected_x, expected_y) in zip(samples, sample_positions):
        sample = _object(sample, "NATIVE_DRAW_PIXELS")
        if (sample.get("x") != expected_x or sample.get("y") != expected_y
                or isinstance(sample.get("x"), bool) or isinstance(sample.get("y"), bool)):
            raise ValueError("NATIVE_DRAW_PIXELS")
        rgba = _draw_vector(sample.get("rgba"), 4)
        if rgba[3] != 255 or any(not component.is_integer() or not 0 <= component <= 255 for component in rgba):
            raise ValueError("NATIVE_DRAW_PIXELS")
        sampled_colors.add(tuple(rgba))
        if rgba != clear and (not foreground_count or not min_x <= expected_x <= max_x
                              or not min_y <= expected_y <= max_y):
            raise ValueError("NATIVE_DRAW_PIXELS")
        if clear_count == pixel_count and rgba != clear or clear_count == 0 and rgba == clear:
            raise ValueError("NATIVE_DRAW_PIXELS")
    if len(sampled_colors) > unique_count:
        raise ValueError("NATIVE_DRAW_PIXELS")
    if clear_count == pixel_count:
        if unique_count != 1:
            raise ValueError("NATIVE_DRAW_PIXELS")
        return "CLEAR_ONLY"
    if unique_count == 1:
        if clear_count != 0 or bounds != [0, 0, width - 1, height - 1]:
            raise ValueError("NATIVE_DRAW_PIXELS")
        return "FLAT_UNCLASSIFIED"
    if (0 < foreground_count < pixel_count and unique_count <= foreground_count + 1
            and 0 < min_x <= max_x < width - 1 and 0 < min_y <= max_y < height - 1
            and all(sample["rgba"] == clear for sample in samples[:4])):
        return "RASTER_CONTENT_OBSERVED"
    return "UNKNOWN"


def _classify_draw_observation(value: object) -> dict[str, object]:
    """Return a conservative pixel class; native originals always need actual viewing."""
    try:
        pixel_class = _draw_pixel_class(_object(value, "NATIVE_DRAW_OBSERVATION"))
    except (ValueError, TypeError, KeyError):
        pixel_class = "UNKNOWN"
    return {"pixel_class": pixel_class, "native_visible_model": "UNESTABLISHED"}


def _diagnostic_capture_provenance(value: object) -> dict[str, object]:
    """Accept only the two completed native originals, without classifying their pixels."""
    status = "UNKNOWN"
    try:
        if not isinstance(value, list) or len(value) != 2:
            raise ValueError("NATIVE_DRAW_ORIGINALS")
        for image, name, method, target in zip(value, ("draw-canvas", "draw-viewport"),
                                              ("element", "viewport"), ("#view", "viewport")):
            image = _object(image, "NATIVE_DRAW_ORIGINALS")
            if any(image.get(field) != expected for field, expected in (
                    ("name", name), ("capture_method", method), ("target", target),
                    ("outcome", "completed"), ("command_outcome", "completed"))):
                raise ValueError("NATIVE_DRAW_ORIGINALS")
            for field in ("png_width", "png_height"):
                _draw_integer(image.get(field), 1, 0x7fffffff)
            _draw_integer(image.get("png_bytes"), 1, PNG_BYTE_LIMIT)
            if re.fullmatch(r"[0-9a-f]{64}", _string(image.get("sha256"), "NATIVE_DRAW_ORIGINALS")) is None:
                raise ValueError("NATIVE_DRAW_ORIGINALS")
        status = "COMPLETED_ORIGINALS"
    except (ValueError, TypeError):
        pass
    return {"capture_status": status, "native_visible_model": "UNESTABLISHED", "originals": value}


def _draw_observer_command(session: Session, script: str, arguments: tuple[object, ...], name: str) -> object:
    """Own observer script effects once; uncertainty requires session termination, not replay."""
    try:
        return _command(session, "POST", "/execute/sync", {"script": script, "args": arguments}, name)
    except Exception as error:
        if not _failure_code(error).startswith("WEBDRIVER_REMOTE_ERROR:"):
            session[4]["draw_observer_transport"] = "unknown"
        raise


def _remove_draw_observer(session: Session, key: str) -> None:
    """Remove exactly this phase's listener/queue once; unknown transport uses session cleanup."""
    if session[4].get("draw_observer_transport") == "unknown":
        session[4]["draw_observer_cleanup"] = "uncertain-session-termination-required"
        return
    session[4]["draw_observer_cleanup"] = "unknown"
    receipt = _draw_observer_command(session, """
const key=arguments[0],queue=window[key];
if(!queue)return 'absent';
document.removeEventListener('click',queue.listener,false);
delete window[key];return 'removed';
""", (key,), "remove-draw-observer")
    if receipt not in ("removed", "absent"):
        raise ValueError("NATIVE_DRAW_OBSERVER_CLEANUP")
    session[4]["draw_observer_cleanup"] = receipt


def _observe_fit_draw(session: Session) -> dict[str, object]:
    """Observe one trusted Fit draw in the target's synchronous bubbling event task.

    Exact app/viewer body hashes admit the known synchronous target handler. The
    narrowly permitted callback owns only bounded test telemetry. DOM timestamps
    all use performance's origin; no Python/UTC clock enters event ordering.
    """
    fit_element = _element(session, "[data-view=fit]")
    key = "__public_qa_fit_draw_" + uuid.uuid4().hex
    session[4]["draw_observer_cleanup"] = "pending"
    try:
        receipt = _draw_observer_command(session, """
const key=arguments[0],fit=arguments[1],limit=arguments[2];
const canvas=document.getElementById('view'),overlay=document.getElementById('overlay');
if(window[key]||!canvas||!overlay||fit!==document.querySelector('[data-view=fit]')
 ||typeof fit.onclick!=='function')return 'admission-failed';
const gl=canvas.getContext('webgl2'),width=gl?.drawingBufferWidth,height=gl?.drawingBufferHeight;
if(!gl||gl.isContextLost()||!Number.isSafeInteger(width)||!Number.isSafeInteger(height)
 ||width<=0||height<=0||width*height*4>limit)return 'admission-failed';
const destination=new Uint8Array(width*height*4),colors=new Uint32Array(width*height);
const sentinel=[19,37,73,109],targetHandler=fit.onclick;
for(let offset=0;offset<destination.length;offset+=4)destination.set(sentinel,offset);
const rectangle=element=>{const r=element.getBoundingClientRect();return [r.left,r.top,r.width,r.height];};
const style=element=>{const s=getComputedStyle(element);return {display:s.display,visibility:s.visibility,
 opacity:Number(s.opacity),rectangle:rectangle(element)};};
const queue={records:[],listener:null,click_started_ms:performance.now()};
function observeFitDraw(event){
 if(!event.isTrusted||event.type!=='click'||!(event.target instanceof Element)
  ||event.target.closest('[data-view=fit]')!==fit)return;
 if(queue.records.length>=2)return;
 const observed_ms=performance.now();
 if(queue.records.length){queue.records.push(Object.freeze({error:'duplicate-event'}));return;}
 try{
  const visibility={document:document.visibilityState,focus:document.hasFocus()?'focused':'unfocused',
   active_element:document.activeElement===fit?'button[data-view=fit]':document.activeElement?.tagName||'absent',
   canvas:style(canvas),overlay:style(overlay),viewport:[innerWidth,innerHeight],scroll:[scrollX,scrollY]};
  const program=gl.getParameter(gl.CURRENT_PROGRAM),framebuffer=gl.getParameter(gl.FRAMEBUFFER_BINDING);
  const readFramebuffer=gl.getParameter(gl.READ_FRAMEBUFFER_BINDING),readBuffer=gl.getParameter(gl.READ_BUFFER);
  const shaders=program?gl.getAttachedShaders(program):[];
  const uniforms={};for(const name of ['eye','right','up','forward','scale','planes']){
   const location=program?gl.getUniformLocation(program,name):null;
   const value=location===null?null:gl.getUniform(program,location);
   uniforms[name]=value===null?null:Array.from(value);
  }
  const attribute=program?gl.getAttribLocation(program,'position'):-1;
  const attributeBuffer=attribute<0?null:gl.getVertexAttrib(attribute,gl.VERTEX_ATTRIB_ARRAY_BUFFER_BINDING);
  const graphics={context:'webgl2',context_status:gl.isContextLost()?'lost':'healthy',
   framebuffer:framebuffer===null&&readFramebuffer===null&&readBuffer===gl.BACK?'default':'non-default',
   context_attributes:gl.getContextAttributes(),
   drawing_buffer:[gl.drawingBufferWidth,gl.drawingBufferHeight],viewport:Array.from(gl.getParameter(gl.VIEWPORT)),
   program_link:program&&gl.getProgramParameter(program,gl.LINK_STATUS)?'linked':'failed',
   program_log:program?gl.getProgramInfoLog(program):'',
   shader_logs:(shaders||[]).map(shader=>({type:gl.getShaderParameter(shader,gl.SHADER_TYPE)===gl.VERTEX_SHADER?'vertex':'fragment',
    status:gl.getShaderParameter(shader,gl.COMPILE_STATUS)?'compiled':'failed',log:gl.getShaderInfoLog(shader)||''})),
   uniforms,position_buffer_bytes:attributeBuffer&&attributeBuffer===gl.getParameter(gl.ARRAY_BUFFER_BINDING)
    ?gl.getBufferParameter(gl.ARRAY_BUFFER,gl.BUFFER_SIZE):null};
  const clear=Array.from(gl.getParameter(gl.COLOR_CLEAR_VALUE),component=>Math.round(component*255));
  const pixels={readback:'not-admitted',error:'',width,height,byte_length:destination.length,
   sentinel_rgba:sentinel,sentinel_unchanged_count:0,zero_pixel_count:0,opaque_pixel_count:0,
   clear_rgba:clear,clear_pixel_count:0,unique_color_count:0,foreground_count:0,foreground_bounds:[],samples:[]};
  if(graphics.framebuffer==='default'&&width===gl.drawingBufferWidth&&height===gl.drawingBufferHeight){
   gl.readPixels(0,0,width,height,gl.RGBA,gl.UNSIGNED_BYTE,destination);pixels.readback='completed';
   let minX=width,minY=height,maxX=-1,maxY=-1;
   for(let offset=0,index=0;offset<destination.length;offset+=4,index++){
    const r=destination[offset],g=destination[offset+1],b=destination[offset+2],a=destination[offset+3];
    colors[index]=((r*256+g)*256+b)*256+a;
    if(r===19&&g===37&&b===73&&a===109)pixels.sentinel_unchanged_count++;
    if(r===0&&g===0&&b===0&&a===0)pixels.zero_pixel_count++;
    if(a===255)pixels.opaque_pixel_count++;
    if(r===clear[0]&&g===clear[1]&&b===clear[2]&&a===clear[3])pixels.clear_pixel_count++;
    else{pixels.foreground_count++;const x=index%width,y=Math.floor(index/width);
     minX=Math.min(minX,x);minY=Math.min(minY,y);maxX=Math.max(maxX,x);maxY=Math.max(maxY,y);}
   }
   colors.sort();for(let index=0;index<colors.length;index++)if(index===0||colors[index]!==colors[index-1])pixels.unique_color_count++;
   if(pixels.foreground_count)pixels.foreground_bounds=[minX,minY,maxX,maxY];
   for(const [x,y] of [[0,0],[width-1,0],[0,height-1],[width-1,height-1],[Math.floor(width/2),Math.floor(height/2)]]){
    const offset=(y*width+x)*4;pixels.samples.push({x,y,rgba:Array.from(destination.subarray(offset,offset+4))});
   }
  }
  queue.records.push(Object.freeze({event:{type:event.type,trust:'trusted',target:'[data-view=fit]',
   order:event.eventPhase===Event.BUBBLING_PHASE&&event.currentTarget===document&&fit.onclick===targetHandler
    ?'document-bubble-after-target':'unknown',click_started_ms:queue.click_started_ms,
   event_timestamp_ms:event.timeStamp,observed_ms},visibility,gl:graphics,pixels}));
 }catch(error){queue.records.push(Object.freeze({error:error instanceof Error?error.name:'readback-error'}));}
}
queue.listener=observeFitDraw;window[key]=queue;
document.addEventListener('click',observeFitDraw,false);return 'installed';
""", (key, {ELEMENT_KEY: fit_element}, DRAW_READBACK_BYTE_LIMIT), "install-draw-observer")
        if receipt != "installed":
            raise ValueError("NATIVE_DRAW_OBSERVER_ADMISSION")
        try:
            click_receipt = _command(session, "POST", "/element/" + fit_element + "/click", {}, "diagnostic-once-only-fit")
        except Exception as error:
            if not _failure_code(error).startswith("WEBDRIVER_REMOTE_ERROR:"):
                session[4]["draw_observer_transport"] = "unknown"
            raise
        if click_receipt is not None:
            raise ValueError("NATIVE_DRAW_CLICK_RECEIPT")
        observed = _object(_draw_observer_command(session, """
const queue=window[arguments[0]],completed=performance.now();
if(!queue)return {observer:'absent',native_click:'completed',record_count:0};
const records=queue.records.splice(0),record=records.length===1?records[0]:{};
return {...record,observer:'completed',native_click:'completed',record_count:records.length,
 event:record.event?{...record.event,click_completed_ms:completed}:null};
""", (key,), "collect-draw-observer"), "NATIVE_DRAW_OBSERVER_RESULT")
        session[4]["draw_observation_cache"] = observed
        return observed
    finally:
        body_error = sys.exc_info()[1]
        try:
            _remove_draw_observer(session, key)
        except Exception as cleanup_error:
            session[4]["draw_observer_cleanup_code"] = _failure_code(cleanup_error)
            if body_error is None:
                raise


def _current_diagnostic(session: Session, output: pathlib.Path, run_id: str, checks: Checks, images: Images) -> None:
    """Import once, observe one real Fit draw, then retain exactly two native originals."""
    session[4]["stage"] = "current-diagnostic-navigation"
    _command(session, "POST", "/url", {"url": CURRENT_ORIGIN + "/"}, "open-current-public")
    startup = _object(_poll(session[3], lambda: _snapshot(session), product_startup_ready,
                            "NATIVE_PUBLIC_STARTUP_DEADLINE"), "NATIVE_DOM_OBSERVATION")
    checks.append({"name": "diagnostic-startup-before-file-selection", "dom": startup})
    identity = _current_public_identity(session, _current_empty_page(session))
    checks.append({"name": "diagnostic-public-identity-and-synchronous-fit-source", "identity": identity})
    _current_empty_page(session)
    fixture, summary = _new_fixture(output, run_id, "current", (17.0, 11.0, 7.0))
    session[4]["stage"] = "current-diagnostic-once-only-import"
    supplied = _supply_product_file(session, fixture)
    imported = _model(session, (17.0, 11.0, 7.0), fixture.name, CURRENT_RELEASE, "required")
    if not _current_original_dimensions_match(imported) or supplied.get("sha256") != summary["sha256"]:
        raise ValueError("NATIVE_DRAW_IMPORT_MISMATCH")
    checks.append({"name": "diagnostic-normal-import", "supplied_file": supplied, "stl": summary, "dom": imported})
    _current_position_canvas(session, "draw-canvas", checks)
    checks.append({"name": "diagnostic-fit-and-canvas-layout", "layout": _layout(session, ("#view", "[data-view=fit]"))})
    session[4]["stage"] = "current-diagnostic-fit-observation"
    observation = _observe_fit_draw(session)
    classification = _classify_draw_observation(observation)
    checks.append({"name": "diagnostic-same-task-draw", "observation": observation, **classification})
    if classification["pixel_class"] == "UNKNOWN":
        raise ValueError("NATIVE_DRAW_OBSERVATION_INSUFFICIENT")
    if session[4].get("draw_observer_cleanup") != "removed":
        raise ValueError("NATIVE_DRAW_OBSERVER_CLEANUP")
    session[4]["stage"] = "current-diagnostic-native-originals"
    try:
        canvas_image = _capture(session, output, "draw-canvas", images, "#view")
        layout = _layout(session, ("#view",))
        rectangle = _object(layout["controls"][0], "NATIVE_CURRENT_CANVAS_LAYOUT")["rectangle"]
        expected_height = _number(canvas_image.get("png_width"), "NATIVE_SCREENSHOT_DIMENSIONS") * rectangle[3] / rectangle[2]
        if abs(_number(canvas_image.get("png_height"), "NATIVE_SCREENSHOT_DIMENSIONS") - expected_height) > 2:
            raise ValueError("NATIVE_CURRENT_CANVAS_CAPTURE_CLIPPED")
        checks.append({"name": "diagnostic-complete-native-canvas", "layout": layout, "image": canvas_image})
        _capture(session, output, "draw-viewport", images)
    finally:
        provenance = _diagnostic_capture_provenance(session[4].get("capture_observations_cache", []))
        session[4]["draw_capture_provenance_cache"] = provenance
    checks.append({"name": "diagnostic-native-originals", **provenance})
    if provenance["capture_status"] != "COMPLETED_ORIGINALS":
        raise ValueError("NATIVE_DRAW_ORIGINALS_INCOMPLETE")
    final_model = _model(session, (17.0, 11.0, 7.0), fixture.name, CURRENT_RELEASE, "required")
    if (not _current_original_dimensions_match(final_model)
            or hashlib.sha256(fixture.read_bytes()).hexdigest() != summary["sha256"]):
        raise ValueError("NATIVE_DRAW_IMPORT_MISMATCH")
    checks.append({"name": "diagnostic-unchanged-model", "dom": final_model,
                   "remaining": "actual-native-image-view-and-full-Safari-download-reopen-controls"})


def _phase_contracts() -> dict[str, dict[str, object]]:
    return {
        "integration": {"handler": _integration, "previous_phases": (), "result_name": "native-file-controls"},
        "guest": {"handler": _product, "previous_phases": ("integration",), "result_name": "public-native-guest"},
        "controls": {"handler": _product, "previous_phases": ("integration", "guest"), "result_name": "public-native-controls"},
        "current": {"handler": _current_diagnostic, "previous_phases": (),
                    "result_name": "current-public-native-draw-diagnostic", "image_limit": 2, "edit_policy": "forbidden"},
        "full-current": {"handler": _current_product, "previous_phases": (),
                         "result_name": "current-public-native-import-edit-render", "edit_policy": "existing-import-edit-camera"}}


def _phase_contract(phase: str) -> dict[str, object]:
    """Own actual CLI handler, predecessors and result meaning in one pure contract."""
    contracts = _phase_contracts()
    if phase not in contracts:
        raise ValueError("NATIVE_PHASE_UNKNOWN")
    return contracts[phase]


def _argument_parser() -> argparse.ArgumentParser:
    """Construct the real CLI parser from the same phase contract used at dispatch."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=tuple(_phase_contracts()))
    parser.add_argument("--output", required=True, type=pathlib.Path)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--deadline-seconds", type=float, default=55.0)
    return parser


def _source_hashes() -> list[dict[str, object]]:
    """Identify every actual source byte used by this run, excluding runtime output."""
    root = pathlib.Path(__file__).resolve().parents[1]
    return [{"path": relative, "bytes": (root / relative).stat().st_size,
             "sha256": hashlib.sha256((root / relative).read_bytes()).hexdigest()} for relative in SOURCE_PATHS]


def _prerequisites(output: pathlib.Path, run_id: str, phase: str, sources: list[dict[str, object]]) -> int:
    """Require same-run guest/controls predecessors; current retains external transport."""
    previous_phases = _phase_contract(phase)["previous_phases"]
    previous_image_bytes = 0
    for previous in previous_phases:
        path = output.parent / previous / "result.json"
        if not path.is_file() or path.is_symlink():
            raise ValueError("NATIVE_PREREQUISITE_RESULT_MISSING:" + previous)
        record = _object(json.loads(path.read_text(encoding="utf-8")), "NATIVE_PREREQUISITE_RESULT_INVALID")
        if (record.get("run_id") != run_id or record.get("phase") != previous
                or record.get("result") != "automated-checks-passed" or record.get("source_files") != sources):
            raise ValueError("NATIVE_PREREQUISITE_NOT_PASSED:" + previous)
        previous_image_bytes += int(_number(record.get("image_output_bytes"), "NATIVE_IMAGE_ACCOUNTING_MISSING"))
    return previous_image_bytes


def _subprocess_text(arguments: tuple[str, ...], deadline: float) -> str:
    """Read a real installed-tool/version observation with a finite process timeout."""
    result = subprocess.run(arguments, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            timeout=_remaining(deadline), check=False)
    if result.returncode != 0:
        raise ValueError("NATIVE_VERSION_COMMAND_FAILED:" + pathlib.Path(arguments[0]).name)
    return result.stdout.decode("utf-8", errors="strict").strip()


def _versions(deadline: float, observations: dict[str, object]) -> None:
    """Read actual macOS/bundle/driver versions and Apple's stable release listing.

    Completed reads are written to the caller-owned result as they arrive, so a
    later failure does not erase them. The public release list compares versions,
    not exact Safari build currency or latest macOS. Gaps fail the phase.
    """
    observations["host_system"] = platform.system()
    observations["macos_version"] = _subprocess_text(("/usr/bin/sw_vers", "-productVersion"), deadline)
    observations["macos_build"] = _subprocess_text(("/usr/bin/sw_vers", "-buildVersion"), deadline)
    short = _subprocess_text(("/usr/bin/defaults", "read", "/Applications/Safari.app/Contents/Info", "CFBundleShortVersionString"), deadline)
    observations["safari_short_version"] = short
    observations["safari_build"] = _subprocess_text(("/usr/bin/defaults", "read", "/Applications/Safari.app/Contents/Info", "CFBundleVersion"), deadline)
    observations["driver_version"] = _subprocess_text(("/usr/bin/safaridriver", "--version"), deadline)
    observations["apple_source"] = APPLE_RELEASES_URL
    with urllib.request.urlopen(APPLE_RELEASES_URL, timeout=_remaining(deadline)) as response:
        release_text = re.sub(r"<[^>]*>", " ", response.read().decode("utf-8"))
    stable = latest_stable_safari_version(release_text)
    observations["apple_stable_safari"] = stable
    observations["apple_observed_utc"] = _utc()
    observations["build_currency"] = "not-established-by-release-list"
    observations["physical_ios"] = "not-exercised"
    require_current_safari_version(short, stable)


def _free_port() -> int:
    """Reserve an ephemeral loopback address long enough to select its port.

    The child owns its later bind. A bind race is a startup failure, never a reason
    to relaunch an uncertain process or change host permissions.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def _static_status(origin: str, deadline: float) -> int:
    """Read only the task-owned static root while its one server starts."""
    try:
        with urllib.request.urlopen(origin + "/", timeout=_remaining(deadline, 0.5)) as response:
            return int(response.status)
    except (OSError, urllib.error.URLError):
        return 0


def _launch(arguments: tuple[str, ...], name: str,
            resources: list[subprocess.Popen[bytes]], journal: pathlib.Path) -> subprocess.Popen[bytes]:
    """Own one native child, without retaining raw driver/session output.

    The operation journal retains creation/PID and startup failure status; the
    caller drains/terminates the process instead of detaching it.
    """
    _journal(journal, {"name": name, "outcome": "process-launch-requested"})
    process = subprocess.Popen(arguments, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    resources.append(process)
    _journal(journal, {"name": name, "outcome": "process-created", "pid": process.pid})
    return process


def _driver_status(origin: str, deadline: float, journal: pathlib.Path, process: subprocess.Popen[bytes]) -> object:
    """Only startup GET observations may repeat; process creation is never retried."""
    if process.poll() is not None:
        _journal(journal, {"name": "safaridriver", "outcome": "process-exited", "exit_code": process.returncode})
        raise ValueError("NATIVE_SAFARIDRIVER_EXITED")
    try:
        return _request(origin, "/status", "GET", None, deadline, journal, "driver-status")
    except RuntimeError:
        return None


def _session(origin: str, deadline: float, journal: pathlib.Path, process: subprocess.Popen[bytes],
             observation_cache: dict[str, object]) -> tuple[Session, object]:
    """Create exactly one real Safari session after bounded driver readiness."""
    startup_deadline = min(deadline, time.monotonic() + 8.0)
    _poll(startup_deadline, lambda: _driver_status(origin, startup_deadline, journal, process),
          lambda value: isinstance(value, dict) and value.get("ready") is True, "NATIVE_SAFARIDRIVER_STARTUP_DEADLINE")
    envelope = _object(_request(origin, "/session", "POST", {"capabilities": {"alwaysMatch": {"browserName": "safari"}}},
                                deadline, journal, "create-native-session"), "NATIVE_SESSION_ENVELOPE")
    session_id = _string(envelope.get("sessionId"), "NATIVE_SESSION_ID_MISSING")
    session: Session = origin, session_id, journal, deadline, observation_cache
    return session, envelope.get("capabilities")


def _cleanup(session: Session | None, resources: list[subprocess.Popen[bytes]], deadline: float) -> list[str]:
    """Delete the known session once and stop only this phase's child processes.

    Cleanup failures are retained separately and cannot replace an earlier error.
    Unknown session creation never authorizes a second create/delete attempt.
    """
    errors: list[str] = []
    if session is not None:
        try:
            _request(session[0], "/session/" + urllib.parse.quote(session[1], safe=""), "DELETE", None,
                     min(deadline, time.monotonic() + 1.5), session[2], "delete-native-session")
        except Exception as error:
            errors.append(_failure_code(error))
    for process in reversed(resources):
        if process.poll() is None:
            try:
                process.terminate()
                process.wait(timeout=max(0.01, min(0.5, deadline - time.monotonic())))
            except subprocess.TimeoutExpired:
                process.kill()
                try:
                    process.wait(timeout=max(0.01, min(0.5, deadline - time.monotonic())))
                except subprocess.TimeoutExpired:
                    errors.append("NATIVE_CHILD_REAP_DEADLINE")
            except OSError:
                errors.append("NATIVE_CHILD_CLEANUP_OS_ERROR")
    return errors


def _image_records(output: pathlib.Path, run_id: str, phase: str, images: Images,
                   previous_image_bytes: int) -> tuple[list[str], int]:
    """Prepare bounded records of the original PNG bytes; never fabricate pixels."""
    records: list[str] = []
    encoded_bytes = 0
    for image in images:
        name = _string(image.get("name"), "NATIVE_IMAGE_NAME")
        payload = (output / (name + ".png")).read_bytes()
        if len(payload) != image.get("png_bytes") or hashlib.sha256(payload).hexdigest() != image.get("sha256"):
            raise ValueError("NATIVE_IMAGE_BYTES_CHANGED")
        if len(payload) > PNG_BYTE_LIMIT:
            raise ValueError("NATIVE_IMAGE_COLLECTION_INCOMPLETE:PNG_LIMIT")
        encoded = base64.b64encode(payload).decode("ascii")
        chunk_count = (len(encoded) + 4095) // 4096
        for chunk_index in range(chunk_count):
            record = "PUBLIC_QA_IMAGE " + json.dumps({"run_id": run_id, "phase": phase, **image,
                "chunk_index": chunk_index, "chunk_count": chunk_count,
                "base64": encoded[chunk_index * 4096:(chunk_index + 1) * 4096]}, sort_keys=True, separators=(",", ":"))
            encoded_bytes += len(record.encode("utf-8")) + 1
            if previous_image_bytes + encoded_bytes > IMAGE_LOG_BYTE_LIMIT:
                raise ValueError("NATIVE_IMAGE_COLLECTION_INCOMPLETE:JOB_LOG_LIMIT")
            records.append(record)
    return records, encoded_bytes


def _failure_code(error: BaseException) -> str:
    if isinstance(error, (ValueError, RuntimeError, TimeoutError)):
        code = str(error)
        if re.fullmatch(r"[A-Za-z0-9_:.#=+ -]{1,180}", code):
            return code
    return "NATIVE_FAILURE:" + type(error).__name__


def _alarm(signum: int, frame: FrameType | None) -> None:
    """Report the owned phase timeout as an exception; mutate no application state."""
    raise TimeoutError("NATIVE_PHASE_DEADLINE")


def main() -> int:
    """Run one bounded phase, retaining original failure, cleanup and pending views.

    Arguments and actual Darwin admission precede browser/process effects. Existing
    output paths are refused so a repeated invocation cannot replay an operation.
    """
    parser = _argument_parser()
    arguments = parser.parse_args()
    phase_contract = _phase_contract(arguments.phase)
    if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", arguments.run_id) is None:
        parser.error("run-id must be 1..64 ASCII letters, digits, underscores or hyphens")
    if not math.isfinite(arguments.deadline_seconds) or not 0 < arguments.deadline_seconds <= 55:
        parser.error("deadline-seconds must be finite, positive and at most 55")
    if platform.system() != "Darwin":
        print("NATIVE_MACOS_REQUIRED", file=sys.stderr)
        return 2
    output = arguments.output.resolve()
    if output.exists():
        print("NATIVE_OUTPUT_ALREADY_EXISTS_NO_REPLAY", file=sys.stderr)
        return 2
    source_root = pathlib.Path(__file__).resolve().parents[1]
    if output == source_root or output.is_relative_to(source_root / "qa"):
        parser.error("output must not replace source files")
    sources = _source_hashes()
    previous_image_bytes = _prerequisites(output, arguments.run_id, arguments.phase, sources)
    output.mkdir(parents=True, exist_ok=False)
    journal = output / "operations.jsonl"
    checks: Checks = []
    images: Images = []
    resources: list[subprocess.Popen[bytes]] = []
    session: Session | None = None
    original_failure: dict[str, object] = {}
    versions: dict[str, object] = {}
    # Retain the last bounded DOM read and command location when the body deadline
    # leaves no time for another browser call. This is not application state.
    observation_cache: dict[str, object] = {"stage": "native-session-setup"}
    image_lines: list[str] = []
    image_bytes = 0
    started_utc, started = _utc(), time.monotonic()
    deadline = started + arguments.deadline_seconds
    signal.signal(signal.SIGALRM, _alarm)
    signal.setitimer(signal.ITIMER_REAL, arguments.deadline_seconds)
    try:
        try:
            _versions(deadline, versions)
            driver_port = _free_port()
            driver = _launch(("/usr/bin/safaridriver", "--port", str(driver_port)), "safaridriver", resources, journal)
            session, capabilities = _session("http://127.0.0.1:" + str(driver_port), deadline, journal, driver, observation_cache)
            identity = admit_native_session(platform.system(), capabilities)
            versions["session"] = identity
            if identity["browser_version"] != versions["safari_short_version"]:
                raise ValueError("NATIVE_SESSION_BUNDLE_VERSION_MISMATCH")
            _command(session, "POST", "/timeouts", {"script": 7000, "pageLoad": 8000, "implicit": 0}, "set-finite-session-timeouts")
            _command(session, "POST", "/window/rect", {"width": 1024, "height": 768}, "set-observed-desktop-viewport")
            handler = phase_contract["handler"]
            if handler is _integration:
                server_port = _free_port()
                _launch((sys.executable, "-E", "-S", "-B", "-m", "http.server", str(server_port), "--bind", "127.0.0.1",
                         "--directory", str(output / "transport")), "static-server", resources, journal)
                handler(session, output, arguments.run_id, "http://127.0.0.1:" + str(server_port), checks, images)
            elif handler is _current_diagnostic or handler is _current_product:
                handler(session, output, arguments.run_id, checks, images)
            else:
                handler(session, output, arguments.run_id, arguments.phase, checks, images)
            if "image_limit" in phase_contract and len(images) != phase_contract["image_limit"]:
                raise ValueError("NATIVE_DRAW_ORIGINALS_INCOMPLETE")
        except Exception as error:
            original_failure = {"code": _failure_code(error), "exception": type(error).__name__}
            if (session is not None and "session" in versions and time.monotonic() < deadline
                    and arguments.phase != "current"):
                try:
                    original_failure["selected_dom"] = _snapshot(session)
                except Exception as diagnostic_error:
                    original_failure["diagnostic_code"] = _failure_code(diagnostic_error)
        try:
            _remaining(deadline)
            image_lines, image_bytes = _image_records(output, arguments.run_id, arguments.phase, images, previous_image_bytes)
        except Exception as collection_error:
            if not original_failure:
                original_failure = {"code": _failure_code(collection_error), "exception": type(collection_error).__name__}
            else:
                original_failure["image_collection_code"] = _failure_code(collection_error)
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        cleanup_errors = _cleanup(session, resources, time.monotonic() + 5.0)
    signal.setitimer(signal.ITIMER_REAL, max(0.001, started + arguments.deadline_seconds + 5.0 - time.monotonic()))
    result: dict[str, object] = {
        "format_version": 1, "run_id": arguments.run_id, "phase": arguments.phase,
        "result": "failed" if original_failure or cleanup_errors else "automated-checks-passed",
        "image_observation": "pending-executor-view", "source_files": sources, "versions": versions,
        "started_utc": started_utc, "ended_utc": _utc(), "elapsed_seconds": time.monotonic() - started,
        "checks": checks, "images": images, "image_output_bytes": image_bytes,
        "original_failure": original_failure, "cleanup_errors": cleanup_errors,
        "observation_cache": observation_cache,
        "limits": ["desktop-not-physical-ios", "actual-image-view-pending", "private-services-not-exercised",
                   "executor-must-retain-provider-identities-and-pre-post-balance"]}
    if arguments.phase in ("current", "full-current"):
        result["result_name"] = phase_contract["result_name"]
    _json_file(output / "result.json", result)
    for line in image_lines:
        print(line, flush=True)
    print("PUBLIC_QA_RESULT " + json.dumps(result, sort_keys=True, separators=(",", ":"), allow_nan=False), flush=True)
    signal.setitimer(signal.ITIMER_REAL, 0)
    return 1 if original_failure or cleanup_errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
