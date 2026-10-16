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


# The public guest release is the only product target. Resource limits are policy,
# not conclusions about a model, a browser's capabilities, or image contents.
PUBLIC_URL = "https://part-stretch-free.pages.dev/"
PUBLIC_RELEASE = "9b0731642df08c879cbea912b6ff7daf3401a164"
APPLE_RELEASES_URL = "https://support.apple.com/en-us/100100"
PNG_BYTE_LIMIT = 256 * 1024
IMAGE_LOG_BYTE_LIMIT = 1024 * 1024
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


def _model(session: Session, size_mm: Point, expected_filename: str = "") -> dict[str, object]:
    """Wait for settled public geometry/source and reject its displayed error."""
    observed = _object(_poll(session[3], lambda: _snapshot(session),
                             lambda value: _matches_model(value, size_mm, expected_filename),
                             "NATIVE_MODEL_DIMENSIONS_DEADLINE"), "NATIVE_DOM_OBSERVATION")
    if observed.get("release") != PUBLIC_RELEASE or observed.get("services") != "guest-beta":
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


def _edit(session: Session, size_mm: Point, end_mm: float, delta_mm: float) -> dict[str, object]:
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
    original_operation = _model(session, size_mm)
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


def _source_hashes() -> list[dict[str, object]]:
    """Identify every actual source byte used by this run, excluding runtime output."""
    root = pathlib.Path(__file__).resolve().parents[1]
    return [{"path": relative, "bytes": (root / relative).stat().st_size,
             "sha256": hashlib.sha256((root / relative).read_bytes()).hexdigest()} for relative in SOURCE_PATHS]


def _prerequisites(output: pathlib.Path, run_id: str, phase: str, sources: list[dict[str, object]]) -> int:
    """Require earlier successful phases from this exact run and eight-file revision."""
    previous_phases = () if phase == "integration" else ("integration",) if phase == "guest" else ("integration", "guest")
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
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=("integration", "guest", "controls"))
    parser.add_argument("--output", required=True, type=pathlib.Path)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--deadline-seconds", type=float, default=55.0)
    arguments = parser.parse_args()
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
            if arguments.phase == "integration":
                server_port = _free_port()
                _launch((sys.executable, "-E", "-S", "-B", "-m", "http.server", str(server_port), "--bind", "127.0.0.1",
                         "--directory", str(output / "transport")), "static-server", resources, journal)
                _integration(session, output, arguments.run_id, "http://127.0.0.1:" + str(server_port), checks, images)
            else:
                _product(session, output, arguments.run_id, arguments.phase, checks, images)
        except Exception as error:
            original_failure = {"code": _failure_code(error), "exception": type(error).__name__}
            if session is not None and "session" in versions and time.monotonic() < deadline:
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
    _json_file(output / "result.json", result)
    for line in image_lines:
        print(line, flush=True)
    print("PUBLIC_QA_RESULT " + json.dumps(result, sort_keys=True, separators=(",", ":"), allow_nan=False), flush=True)
    signal.setitimer(signal.ITIMER_REAL, 0)
    return 1 if original_failure or cleanup_errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
