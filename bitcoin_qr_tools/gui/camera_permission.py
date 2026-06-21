import logging
import subprocess
import sys
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

logger = logging.getLogger(__name__)


class CameraPermissionStatus(Enum):
    AUTHORIZED = "authorized"
    DENIED = "denied"
    NOT_DETERMINED = "notDetermined"
    RESTRICTED = "restricted"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class CameraPermissionProbeResult:
    status_before: CameraPermissionStatus
    status_after: CameraPermissionStatus
    callback_granted: bool | None = None
    waited_seconds: float | None = None
    raw_output: str = ""


def _parse_camera_permission_probe_output(output: str) -> CameraPermissionProbeResult:
    parsed: dict[str, str] = {}
    for line in output.splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        parsed[key.strip()] = value.strip()

    def to_status(key: str) -> CameraPermissionStatus:
        value = parsed.get(key, CameraPermissionStatus.UNKNOWN.value)
        try:
            return CameraPermissionStatus(value)
        except ValueError:
            return CameraPermissionStatus.UNKNOWN

    callback_granted_value = parsed.get("callback_granted")
    if callback_granted_value is None:
        callback_granted = None
    else:
        callback_granted = callback_granted_value.lower() == "true"

    waited_seconds_value = parsed.get("waited_seconds")
    if waited_seconds_value is None:
        waited_seconds = None
    else:
        try:
            waited_seconds = float(waited_seconds_value)
        except ValueError:
            waited_seconds = None

    return CameraPermissionProbeResult(
        status_before=to_status("status_before"),
        status_after=to_status("status_after"),
        callback_granted=callback_granted,
        waited_seconds=waited_seconds,
        raw_output=output,
    )


def probe_camera_permission(request_access: bool = False) -> CameraPermissionProbeResult:
    if sys.platform != "darwin":
        return CameraPermissionProbeResult(
            status_before=CameraPermissionStatus.AUTHORIZED,
            status_after=CameraPermissionStatus.AUTHORIZED,
        )

    script_path = Path(__file__).with_name("macos_camera_permission.swift")
    command = ["/usr/bin/xcrun", "swift", str(script_path)]
    if request_access:
        command.append("--request")

    try:
        result = subprocess.run(command, capture_output=True, text=True, check=False)
    except FileNotFoundError:
        logger.warning("Swift is not available; cannot probe macOS camera permission state")
        return CameraPermissionProbeResult(
            status_before=CameraPermissionStatus.UNKNOWN,
            status_after=CameraPermissionStatus.UNKNOWN,
        )

    if result.returncode != 0:
        logger.warning("Camera permission probe failed: %s", result.stderr.strip())
        return CameraPermissionProbeResult(
            status_before=CameraPermissionStatus.UNKNOWN,
            status_after=CameraPermissionStatus.UNKNOWN,
            raw_output=result.stdout,
        )

    return _parse_camera_permission_probe_output(result.stdout)


def ensure_camera_permission() -> CameraPermissionStatus:
    return probe_camera_permission(request_access=True).status_after
