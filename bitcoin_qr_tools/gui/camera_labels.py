from __future__ import annotations

from collections import Counter
from typing import Any

from PyQt6.QtMultimedia import QMediaDevices


def _normalize_camera_identifier(value: Any) -> str:
    return str(value).strip().casefold()


def _decode_qt_camera_id(camera_id: Any) -> str:
    try:
        return bytes(camera_id).decode("utf-8", errors="ignore").strip()
    except Exception:
        return str(camera_id).strip()


def get_qt_camera_devices() -> list[tuple[str, str]]:
    camera_devices: list[tuple[str, str]] = []
    for device in QMediaDevices.videoInputs():
        description = device.description().strip()
        identifier = _decode_qt_camera_id(device.id())
        camera_devices.append((description, identifier))
    return camera_devices


def resolve_camera_display_name(
    index: int, source_name: str | int, qt_camera_devices: list[tuple[str, str]]
) -> str:
    source_name_text = str(source_name).strip()
    normalized_source = _normalize_camera_identifier(source_name)
    allow_partial_identifier_match = isinstance(source_name, str) and any(
        marker in source_name_text for marker in ("/", "\\", ":", "#", "-")
    )
    for description, identifier in qt_camera_devices:
        if not description:
            continue

        normalized_identifier = _normalize_camera_identifier(identifier)
        normalized_description = _normalize_camera_identifier(description)
        if normalized_source and (
            normalized_source == normalized_identifier
            or normalized_source == normalized_description
            or (allow_partial_identifier_match and normalized_source in normalized_identifier)
        ):
            return description

    if index == 0 and len(qt_camera_devices) == 1:
        description = qt_camera_devices[0][0].strip()
        if description:
            return description

    fallback_name = str(source_name).strip()
    return fallback_name if fallback_name else str(index)


def uniquify_camera_labels(labels: list[str]) -> list[str]:
    duplicates = Counter(labels)
    seen: Counter[str] = Counter()
    unique_labels: list[str] = []

    for label in labels:
        seen[label] += 1
        if duplicates[label] == 1:
            unique_labels.append(label)
            continue
        unique_labels.append(f"{label} ({seen[label]})")

    return unique_labels
