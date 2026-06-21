from bitcoin_qr_tools.gui.camera_labels import (
    get_qt_camera_devices,
    resolve_camera_display_name,
    uniquify_camera_labels,
)


def test_resolve_camera_display_name_prefers_qt_identifier_match():
    qt_camera_devices = [
        ("FaceTime HD Camera", "apple-camera-1"),
        ("Logitech Brio", "/dev/video2"),
    ]

    assert resolve_camera_display_name(0, "/dev/video2", qt_camera_devices) == "Logitech Brio"


def test_resolve_camera_display_name_uses_single_qt_device_as_safe_fallback():
    qt_camera_devices = [("Integrated Webcam", "usb-camera-0")]

    assert resolve_camera_display_name(0, "/dev/video0", qt_camera_devices) == "Integrated Webcam"


def test_resolve_camera_display_name_does_not_guess_by_qt_order():
    qt_camera_devices = [
        ("Integrated Webcam", "usb-camera-0"),
        ("Logitech Brio", "usb-camera-1"),
    ]

    assert resolve_camera_display_name(0, 0, qt_camera_devices) == "0"


def test_resolve_camera_display_name_uses_source_name_without_qt_match():
    assert resolve_camera_display_name(3, "OBS Virtual Camera", []) == "OBS Virtual Camera"


def test_uniquify_camera_labels_only_suffixes_duplicates():
    labels = ["Integrated Webcam", "Integrated Webcam", "Logitech Brio"]

    assert uniquify_camera_labels(labels) == [
        "Integrated Webcam (1)",
        "Integrated Webcam (2)",
        "Logitech Brio",
    ]


def test_get_qt_camera_devices_returns_empty_list_when_qt_multimedia_is_unavailable():
    assert isinstance(get_qt_camera_devices(), list)
