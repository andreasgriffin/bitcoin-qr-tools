from bitcoin_qr_tools.gui.camera_permission import (
    CameraPermissionStatus,
    _parse_camera_permission_probe_output,
)


def test_parse_camera_permission_probe_output_reads_granted_callback():
    result = _parse_camera_permission_probe_output(
        "\n".join(
            [
                "status_before=notDetermined",
                "callback_granted=true",
                "status_after=authorized",
                "waited_seconds=3.715",
            ]
        )
    )

    assert result.status_before == CameraPermissionStatus.NOT_DETERMINED
    assert result.status_after == CameraPermissionStatus.AUTHORIZED
    assert result.callback_granted is True
    assert result.waited_seconds == 3.715


def test_parse_camera_permission_probe_output_falls_back_to_unknown():
    result = _parse_camera_permission_probe_output("not machine readable")

    assert result.status_before == CameraPermissionStatus.UNKNOWN
    assert result.status_after == CameraPermissionStatus.UNKNOWN
    assert result.callback_granted is None
    assert result.waited_seconds is None
