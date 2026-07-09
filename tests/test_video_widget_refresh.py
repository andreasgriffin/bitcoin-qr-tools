from bitcoin_qr_tools.gui.video_widget import (
    SCREEN_CAMERA_KEY,
    choose_camera_key_after_refresh,
    device_camera_key,
    device_identifier,
    rtsp_camera_key,
    should_retry_empty_camera_refresh,
)


def test_choose_camera_key_after_refresh_switches_to_new_device_when_requested():
    assert choose_camera_key_after_refresh(
        current_key=SCREEN_CAMERA_KEY,
        previous_device_keys=[device_camera_key(0)],
        refreshed_device_keys=[device_camera_key(0), device_camera_key(1)],
        preserved_custom_keys=[SCREEN_CAMERA_KEY],
        auto_switch_new=True,
    ) == device_camera_key(1)


def test_choose_camera_key_after_refresh_preserves_current_device_without_new_camera():
    assert choose_camera_key_after_refresh(
        current_key=device_camera_key(0),
        previous_device_keys=[device_camera_key(0)],
        refreshed_device_keys=[device_camera_key(0)],
        preserved_custom_keys=[SCREEN_CAMERA_KEY],
        auto_switch_new=True,
    ) == device_camera_key(0)


def test_choose_camera_key_after_refresh_falls_back_to_remaining_device():
    assert choose_camera_key_after_refresh(
        current_key=device_camera_key(1),
        previous_device_keys=[device_camera_key(0), device_camera_key(1)],
        refreshed_device_keys=[device_camera_key(0)],
        preserved_custom_keys=[SCREEN_CAMERA_KEY],
        auto_switch_new=False,
    ) == device_camera_key(0)


def test_choose_camera_key_after_refresh_prefers_rtsp_before_screen_when_no_devices_remain():
    assert choose_camera_key_after_refresh(
        current_key=device_camera_key(0),
        previous_device_keys=[device_camera_key(0)],
        refreshed_device_keys=[],
        preserved_custom_keys=[SCREEN_CAMERA_KEY, rtsp_camera_key("rtsp://example.local/cam")],
        auto_switch_new=False,
    ) == rtsp_camera_key("rtsp://example.local/cam")


def test_choose_camera_key_after_refresh_defaults_to_first_camera_on_startup():
    assert choose_camera_key_after_refresh(
        current_key=None,
        previous_device_keys=[],
        refreshed_device_keys=[device_camera_key("/dev/video0"), device_camera_key("/dev/video2")],
        preserved_custom_keys=[],
        auto_switch_new=False,
    ) == device_camera_key("/dev/video0")


def test_device_identifier_prefers_camera_name_when_available():
    assert device_identifier("/dev/video2", 1) == "/dev/video2"
    assert device_identifier("", 1) == 1


def test_should_retry_empty_camera_refresh_when_previous_devices_exist():
    assert should_retry_empty_camera_refresh(
        previous_device_keys=[device_camera_key("/dev/video0")],
        refreshed_device_keys=[],
        retries_remaining=2,
    )
    assert not should_retry_empty_camera_refresh(
        previous_device_keys=[],
        refreshed_device_keys=[],
        retries_remaining=2,
    )
