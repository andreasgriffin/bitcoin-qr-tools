import threading
import time
from concurrent.futures import ThreadPoolExecutor

from PyQt6.QtWidgets import QApplication

import bitcoin_qr_tools.gui.video_widget as video_widget_module
from bitcoin_qr_tools.gui.video_widget import (
    SCREEN_CAMERA_KEY,
    CameraPermissionStatus,
    VideoWidget,
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


class _FakeScreenCamera:
    def stop(self):
        pass


def _get_qapplication() -> QApplication:
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    return app


def test_close_returns_quickly_with_blocked_detection_worker(monkeypatch):
    _get_qapplication()
    monkeypatch.setattr(
        video_widget_module, "ensure_camera_permission", lambda: CameraPermissionStatus.DENIED
    )
    monkeypatch.setattr(video_widget_module.pygame.camera, "init", lambda: None)
    monkeypatch.setattr(video_widget_module, "ScreenCamera", _FakeScreenCamera)
    monkeypatch.setattr(VideoWidget, "_connect_camera_hotplug_notifications", lambda self: None)

    widget = VideoWidget()
    unblock_worker = threading.Event()
    executor = ThreadPoolExecutor(max_workers=1)
    future = executor.submit(unblock_worker.wait)
    widget._detection_executor = executor
    widget._detection_executor_workers = 1
    widget._active_detection_futures = {future: None}

    started = time.monotonic()
    widget.close()
    elapsed = time.monotonic() - started

    assert elapsed < 0.2
    assert widget._detection_executor is None
    assert widget._detection_executor_workers is None
    assert widget._active_detection_futures == {}

    unblock_worker.set()
    future.result(timeout=1)
