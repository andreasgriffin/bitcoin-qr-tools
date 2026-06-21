import time

from bitcoin_qr_tools.gui.camera_permission import probe_camera_permission


def main() -> int:
    started_at = time.monotonic()
    result = probe_camera_permission(request_access=True)
    print(f"initial_status={result.status_before.value}", flush=True)
    print(f"final_status={result.status_after.value}", flush=True)
    if result.callback_granted is not None:
        print(f"callback_granted={str(result.callback_granted).lower()}", flush=True)
    print(f"waited_seconds={time.monotonic() - started_at:.3f}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
