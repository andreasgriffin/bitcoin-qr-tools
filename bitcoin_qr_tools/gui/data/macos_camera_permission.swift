import AVFoundation
import Dispatch
import Foundation

func statusName(_ status: AVAuthorizationStatus) -> String {
    switch status {
    case .authorized:
        return "authorized"
    case .denied:
        return "denied"
    case .notDetermined:
        return "notDetermined"
    case .restricted:
        return "restricted"
    @unknown default:
        return "unknown"
    }
}

let shouldRequestAccess = CommandLine.arguments.contains("--request")
let startedAt = Date()
let statusBefore = AVCaptureDevice.authorizationStatus(for: .video)

print("status_before=\(statusName(statusBefore))")
fflush(stdout)

if shouldRequestAccess && statusBefore == .notDetermined {
    let semaphore = DispatchSemaphore(value: 0)

    AVCaptureDevice.requestAccess(for: .video) { granted in
        print("callback_granted=\(granted)")
        print("status_after=\(statusName(AVCaptureDevice.authorizationStatus(for: .video)))")
        print(String(format: "waited_seconds=%.3f", Date().timeIntervalSince(startedAt)))
        fflush(stdout)
        semaphore.signal()
    }

    semaphore.wait()
} else {
    print("status_after=\(statusName(AVCaptureDevice.authorizationStatus(for: .video)))")
    print(String(format: "waited_seconds=%.3f", Date().timeIntervalSince(startedAt)))
    fflush(stdout)
}
