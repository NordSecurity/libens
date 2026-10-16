import EnsSwift
import XCTest

final class NotificationRecorder: ErrorNotificationCallback {
    let notified = XCTestExpectation(description: "notification")
    let ended = XCTestExpectation(description: "disconnect")

    private(set) var notifications: [ConnectionErrorNotification] = []
    private(set) var disconnectReason: String?

    private let received = DispatchSemaphore(value: 0)

    init() {
        notified.assertForOverFulfill = false
    }

    func notify(notification: ConnectionErrorNotification) {
        notifications.append(notification)
        notified.fulfill()
        received.signal()
    }

    func waitNotification(timeout: TimeInterval) -> Bool {
        received.wait(timeout: .now() + timeout) == .success
    }

    func disconnected(reason: String?) {
        disconnectReason = reason
        ended.fulfill()
    }
}
