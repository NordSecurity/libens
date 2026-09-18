import EnsSwift
import XCTest

final class NotificationRecorder: ErrorNotificationCallback {
    let notified = XCTestExpectation(description: "notification")
    let ended = XCTestExpectation(description: "disconnect")

    private(set) var notifications: [ConnectionErrorNotification] = []
    private(set) var disconnectReason: String?

    func notify(notification: ConnectionErrorNotification) {
        notifications.append(notification)
        notified.fulfill()
    }

    func disconnected(reason: String?) {
        disconnectReason = reason
        ended.fulfill()
    }
}
