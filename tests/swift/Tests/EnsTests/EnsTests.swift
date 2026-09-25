import EnsSwift
import Foundation
import XCTest

final class EnsTests: XCTestCase {
    private static let nordLynxSchema = "nordlynx"
    private static let openVpnSchema = "openvpn"
    private static let privateKeyLen = 32
    private static let serverMaintenanceCode: Int32 = 2
    private static let maintenanceInfo = "planned maintenance"
    private static let wrongPassword = "wrong"
    private static let shutdownReason = "shutdown"
    private static let callbackTimeout: TimeInterval = 10

    override func setUp() {
        LibraryFixture.start()
    }

    func testNotificationOverKeyAuthentication() throws {
        let server = try StubServer(schema: EnsTests.nordLynxSchema)
        defer { XCTAssertNoThrow(try server.shutdown()) }

        let callback = NotificationRecorder()
        let keys = Keys(
            localPrivateKey: EnsTests.randomKey(),
            vpnPublicKey: server.publicKey,
            kind: .nordLynx)
        let connection = try EnsTests.connect(server, .withKeys(keys: keys), callback)
        defer { try? connection.shutdown() }

        server.notify(code: EnsTests.serverMaintenanceCode, additionalInfo: EnsTests.maintenanceInfo)

        wait(for: [callback.notified], timeout: EnsTests.callbackTimeout)

        let notification = try XCTUnwrap(callback.notifications.first)
        XCTAssertEqual(notification.kind, .serverMaintenance)
        XCTAssertEqual(notification.additionalInfo, EnsTests.maintenanceInfo)

        try connection.shutdown()

        wait(for: [callback.ended], timeout: EnsTests.callbackTimeout)

        XCTAssertEqual(callback.disconnectReason, EnsTests.shutdownReason)
    }

    func testNotificationOverPasswordAuthentication() throws {
        let server = try StubServer(schema: EnsTests.openVpnSchema)
        defer { XCTAssertNoThrow(try server.shutdown()) }

        let callback = NotificationRecorder()
        let credentials = Credentials(
            username: server.handshake.username!,
            password: server.handshake.password!,
            kind: .openVpn)
        let connection = try EnsTests.connect(
            server, .withCredentials(credentials: credentials), callback)
        defer { try? connection.shutdown() }

        server.notify(code: EnsTests.serverMaintenanceCode, additionalInfo: EnsTests.maintenanceInfo)

        wait(for: [callback.notified], timeout: EnsTests.callbackTimeout)

        let notification = try XCTUnwrap(callback.notifications.first)
        XCTAssertEqual(notification.kind, .serverMaintenance)
        XCTAssertEqual(notification.additionalInfo, EnsTests.maintenanceInfo)

        try connection.shutdown()

        wait(for: [callback.ended], timeout: EnsTests.callbackTimeout)

        XCTAssertEqual(callback.disconnectReason, EnsTests.shutdownReason)
    }

    func testAuthenticationRejection() throws {
        let server = try StubServer(schema: EnsTests.openVpnSchema)
        defer { XCTAssertNoThrow(try server.shutdown()) }

        let callback = NotificationRecorder()
        let credentials = Credentials(
            username: server.handshake.username!,
            password: EnsTests.wrongPassword,
            kind: .openVpn)
        let connection = try EnsTests.connect(
            server, .withCredentials(credentials: credentials), callback)
        defer { try? connection.shutdown() }

        let expected = "'http://127.0.0.1:\(server.handshake.port)/' rejected the authentication"

        wait(for: [callback.ended], timeout: EnsTests.callbackTimeout)

        XCTAssertEqual(callback.disconnectReason, expected)
        XCTAssertTrue(callback.notifications.isEmpty)
    }

    private static func connect(
        _ server: StubServer,
        _ authentication: Authentication,
        _ callback: ErrorNotificationCallback
    ) throws -> Connection {
        let config = Config()
        config.setRootCertificateOverride(override: server.rootCertificate)

        return try EnsSwift.connect(
            socketAddr: "127.0.0.1:\(server.handshake.port)",
            protectCallback: nil,
            authentication: authentication,
            notificationCallback: callback,
            config: config)
    }

    private static func randomKey() -> Data {
        Data((0..<privateKeyLen).map { _ in UInt8.random(in: .min ... .max) })
    }
}
