import EnsSwift
import Foundation
import XCTest

final class EnsTests: XCTestCase {
    private static let appVersion = "swift-tests"
    private static let nordLynxSchema = "nordlynx"
    private static let nordWhisperSchema = "nordwhisper"
    private static let openVpnSchema = "openvpn"
    private static let privateKeyLen = 32
    private static let connectionLimitReachedCode: Int32 = 1
    private static let serverMaintenanceCode: Int32 = 2
    private static let unauthenticatedCode: Int32 = 3
    private static let supersededCode: Int32 = 4
    private static let unsupportedCipherCode: Int32 = 5
    private static let unknownCode: Int32 = 99
    private static let maintenanceInfo = "planned maintenance"
    private static let malformedAddress = "not-an-address"
    private static let versionPattern = #"^v\d+\.\d+\.\d+"#
    private static let bufferSize: UInt32 = 8
    private static let backoffInitialSeconds: UInt32 = 1
    private static let keepaliveIntervalSeconds: UInt32 = 30
    private static let bootstrapEchTimeoutSeconds: UInt32 = 10
    private static let wrongPassword = "wrong"
    private static let shutdownReason = "shutdown"
    private static let authRejectionReason =
        "persistent error code: 'The request does not have valid authentication credentials', message: \"Incorrect password\""
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
        try receiveOverPasswordAuthentication(schema: EnsTests.openVpnSchema, kind: .openVpn)
    }

    func testNotificationOverNordWhisperAuthentication() throws {
        try receiveOverPasswordAuthentication(schema: EnsTests.nordWhisperSchema, kind: .nordWhisper)
    }

    private func receiveOverPasswordAuthentication(schema: String, kind: CredentialsKind) throws {
        let server = try StubServer(schema: schema)
        defer { XCTAssertNoThrow(try server.shutdown()) }

        let callback = NotificationRecorder()
        let credentials = Credentials(
            username: server.handshake.username!,
            password: server.handshake.password!,
            kind: kind)
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

        wait(for: [callback.ended], timeout: EnsTests.callbackTimeout)

        XCTAssertEqual(callback.disconnectReason, EnsTests.authRejectionReason)
        XCTAssertTrue(callback.notifications.isEmpty)
    }

    func testNotificationKinds() throws {
        let expected: [(Int32, ConnectionErrorNotificationKind)] = [
            (EnsTests.connectionLimitReachedCode, .connectionLimitReached),
            (EnsTests.serverMaintenanceCode, .serverMaintenance),
            (EnsTests.unauthenticatedCode, .unauthenticated),
            (EnsTests.supersededCode, .superseded),
            (EnsTests.unsupportedCipherCode, .unsupportedCipher),
            (EnsTests.unknownCode, .unknown(kind: EnsTests.unknownCode)),
        ]

        let received = try receiveNotifications(expected.map { code, _ in code })

        XCTAssertEqual(received.map(\.kind), expected.map { _, kind in kind })
    }

    func testMalformedAddress() {
        let keys = Keys(
            localPrivateKey: EnsTests.randomKey(),
            vpnPublicKey: EnsTests.randomKey(),
            kind: .nordLynx)

        XCTAssertThrowsError(
            try EnsSwift.connect(
                socketAddr: EnsTests.malformedAddress,
                protectCallback: nil,
                authentication: .withKeys(keys: keys),
                notificationCallback: NotificationRecorder(),
                config: Config())
        ) { error in
            guard case EnsError.InvalidInput = error else {
                return XCTFail("Expected an invalid input error, got \(error)")
            }
        }
    }

    func testSecondInit() {
        XCTAssertThrowsError(try EnsSwift.`init`(appVersion: EnsTests.appVersion)) { error in
            guard case EnsError.AlreadyInitialized = error else {
                return XCTFail("Expected an already initialized error, got \(error)")
            }
        }
    }

    func testProtectCallback() throws {
        let server = try StubServer(schema: EnsTests.nordLynxSchema)
        defer { XCTAssertNoThrow(try server.shutdown()) }

        let protect = ProtectRecorder()
        let connection = try EnsTests.connect(
            server, .withKeys(keys: EnsTests.keys(server)), NotificationRecorder(), protect)
        defer { try? connection.shutdown() }

        wait(for: [protect.protected], timeout: EnsTests.callbackTimeout)

        XCTAssertGreaterThanOrEqual(try XCTUnwrap(protect.sockets.first), 0)
    }

    func testLogCallback() {
        wait(for: [LibraryFixture.logged], timeout: EnsTests.callbackTimeout)
    }

    func testVersion() {
        let version = EnsSwift.getVersion()

        XCTAssertNotNil(version.range(of: EnsTests.versionPattern, options: .regularExpression), version)
    }

    func testMemoryUsage() {
        XCTAssertGreaterThan(EnsSwift.getMemoryUsage(), 0)
    }

    func testConfigSetters() throws {
        let server = try StubServer(schema: EnsTests.nordLynxSchema)
        defer { XCTAssertNoThrow(try server.shutdown()) }

        let config = Config()
        config.setBufferSize(size: EnsTests.bufferSize)
        config.setAllowOnlyPq(allowOnlyPq: true)
        config.setTlsDomain(tlsDomain: nil)
        config.setEnableEchBootstrap(enableEch: false)
        config.setBackoffInitial(seconds: EnsTests.backoffInitialSeconds)
        config.setBackoffMaximal(seconds: nil)
        config.setKeepaliveInterval(seconds: EnsTests.keepaliveIntervalSeconds)
        config.setKeepaliveTimeout(seconds: nil)
        config.setBootstrapEchTimeout(seconds: EnsTests.bootstrapEchTimeoutSeconds)

        let callback = NotificationRecorder()
        let connection = try EnsTests.connect(
            server, .withKeys(keys: EnsTests.keys(server)), callback, config: config)
        defer { try? connection.shutdown() }

        server.notify(code: EnsTests.serverMaintenanceCode, additionalInfo: EnsTests.maintenanceInfo)

        XCTAssertTrue(callback.waitNotification(timeout: EnsTests.callbackTimeout))
    }

    private func receiveNotifications(_ codes: [Int32]) throws -> [ConnectionErrorNotification] {
        let server = try StubServer(schema: EnsTests.nordLynxSchema)
        defer { XCTAssertNoThrow(try server.shutdown()) }

        let callback = NotificationRecorder()
        let connection = try EnsTests.connect(server, .withKeys(keys: EnsTests.keys(server)), callback)
        defer { try? connection.shutdown() }

        for code in codes {
            server.notify(code: code, additionalInfo: nil)

            XCTAssertTrue(callback.waitNotification(timeout: EnsTests.callbackTimeout))
        }

        return callback.notifications
    }

    private static func connect(
        _ server: StubServer,
        _ authentication: Authentication,
        _ callback: ErrorNotificationCallback,
        _ protect: ProtectCallback? = nil,
        config: Config = Config()
    ) throws -> Connection {
        config.setRootCertificateOverride(override: server.rootCertificate)

        return try EnsSwift.connect(
            socketAddr: "127.0.0.1:\(server.handshake.port)",
            protectCallback: protect,
            authentication: authentication,
            notificationCallback: callback,
            config: config)
    }

    private static func keys(_ server: StubServer) -> Keys {
        Keys(localPrivateKey: randomKey(), vpnPublicKey: server.publicKey, kind: .nordLynx)
    }

    private static func randomKey() -> Data {
        Data((0..<privateKeyLen).map { _ in UInt8.random(in: .min ... .max) })
    }
}

private final class ProtectRecorder: ProtectCallback {
    let protected: XCTestExpectation = {
        let expectation = XCTestExpectation(description: "protect")
        expectation.assertForOverFulfill = false
        return expectation
    }()

    private(set) var sockets: [Int32] = []

    func protect(socketFd: Int32) throws {
        sockets.append(socketFd)
        protected.fulfill()
    }
}
