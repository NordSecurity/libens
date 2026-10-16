package com.nordsec.ens.test

import android.util.Log
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.nordsec.ens.Authentication
import com.nordsec.ens.Config
import com.nordsec.ens.Connection
import com.nordsec.ens.ConnectionErrorNotification
import com.nordsec.ens.ConnectionErrorNotificationKind
import com.nordsec.ens.CredentialsKind
import com.nordsec.ens.Credentials
import com.nordsec.ens.EnsException
import com.nordsec.ens.ErrorNotificationCallback
import com.nordsec.ens.KeyKind
import com.nordsec.ens.Keys
import com.nordsec.ens.LogCallback
import com.nordsec.ens.LogLevel
import com.nordsec.ens.ProtectCallback
import com.nordsec.ens.connect
import com.nordsec.ens.`deinit`
import com.nordsec.ens.getMemoryUsage
import com.nordsec.ens.getVersion
import com.nordsec.ens.`init`
import com.nordsec.ens.setLogCallback
import java.security.SecureRandom
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import org.junit.AfterClass
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.BeforeClass
import org.junit.Test
import org.junit.runner.RunWith

private const val LOG_TAG = "libens"
private const val APP_VERSION = "kotlin-tests"
private const val NORDLYNX_SCHEMA = "nordlynx"
private const val NORDWHISPER_SCHEMA = "nordwhisper"
private const val OPENVPN_SCHEMA = "openvpn"
private const val PRIVATE_KEY_LEN = 32
private const val CONNECTION_LIMIT_REACHED_CODE = 1
private const val SERVER_MAINTENANCE_CODE = 2
private const val UNAUTHENTICATED_CODE = 3
private const val SUPERSEDED_CODE = 4
private const val UNSUPPORTED_CIPHER_CODE = 5
private const val UNKNOWN_CODE = 99
private const val MAINTENANCE_INFO = "planned maintenance"
private const val MALFORMED_ADDRESS = "not-an-address"
private const val VERSION_PATTERN = "^v\\d+\\.\\d+\\.\\d+"
private const val BUFFER_SIZE = 8u
private const val BACKOFF_INITIAL_SECONDS = 1u
private const val KEEPALIVE_INTERVAL_SECONDS = 30u
private const val BOOTSTRAP_ECH_TIMEOUT_SECONDS = 10u
private const val CALLBACK_PANIC_REASON = "callback panicked"
private const val CALLBACK_TIMEOUT_SECONDS = 10L
private const val WRONG_PASSWORD = "wrong"
private const val AUTH_REJECTION_REASON =
    "persistent error code: 'The request does not have valid authentication credentials', message: \"Incorrect password\""
private const val SHUTDOWN_REASON = "shutdown"

@RunWith(AndroidJUnit4::class)
class EnsTest {
    companion object {
        @BeforeClass
        @JvmStatic
        fun setUpLibrary() {
            setLogCallback(LogLevel.DEBUG, LogcatCallback())
            `init`(APP_VERSION)
        }

        @AfterClass
        @JvmStatic
        fun tearDownLibrary() = `deinit`()
    }

    @Test
    fun testNotificationOverKeyAuthentication() {
        val server = StubServer(NORDLYNX_SCHEMA)
        val callback = NotificationRecorder()
        val keys = Keys(randomKey(), server.handshake.publicKey, KeyKind.NORD_LYNX)
        var connection: Connection? = null

        try {
            connection = connectToStub(server, Authentication.WithKeys(keys), callback)

            server.notify(SERVER_MAINTENANCE_CODE, MAINTENANCE_INFO)
            callback.awaitNotification()

            val notification = callback.notifications.first()
            assertEquals(ConnectionErrorNotificationKind.ServerMaintenance, notification.kind)
            assertEquals(MAINTENANCE_INFO, notification.additionalInfo)

            connection.shutdown()
            callback.awaitDisconnect()

            assertEquals(SHUTDOWN_REASON, callback.disconnectReason)
        } finally {
            connection?.shutdown()
            server.shutdown()
        }
    }

    @Test
    fun testNotificationOverPasswordAuthentication() =
        receiveOverPasswordAuthentication(OPENVPN_SCHEMA, CredentialsKind.OPEN_VPN)

    @Test
    fun testNotificationOverNordWhisperAuthentication() =
        receiveOverPasswordAuthentication(NORDWHISPER_SCHEMA, CredentialsKind.NORD_WHISPER)

    private fun receiveOverPasswordAuthentication(schema: String, kind: CredentialsKind) {
        val server = StubServer(schema)
        val callback = NotificationRecorder()
        val credentials = Credentials(
            server.handshake.username!!,
            server.handshake.password!!,
            kind,
        )
        var connection: Connection? = null

        try {
            connection = connectToStub(server, Authentication.WithCredentials(credentials), callback)

            server.notify(SERVER_MAINTENANCE_CODE, MAINTENANCE_INFO)
            callback.awaitNotification()

            val notification = callback.notifications.first()
            assertEquals(ConnectionErrorNotificationKind.ServerMaintenance, notification.kind)
            assertEquals(MAINTENANCE_INFO, notification.additionalInfo)

            connection.shutdown()
            callback.awaitDisconnect()

            assertEquals(SHUTDOWN_REASON, callback.disconnectReason)
        } finally {
            connection?.shutdown()
            server.shutdown()
        }
    }

    @Test
    fun testAuthenticationRejection() {
        val server = StubServer(OPENVPN_SCHEMA)
        val callback = NotificationRecorder()
        val credentials = Credentials(
            server.handshake.username!!,
            WRONG_PASSWORD,
            CredentialsKind.OPEN_VPN,
        )
        var connection: Connection? = null

        try {
            connection = connectToStub(server, Authentication.WithCredentials(credentials), callback)

            callback.awaitDisconnect()

            assertEquals(AUTH_REJECTION_REASON, callback.disconnectReason)
            assertTrue(callback.notifications.isEmpty())
        } finally {
            connection?.shutdown()
            server.shutdown()
        }
    }

    @Test
    fun testNotificationKinds() {
        val expected = listOf(
            CONNECTION_LIMIT_REACHED_CODE to ConnectionErrorNotificationKind.ConnectionLimitReached,
            SERVER_MAINTENANCE_CODE to ConnectionErrorNotificationKind.ServerMaintenance,
            UNAUTHENTICATED_CODE to ConnectionErrorNotificationKind.Unauthenticated,
            SUPERSEDED_CODE to ConnectionErrorNotificationKind.Superseded,
            UNSUPPORTED_CIPHER_CODE to ConnectionErrorNotificationKind.UnsupportedCipher,
            UNKNOWN_CODE to ConnectionErrorNotificationKind.Unknown(UNKNOWN_CODE),
        )

        val received = receiveNotifications(expected.map { (code, _) -> code })

        assertEquals(expected.map { (_, kind) -> kind }, received.map { it.kind })
    }

    @Test
    fun testExceptionInNotify() {
        val server = StubServer(NORDLYNX_SCHEMA)
        val callback = NotificationRecorder(IllegalStateException())
        var connection: Connection? = null

        try {
            connection = connectToStub(server, keyAuthentication(server), callback)

            server.notify(SERVER_MAINTENANCE_CODE, MAINTENANCE_INFO)
            callback.awaitDisconnect()

            assertTrue(callback.disconnectReason!!.startsWith(CALLBACK_PANIC_REASON))
        } finally {
            connection?.shutdown()
            server.shutdown()
        }
    }

    @Test
    fun testMalformedAddress() {
        assertThrows(EnsException.InvalidInput::class.java) {
            connect(
                MALFORMED_ADDRESS,
                null,
                Authentication.WithKeys(Keys(randomKey(), randomKey(), KeyKind.NORD_LYNX)),
                NotificationRecorder(),
                Config(),
            )
        }
    }

    @Test
    fun testSecondInit() {
        assertThrows(EnsException.AlreadyInitialized::class.java) { `init`(APP_VERSION) }
    }

    @Test
    fun testProtectCallback() {
        val server = StubServer(NORDLYNX_SCHEMA)
        val protect = ProtectRecorder()
        var connection: Connection? = null

        try {
            connection = connectToStub(server, keyAuthentication(server), NotificationRecorder(), protect)

            val socket = protect.sockets.poll(CALLBACK_TIMEOUT_SECONDS, TimeUnit.SECONDS)

            assertNotNull("No socket protected", socket)
            assertTrue(socket!! >= 0)
        } finally {
            connection?.shutdown()
            server.shutdown()
        }
    }

    @Test
    fun testLogCallback() {
        assertTrue("No log message arrived", logCount.get() > 0)
    }

    @Test
    fun testVersion() {
        assertTrue(getVersion(), Regex(VERSION_PATTERN).containsMatchIn(getVersion()))
    }

    @Test
    fun testMemoryUsage() {
        assertTrue(getMemoryUsage() > 0u)
    }

    @Test
    fun testConfigSetters() {
        val server = StubServer(NORDLYNX_SCHEMA)
        val callback = NotificationRecorder()
        val config = Config()
        var connection: Connection? = null

        config.setBufferSize(BUFFER_SIZE)
        config.setAllowOnlyPq(true)
        config.setTlsDomain(null)
        config.setEnableEchBootstrap(false)
        config.setBackoffInitial(BACKOFF_INITIAL_SECONDS)
        config.setBackoffMaximal(null)
        config.setKeepaliveInterval(KEEPALIVE_INTERVAL_SECONDS)
        config.setKeepaliveTimeout(null)
        config.setBootstrapEchTimeout(BOOTSTRAP_ECH_TIMEOUT_SECONDS)

        try {
            connection = connectToStub(server, keyAuthentication(server), callback, config = config)

            server.notify(SERVER_MAINTENANCE_CODE, MAINTENANCE_INFO)
            callback.awaitNotification()
        } finally {
            connection?.shutdown()
            server.shutdown()
        }
    }

    private fun receiveNotifications(codes: List<Int>): List<ConnectionErrorNotification> {
        val server = StubServer(NORDLYNX_SCHEMA)
        val callback = NotificationRecorder()
        var connection: Connection? = null

        try {
            connection = connectToStub(server, keyAuthentication(server), callback)

            codes.forEach { code ->
                server.notify(code, null)
                callback.awaitNotification()
            }

            return callback.notifications.toList()
        } finally {
            connection?.shutdown()
            server.shutdown()
        }
    }

    private fun connectToStub(
        server: StubServer,
        authentication: Authentication,
        callback: ErrorNotificationCallback,
        protect: ProtectCallback? = null,
        config: Config = Config(),
    ): Connection {
        config.setRootCertificateOverride(server.handshake.rootCertificate)

        return connect(
            "127.0.0.1:${server.handshake.port}",
            protect,
            authentication,
            callback,
            config,
        )
    }

    private fun keyAuthentication(server: StubServer) =
        Authentication.WithKeys(Keys(randomKey(), server.handshake.publicKey, KeyKind.NORD_LYNX))

    private fun randomKey() = ByteArray(PRIVATE_KEY_LEN).also { SecureRandom().nextBytes(it) }
}

private val logCount = AtomicInteger()

private class LogcatCallback : LogCallback {
    override fun log(logLevel: LogLevel, message: String) {
        logCount.incrementAndGet()
        Log.d(LOG_TAG, "[$logLevel] $message")
    }
}

private class ProtectRecorder : ProtectCallback {
    val sockets = LinkedBlockingQueue<Int>()

    override fun protect(socketFd: Int) {
        sockets.add(socketFd)
    }
}
