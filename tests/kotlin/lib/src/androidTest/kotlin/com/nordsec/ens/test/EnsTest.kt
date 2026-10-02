package com.nordsec.ens.test

import android.util.Log
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.nordsec.ens.Authentication
import com.nordsec.ens.Config
import com.nordsec.ens.Connection
import com.nordsec.ens.ConnectionErrorNotificationKind
import com.nordsec.ens.CredentialsKind
import com.nordsec.ens.Credentials
import com.nordsec.ens.ErrorNotificationCallback
import com.nordsec.ens.KeyKind
import com.nordsec.ens.Keys
import com.nordsec.ens.LogCallback
import com.nordsec.ens.LogLevel
import com.nordsec.ens.connect
import com.nordsec.ens.`deinit`
import com.nordsec.ens.`init`
import com.nordsec.ens.setLogCallback
import java.security.SecureRandom
import org.junit.AfterClass
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.BeforeClass
import org.junit.Test
import org.junit.runner.RunWith

private const val LOG_TAG = "libens"
private const val APP_VERSION = "kotlin-tests"
private const val NORDLYNX_SCHEMA = "nordlynx"
private const val OPENVPN_SCHEMA = "openvpn"
private const val PRIVATE_KEY_LEN = 32
private const val SERVER_MAINTENANCE_CODE = 2
private const val MAINTENANCE_INFO = "planned maintenance"
private const val WRONG_PASSWORD = "wrong"
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
    fun testNotificationOverPasswordAuthentication() {
        val server = StubServer(OPENVPN_SCHEMA)
        val callback = NotificationRecorder()
        val credentials = Credentials(
            server.handshake.username!!,
            server.handshake.password!!,
            CredentialsKind.OPEN_VPN,
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

            val expected =
                "'http://127.0.0.1:${server.handshake.port}' rejected the authentication"
            assertEquals(expected, callback.disconnectReason)
            assertTrue(callback.notifications.isEmpty())
        } finally {
            connection?.shutdown()
            server.shutdown()
        }
    }

    private fun connectToStub(
        server: StubServer,
        authentication: Authentication,
        callback: ErrorNotificationCallback,
    ): Connection {
        val config = Config()
        config.setRootCertificateOverride(server.handshake.rootCertificate)

        return connect(
            "127.0.0.1:${server.handshake.port}",
            null,
            authentication,
            callback,
            config,
        )
    }

    private fun randomKey() = ByteArray(PRIVATE_KEY_LEN).also { SecureRandom().nextBytes(it) }
}

private class LogcatCallback : LogCallback {
    override fun log(logLevel: LogLevel, message: String) {
        Log.d(LOG_TAG, "[$logLevel] $message")
    }
}
