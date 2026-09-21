package com.nordsec.ens.test

import android.util.Base64
import android.util.Log
import androidx.test.platform.app.InstrumentationRegistry
import java.io.BufferedReader
import java.io.BufferedWriter
import java.util.concurrent.TimeUnit
import kotlin.concurrent.thread
import org.json.JSONObject

private const val LOG_TAG = "ens-stub"
private const val STUB_LIBRARY = "libens_stub.so"
private const val EXIT_TIMEOUT_SECONDS = 10L

class Handshake(announcement: JSONObject) {
    val port: Int = announcement.getInt("port")
    val publicKey: ByteArray = announcement.decodeBase64("public_key")
    val rootCertificate: ByteArray = announcement.decodeBase64("root_certificate")
    val username: String? = announcement.optString("username", null)
    val password: String? = announcement.optString("password", null)
}

class StubServer(schema: String) {
    private val process: Process = ProcessBuilder(stubPath(), schema).start()
    private val input: BufferedWriter = process.outputStream.bufferedWriter()
    private val output: BufferedReader = process.inputStream.bufferedReader()

    val handshake: Handshake

    init {
        drainStderr()

        handshake = try {
            Handshake(JSONObject(checkNotNull(output.readLine()) { "The stub announced nothing" }))
        } catch (e: Exception) {
            process.destroy()
            throw e
        }
    }

    fun notify(code: Int, additionalInfo: String?) {
        val command = JSONObject()
            .put("command", "notification")
            .put("code", code)
            .put("additional_info", additionalInfo)

        input.write(command.toString())
        input.newLine()
        input.flush()
    }

    fun shutdown() {
        input.close()

        if (!process.waitFor(EXIT_TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
            process.destroy()
            error("The stub did not exit")
        }

        check(process.exitValue() == 0) { "The stub exited with ${process.exitValue()}" }
    }

    private fun drainStderr() {
        val stderr = process.errorStream.bufferedReader()
        thread(isDaemon = true, name = LOG_TAG) {
            stderr.forEachLine { Log.d(LOG_TAG, it) }
        }
    }
}

private fun JSONObject.decodeBase64(key: String): ByteArray =
    Base64.decode(getString(key), Base64.DEFAULT)

private fun stubPath(): String {
    val context = InstrumentationRegistry.getInstrumentation().context
    return "${context.applicationInfo.nativeLibraryDir}/$STUB_LIBRARY"
}
