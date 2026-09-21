package com.nordsec.ens.test

import com.nordsec.ens.ConnectionErrorNotification
import com.nordsec.ens.ErrorNotificationCallback
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

private const val CALLBACK_TIMEOUT_SECONDS = 10L

class NotificationRecorder : ErrorNotificationCallback {
    private val notified = CountDownLatch(1)
    private val ended = CountDownLatch(1)

    val notifications = CopyOnWriteArrayList<ConnectionErrorNotification>()

    @Volatile
    var disconnectReason: String? = null
        private set

    override fun notify(notification: ConnectionErrorNotification) {
        notifications.add(notification)
        notified.countDown()
    }

    override fun disconnected(reason: String?) {
        disconnectReason = reason
        ended.countDown()
    }

    fun awaitNotification() = await(notified, "notification")

    fun awaitDisconnect() = await(ended, "disconnect")

    private fun await(latch: CountDownLatch, what: String) {
        check(latch.await(CALLBACK_TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
            "No $what within $CALLBACK_TIMEOUT_SECONDS seconds"
        }
    }
}
