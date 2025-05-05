// SMSNotificationListener.kt
package com.example.malicious_sms

import android.service.notification.NotificationListenerService
import android.service.notification.StatusBarNotification
import android.util.Log

class SMSNotificationListener : NotificationListenerService() {

    override fun onNotificationPosted(sbn: StatusBarNotification?) {
        val packageName = sbn?.packageName ?: return
        val extras = sbn.notification.extras

        // Check if it's an SMS app (adjust for your default SMS app if needed)
        if (packageName.contains("messaging") || packageName.contains("sms")) {
            val title = extras.getString("android.title") ?: ""
            val text = extras.getString("android.text") ?: ""

            if ("//http" in text) {
                Log.d("SMSNotificationListener", "Suspicious link detected from $title: $text")
                // TODO: Optionally trigger a custom notification here
            }
        }
    }
}
