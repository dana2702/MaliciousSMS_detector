package com.example.malicious_sms

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.os.Build
import android.telephony.SmsMessage
import androidx.core.app.NotificationCompat

class SMSReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context, intent: Intent?) {
        // Get the SMS messages from the intent
        val pdus = intent?.extras?.get("pdus") as? Array<*>
        val messages = pdus?.mapNotNull { pdu ->
            SmsMessage.createFromPdu(pdu as ByteArray)
        }

        // Check if any message contains the suspicious pattern "//http"
        messages?.forEach { message ->
            val messageBody = message.messageBody
            if (messageBody.contains("//http", ignoreCase = true)) {
                // Build the notification for suspicious SMS
                val smsNotification = NotificationCompat.Builder(context, "SMS_CHANNEL")
                    .setSmallIcon(android.R.drawable.ic_dialog_alert) // Set an alert icon
                    .setContentTitle("Suspicious SMS Detected")
                    .setContentText("A suspicious message was received containing a URL: $messageBody")
                    .setPriority(NotificationCompat.PRIORITY_HIGH) // Make the notification high priority
                    .setCategory(NotificationCompat.CATEGORY_MESSAGE)
                    .setAutoCancel(true) // Auto-cancel when tapped
                    .setDefaults(Notification.DEFAULT_SOUND or Notification.DEFAULT_VIBRATE) // Default sound and vibration
                    .build()

                // Create notification channel for Android 8.0 and above
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                    val channel = NotificationChannel(
                        "SMS_CHANNEL", // Unique channel ID
                        "SMS Notifications", // Channel name
                        NotificationManager.IMPORTANCE_HIGH // High importance to show the notification immediately
                    )
                    channel.enableLights(true) // Optional: Enable light for notifications
                    channel.enableVibration(true) // Optional: Enable vibration for notifications

                    val notificationManager =
                        context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
                    notificationManager.createNotificationChannel(channel)
                }

                // Issue the notification
                val notificationManager = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
                notificationManager.notify(1, smsNotification) // Use ID 1 to allow updating/canceling
            }
        }
    }
}
