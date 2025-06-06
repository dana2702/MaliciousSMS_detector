package com.example.malicious_sms

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.os.Build
import android.telephony.SmsMessage
import android.util.Base64
import androidx.core.app.NotificationCompat
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import java.net.URLEncoder

class SMSReceiver : BroadcastReceiver() {

    private val virusTotalApiKey = "0f481f09151679f72cda593a5e824fe8c3cda57dc02982330fe551122607270b" // our KEY


    // Triggered when an SMS is received. Extracts the message content,
    // searches for URLs, and checks them for malicious activity using VirusTotal.
    override fun onReceive(context: Context, intent: Intent?) {
        val pdus = intent?.extras?.get("pdus") as? Array<*>
        val messages = pdus?.mapNotNull { pdu ->
            SmsMessage.createFromPdu(pdu as ByteArray)
        }

        messages?.forEach { message ->
            val messageBody = message.messageBody

            // Look for URLs (can start with either http or https)
            val regex = Regex("(https?://\\S+)")
            val foundUrls = regex.findAll(messageBody)

            for (match in foundUrls) {
                val url = match.value

                // Check the URL using VirusTotal
                checkUrlWithVirusTotal(context, url) { isMalicious ->
                    if (isMalicious) {
                        showWarningNotification(context, "Malicious link detected: $url")
                    }
                }
            }
        }
    }



    // Displays a high-priority notification alerting the user about
    // a detected malicious URL in an SMS.
    private fun showWarningNotification(context: Context, message: String) {
        val channelId = "MALICIOUS_SMS_CHANNEL"

        // Create notification channel for Android O+
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                channelId,
                "Malicious SMS Alerts",
                NotificationManager.IMPORTANCE_HIGH
            ).apply {
                enableLights(true)
                enableVibration(true)
            }
            val manager = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            manager.createNotificationChannel(channel)
        }

        val notification = NotificationCompat.Builder(context, channelId)
            .setSmallIcon(android.R.drawable.ic_dialog_alert)
            .setContentTitle("⚠️ Malicious URL Detected!")
            .setContentText(message)
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setCategory(NotificationCompat.CATEGORY_MESSAGE)
            .setDefaults(Notification.DEFAULT_ALL)
            .setAutoCancel(true)
            .build()

        val manager = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        manager.notify(System.currentTimeMillis().toInt(), notification) // unique ID for each notification
    }



    // Sends the given URL to the VirusTotal API to check if it's marked as malicious.
    // Calls onResult(true) if malicious, otherwise false.
    private fun checkUrlWithVirusTotal(context: Context, urlToCheck: String, onResult: (Boolean) -> Unit) {
        val client = OkHttpClient()

        // Encode URL as required by VirusTotal API
        val base64Url = Base64.encodeToString(urlToCheck.toByteArray(), Base64.URL_SAFE or Base64.NO_WRAP)

        val request = Request.Builder()
            .url("https://www.virustotal.com/api/v3/urls/$base64Url")
            .get()
            .addHeader("x-apikey", virusTotalApiKey)
            .build()

        val call = client.newCall(request)
        call.enqueue(object : okhttp3.Callback {
            override fun onFailure(call: okhttp3.Call, e: java.io.IOException) {
                e.printStackTrace()
                onResult(false)
            }

            override fun onResponse(call: okhttp3.Call, response: Response) {
                response.use {
                    if (!response.isSuccessful) {
                        onResult(false)
                    } else {
                        val body = response.body?.string()
                        if (body != null && body.contains("\"malicious\"", ignoreCase = true)) {
                            onResult(true)
                        } else {
                            onResult(false)
                        }
                    }
                }
            }
        })
    }
}
