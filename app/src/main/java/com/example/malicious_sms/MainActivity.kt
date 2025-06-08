package com.example.malicious_sms

import android.Manifest
import android.annotation.SuppressLint
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.widget.TextView
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import androidx.appcompat.app.AppCompatActivity

class MainActivity : AppCompatActivity() {

    private val permissions = arrayOf(
        Manifest.permission.RECEIVE_SMS,
        Manifest.permission.READ_SMS,
    ).toMutableList()

    private lateinit var smsTextView: TextView
    private val handler = Handler(Looper.getMainLooper())
    private val refreshInterval = 3000L

    // Entry point for the activity. Sets up the UI, requests permissions,
    // creates the notification channel, and prompts for notification access.
    @SuppressLint("MissingInflatedId")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // Set the content view for the homepage (XML layout)
        setContentView(R.layout.activity_main)

        // Add POST_NOTIFICATIONS permission if needed (Android 13+)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            permissions.add(Manifest.permission.POST_NOTIFICATIONS)
        }

        // Request permissions if needed
        requestPermissionsIfNeeded()

        // Create notification channel for suspicious SMS alerts
        createNotificationChannel()

        // Prompt for notification access if not granted
        smsTextView = findViewById(R.id.smsTextView)

        startAutoRefresh()
    }

    //starts a loop that automatically refreshes the SMS display every 3 seconds.
    private fun startAutoRefresh() {
        handler.post(object : Runnable {
            override fun run() {
                updateSMSDisplay()
                handler.postDelayed(this, refreshInterval)
            }
        })
    }

    //updates the TextView on the screen with the current list of suspicious SMS
    private fun updateSMSDisplay() {
        val smsList = SuspiciousSMS.list1
        val displayText = if (smsList.isNotEmpty()) {
            "Suspicious Messages:\n\n" + smsList.joinToString("\n\n")
        } else {
            "No suspicious messages found."
        }
        smsTextView.text = displayText
    }

    // Checks which permissions (SMS and notifications) are not yet granted,
    // and requests them from the user if needed.
    private fun requestPermissionsIfNeeded() {
        val toRequest = permissions.filter {
            ContextCompat.checkSelfPermission(this, it) != PackageManager.PERMISSION_GRANTED
        }

        if (toRequest.isNotEmpty()) {
            ActivityCompat.requestPermissions(this, toRequest.toTypedArray(), 1)
        }
    }

    // Create high-priority notification channel for suspicious SMS alerts
    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val name = "SuspiciousSMSChannel"
            val descriptionText = "Channel for suspicious SMS alerts"
            val importance = NotificationManager.IMPORTANCE_HIGH
            val channel = NotificationChannel("suspicious_sms_channel", name, importance).apply {
                description = descriptionText
            }

            val notificationManager: NotificationManager =
                getSystemService(NOTIFICATION_SERVICE) as NotificationManager
            notificationManager.createNotificationChannel(channel)
        }
    }
}