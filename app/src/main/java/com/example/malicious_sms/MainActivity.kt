package com.example.malicious_sms

import android.Manifest
import android.app.AlertDialog
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import androidx.appcompat.app.AlertDialog.Builder

class MainActivity : ComponentActivity() {

    private val permissions = arrayOf(
        Manifest.permission.RECEIVE_SMS,
        Manifest.permission.READ_SMS,
    ).toMutableList()

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
        promptNotificationAccessIfNeeded()


    }

    // Request SMS and notification permissions if not granted
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
                getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            notificationManager.createNotificationChannel(channel)
        }
    }

    // Prompt user to grant notification access if not already granted
    private fun promptNotificationAccessIfNeeded() {
        val enabledListeners = Settings.Secure.getString(
            contentResolver,
            "enabled_notification_listeners"
        )
        val packageName = packageName

        if (enabledListeners == null || !enabledListeners.contains(packageName)) {
            Builder(this)
                .setTitle("Enable Notification Access")
                .setMessage("To monitor suspicious messages, please enable notification access for this app.")
                .setPositiveButton("Go to Settings") { _, _ ->
                    startActivity(Intent(Settings.ACTION_NOTIFICATION_LISTENER_SETTINGS))
                }
                .setNegativeButton("Cancel", null)
                .show()
        }
    }

    // Function to handle "Allow Access" button click
    fun onAllowAccessClicked() {
        // You can add additional logic or display a toast when the button is clicked
        Toast.makeText(this, "Please grant access to the app.", Toast.LENGTH_SHORT).show()
    }
}
