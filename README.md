# 📱 Malicious SMS Detector

This Android app detects suspicious or malicious URLs sent via SMS messages. It uses the [VirusTotal](https://www.virustotal.com/) API to scan links and notifies the user if a link is potentially harmful.

---

## 🔧 Features

- 📩 Intercepts incoming SMS messages.
- 🔗 Extracts URLs from the SMS content.
- 🧪 Sends URLs to the VirusTotal API to check if they are malicious.
- 🚨 Sends high-priority Android notifications when a suspicious link is detected.
- 🔍 Also monitors notification bar messages from default SMS apps (for enhanced compatibility).

---

## 🚀 How to Run the App (Emulator or Physical Device)

### ✅ Prerequisites

- Android Studio (Arctic Fox or newer recommended)
- Android Emulator or physical device with SMS capability (API level 26+)

### 🧪 Using the Emulator

> ⚠️ *Android emulators typically don't support actual SMS receiving. Use these steps to simulate SMS messages or test on a real device.*

1. Open the project in **Android Studio**.
2. Connect a physical Android device or start an **emulator**.
3. Run the app with the green "Run" ▶️ button.
4. On a real device, send a test SMS to yourself containing a link (e.g., `http://example.com`) to trigger detection.

#### To simulate an SMS on emulator (optional):

Use ADB to send an SMS:

```bash
adb emu sms send 1234567890 "Check this link: http://malicious.com"
