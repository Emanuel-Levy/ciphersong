package com.ciphersong.ciphersong

import android.Manifest
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.media.AudioAttributes
import android.media.RingtoneManager
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.IBinder
import android.os.PowerManager
import android.os.VibrationEffect
import android.os.Vibrator
import android.provider.Settings
import android.view.WindowManager
import androidx.core.app.ActivityCompat
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat
import io.flutter.embedding.android.FlutterFragmentActivity
import org.json.JSONObject
import java.io.BufferedReader
import java.io.InputStreamReader
import java.io.PrintWriter
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import kotlin.concurrent.thread

class CipherSongForegroundService : Service() {
    companion object {
        const val SERVICE_NOTIFICATION_ID = 9001
        const val CHANNEL_SERVICE_ID = "ciphersong_service_channel_v2"
        var isRunning = false
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onCreate() {
        super.onCreate()
        createServiceChannel()
        val notif = createServiceNotification()
        try {
            startForeground(SERVICE_NOTIFICATION_ID, notif)
            isRunning = true
            android.util.Log.i("CipherSong", "Foreground service started successfully.")
        } catch (e: Exception) {
            android.util.Log.w("CipherSong", "startForeground error: ${e.message}")
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        return START_STICKY
    }

    override fun onDestroy() {
        super.onDestroy()
        isRunning = false
    }

    private fun createServiceChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            val chan = NotificationChannel(
                CHANNEL_SERVICE_ID,
                "CipherSong Sincronização em Segundo Plano",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "Mantém a escuta de chamadas e repertório ativa mesmo fora do aplicativo"
                setShowBadge(false)
            }
            nm.createNotificationChannel(chan)
        }
    }

    private fun createServiceNotification(): android.app.Notification {
        val launchIntent = Intent(this, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP
        }
        val pIntent = PendingIntent.getActivity(
            this, 0, launchIntent,
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) PendingIntent.FLAG_IMMUTABLE else 0
        )

        val iconRes = try {
            val id = resources.getIdentifier("ic_ciphersong_notification", "drawable", packageName)
            if (id != 0) id else android.R.drawable.stat_notify_chat
        } catch (e: Exception) {
            android.R.drawable.stat_notify_chat
        }

        return NotificationCompat.Builder(this, CHANNEL_SERVICE_ID)
            .setSmallIcon(iconRes)
            .setContentTitle("CipherSong Ativo")
            .setContentText("Pronto para receber chamadas de ensaio e repertório")
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .setOngoing(true)
            .setContentIntent(pIntent)
            .build()
    }
}

class MainActivity : FlutterFragmentActivity() {

    companion object {
        const val CHANNEL_CALLS_ID = "ciphersong_calls_channel_v3"
        const val CHANNEL_UPDATES_ID = "ciphersong_updates_channel_v3"
        const val TCP_PORT = 19876
        const val NOTIFICATION_PERMISSION_CODE = 1010
    }

    private var serverSocket: ServerSocket? = null
    @Volatile
    private var isServerRunning = false
    private var wakeLock: PowerManager.WakeLock? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        try {
            window.setSoftInputMode(WindowManager.LayoutParams.SOFT_INPUT_ADJUST_RESIZE)
        } catch (e: Exception) {
            android.util.Log.w("CipherSong", "Error setting soft input mode: ${e.message}")
        }
        createNotificationChannels()
        requestNotificationPermission()
        acquireBackgroundWakeLock()
        startNotificationIpcServer()
        startForegroundSyncService()
    }

    override fun onResume() {
        super.onResume()
        requestNotificationPermission()
    }

    fun startForegroundSyncService() {
        try {
            val svcIntent = Intent(this, CipherSongForegroundService::class.java)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                ContextCompat.startForegroundService(this, svcIntent)
            } else {
                startService(svcIntent)
            }
        } catch (e: Exception) {
            android.util.Log.w("CipherSong", "Failed to start foreground service: ${e.message}")
        }
    }

    private fun createNotificationChannels() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val notificationManager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager

            // 1. Canal de Chamadas Urgentes (Som alto + Vibração intensa 3 pulsos)
            val callChannel = NotificationChannel(
                CHANNEL_CALLS_ID,
                "CipherSong Chamadas Urgentes",
                NotificationManager.IMPORTANCE_HIGH
            ).apply {
                description = "Notificações de chamada e ping de músicos da equipe"
                enableVibration(true)
                vibrationPattern = longArrayOf(0, 500, 200, 500, 200, 500)
                val soundUri = RingtoneManager.getDefaultUri(RingtoneManager.TYPE_NOTIFICATION)
                val audioAttributes = AudioAttributes.Builder()
                    .setContentType(AudioAttributes.CONTENT_TYPE_SONIFICATION)
                    .setUsage(AudioAttributes.USAGE_NOTIFICATION_COMMUNICATION_INSTANT)
                    .build()
                setSound(soundUri, audioAttributes)
                lockscreenVisibility = NotificationCompat.VISIBILITY_PUBLIC
                enableLights(true)
                lightColor = android.graphics.Color.CYAN
            }
            notificationManager.createNotificationChannel(callChannel)

            // 2. Canal de Atualizações de Repertório (Semana e Ensaio)
            val updateChannel = NotificationChannel(
                CHANNEL_UPDATES_ID,
                "CipherSong Repertório & Ensaio",
                NotificationManager.IMPORTANCE_HIGH
            ).apply {
                description = "Novas músicas adicionadas no repertório da semana ou a ensaiar"
                enableVibration(true)
                vibrationPattern = longArrayOf(0, 350, 150, 350)
                val soundUri = RingtoneManager.getDefaultUri(RingtoneManager.TYPE_NOTIFICATION)
                val audioAttributes = AudioAttributes.Builder()
                    .setContentType(AudioAttributes.CONTENT_TYPE_SONIFICATION)
                    .setUsage(AudioAttributes.USAGE_NOTIFICATION)
                    .build()
                setSound(soundUri, audioAttributes)
                lockscreenVisibility = NotificationCompat.VISIBILITY_PUBLIC
                enableLights(true)
                lightColor = android.graphics.Color.CYAN
            }
            notificationManager.createNotificationChannel(updateChannel)
        }
    }

    private fun requestNotificationPermission() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            if (ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS)
                != PackageManager.PERMISSION_GRANTED
            ) {
                ActivityCompat.requestPermissions(
                    this,
                    arrayOf(Manifest.permission.POST_NOTIFICATIONS),
                    NOTIFICATION_PERMISSION_CODE
                )
            }
        }
    }

    private fun acquireBackgroundWakeLock() {
        try {
            val powerManager = getSystemService(Context.POWER_SERVICE) as PowerManager
            wakeLock = powerManager.newWakeLock(
                PowerManager.PARTIAL_WAKE_LOCK,
                "CipherSong:BackgroundSyncWakeLock"
            ).apply {
                setReferenceCounted(false)
                acquire(24 * 60 * 60 * 1000L) // 24 horas de segurança
            }
        } catch (e: Exception) {
            android.util.Log.w("CipherSong", "WakeLock acquire warning: ${e.message}")
        }
    }

    private fun startNotificationIpcServer() {
        if (isServerRunning) return
        isServerRunning = true

        thread(name = "CipherSongNotificationIpc", isDaemon = true) {
            try {
                val loopback = InetAddress.getByName("127.0.0.1")
                serverSocket = ServerSocket(TCP_PORT, 50, loopback)
                android.util.Log.i("CipherSong", "IPC Server bound to 127.0.0.1:$TCP_PORT")
                while (isServerRunning && serverSocket?.isClosed == false) {
                    val client = serverSocket?.accept() ?: break
                    thread(isDaemon = true) {
                        handleClient(client)
                    }
                }
            } catch (e: Exception) {
                if (isServerRunning) {
                    android.util.Log.e("CipherSong", "IPC Server error: ${e.message}")
                }
            }
        }
    }

    private fun handleClient(socket: Socket) {
        try {
            socket.soTimeout = 5000
            val reader = BufferedReader(InputStreamReader(socket.getInputStream(), "UTF-8"))
            val writer = PrintWriter(socket.getOutputStream(), true)

            val line = reader.readLine()
            if (!line.isNullOrBlank()) {
                val json = JSONObject(line)
                val action = json.optString("action", "notify")

                if (action == "notify") {
                    val title = json.optString("title", "CipherSong")
                    val body = json.optString("body", "")
                    val isCall = json.optBoolean("is_call", false)
                    val id = json.optInt("id", (System.currentTimeMillis() % 100000).toInt())

                    triggerSystemNotification(id, title, body, isCall)
                    writer.println("""{"status":"ok","notified":true}""")
                } else if (action == "vibrate") {
                    val pattern = json.optString("pattern", "normal")
                    vibrateDevice(pattern)
                    writer.println("""{"status":"ok","vibrated":true}""")
                } else if (action == "ping") {
                    val hasPerm = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                        ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) == PackageManager.PERMISSION_GRANTED
                    } else true
                    writer.println("""{"status":"ok","alive":true,"notifications_enabled":$hasPerm,"service_running":${CipherSongForegroundService.isRunning}}""")
                } else if (action == "request_permission") {
                    runOnUiThread { requestNotificationPermission() }
                    writer.println("""{"status":"ok","requested":true}""")
                } else if (action == "open_settings") {
                    runOnUiThread { openAppSettings() }
                    writer.println("""{"status":"ok","opened":true}""")
                } else {
                    writer.println("""{"status":"error","message":"unknown action"}""")
                }
            }
        } catch (e: Exception) {
            android.util.Log.w("CipherSong", "Client handle error: ${e.message}")
        } finally {
            try {
                socket.close()
            } catch (ignored: Exception) {}
        }
    }

    private fun openAppSettings() {
        try {
            val intent = Intent(Settings.ACTION_APP_NOTIFICATION_SETTINGS).apply {
                putExtra(Settings.EXTRA_APP_PACKAGE, packageName)
            }
            startActivity(intent)
        } catch (e: Exception) {
            try {
                val intent = Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS).apply {
                    data = Uri.parse("package:$packageName")
                }
                startActivity(intent)
            } catch (ignored: Exception) {}
        }
    }

    private fun triggerSystemNotification(id: Int, title: String, body: String, isCall: Boolean) {
        try {
            val channelId = if (isCall) CHANNEL_CALLS_ID else CHANNEL_UPDATES_ID

            val intent = Intent(this, MainActivity::class.java).apply {
                flags = Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP
                putExtra("from_notification", true)
                putExtra("is_call", isCall)
            }

            val flagImmutable = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
            } else {
                PendingIntent.FLAG_UPDATE_CURRENT
            }

            val pendingIntent = PendingIntent.getActivity(this, id, intent, flagImmutable)

            // Usa ícone de notificação monocromático oficial ou fallback seguro do sistema
            val customIconName = if (isCall) "ic_ciphersong_call" else "ic_ciphersong_notification"
            val iconRes = try {
                val resId = resources.getIdentifier(customIconName, "drawable", packageName)
                if (resId != 0) resId else android.R.drawable.stat_notify_chat
            } catch (e: Exception) {
                android.R.drawable.stat_notify_chat
            }

            val builder = NotificationCompat.Builder(this, channelId)
                .setSmallIcon(iconRes)
                .setContentTitle(title)
                .setContentText(body)
                .setStyle(NotificationCompat.BigTextStyle().bigText(body))
                .setPriority(if (isCall) NotificationCompat.PRIORITY_MAX else NotificationCompat.PRIORITY_HIGH)
                .setCategory(if (isCall) NotificationCompat.CATEGORY_CALL else NotificationCompat.CATEGORY_MESSAGE)
                .setContentIntent(pendingIntent)
                .setAutoCancel(true)
                .setOnlyAlertOnce(false)
                .setVisibility(NotificationCompat.VISIBILITY_PUBLIC)

            if (isCall) {
                builder.setVibrate(longArrayOf(0, 500, 200, 500, 200, 500))
                builder.setFullScreenIntent(pendingIntent, true)
            } else {
                builder.setVibrate(longArrayOf(0, 350, 150, 350))
            }

            with(NotificationManagerCompat.from(this)) {
                if (ActivityCompat.checkSelfPermission(
                        this@MainActivity,
                        Manifest.permission.POST_NOTIFICATIONS
                    ) == PackageManager.PERMISSION_GRANTED || Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU
                ) {
                    notify(id, builder.build())
                } else {
                    val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
                    nm.notify(id, builder.build())
                }
            }

            vibrateDevice(if (isCall) "call" else "normal")
        } catch (e: Exception) {
            android.util.Log.e("CipherSong", "Notification dispatch error: ${e.message}")
        }
    }

    private fun vibrateDevice(pattern: String) {
        try {
            val vibrator = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                val vm = getSystemService(Context.VIBRATOR_MANAGER_SERVICE) as? android.os.VibratorManager
                vm?.defaultVibrator ?: (getSystemService(Context.VIBRATOR_SERVICE) as? Vibrator)
            } else {
                @Suppress("DEPRECATION")
                getSystemService(Context.VIBRATOR_SERVICE) as? Vibrator
            } ?: return

            if (!vibrator.hasVibrator()) return

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                if (pattern == "call") {
                    val timings = longArrayOf(0, 500, 200, 500, 200, 500)
                    val amplitudes = intArrayOf(0, 255, 0, 255, 0, 255)
                    vibrator.vibrate(VibrationEffect.createWaveform(timings, amplitudes, -1))
                } else {
                    val timings = longArrayOf(0, 350, 150, 350)
                    val amplitudes = intArrayOf(0, 200, 0, 200)
                    vibrator.vibrate(VibrationEffect.createWaveform(timings, amplitudes, -1))
                }
            } else {
                @Suppress("DEPRECATION")
                if (pattern == "call") {
                    vibrator.vibrate(longArrayOf(0, 500, 200, 500, 200, 500), -1)
                } else {
                    vibrator.vibrate(longArrayOf(0, 350, 150, 350), -1)
                }
            }
        } catch (e: Exception) {
            android.util.Log.w("CipherSong", "Vibrate error: ${e.message}")
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        isServerRunning = false
        try {
            serverSocket?.close()
        } catch (ignored: Exception) {}
        try {
            if (wakeLock?.isHeld == true) {
                wakeLock?.release()
            }
        } catch (ignored: Exception) {}
    }
}
