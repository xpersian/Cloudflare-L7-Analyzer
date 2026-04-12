package com.example.hostextractor

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.IBinder
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowBack
import androidx.compose.material.icons.filled.Cloud
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.ContentPaste
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material.icons.filled.Public
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.app.NotificationCompat
import androidx.core.view.WindowCompat
import androidx.activity.result.contract.ActivityResultContracts
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import java.io.BufferedInputStream
import java.io.InputStreamReader
import java.net.InetSocketAddress
import java.net.Socket
import java.net.URLDecoder
import java.net.URLEncoder
import java.security.SecureRandom
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLParameters
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory
import androidx.compose.material3.NavigationBarItemDefaults
private const val APP_VERSION = "v1.5.6"

enum class ScannerCore { CLOUDFLARE, CLOUDFRONT }
enum class ResultTier { VERIFIED, STRONG, GOOD, BORDERLINE, FAILED }

private const val SCAN_SERVICE_CHANNEL_ID = "scanner_fg_channel"
private const val SCAN_SERVICE_NOTIFICATION_ID = 701
private const val ACTION_START_SCAN = "com.example.hostextractor.action.START_SCAN"
private const val ACTION_STOP_SCAN = "com.example.hostextractor.action.STOP_SCAN"
private const val ACTION_PAUSE_SCAN = "com.example.hostextractor.action.PAUSE_SCAN"
private const val ACTION_RESUME_SCAN = "com.example.hostextractor.action.RESUME_SCAN"
private const val EXTRA_SCAN_MODE = "scan_mode"
private const val EXTRA_SCAN_CORE = "scan_core"
private const val EXTRA_SCAN_PAYLOAD = "scan_payload"
private const val EXTRA_CFG_PROTOCOL = "cfg_protocol"
private const val EXTRA_CFG_USER_ID = "cfg_user_id"
private const val EXTRA_CFG_ORIGINAL_HOST = "cfg_original_host"
private const val EXTRA_CFG_PORT = "cfg_port"
private const val EXTRA_CFG_HOST = "cfg_host"
private const val EXTRA_CFG_SNI = "cfg_sni"
private const val EXTRA_CFG_PATH = "cfg_path"
private const val EXTRA_CFG_TRANSPORT = "cfg_transport"
private const val EXTRA_CFG_TLS = "cfg_tls"
private const val EXTRA_CFG_ALPN = "cfg_alpn"
private const val EXTRA_CFG_FINGERPRINT = "cfg_fingerprint"
private const val EXTRA_CFG_FLOW = "cfg_flow"
private const val EXTRA_CFG_ALLOW_INSECURE = "cfg_allow_insecure"
private const val EXTRA_CFG_LABEL = "cfg_label"
private const val EXTRA_CFG_ORIGINAL_URI = "cfg_original_uri"

enum class ScanMode { CONFIG, IP }

data class ScanUiState(
    val running: Boolean = false,
    val paused: Boolean = false,
    val core: ScannerCore? = null,
    val mode: ScanMode? = null,
    val progress: Float = 0f,
    val progressLabel: String = "Idle",
    val results: List<DisplayResult> = emptyList(),
    val errorMessage: String? = null,
    val resumeAvailable: Boolean = false
)

data class ScanResumeRequest(
    val core: ScannerCore,
    val mode: ScanMode,
    val payload: String,
    val config: ParsedTunnelConfig,
    val nextIndex: Int = 0,
    val currentResults: List<DisplayResult> = emptyList()
)

private class PauseScanException : CancellationException("Paused")

object ScanRuntime {
    private val _state = MutableStateFlow(ScanUiState())
    val state: StateFlow<ScanUiState> = _state.asStateFlow()

    @Volatile
    private var lastRequest: ScanResumeRequest? = null

    @Volatile
    var pauseRequested: Boolean = false

    fun rememberRequest(request: ScanResumeRequest) {
        lastRequest = request
    }

    fun rememberRequest(core: ScannerCore, mode: ScanMode, payload: String, config: ParsedTunnelConfig) {
        lastRequest = ScanResumeRequest(core, mode, payload, config)
    }

    fun consumeResumeRequest(): ScanResumeRequest? = lastRequest

    fun clearResume() {
        lastRequest = null
        pauseRequested = false
        val current = _state.value
        _state.value = current.copy(resumeAvailable = false, paused = false)
    }

    fun requestPause() {
        pauseRequested = true
    }

    fun start(core: ScannerCore, mode: ScanMode, label: String, keepResults: List<DisplayResult> = _state.value.results) {
        _state.value = ScanUiState(
            running = true,
            paused = false,
            core = core,
            mode = mode,
            progress = 0f,
            progressLabel = label,
            results = keepResults,
            resumeAvailable = false
        )
    }

    fun progress(value: Float, label: String) {
        val current = _state.value
        _state.value = current.copy(running = true, paused = false, progress = value.coerceIn(0f, 1f), progressLabel = label, resumeAvailable = false)
    }

    fun pause(label: String = "Paused") {
        val current = _state.value
        _state.value = current.copy(running = false, paused = true, progressLabel = label, resumeAvailable = lastRequest != null)
    }

    fun complete(results: List<DisplayResult>, label: String = "Completed") {
        val current = _state.value
        _state.value = current.copy(running = false, paused = false, progress = 1f, progressLabel = label, results = results, errorMessage = null, resumeAvailable = false)
        lastRequest = null
        pauseRequested = false
    }

    fun stop(label: String = "Stopped") {
        val current = _state.value
        _state.value = current.copy(running = false, paused = false, progressLabel = label, resumeAvailable = lastRequest != null)
    }

    fun fail(label: String) {
        val current = _state.value
        _state.value = current.copy(running = false, paused = false, progressLabel = label, errorMessage = label, resumeAvailable = lastRequest != null)
    }
}

private fun Intent.putParsedConfigExtras(config: ParsedTunnelConfig): Intent = apply {
    putExtra(EXTRA_CFG_PROTOCOL, config.protocol)
    putExtra(EXTRA_CFG_USER_ID, config.userId)
    putExtra(EXTRA_CFG_ORIGINAL_HOST, config.originalHost)
    putExtra(EXTRA_CFG_PORT, config.port)
    putExtra(EXTRA_CFG_HOST, config.host)
    putExtra(EXTRA_CFG_SNI, config.sni)
    putExtra(EXTRA_CFG_PATH, config.path)
    putExtra(EXTRA_CFG_TRANSPORT, config.transport)
    putExtra(EXTRA_CFG_TLS, config.tls)
    putExtra(EXTRA_CFG_ALPN, config.alpn)
    putExtra(EXTRA_CFG_FINGERPRINT, config.fingerprint)
    putExtra(EXTRA_CFG_FLOW, config.flow)
    putExtra(EXTRA_CFG_ALLOW_INSECURE, config.allowInsecure)
    putExtra(EXTRA_CFG_LABEL, config.label)
    putExtra(EXTRA_CFG_ORIGINAL_URI, config.originalUri)
}

private fun Intent.readParsedConfigExtras(): ParsedTunnelConfig = ParsedTunnelConfig(
    protocol = getStringExtra(EXTRA_CFG_PROTOCOL) ?: "vless",
    userId = getStringExtra(EXTRA_CFG_USER_ID) ?: "",
    originalHost = getStringExtra(EXTRA_CFG_ORIGINAL_HOST) ?: "",
    port = getIntExtra(EXTRA_CFG_PORT, 443),
    host = getStringExtra(EXTRA_CFG_HOST) ?: "",
    sni = getStringExtra(EXTRA_CFG_SNI) ?: "",
    path = getStringExtra(EXTRA_CFG_PATH) ?: "/",
    transport = getStringExtra(EXTRA_CFG_TRANSPORT) ?: "ws",
    tls = getBooleanExtra(EXTRA_CFG_TLS, true),
    alpn = getStringExtra(EXTRA_CFG_ALPN) ?: "",
    fingerprint = getStringExtra(EXTRA_CFG_FINGERPRINT) ?: "",
    flow = getStringExtra(EXTRA_CFG_FLOW) ?: "",
    allowInsecure = getBooleanExtra(EXTRA_CFG_ALLOW_INSECURE, false),
    label = getStringExtra(EXTRA_CFG_LABEL) ?: "manual",
    originalUri = getStringExtra(EXTRA_CFG_ORIGINAL_URI)
)

private fun buildScanServiceIntent(
    context: Context,
    core: ScannerCore,
    mode: ScanMode,
    payload: String,
    config: ParsedTunnelConfig
): Intent = Intent(context, ScanService::class.java)
    .setAction(ACTION_START_SCAN)
    .putExtra(EXTRA_SCAN_CORE, core.name)
    .putExtra(EXTRA_SCAN_MODE, mode.name)
    .putExtra(EXTRA_SCAN_PAYLOAD, payload)
    .putParsedConfigExtras(config)

private fun buildResumeScanServiceIntent(context: Context): Intent =
    Intent(context, ScanService::class.java).setAction(ACTION_RESUME_SCAN)


private fun readTextFromUri(context: Context, uri: Uri): String =
    context.contentResolver.openInputStream(uri)?.use { input ->
        InputStreamReader(input).readText()
    } ?: ""

private fun extractCandidateTokens(raw: String): List<String> {
    val tokenRegex = Regex("""\b(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}\b|\b(?:\d{1,3}\.){3}\d{1,3}\s*-\s*(?:\d{1,3}\.){3}\d{1,3}\b|\b(?:\d{1,3}\.){3}\d{1,3}\b""")
    val jsonPrefixes = Regex("""\"(?:ip_prefix|ipv4Prefix|ipv4_prefix)\"\s*:\s*\"([^\"]+)\"""")
        .findAll(raw)
        .map { it.groupValues[1].trim() }
        .toList()

    return buildList {
        addAll(raw.lineSequence().map { it.trim() }.filter { it.isNotBlank() }.toList())
        addAll(jsonPrefixes)
        addAll(tokenRegex.findAll(raw).map { it.value.trim() }.toList())
    }.distinct()
}

class ScanService : Service() {
    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)
    private var scanJob: Job? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP_SCAN -> {
                ScanRuntime.clearResume()
                scanJob?.cancel()
                ScanRuntime.stop("Stopped")
                stopForeground(true)
                stopSelf()
                return START_NOT_STICKY
            }
            ACTION_PAUSE_SCAN -> {
                if (scanJob?.isActive == true) {
                    ScanRuntime.requestPause()
                    ScanRuntime.pause("Pausing...")
                    notifyProgress("Pausing...", 0f, false)
                }
                return START_STICKY
            }
            ACTION_RESUME_SCAN -> {
                val request = ScanRuntime.consumeResumeRequest()
                if (request == null) return START_NOT_STICKY
                startForeground(SCAN_SERVICE_NOTIFICATION_ID, buildNotification("Resuming scan", 0f, true))
                startScan(request.core, request.mode, request.payload, request.config, request.nextIndex, request.currentResults, true)
                return START_STICKY
            }
            ACTION_START_SCAN -> {
                val core = runCatching { ScannerCore.valueOf(intent.getStringExtra(EXTRA_SCAN_CORE) ?: ScannerCore.CLOUDFLARE.name) }.getOrDefault(ScannerCore.CLOUDFLARE)
                val mode = runCatching { ScanMode.valueOf(intent.getStringExtra(EXTRA_SCAN_MODE) ?: ScanMode.IP.name) }.getOrDefault(ScanMode.IP)
                val payload = intent.getStringExtra(EXTRA_SCAN_PAYLOAD).orEmpty()
                val config = intent.readParsedConfigExtras()
                startForeground(SCAN_SERVICE_NOTIFICATION_ID, buildNotification("Preparing scan", 0f, true))
                startScan(core, mode, payload, config, 0, emptyList(), false)
                return START_STICKY
            }
        }
        return START_NOT_STICKY
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onDestroy() {
        scanJob?.cancel()
        serviceScope.cancel()
        super.onDestroy()
    }

    private fun startScan(
        core: ScannerCore,
        mode: ScanMode,
        payload: String,
        config: ParsedTunnelConfig,
        startIndex: Int,
        resumeResults: List<DisplayResult>,
        isResume: Boolean
    ) {
        scanJob?.cancel()
        ScanRuntime.pauseRequested = false
        ScanRuntime.rememberRequest(ScanResumeRequest(core, mode, payload, config, startIndex, resumeResults))
        ScanRuntime.start(core, mode, if (isResume) "Resuming ${if (mode == ScanMode.CONFIG) "Config scan" else "IP scan"}" else if (mode == ScanMode.CONFIG) "Config scan" else "IP scan", resumeResults)
        scanJob = serviceScope.launch {
            try {
                val results = when (mode) {
                    ScanMode.CONFIG -> runConfigScan(core, payload, startIndex, resumeResults)
                    ScanMode.IP -> runIpScan(core, config, payload, startIndex, resumeResults)
                }
                ScanRuntime.complete(results, "Completed (${results.size})")
                notifyProgress("Completed (${results.size})", 1f, false)
                stopForeground(true)
                stopSelf()
            } catch (_: PauseScanException) {
                ScanRuntime.pause("Paused")
                notifyProgress("Paused", 0f, false)
                stopForeground(true)
                stopSelf()
            } catch (cancel: CancellationException) {
                ScanRuntime.stop("Stopped")
                notifyProgress("Stopped", 0f, false)
                stopForeground(true)
                stopSelf()
            } catch (t: Throwable) {
                val msg = t.message ?: t.javaClass.simpleName
                ScanRuntime.fail("Failed: $msg")
                notifyProgress("Failed: $msg", 0f, false)
                stopForeground(true)
                stopSelf()
            }
        }
    }

    private suspend fun runConfigScan(
        core: ScannerCore,
        payload: String,
        startIndex: Int,
        resumeResults: List<DisplayResult>
    ): List<DisplayResult> {
        val configs = parseConfigLinks(payload)
        if (configs.isEmpty()) throw IllegalArgumentException("No valid configs found")

        val output = resumeResults.toMutableList()

        for (index in startIndex until configs.size) {
            val parsedInputConfig = configs[index]

            if (ScanRuntime.pauseRequested) {
                ScanRuntime.rememberRequest(
                    ScanResumeRequest(
                        core = core,
                        mode = ScanMode.CONFIG,
                        payload = payload,
                        config = parsedInputConfig,
                        nextIndex = index,
                        currentResults = output.toList()
                    )
                )
                throw PauseScanException()
            }

            val extractedAddress = parsedInputConfig.originalHost.trim()
            if (extractedAddress.isBlank()) continue

            val templateConfig = intentTemplateForCore(core)

            val result = runThreeStageScan(
                context = this@ScanService,
                core = core,
                baseConfig = templateConfig,
                candidates = listOf(extractedAddress),
                progressPrefix = "Config ${index + 1}/${configs.size}"
            ) { frac, label ->
                ScanRuntime.progress(frac, label)
                notifyProgress(label, frac, false)
            }

            output += result

            ScanRuntime.rememberRequest(
                ScanResumeRequest(
                    core = core,
                    mode = ScanMode.CONFIG,
                    payload = payload,
                    config = parsedInputConfig,
                    nextIndex = index + 1,
                    currentResults = output.toList()
                )
            )
        }

        return output.sortedByDescending { it.confidence }
    }

    private fun intentTemplateForCore(core: ScannerCore): ParsedTunnelConfig {
        val currentIntentConfig = ScanRuntime.consumeResumeRequest()?.config
        if (currentIntentConfig != null) return currentIntentConfig

        return ParsedTunnelConfig(
            protocol = "vless",
            userId = "",
            originalHost = "",
            port = 443,
            host = "",
            sni = "",
            path = "/",
            transport = "ws",
            tls = true,
            alpn = "",
            fingerprint = "",
            flow = "",
            allowInsecure = false,
            label = if (core == ScannerCore.CLOUDFRONT) "cloudfront-manual" else "cloudflare-manual"
        )
    }
    private suspend fun runIpScan(
        core: ScannerCore,
        config: ParsedTunnelConfig,
        payload: String,
        startIndex: Int,
        resumeResults: List<DisplayResult>
    ): List<DisplayResult> {
        val candidates = expandCandidateText(payload)
        if (candidates.isEmpty()) throw IllegalArgumentException("No valid IPs/ranges found")

        val output = resumeResults.toMutableList()
        val batchSize = detectBatchSize(candidates.size)
        var index = startIndex.coerceAtLeast(0)

        while (index < candidates.size) {
            if (ScanRuntime.pauseRequested) {
                ScanRuntime.rememberRequest(ScanResumeRequest(core, ScanMode.IP, payload, config, index, output.toList()))
                throw PauseScanException()
            }

            val endExclusive = minOf(index + batchSize, candidates.size)
            val batch = candidates.subList(index, endExclusive)
            val chunkPrefix = "IP scan ${index + 1}-${endExclusive}/${candidates.size}"
            val batchResults = runThreeStageScan(this@ScanService, core, config, batch, chunkPrefix) { frac, label ->
                val global = ((index.toFloat() / candidates.size.coerceAtLeast(1)) + (frac * (batch.size.toFloat() / candidates.size.coerceAtLeast(1)))).coerceIn(0f, 1f)
                ScanRuntime.progress(global, label)
                notifyProgress(label, global, false)
            }
            output += batchResults
            index = endExclusive
            ScanRuntime.rememberRequest(ScanResumeRequest(core, ScanMode.IP, payload, config, index, output.toList()))
            gcIfNeeded()
        }

        return output.sortedByDescending { it.confidence }.take(200)
    }

    private fun detectBatchSize(totalCandidates: Int): Int {
        val runtime = Runtime.getRuntime()
        val maxMb = runtime.maxMemory() / (1024 * 1024)
        val usedMb = (runtime.totalMemory() - runtime.freeMemory()) / (1024 * 1024)
        val headroom = (maxMb - usedMb).coerceAtLeast(32)
        return when {
            totalCandidates >= 20000 && headroom < 256 -> 96
            totalCandidates >= 10000 && headroom < 384 -> 128
            totalCandidates >= 5000 -> 192
            totalCandidates >= 1000 -> 256
            else -> 384
        }
    }

    private fun gcIfNeeded() {
        val runtime = Runtime.getRuntime()
        val maxMb = runtime.maxMemory() / (1024 * 1024)
        val usedMb = (runtime.totalMemory() - runtime.freeMemory()) / (1024 * 1024)
        if (maxMb - usedMb < 128) System.gc()
    }

    private fun notifyProgress(label: String, progress: Float, indeterminate: Boolean) {
        val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        nm.notify(SCAN_SERVICE_NOTIFICATION_ID, buildNotification(label, progress, indeterminate))
    }

    private fun buildNotification(label: String, progress: Float, indeterminate: Boolean): Notification {
        val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O && nm.getNotificationChannel(SCAN_SERVICE_CHANNEL_ID) == null) {
            nm.createNotificationChannel(
                NotificationChannel(
                    SCAN_SERVICE_CHANNEL_ID,
                    "Scanner",
                    NotificationManager.IMPORTANCE_LOW
                )
            )
        }
        return NotificationCompat.Builder(this, SCAN_SERVICE_CHANNEL_ID)
            .setSmallIcon(android.R.drawable.stat_notify_sync)
            .setContentTitle("Host Extractor scan")
            .setContentText(label)
            .setOnlyAlertOnce(true)
            .setOngoing(true)
            .setProgress(100, (progress.coerceIn(0f, 1f) * 100).toInt(), indeterminate)
            .build()
    }
}

data class CoreThemePalette(
    val primary: Color,
    val background: Color,
    val surface: Color,
    val accent: Color,
    val success: Color
)

fun themeForCore(core: ScannerCore): CoreThemePalette = when (core) {
    ScannerCore.CLOUDFLARE -> CoreThemePalette(Color(0xFFF38020), Color(0xFF130A00), Color(0xFF221200), Color(0xFFFFB74D), Color(0xFF00C853))
    ScannerCore.CLOUDFRONT -> CoreThemePalette(Color(0xFF7C4DFF), Color(0xFF0A0E22), Color(0xFF111A33), Color(0xFFB388FF), Color(0xFF00E676))
}

class SettingsManager(context: Context, profileName: String) {
    private val prefs = context.getSharedPreferences("app_settings_$profileName", Context.MODE_PRIVATE)
    var protocol: String get() = prefs.getString("protocol", "vless") ?: "vless"; set(v) = prefs.edit().putString("protocol", v).apply()
    var host: String get() = prefs.getString("host", "") ?: ""; set(v) = prefs.edit().putString("host", v).apply()
    var sni: String get() = prefs.getString("sni", "") ?: ""; set(v) = prefs.edit().putString("sni", v).apply()
    var path: String get() = prefs.getString("path", "/") ?: "/"; set(v) = prefs.edit().putString("path", v).apply()
    var userId: String get() = prefs.getString("userId", "") ?: ""; set(v) = prefs.edit().putString("userId", v).apply()
    var port: String get() = prefs.getString("port", "443") ?: "443"; set(v) = prefs.edit().putString("port", v).apply()
    var alpn: String get() = prefs.getString("alpn", "") ?: ""; set(v) = prefs.edit().putString("alpn", v).apply()
    var transport: String get() = prefs.getString("transport", "ws") ?: "ws"; set(v) = prefs.edit().putString("transport", v).apply()
    var flow: String get() = prefs.getString("flow", "") ?: ""; set(v) = prefs.edit().putString("flow", v).apply()
    var fingerprint: String get() = prefs.getString("fingerprint", "") ?: ""; set(v) = prefs.edit().putString("fingerprint", v).apply()
    var tls: Boolean get() = prefs.getBoolean("tls", true); set(v) = prefs.edit().putBoolean("tls", v).apply()
    var insecure: Boolean get() = prefs.getBoolean("insecure", false); set(v) = prefs.edit().putBoolean("insecure", v).apply()
    fun clearAll() = prefs.edit().clear().apply()
    fun toParsedConfig(core: ScannerCore) = ParsedTunnelConfig(
        protocol = protocol,
        userId = userId,
        originalHost = sni.ifBlank { host },
        port = port.toIntOrNull() ?: if (tls) 443 else 80,
        host = host,
        sni = if (tls) sni else "",
        path = path.ifBlank { "/" },
        transport = transport,
        tls = tls,
        alpn = if (tls) alpn else "",
        fingerprint = if (tls) fingerprint else "",
        flow = flow,
        allowInsecure = if (tls) insecure else false,
        label = if (core == ScannerCore.CLOUDFRONT) "cloudfront-manual" else "cloudflare-manual"
    )
}

data class ParsedTunnelConfig(
    val protocol: String,
    val userId: String,
    val originalHost: String,
    val port: Int,
    val host: String,
    val sni: String,
    val path: String,
    val transport: String,
    val tls: Boolean,
    val alpn: String,
    val fingerprint: String,
    val flow: String,
    val allowInsecure: Boolean,
    val label: String,
    val originalUri: String? = null
)

data class Stage1Probe(
    val ip: String,
    val success: Boolean,
    val latencyMs: Long,
    val stage: String,
    val bytesReceived: Int,
    val aliveMs: Long,
    val alpnMismatch: Boolean = false,
    val error: String = ""
)

data class FastScanProbe(
    val ip: String,
    val bestPort: Int,
    val avgLatencyMs: Long,
    val jitterMs: Long,
    val successCount: Int,
    val attempts: Int,
    val bytesReceived: Int,
    val score: Int,
    val status: String,
    val sampleStage: String,
    val alpnMismatch: Boolean = false,
    val error: String = ""
)

data class FinalValidation(
    val success: Boolean,
    val latencyMs: Long,
    val aliveMs: Long,
    val bytesReceived: Int,
    val xraySuccess: Boolean,
    val xrayDelayMs: Long,
    val xrayMessage: String,
    val confidence: Int
)

data class DisplayResult(
    val ip: String,
    val builtConfig: String,
    val stage1LatencyMs: Long,
    val finalLatencyMs: Long,
    val aliveMs: Long,
    val bytesReceived: Int,
    val confidence: Int,
    val tier: ResultTier,
    val status: String,
    val xrayStatus: String,
    val sourceLabel: String
)

private val CLOUDFLARE_RANGES = listOf(
    "104.16.0.0/20", "172.64.0.0/20", "108.162.192.0/20", "162.158.0.0/20",
    "173.245.48.0/20", "188.114.96.0/20", "190.93.240.0/20", "197.234.240.0/22",
    "198.41.128.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22"
)
private val CLOUDFRONT_SAMPLE_RANGES = listOf(
    "13.32.0.0/15", "13.35.0.0/16", "18.64.0.0/14", "52.46.0.0/18", "54.182.0.0/16", "99.84.0.0/16", "108.138.0.0/15", "143.204.0.0/16"
)

class MainActivity : ComponentActivity() {
    private val activityScope = CoroutineScope(SupervisorJob() + Dispatchers.Main)
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        WindowCompat.setDecorFitsSystemWindows(window, false)
        setContent {
            MaterialTheme {
                Surface(modifier = Modifier.fillMaxSize(), color = Color(0xFF101010)) { AppRoot(activityScope) }
            }
        }
    }
    override fun onDestroy() { super.onDestroy(); activityScope.cancel() }
}

@Composable
fun AppRoot(activityScope: CoroutineScope) {
    var selectedCore by rememberSaveable { mutableStateOf<ScannerCore?>(null) }
    Box(Modifier.fillMaxSize().background(Color(0xFF0E0E0E)).statusBarsPadding()) {
        if (selectedCore == null) HomeSelectionScreen { selectedCore = it }
        else ScannerWorkspace(activityScope, selectedCore!!, { selectedCore = null }, { selectedCore = it })
        Text(APP_VERSION, color = Color.Gray, fontSize = 11.sp, modifier = Modifier.align(Alignment.BottomEnd).padding(14.dp))
    }
}

@Composable
fun HomeSelectionScreen(onSelect: (ScannerCore) -> Unit) {
    Column(Modifier.fillMaxSize().padding(20.dp), verticalArrangement = Arrangement.spacedBy(16.dp, Alignment.CenterVertically)) {
        Text("Select Scanner Core", color = Color.White, fontSize = 24.sp, fontWeight = FontWeight.Bold)
        Text("Stage 1 foundation: initial scan → top 100 → final validation + optional Xray", color = Color.LightGray, fontSize = 13.sp)
        CoreHomeCard("Cloudflare Scanner", "Orange core for Cloudflare edge probing and validation", ScannerCore.CLOUDFLARE, onSelect)
        CoreHomeCard("CloudFront Scanner", "Blue core for stricter CloudFront validation", ScannerCore.CLOUDFRONT, onSelect)
    }
}


@Composable
fun CoreLogo(core: ScannerCore, modifier: Modifier = Modifier, size: Int = 24) {
    val tint = when (core) {
        ScannerCore.CLOUDFLARE -> Color(0xFFF38020)
        ScannerCore.CLOUDFRONT -> Color(0xFFB388FF)
    }
    Icon(
        imageVector = if (core == ScannerCore.CLOUDFLARE) Icons.Default.Cloud else Icons.Default.Public,
        contentDescription = null,
        tint = tint,
        modifier = modifier.size(size.dp)
    )
}

@Composable
fun CoreHomeCard(title: String, subtitle: String, core: ScannerCore, onSelect: (ScannerCore) -> Unit) {
    val palette = themeForCore(core)
    Card(modifier = Modifier.fillMaxWidth().clickable { onSelect(core) }, colors = CardDefaults.cardColors(containerColor = palette.surface)) {
        Row(
            Modifier.padding(20.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(14.dp)
        ) {
            CoreLogo(core = core, size = 32)
            Column {
                Text(title, color = palette.primary, fontWeight = FontWeight.Bold, fontSize = 20.sp)
                Spacer(Modifier.height(6.dp))
                Text(subtitle, color = Color.White.copy(alpha = 0.85f), fontSize = 13.sp)
            }
        }
    }
}

@Composable
fun ScannerWorkspace(
    activityScope: CoroutineScope,
    core: ScannerCore,
    onBackHome: () -> Unit,
    onSwitchCore: (ScannerCore) -> Unit
) {
    val palette = themeForCore(core)
    val context = LocalContext.current
    val settings = remember(core) {
        SettingsManager(context, if (core == ScannerCore.CLOUDFRONT) "cloudfront" else "cloudflare")
    }
    var selectedTab by rememberSaveable(core) { mutableIntStateOf(0) }
    var configInput by rememberSaveable(core) { mutableStateOf("") }
    var configResults by remember(core) { mutableStateOf<List<DisplayResult>>(emptyList()) }
    var ipInput by rememberSaveable(core) { mutableStateOf("") }
    var ipResults by remember(core) { mutableStateOf<List<DisplayResult>>(emptyList()) }

    Scaffold(
        containerColor = palette.background,
        bottomBar = {
            NavigationBar(
                containerColor = Color(0xFF07141F),
                tonalElevation = 0.dp,
                modifier = Modifier.height(72.dp)
            ) {
                NavigationBarItem(
                    selected = core == ScannerCore.CLOUDFLARE,
                    onClick = { onSwitchCore(ScannerCore.CLOUDFLARE) },
                    icon = {
                        Icon(
                            Icons.Default.Cloud,
                            contentDescription = null,
                            modifier = Modifier.size(22.dp)
                        )
                    },
                    label = {
                        Text(
                            "Cloudflare",
                            fontSize = 11.sp,
                            maxLines = 1
                        )
                    },
                    alwaysShowLabel = true,
                    colors = NavigationBarItemDefaults.colors(
                        selectedIconColor = Color(0xFF111827),
                        selectedTextColor = Color.White,
                        indicatorColor = Color(0xFFE9DDFE),
                        unselectedIconColor = Color(0xFFB8C7D9),
                        unselectedTextColor = Color(0xFFB8C7D9)
                    )
                )

                NavigationBarItem(
                    selected = core == ScannerCore.CLOUDFRONT,
                    onClick = { onSwitchCore(ScannerCore.CLOUDFRONT) },
                    icon = {
                        Icon(
                            Icons.Default.Public,
                            contentDescription = null,
                            modifier = Modifier.size(22.dp)
                        )
                    },
                    label = {
                        Text(
                            "CloudFront",
                            fontSize = 11.sp,
                            maxLines = 1
                        )
                    },
                    alwaysShowLabel = true,
                    colors = NavigationBarItemDefaults.colors(
                        selectedIconColor = Color(0xFF111827),
                        selectedTextColor = Color.White,
                        indicatorColor = Color(0xFFE9DDFE),
                        unselectedIconColor = Color(0xFFB8C7D9),
                        unselectedTextColor = Color(0xFFB8C7D9)
                    )
                )
            }
        }
    ) { innerPadding ->

        Column(
            Modifier
                .fillMaxSize()
                .background(palette.background)
                .padding(innerPadding)
        ) {
            Row(
                Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp, vertical = 12.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                IconButton(onClick = onBackHome) {
                    Icon(Icons.Default.ArrowBack, null, tint = Color.White)
                }

                Spacer(Modifier.width(6.dp))

                Column(Modifier.weight(1f)) {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(10.dp)
                    ) {
                        CoreLogo(core = core, size = 26)
                        Text(
                            if (core == ScannerCore.CLOUDFRONT) "CloudFront Scanner" else "Cloudflare Scanner",
                            color = palette.primary,
                            fontWeight = FontWeight.Bold,
                            fontSize = 18.sp,
                            lineHeight = 20.sp
                        )
                    }
                    Text(
                        "Stage 1: initial scan → top 100 → final validation",
                        color = Color(0xFFD6E4F0),
                        fontSize = 8.sp,
                        lineHeight = 18.sp
                    )
                    Text(
                        XrayLiteBridge.versionOrNull() ?: "XRAY OFF",
                        color = if (XrayLiteBridge.isAvailable()) palette.success else Color(0xFFB0BEC5),
                        fontSize = 11.sp
                    )
                }

                Text(
                    if (XrayLiteBridge.isAvailable()) "XRAY READY" else "XRAY AAR MISSING",
                    color = if (XrayLiteBridge.isAvailable()) Color(0xFF00E676) else Color(0xFFFFB300),
                    fontWeight = FontWeight.Bold,
                    fontSize = 13.sp,
                    maxLines = 1
                )
            }

            TabRow(
                selectedTabIndex = selectedTab,
                containerColor = palette.surface,
                contentColor = palette.primary
            ) {
                listOf("INPUT", "CONFIG", "IP SCAN", "HELP").forEachIndexed { i, t ->
                    Tab(
                        selected = selectedTab == i,
                        onClick = { selectedTab = i },
                        text = { Text(t, fontSize = 11.sp, color = Color(0xFFEAF4FF)) }
                    )
                }
            }

            when (selectedTab) {
                0 -> InputTab(core, settings)
                1 -> ConfigScannerTab(core, settings, configInput, configResults, { configInput = it }, { configResults = it }, activityScope)
                2 -> IpScannerTab(core, settings, ipInput, ipResults, { ipInput = it }, { ipResults = it }, activityScope)
                else -> HelpTab(core)
            }
        }
    }
}

@Composable
fun CoreRailItem(label: String, selected: Boolean, color: Color, onClick: () -> Unit) {
    Card(
        modifier = Modifier.fillMaxWidth().clickable(onClick = onClick),
        colors = CardDefaults.cardColors(
            containerColor = if (selected) color.copy(alpha = 0.18f) else Color.Transparent
        )
    ) {
        Text(
            text = label,
            color = if (selected) color else Color(0xFFEAF4FF),
            fontSize = 13.sp,
            fontWeight = if (selected) FontWeight.Bold else FontWeight.Medium,
            maxLines = 2,
            overflow = TextOverflow.Ellipsis,
            modifier = Modifier.padding(horizontal = 10.dp, vertical = 14.dp)
        )
    }
}
@Composable
fun HelpTab(core: ScannerCore) {
    val palette = themeForCore(core)
    val xrayStatus = if (XrayLiteBridge.isAvailable()) XrayLiteBridge.versionOrNull() ?: "libv2ray loaded" else "Put libv2ray.aar inside app/libs to enable Xray validation"
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        InfoCard("Stage 1 Pipeline", palette) {
            Text("1) Parse config or manual fields", color = Color.White)
            Text("2) Initial scan on all candidates", color = Color.White)
            Text("3) Keep the top 100 candidates", color = Color.White)
            Text("4) Final validation with longer session + optional Xray", color = Color.White)
            Text("5) Build final configs with verified IPs", color = Color.White)
        }
        InfoCard("Inputs accepted", palette) {
            Text("• Full configs pasted line-by-line", color = Color.White)
            Text("• Manual fields from INPUT tab", color = Color.White)
            Text("• Manual IPs", color = Color.White)
            Text("• Range/CIDR lines like 104.16.0.0/20", color = Color.White)
            Text("• File content pasted or loaded into the IP SCAN textbox", color = Color.White)
        }
        InfoCard("Xray integration", palette) {
            Text(xrayStatus, color = palette.accent)
            Text("This build is wired for AndroidLibXrayLite. It auto-detects the libv2ray bridge and calls MeasureOutboundDelay(...) when the AAR is present.", color = Color.White.copy(alpha = 0.85f), fontSize = 12.sp)
        }
    }
}

@Composable
fun InfoCard(title: String, palette: CoreThemePalette, content: @Composable ColumnScope.() -> Unit) {
    Card(colors = CardDefaults.cardColors(containerColor = palette.surface), modifier = Modifier.fillMaxWidth()) {
        Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(6.dp), content = {
            Text(title, color = palette.primary, fontWeight = FontWeight.Bold)
            content()
        })
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun InputTab(core: ScannerCore, settings: SettingsManager) {
    val palette = themeForCore(core)
    val context = LocalContext.current
    var protocol by remember { mutableStateOf(settings.protocol) }
    var host by remember { mutableStateOf(settings.host) }
    var sni by remember { mutableStateOf(settings.sni) }
    var path by remember { mutableStateOf(settings.path) }
    var userId by remember { mutableStateOf(settings.userId) }
    var port by remember { mutableStateOf(settings.port) }
    var alpn by remember { mutableStateOf(settings.alpn) }
    var transport by remember { mutableStateOf(settings.transport) }
    var flow by remember { mutableStateOf(settings.flow) }
    var fingerprint by remember { mutableStateOf(settings.fingerprint) }
    var tlsEnabled by remember { mutableStateOf(settings.tls) }
    var insecure by remember { mutableStateOf(settings.insecure) }
    var smartImport by remember { mutableStateOf("") }
    var alpnExpanded by remember { mutableStateOf(false) }
    var flowExpanded by remember { mutableStateOf(false) }
    var fingerprintExpanded by remember { mutableStateOf(false) }
    val alpnOptions = listOf("","http/1.1", "h2", "h3")
    val flowOptions = listOf("", "xtls-rprx-vision", "xtls-rprx-direct")
    val fingerprintOptions = listOf("","chrome", "firefox", "safari", "edge", "random")
    val inputColors = OutlinedTextFieldDefaults.colors(
        focusedTextColor = Color.White,
        unfocusedTextColor = Color.White,
        disabledTextColor = Color.White.copy(alpha = 0.7f),
        focusedLabelColor = palette.accent,
        unfocusedLabelColor = Color(0xFFD6E4F0),
        focusedBorderColor = Color(0xFF8E6BE8),
        unfocusedBorderColor = Color(0xFF8A7CA8),
        cursorColor = palette.primary,
        focusedContainerColor = Color(0xFF0F1A24),
        unfocusedContainerColor = Color(0xFF0F1A24)
    )

    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
        Text("Manual input + smart importer", color = palette.primary, fontWeight = FontWeight.Bold)
        OutlinedTextField(
            value = smartImport,
            onValueChange = {
                smartImport = it
                parseConfigLinks(it).firstOrNull()?.let { cfg ->
                    protocol = cfg.protocol

                    host = cfg.host

                    sni = if (cfg.tls) cfg.sni else ""

                    path = cfg.path
                    userId = cfg.userId
                    port = cfg.port.toString()

                    alpn = if (cfg.tls) cfg.alpn else ""
                    transport = cfg.transport
                    flow = cfg.flow
                    fingerprint = if (cfg.tls) cfg.fingerprint else ""

                    tlsEnabled = cfg.tls
                    insecure = if (cfg.tls) cfg.allowInsecure else false
                }
            },
            label = { Text("Paste one VLESS/Trojan config") },
            modifier = Modifier.fillMaxWidth(),
            maxLines = 3,
            textStyle = LocalTextStyle.current.copy(
                color = Color.White,
                fontSize = 16.sp,
                lineHeight = 22.sp
            ),
            colors = inputColors
        )
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            ToggleChip("VLESS", protocol.equals("vless", true), palette.primary) { protocol = "vless" }
            ToggleChip("TROJAN", protocol.equals("trojan", true), palette.primary) { protocol = "trojan" }
            ToggleChip("WS", transport.equals("ws", true), palette.accent) { transport = "ws" }
            ToggleChip("gRPC", transport.equals("grpc", true), palette.accent) { transport = "grpc" }
        }
        OutlinedTextField(
            value = host,
            onValueChange = { host = it },
            label = { Text("Host") },
            modifier = Modifier.fillMaxWidth(),
            textStyle = LocalTextStyle.current.copy(color = Color.White, fontSize = 16.sp),
            colors = inputColors
        )
        OutlinedTextField(
            value = sni,
            onValueChange = { sni = it },
            label = { Text("SNI") },
            modifier = Modifier.fillMaxWidth(),
            textStyle = LocalTextStyle.current.copy(color = Color.White, fontSize = 16.sp),
            colors = inputColors
        )
        OutlinedTextField(
            value = path,
            onValueChange = { path = it },
            label = { Text("Path or Service Name") },
            modifier = Modifier.fillMaxWidth(),
            textStyle = LocalTextStyle.current.copy(color = Color.White, fontSize = 16.sp, lineHeight = 22.sp),
            colors = inputColors
        )
        OutlinedTextField(
            value = userId,
            onValueChange = { userId = it },
            label = { Text(if (protocol == "trojan") "Password" else "UUID") },
            modifier = Modifier.fillMaxWidth(),
            textStyle = LocalTextStyle.current.copy(color = Color.White, fontSize = 16.sp, lineHeight = 22.sp),
            colors = inputColors
        )
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedTextField(
                value = port,
                onValueChange = { port = it.filter(Char::isDigit) },
                label = { Text("Port") },
                modifier = Modifier.weight(1f),
                textStyle = LocalTextStyle.current.copy(color = Color.White, fontSize = 16.sp),
                colors = inputColors
            )
            ExposedDropdownMenuBox(
                expanded = alpnExpanded,
                onExpandedChange = { alpnExpanded = !alpnExpanded },
                modifier = Modifier.weight(1f)
            ) {
                OutlinedTextField(
                    value = alpn,
                    onValueChange = {},
                    readOnly = true,
                    label = { Text("ALPN") },
                    trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expanded = alpnExpanded) },
                    modifier = Modifier.menuAnchor().fillMaxWidth(),
                    textStyle = LocalTextStyle.current.copy(color = Color.White, fontSize = 16.sp),
                    colors = inputColors
                )
                ExposedDropdownMenu(
                    expanded = alpnExpanded,
                    onDismissRequest = { alpnExpanded = false }
                ) {
                    alpnOptions.forEach { option ->
                        DropdownMenuItem(
                            text = { Text(if (option.isBlank()) "(empty)" else option) },
                            onClick = {
                                alpn = option
                                alpnExpanded = false
                            }
                        )
                    }
                }
            }
        }
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            ExposedDropdownMenuBox(
                expanded = flowExpanded,
                onExpandedChange = { flowExpanded = !flowExpanded },
                modifier = Modifier.weight(1f)
            ) {
                OutlinedTextField(
                    value = flow,
                    onValueChange = {},
                    readOnly = true,
                    label = { Text("Flow") },
                    trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expanded = flowExpanded) },
                    modifier = Modifier.menuAnchor().fillMaxWidth(),
                    textStyle = LocalTextStyle.current.copy(color = Color.White, fontSize = 16.sp),
                    colors = inputColors
                )
                ExposedDropdownMenu(
                    expanded = flowExpanded,
                    onDismissRequest = { flowExpanded = false }
                ) {
                    flowOptions.forEach { option ->
                        DropdownMenuItem(
                            text = { Text(if (option.isBlank()) "(empty)" else option) },
                            onClick = {
                                flow = option
                                flowExpanded = false
                            }
                        )
                    }
                }
            }
            ExposedDropdownMenuBox(
                expanded = fingerprintExpanded,
                onExpandedChange = { fingerprintExpanded = !fingerprintExpanded },
                modifier = Modifier.weight(1f)
            ) {
                OutlinedTextField(
                    value = fingerprint,
                    onValueChange = {},
                    readOnly = true,
                    label = { Text("Fingerprint") },
                    trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expanded = fingerprintExpanded) },
                    modifier = Modifier.menuAnchor().fillMaxWidth(),
                    textStyle = LocalTextStyle.current.copy(color = Color.White, fontSize = 16.sp),
                    colors = inputColors
                )
                ExposedDropdownMenu(
                    expanded = fingerprintExpanded,
                    onDismissRequest = { fingerprintExpanded = false }
                ) {
                    fingerprintOptions.forEach { option ->
                        DropdownMenuItem(
                            text = { Text(if (option.isBlank()) "(empty)" else option) },
                            onClick = {
                                fingerprint = option
                                fingerprintExpanded = false
                            }
                        )
                    }
                }
            }
        }
        Row(verticalAlignment = Alignment.CenterVertically) { Text("TLS", color = Color.White, modifier = Modifier.weight(1f)); Switch(checked = tlsEnabled, onCheckedChange = { tlsEnabled = it }) }
        Row(verticalAlignment = Alignment.CenterVertically) { Text("Allow insecure", color = Color.White, modifier = Modifier.weight(1f)); Switch(checked = insecure, onCheckedChange = { insecure = it }) }
        Button(onClick = {
            settings.protocol = protocol
            settings.host = host.trim()
            settings.sni = if (tlsEnabled) sni.trim() else ""
            settings.path = path.trim().ifBlank { "/" }
            settings.userId = userId.trim()
            settings.port = port.trim().ifBlank { if (tlsEnabled) "443" else "80" }
            settings.alpn = if (tlsEnabled) alpn.trim() else ""
            settings.transport = transport.trim().ifBlank { "ws" }
            settings.flow = flow.trim()
            settings.fingerprint = if (tlsEnabled) fingerprint.trim() else ""
            settings.tls = tlsEnabled
            settings.insecure = if (tlsEnabled) insecure else false
            Toast.makeText(context, "Saved for ${if (core == ScannerCore.CLOUDFRONT) "CloudFront" else "Cloudflare"}", Toast.LENGTH_SHORT).show()
        }, modifier = Modifier.fillMaxWidth(), colors = ButtonDefaults.buttonColors(containerColor = palette.primary, contentColor = Color.Black)) { Text("SAVE INPUT") }
        Button(onClick = {
            settings.clearAll()
            protocol = "vless"
            host = ""
            sni = ""
            path = "/"
            userId = ""
            port = "443"
            alpn = ""
            transport = "ws"
            flow = ""
            fingerprint = ""
            tlsEnabled = true
            insecure = false
            smartImport = ""
        }, modifier = Modifier.fillMaxWidth(), colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF8E2424))) { Text("RESET INPUT") }
    }
}

@Composable
fun ToggleChip(label: String, selected: Boolean, selectedColor: Color, onClick: () -> Unit) {
    Card(modifier = Modifier.clickable(onClick = onClick), colors = CardDefaults.cardColors(containerColor = if (selected) selectedColor.copy(alpha = 0.25f) else Color.Transparent)) {
        Text(label, color = if (selected) selectedColor else Color.White, modifier = Modifier.padding(horizontal = 12.dp, vertical = 8.dp), fontSize = 12.sp)
    }
}

@Composable
fun ConfigScannerTab(core: ScannerCore, settings: SettingsManager, input: String, results: List<DisplayResult>, onInputChange: (String) -> Unit, onResultsChange: (List<DisplayResult>) -> Unit, activityScope: CoroutineScope) {
    val palette = themeForCore(core)
    val context = LocalContext.current
    val clipboard = LocalClipboardManager.current
    val scanState by ScanRuntime.state.collectAsState()
    val isTesting = scanState.running && scanState.mode == ScanMode.CONFIG && scanState.core == core
    val isPaused = scanState.paused && scanState.mode == ScanMode.CONFIG && scanState.core == core
    val canResume = scanState.resumeAvailable && scanState.mode == ScanMode.CONFIG && scanState.core == core
    val progress = if (scanState.mode == ScanMode.CONFIG && scanState.core == core) scanState.progress else 0f
    val progressLabel = if (scanState.mode == ScanMode.CONFIG && scanState.core == core) scanState.progressLabel else "Idle"
    LaunchedEffect(scanState.results, scanState.mode, scanState.core) {
        if (scanState.mode == ScanMode.CONFIG && scanState.core == core) {
            onResultsChange(scanState.results)
        }
    }

    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
        Text("Config scan", color = palette.primary, fontWeight = FontWeight.Bold)

        Box {
            OutlinedTextField(
                value = input,
                onValueChange = onInputChange,
                label = { Text("Paste VLESS/Trojan configs", color = Color(0xFFD6E4F0)) },
                modifier = Modifier.fillMaxWidth().height(170.dp),
                textStyle = LocalTextStyle.current.copy(
                    color = Color.White,
                    fontSize = 16.sp,
                    lineHeight = 22.sp
                ),
                colors = OutlinedTextFieldDefaults.colors(
                    focusedTextColor = Color.White,
                    unfocusedTextColor = Color.White,
                    focusedLabelColor = palette.accent,
                    unfocusedLabelColor = Color(0xFFD6E4F0),
                    cursorColor = palette.primary,
                    focusedBorderColor = Color(0xFF8E6BE8),
                    unfocusedBorderColor = Color(0xFF7E57C2),
                    focusedContainerColor = Color(0xFF0F1A24),
                    unfocusedContainerColor = Color(0xFF0F1A24)
                )
            )

            Row(Modifier.align(Alignment.TopEnd).padding(4.dp)) {
                IconButton(onClick = { clipboard.getText()?.let { onInputChange(it.text) } }) {
                    Icon(Icons.Default.ContentPaste, null, tint = palette.primary)
                }
                IconButton(onClick = { onInputChange("") }) {
                    Icon(Icons.Default.Delete, null, tint = Color.Red)
                }
            }
        }

        if (isTesting || isPaused) { LinearProgressIndicator(progress = { progress }, modifier = Modifier.fillMaxWidth(), color = palette.primary); Text(progressLabel, color = Color.White, fontSize = 12.sp) }
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            Button(
                onClick = {
                    if (canResume) {
                        val resumeIntent = buildResumeScanServiceIntent(context)
                        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) context.startForegroundService(resumeIntent) else context.startService(resumeIntent)
                    } else {
                        val configs = parseConfigLinks(input)
                        if (configs.isEmpty()) {
                            Toast.makeText(context, "No valid configs found", Toast.LENGTH_SHORT).show()
                            return@Button
                        }
                        onResultsChange(emptyList())
                        val serviceIntent = buildScanServiceIntent(
                            context = context,
                            core = core,
                            mode = ScanMode.CONFIG,
                            payload = input,
                            config = settings.toParsedConfig(core)
                        )
                        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) context.startForegroundService(serviceIntent) else context.startService(serviceIntent)
                    }
                },
                enabled = !isTesting || canResume,
                colors = ButtonDefaults.buttonColors(
                    containerColor = if (canResume) Color(0xFF1565C0) else palette.primary,
                    contentColor = if (canResume) Color.White else Color.Black
                ),
                modifier = Modifier.weight(1f).height(64.dp),
                shape = RoundedCornerShape(28.dp)
            ) {
                Text(if (canResume) "RESUME" else "START", fontSize = 16.sp, fontWeight = FontWeight.Bold, maxLines = 1, softWrap = false)
            }

            Button(
                onClick = {
                    val action = if (isTesting) ACTION_PAUSE_SCAN else ACTION_STOP_SCAN
                    context.startService(Intent(context, ScanService::class.java).setAction(action))
                },
                colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF8E2424)),
                modifier = Modifier.weight(1f).height(64.dp),
                shape = RoundedCornerShape(28.dp)
            ) {
                Text(if (isTesting) "PAUSE" else "STOP", fontSize = 16.sp, fontWeight = FontWeight.Bold)
            }

            Button(
                onClick = {
                    clipboard.setText(AnnotatedString(results.joinToString("\n") { it.builtConfig }))
                    Toast.makeText(context, "Copied all rebuilt configs", Toast.LENGTH_SHORT).show()
                },
                colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF1B5E20)),
                modifier = Modifier.weight(1f).height(64.dp),
                shape = RoundedCornerShape(28.dp)
            ) {
                Text("COPY ALL", fontSize = 13.sp, fontWeight = FontWeight.Bold, maxLines = 2)
            }
        }
        results.forEach { ResultRow(it, core) }
    }
}

@Composable
fun IpScannerTab(core: ScannerCore, settings: SettingsManager, input: String, results: List<DisplayResult>, onInputChange: (String) -> Unit, onResultsChange: (List<DisplayResult>) -> Unit, activityScope: CoroutineScope) {
    val palette = themeForCore(core)
    val context = LocalContext.current
    val clipboard = LocalClipboardManager.current
    val filePicker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri == null) return@rememberLauncherForActivityResult
        runCatching {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.KITKAT) {
                val takeFlags = Intent.FLAG_GRANT_READ_URI_PERMISSION
                context.contentResolver.takePersistableUriPermission(uri, takeFlags)
            }
        }
        val loadedText = runCatching { readTextFromUri(context, uri) }.getOrDefault("")
        if (loadedText.isBlank()) {
            Toast.makeText(context, "Selected file is empty", Toast.LENGTH_SHORT).show()
            return@rememberLauncherForActivityResult
        }
        val tokens = extractCandidateTokens(loadedText)
        val displayText = if (tokens.isNotEmpty()) tokens.joinToString("\n") else loadedText
        val candidateCount = expandCandidateText(loadedText).size
        onInputChange(displayText)
        Toast.makeText(context, "Loaded file • extracted ${candidateCount} candidates", Toast.LENGTH_SHORT).show()
    }
    val scanState by ScanRuntime.state.collectAsState()
    val isTesting = scanState.running && scanState.mode == ScanMode.IP && scanState.core == core
    val isPaused = scanState.paused && scanState.mode == ScanMode.IP && scanState.core == core
    val canResume = scanState.resumeAvailable && scanState.mode == ScanMode.IP && scanState.core == core
    val progress = if (scanState.mode == ScanMode.IP && scanState.core == core) scanState.progress else 0f
    val progressLabel = if (scanState.mode == ScanMode.IP && scanState.core == core) scanState.progressLabel else "Idle"
    LaunchedEffect(scanState.results, scanState.mode, scanState.core) {
        if (scanState.mode == ScanMode.IP && scanState.core == core) {
            onResultsChange(scanState.results)
        }
    }

    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Button(
                onClick = { onInputChange((if (core == ScannerCore.CLOUDFRONT) CLOUDFRONT_SAMPLE_RANGES else CLOUDFLARE_RANGES).joinToString("\n")) },
                colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF12314C), contentColor = Color.White),
                shape = RoundedCornerShape(20.dp)
            ) {
                Text(
                    if (core == ScannerCore.CLOUDFRONT) "LOAD SAMPLE CFN RANGES" else "LOAD DEFAULT CF RANGES",
                    fontWeight = FontWeight.Bold,
                    fontSize = 15.sp,
                    maxLines = 1
                )
            }
            Button(
                onClick = { filePicker.launch(arrayOf("text/*", "application/json", "application/octet-stream", "*/*")) },
                colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF12314C), contentColor = Color.White),
                shape = RoundedCornerShape(20.dp)
            ) {
                Text(
                    "LOAD FILE",
                    fontWeight = FontWeight.Bold,
                    fontSize = 15.sp,
                    maxLines = 1
                )
            }
        }
        Box {
            OutlinedTextField(
                value = input,
                onValueChange = onInputChange,
                label = { Text("IPs / ranges") },
                modifier = Modifier.fillMaxWidth().height(170.dp),
                textStyle = LocalTextStyle.current.copy(
                    color = Color.White,
                    fontSize = 16.sp,
                    lineHeight = 22.sp
                ),
                colors = OutlinedTextFieldDefaults.colors(
                    focusedTextColor = Color.White,
                    unfocusedTextColor = Color.White,
                    focusedLabelColor = palette.accent,
                    unfocusedLabelColor = Color(0xFFD6E4F0),
                    cursorColor = palette.primary,
                    focusedBorderColor = Color(0xFF8E6BE8),
                    unfocusedBorderColor = Color(0xFF7E57C2),
                    focusedContainerColor = Color(0xFF0F1A24),
                    unfocusedContainerColor = Color(0xFF0F1A24)
                )
            )
            Row(Modifier.align(Alignment.TopEnd).padding(4.dp)) {
                IconButton(onClick = { clipboard.getText()?.let { onInputChange(it.text) } }) {
                    Icon(Icons.Default.ContentPaste, null, tint = palette.primary)
                }
                IconButton(onClick = { onInputChange("") }) {
                    Icon(Icons.Default.Delete, null, tint = Color.Red)
                }
            }
        }
        if (isTesting || isPaused) { LinearProgressIndicator(progress = { progress }, modifier = Modifier.fillMaxWidth(), color = palette.primary); Text(progressLabel, color = Color.White, fontSize = 12.sp) }
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            Button(
                onClick = {
                    if (canResume) {
                        val resumeIntent = buildResumeScanServiceIntent(context)
                        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) context.startForegroundService(resumeIntent) else context.startService(resumeIntent)
                    } else {
                        val baseConfig = settings.toParsedConfig(core)
                        val candidates = expandCandidateText(input)
                        if (candidates.isEmpty()) {
                            Toast.makeText(context, "No valid IPs/ranges found", Toast.LENGTH_SHORT).show()
                            return@Button
                        }
                        onResultsChange(emptyList())
                        val serviceIntent = buildScanServiceIntent(
                            context = context,
                            core = core,
                            mode = ScanMode.IP,
                            payload = input,
                            config = baseConfig
                        )
                        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) context.startForegroundService(serviceIntent) else context.startService(serviceIntent)
                    }
                },
                enabled = !isTesting || canResume,
                colors = ButtonDefaults.buttonColors(
                    containerColor = if (canResume) Color(0xFF1565C0) else palette.primary,
                    contentColor = if (canResume) Color.White else Color.Black
                ),
                modifier = Modifier.weight(1f).height(64.dp),
                shape = RoundedCornerShape(28.dp)
            ) {
                Text(if (canResume) "RESUME" else "START", fontSize = 16.sp, fontWeight = FontWeight.Bold, maxLines = 1, softWrap = false)
            }

            Button(
                onClick = {
                    val action = if (isTesting) ACTION_PAUSE_SCAN else ACTION_STOP_SCAN
                    context.startService(Intent(context, ScanService::class.java).setAction(action))
                },
                colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF8E2424)),
                modifier = Modifier.weight(1f).height(64.dp),
                shape = RoundedCornerShape(28.dp)
            ) {
                Text(if (isTesting) "PAUSE" else "STOP", fontSize = 16.sp, fontWeight = FontWeight.Bold)
            }

            Button(
                onClick = {
                    clipboard.setText(AnnotatedString(results.joinToString("\n") { it.builtConfig }))
                    Toast.makeText(context, "Copied verified configs", Toast.LENGTH_SHORT).show()
                },
                colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF1B5E20)),
                modifier = Modifier.weight(1f).height(64.dp),
                shape = RoundedCornerShape(28.dp)
            ) {
                Text("COPY ALL", fontSize = 13.sp, fontWeight = FontWeight.Bold, maxLines = 2)
            }
        }
        results.forEach { ResultRow(it, core) }
    }
}

@Composable
fun ResultRow(result: DisplayResult, core: ScannerCore) {
    val context = LocalContext.current
    val palette = themeForCore(core)
    val scope = rememberCoroutineScope()
    var speedRunning by remember(result.builtConfig) { mutableStateOf(false) }
    var speedLabel by remember(result.builtConfig) { mutableStateOf<String?>(null) }

    val verdict = resultVerdictLabel(result)
    val bg = when (verdict) {
        "READY" -> Color(0xFF0E7A2D)
        "MAYBE" -> Color(0xFF8A7A1F)
        else -> Color(0xFF4E1C1C)
    }
    val headlineColor = when (verdict) {
        "READY" -> Color(0xFF6FFFD2)
        "MAYBE" -> Color(0xFFFFF59D)
        else -> Color(0xFFFFCDD2)
    }

    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = bg),
        shape = RoundedCornerShape(24.dp)
    ) {
        Column(
            Modifier.padding(14.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            Text(
                result.ip,
                color = Color.White,
                fontWeight = FontWeight.Bold,
                fontSize = 18.sp
            )

            Text(
                resultHeadline(result),
                color = headlineColor,
                fontSize = 11.sp,
                lineHeight = 17.sp
            )

            Text(
                resultMetricsLine(result),
                color = Color.White.copy(alpha = 0.92f),
                fontSize = 11.sp,
                lineHeight = 17.sp
            )

            Text(
                resultRouteLine(result),
                color = Color.White.copy(alpha = 0.95f),
                fontSize = 11.sp,
                lineHeight = 17.sp
            )

            Text(
                "verdict=$verdict | ${result.sourceLabel}",
                color = Color.White.copy(alpha = 0.9f),
                fontSize = 11.sp,
                lineHeight = 17.sp
            )

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(10.dp)
            ) {
                Button(
                    onClick = { openInNetMod(context, result.builtConfig) },
                    modifier = Modifier.weight(1f),
                    shape = RoundedCornerShape(22.dp),
                    colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF2E9C3F), contentColor = Color.White)
                ) {
                    Text("V2Ray→NetMod", maxLines = 1, fontSize = 13.sp)
                }
                Button(
                    onClick = {
                        val cb = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                        cb.setPrimaryClip(ClipData.newPlainText("ip", result.ip))
                        Toast.makeText(context, "IP copied", Toast.LENGTH_SHORT).show()
                    },
                    modifier = Modifier.weight(1f),
                    shape = RoundedCornerShape(22.dp),
                    colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF2D2E36), contentColor = Color.White)
                ) {
                    Text("Copy IP", maxLines = 1, fontSize = 13.sp)
                }
            }

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(10.dp)
            ) {
                Button(
                    onClick = {
                        if (speedRunning) return@Button
                        speedRunning = true
                        speedLabel = "Testing..."
                        scope.launch {
                            speedLabel = runSpeedRetest(result)
                            speedRunning = false
                        }
                    },
                    modifier = Modifier.weight(1f),
                    shape = RoundedCornerShape(22.dp),
                    colors = ButtonDefaults.buttonColors(containerColor = Color(0xFFF6E539), contentColor = Color.Black)
                ) {
                    Text(if (speedRunning) "Testing..." else "Speed Test", maxLines = 1, fontSize = 13.sp)
                }
                Button(
                    onClick = {
                        val cb = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                        cb.setPrimaryClip(ClipData.newPlainText("config", result.builtConfig))
                        Toast.makeText(context, "Config copied", Toast.LENGTH_SHORT).show()
                    },
                    modifier = Modifier.weight(1f),
                    shape = RoundedCornerShape(22.dp),
                    colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF2D2E36), contentColor = Color.White)
                ) {
                    Text("Copy Config", maxLines = 1, fontSize = 13.sp)
                }
            }

            speedLabel?.let {
                Text(
                    it,
                    color = Color.White.copy(alpha = 0.92f),
                    fontSize = 11.sp,
                    lineHeight = 17.sp
                )
            }

            HorizontalDivider(color = Color.White.copy(alpha = 0.16f))

            Text(
                result.builtConfig,
                color = Color(0xFFE2E8F0),
                fontSize = 11.sp,
                lineHeight = 17.sp,
                maxLines = 4,
                overflow = TextOverflow.Ellipsis
            )
        }
    }
}

private fun resultVerdictLabel(result: DisplayResult): String = when {
    result.status.equals("READY", true) -> "READY"
    result.status.equals("MAYBE", true) -> "MAYBE"
    result.tier == ResultTier.VERIFIED || result.confidence >= 85 -> "READY"
    result.confidence >= 55 || result.xrayStatus.startsWith("XRAY_OK") -> "MAYBE"
    else -> "FAILED"
}

private fun extractFastInfo(sourceLabel: String): String {
    val marker = "|fast:"
    val idx = sourceLabel.indexOf(marker)
    return if (idx >= 0) sourceLabel.substring(idx + 1) else "fast:n/a"
}

private fun extractSourceName(sourceLabel: String): String = sourceLabel.substringBefore('|')

private fun extractXrayDelayText(xrayStatus: String): String = when {
    xrayStatus.startsWith("XRAY_OK") -> xrayStatus.removePrefix("XRAY_OK").trim().ifBlank { "ok" }
    else -> xrayStatus
}

private fun resultHeadline(result: DisplayResult): String {
    val verdictPrefix = when (resultVerdictLabel(result)) {
        "READY" -> "XRAY_READY_OK"
        "MAYBE" -> "XRAY_MAYBE"
        else -> "XRAY_FAIL"
    }
    return "$verdictPrefix | s1=${result.stage1LatencyMs}ms | final=${result.finalLatencyMs}ms | xray=${extractXrayDelayText(result.xrayStatus)}"
}

private fun resultMetricsLine(result: DisplayResult): String =
    "${extractFastInfo(result.sourceLabel)} | alive=${result.aliveMs}ms | bytes=${result.bytesReceived} | score=${result.confidence}"

private fun resultRouteLine(result: DisplayResult): String {
    val verdict = resultVerdictLabel(result).lowercase()
    return "IP → FAST → FINAL → XRAY $verdict"
}

private suspend fun runSpeedRetest(result: DisplayResult): String = withContext(Dispatchers.IO) {
    val cfg = parseSingleConfig(result.builtConfig)
        ?: return@withContext "Speed Test: config parse failed"
    val attempts = mutableListOf<Long>()
    repeat(3) {
        val probe = performStage1Probe(cfg, 5000, 900)
        if (probe.success && probe.latencyMs > 0) attempts += probe.latencyMs
    }
    if (attempts.isEmpty()) return@withContext "Speed Test: failed"
    val avg = attempts.average().toLong()
    val jitter = (attempts.maxOrNull() ?: avg) - (attempts.minOrNull() ?: avg)
    val status = when {
        attempts.size == 3 && jitter < 180 -> "stable"
        attempts.size >= 2 -> "usable"
        else -> "weak"
    }
    "Speed Test | avg=${avg}ms | jitter=${jitter}ms | success=${attempts.size}/3 | $status"
}

suspend fun runThreeStageScan(context: Context, core: ScannerCore, baseConfig: ParsedTunnelConfig, candidates: List<String>, progressPrefix: String, onProgress: (Float, String) -> Unit): List<DisplayResult> = coroutineScope {
    val uniqueCandidates = candidates.filter { it.isNotBlank() }.distinct()
    if (uniqueCandidates.isEmpty()) return@coroutineScope emptyList()

    val fastResults = runFastScanStage(baseConfig, uniqueCandidates, core, progressPrefix, onProgress)
    val top100 = selectTopFastCandidates(fastResults, 100)
    ScannerLog.scan("top100 selected count=${top100.size} from total=${fastResults.size}")

    if (top100.isEmpty()) {
        return@coroutineScope fastResults.take(20).map {
            DisplayResult(
                it.ip,
                buildUri(baseConfig.copy(originalHost = it.ip, port = it.bestPort), it.ip, "FAST_FAILED"),
                it.avgLatencyMs,
                0,
                0,
                it.bytesReceived,
                0,
                ResultTier.FAILED,
                it.status,
                "XRAY_SKIPPED",
                baseConfig.label
            )
        }
    }

    val finals = mutableListOf<DisplayResult>()
    val finalSemaphore = Semaphore(if (core == ScannerCore.CLOUDFRONT) 8 else 12)
    var finalDone = 0

    top100.map { probe ->
        async(Dispatchers.IO) {
            finalSemaphore.withPermit {
                val validationBase = baseConfig.copy(originalHost = probe.ip, port = probe.bestPort)
                val validation = performFinalValidation(context, validationBase, probe.ip, core)
                val tier = tierForConfidence(validation.confidence)
                val status = when {
                    validation.success && validation.xraySuccess && validation.confidence >= 85 -> "READY"
                    validation.success && (validation.xraySuccess || validation.confidence >= 55) -> "MAYBE"
                    validation.success -> "SESSION_OK"
                    else -> "FAILED"
                }
                synchronized(finals) {
                    finals.add(
                        DisplayResult(
                            probe.ip,
                            buildUri(validationBase, probe.ip, status),
                            probe.avgLatencyMs,
                            validation.latencyMs,
                            validation.aliveMs,
                            validation.bytesReceived,
                            validation.confidence,
                            tier,
                            status,
                            validation.xrayMessage,
                            "${baseConfig.label}|fast:${probe.bestPort}/${probe.successCount}"
                        )
                    )
                }
                finalDone += 1
                onProgress(0.45f + (finalDone.toFloat() / top100.size.coerceAtLeast(1)) * 0.55f, "$progressPrefix • final $finalDone/${top100.size}")
            }
        }
    }.awaitAll()
    finals.sortedByDescending { it.confidence }
}

private fun candidatePortsForFastScan(basePort: Int): List<Int> =
    if (basePort == 443) listOf(443, 2053, 8443, 2096) else listOf(basePort)

private fun detectFastScanParallelism(core: ScannerCore, totalCandidates: Int): Int {
    val runtime = Runtime.getRuntime()
    val maxMb = runtime.maxMemory() / (1024 * 1024)
    val usedMb = (runtime.totalMemory() - runtime.freeMemory()) / (1024 * 1024)
    val freeHeadroomMb = (maxMb - usedMb).coerceAtLeast(32)
    val base = if (core == ScannerCore.CLOUDFRONT) 56 else 88
    val memoryCap = when {
        freeHeadroomMb < 96 -> 16
        freeHeadroomMb < 160 -> 24
        freeHeadroomMb < 256 -> 40
        else -> base
    }
    val sizeCap = when {
        totalCandidates >= 10000 -> 96
        totalCandidates >= 5000 -> 72
        totalCandidates >= 1000 -> 56
        else -> 32
    }
    return minOf(memoryCap, sizeCap).coerceAtLeast(8)
}

private fun computeFastScanScore(avgLatencyMs: Long, jitterMs: Long, successCount: Int, attempts: Int, bytesReceived: Int, bestPort: Int, alpnMismatch: Boolean): Int {
    var score = 0
    score += successCount * 22
    score += when {
        avgLatencyMs in 1..250 -> 26
        avgLatencyMs in 251..700 -> 18
        avgLatencyMs in 701..1600 -> 10
        avgLatencyMs > 1600 -> 4
        else -> 0
    }
    score += when {
        jitterMs <= 60 -> 16
        jitterMs <= 140 -> 10
        jitterMs <= 260 -> 5
        else -> 0
    }
    score += when {
        bytesReceived > 700 -> 10
        bytesReceived > 200 -> 6
        bytesReceived > 0 -> 3
        else -> 0
    }
    if (bestPort == 443) score += 6
    if (attempts >= 3 && successCount == attempts) score += 8
    if (alpnMismatch) score -= 20
    return score.coerceIn(0, 100)
}

private fun selectTopFastCandidates(results: List<FastScanProbe>, limit: Int = 100): List<FastScanProbe> =
    results
        .filter { it.successCount > 0 }
        .sortedWith(
            compareByDescending<FastScanProbe> { it.score }
                .thenByDescending { it.successCount }
                .thenBy { it.avgLatencyMs }
                .thenBy { it.jitterMs }
        )
        .take(limit)

private suspend fun runFastScanStage(baseConfig: ParsedTunnelConfig, uniqueCandidates: List<String>, core: ScannerCore, progressPrefix: String, onProgress: (Float, String) -> Unit): List<FastScanProbe> = coroutineScope {
    val fastResults = mutableListOf<FastScanProbe>()
    val semaphore = Semaphore(detectFastScanParallelism(core, uniqueCandidates.size))
    val total = uniqueCandidates.size
    var completed = 0

    uniqueCandidates.map { ip ->
        async(Dispatchers.IO) {
            semaphore.withPermit {
                val probe = performFastScanProbe(baseConfig, ip)
                synchronized(fastResults) { fastResults.add(probe) }
                completed += 1
                onProgress((completed.toFloat() / total.coerceAtLeast(1)) * 0.45f, "$progressPrefix • fast $completed/$total")
            }
        }
    }.awaitAll()
    fastResults
}

private fun performFastScanProbe(baseConfig: ParsedTunnelConfig, ip: String): FastScanProbe {
    val portsToTest = candidatePortsForFastScan(baseConfig.port)
    val quickTimeoutMs = 6000
    val quickKeepAliveMs = 450L
    val portResults = mutableListOf<Pair<Int, Stage1Probe>>()
    var alpnMismatch = false

    for (port in portsToTest) {
        val probeConfig = baseConfig.copy(originalHost = ip, port = port)
        ScannerLog.scan("before fastProbe ip=$ip port=$port host=${probeConfig.host} sni=${probeConfig.sni} transport=${probeConfig.transport} tls=${probeConfig.tls}")
        val probe = performStage1Probe(probeConfig, quickTimeoutMs, quickKeepAliveMs)
        ScannerLog.scan("after fastProbe ip=$ip port=$port latency=${probe.latencyMs}ms success=${probe.success} stage=${probe.stage} bytes=${probe.bytesReceived} alive=${probe.aliveMs} err=${probe.error}")
        if (probe.alpnMismatch) alpnMismatch = true
        portResults += port to probe
    }

    val successfulPorts = portResults.filter { it.second.success }
    if (successfulPorts.isEmpty()) {
        return FastScanProbe(
            ip = ip,
            bestPort = baseConfig.port,
            avgLatencyMs = -1,
            jitterMs = 0,
            successCount = 0,
            attempts = portResults.size.coerceAtLeast(1),
            bytesReceived = 0,
            score = 0,
            status = if (alpnMismatch) "ALPN_WRONG" else "FAST_FAILED",
            sampleStage = portResults.firstOrNull()?.second?.stage ?: "FAST_FAILED",
            alpnMismatch = alpnMismatch,
            error = portResults.firstOrNull { !it.second.success }?.second?.error.orEmpty()
        )
    }

    val best = successfulPorts.minByOrNull { it.second.latencyMs } ?: successfulPorts.first()
    val bestPort = best.first
    val attempts = mutableListOf(best.second)
    repeat(2) {
        val retry = performStage1Probe(baseConfig.copy(originalHost = ip, port = bestPort), 4500, 450L)
        if (retry.success) attempts += retry
    }
    val latencies = attempts.map { it.latencyMs }.filter { it > 0 }
    val avgLatency = if (latencies.isEmpty()) best.second.latencyMs else latencies.average().toLong()
    val jitter = if (latencies.size >= 2) (latencies.maxOrNull() ?: avgLatency) - (latencies.minOrNull() ?: avgLatency) else 0L
    val bytes = attempts.maxOfOrNull { it.bytesReceived } ?: best.second.bytesReceived
    val successCount = attempts.count { it.success }
    val status = when {
        successCount >= 3 && jitter < 220 -> "FAST_STABLE"
        successCount >= 2 -> "FAST_OK"
        else -> "FAST_WEAK"
    }
    val score = computeFastScanScore(avgLatency, jitter, successCount, attempts.size, bytes, bestPort, alpnMismatch)

    return FastScanProbe(
        ip = ip,
        bestPort = bestPort,
        avgLatencyMs = avgLatency,
        jitterMs = jitter,
        successCount = successCount,
        attempts = attempts.size,
        bytesReceived = bytes,
        score = score,
        status = status,
        sampleStage = attempts.firstOrNull()?.stage ?: best.second.stage,
        alpnMismatch = alpnMismatch,
        error = attempts.firstOrNull { !it.success }?.error.orEmpty()
    )
}

private fun tierForConfidence(confidence: Int): ResultTier = when {
    confidence >= 90 -> ResultTier.VERIFIED
    confidence >= 75 -> ResultTier.STRONG
    confidence >= 60 -> ResultTier.GOOD
    confidence >= 40 -> ResultTier.BORDERLINE
    else -> ResultTier.FAILED
}

private fun parseConfigLinks(raw: String): List<ParsedTunnelConfig> = raw.lineSequence().mapNotNull { parseSingleConfig(it.trim()) }.toList()

private fun extractConfigCandidates(config: ParsedTunnelConfig): List<String> {
    return listOf(
        config.originalHost.trim()
    ).filter { it.isNotBlank() }.distinct()
}
private fun parseSingleConfig(link: String): ParsedTunnelConfig? {
    if (link.isBlank() || !link.contains("://") || !link.contains("@")) return null
    return try {
        val uri = Uri.parse(link)
        val protocol = uri.scheme?.lowercase() ?: return null
        if (protocol != "vless" && protocol != "trojan") return null
        val userInfo = uri.encodedUserInfo?.let { URLDecoder.decode(it, "UTF-8") } ?: return null
        val host = uri.host ?: return null
        val port = if (uri.port == -1) 443 else uri.port
        val transport = uri.getQueryParameter("type") ?: "ws"
        val qsHost = uri.getQueryParameter("host") ?: ""

        val sni = uri.getQueryParameter("sni") ?: ""

        val path = uri.getQueryParameter("path")
            ?.let { URLDecoder.decode(it, "UTF-8") }
            ?: "/"

        val alpn = uri.getQueryParameter("alpn")
            ?.let { URLDecoder.decode(it, "UTF-8") }
            ?: ""

        val flow = uri.getQueryParameter("flow") ?: ""

        val fp = uri.getQueryParameter("fp") ?: ""

        val sec = uri.getQueryParameter("security")
            ?: if (port == 443) "tls" else "none"
        val allowInsecure = (uri.getQueryParameter("allowInsecure") ?: uri.getQueryParameter("insecure") ?: "0") in setOf("1", "true")
        ParsedTunnelConfig(protocol, userInfo, host, port, qsHost, sni, path, transport, sec.equals("tls", true) || sec.equals("reality", true), alpn, fp, flow, allowInsecure, Uri.decode(uri.fragment ?: host), link)
    } catch (_: Throwable) { null }
}

private fun expandCandidateText(raw: String): List<String> {
    val tokens = extractCandidateTokens(raw)

    return tokens.asSequence().flatMap { trimmed ->
        when {
            trimmed.isBlank() -> emptySequence()
            trimmed.contains("/") -> generateIpsFromCidr(trimmed).asSequence()
            trimmed.contains("-") && trimmed.count { it == '.' } >= 6 -> expandDashRange(trimmed).asSequence()
            else -> sequenceOf(trimmed)
        }
    }.filter(::isProbablyIp).distinct().toList()
}

private fun isProbablyIp(value: String): Boolean = Regex("""^(\d{1,3}\.){3}\d{1,3}$""").matches(value)

private fun generateIpsFromCidr(cidr: String): List<String> = try {
    val parts = cidr.split("/")
    val base = parts[0]
    val prefix = parts[1].toInt().coerceIn(20, 32)
    val count = (1L shl (32 - prefix)).coerceAtMost(4096)
    val baseLong = base.split(".").map { it.toLong() }.let { (it[0] shl 24) or (it[1] shl 16) or (it[2] shl 8) or it[3] }
    (0 until count).map { offset -> val current = baseLong + offset; "${(current shr 24) and 0xFF}.${(current shr 16) and 0xFF}.${(current shr 8) and 0xFF}.${current and 0xFF}" }
} catch (_: Throwable) { emptyList() }

private fun expandDashRange(range: String): List<String> = try {
    val parts = range.split("-")
    val start = ipToLong(parts[0].trim())
    val end = ipToLong(parts[1].trim())
    val safeEnd = minOf(end, start + 4095)
    (start..safeEnd).map(::longToIp)
} catch (_: Throwable) { emptyList() }

private fun ipToLong(ip: String): Long { val p = ip.split('.').map { it.toLong() }; return (p[0] shl 24) or (p[1] shl 16) or (p[2] shl 8) or p[3] }
private fun longToIp(value: Long): String = "${(value shr 24) and 0xFF}.${(value shr 16) and 0xFF}.${(value shr 8) and 0xFF}.${value and 0xFF}"

private suspend fun performFinalValidation(context: Context, baseConfig: ParsedTunnelConfig, candidateIp: String, core: ScannerCore): FinalValidation {
    val finalConfig = baseConfig.copy(originalHost = candidateIp)

    ScannerLog.scan(
        "before finalProbe ip=$candidateIp port=${finalConfig.port} host=${finalConfig.host} sni=${finalConfig.sni} transport=${finalConfig.transport} tls=${finalConfig.tls}"
    )

    val finalProbe = performStage1Probe(
        finalConfig,
        if (core == ScannerCore.CLOUDFRONT) 12000 else 10000,
        if (core == ScannerCore.CLOUDFRONT) 5000 else 3500
    )

    ScannerLog.scan(
        "after finalProbe ip=$candidateIp latency=${finalProbe.latencyMs}ms success=${finalProbe.success} stage=${finalProbe.stage} bytes=${finalProbe.bytesReceived} alive=${finalProbe.aliveMs} err=${finalProbe.error}"
    )

    val xrayResult = if (XrayLiteBridge.isAvailable()) {
        val xrayConfig = XrayLiteBridge.buildXrayConfig(baseConfig, candidateIp)

        ScannerLog.xray(
            "before measureOutboundDelay ip=$candidateIp version=${XrayLiteBridge.versionOrNull()} port=${baseConfig.port} transport=${baseConfig.transport} tls=${baseConfig.tls}"
        )

        val result = XrayLiteBridge.validateOutbound(context, xrayConfig)

        ScannerLog.xray(
            "after measureOutboundDelay ip=$candidateIp delay=${result.delayMs} success=${result.success} available=${result.available} msg=${result.message}"
        )

        result
    } else {
        ScannerLog.xray("xray not available for ip=$candidateIp")
        XrayValidationResult(false, false, -1, "XRAY_NOT_LOADED")
    }

    var score = 0
    if (finalProbe.success) score += 45
    if (finalProbe.aliveMs >= 3000) score += 15
    if (finalProbe.bytesReceived > 0) score += 10
    if (finalProbe.bytesReceived > 16) score += 10
    if (finalProbe.latencyMs in 1..1000) score += (20 - (finalProbe.latencyMs / 60).toInt()).coerceAtLeast(2)
    if (xrayResult.success) score += 20
    if (core == ScannerCore.CLOUDFRONT && finalProbe.aliveMs < 2500) score -= 10
    if (!finalProbe.success) score = 0
    score = score.coerceIn(0, 100)

    val xrayMessage = if (xrayResult.success) "XRAY_OK ${xrayResult.delayMs}ms" else xrayResult.message

    ScannerLog.scan(
        "final verdict ip=$candidateIp finalSuccess=${finalProbe.success} xraySuccess=${xrayResult.success} score=$score xrayStatus=$xrayMessage"
    )

    return FinalValidation(
        finalProbe.success,
        finalProbe.latencyMs,
        finalProbe.aliveMs,
        finalProbe.bytesReceived,
        xrayResult.success,
        xrayResult.delayMs,
        xrayMessage,
        score
    )
}

private fun performStage1Probe(config: ParsedTunnelConfig, stageTimeoutMs: Int, keepAliveMs: Long = 1200): Stage1Probe {
    val socket = Socket(); val start = System.currentTimeMillis()
    return try {
        socket.soTimeout = stageTimeoutMs
        socket.connect(InetSocketAddress(config.originalHost, config.port), stageTimeoutMs)
        val quad = if (config.tls) {
            val ssl = (SSLSocketFactory.getDefault() as SSLSocketFactory).createSocket(socket, config.originalHost, config.port, true) as SSLSocket
            val requestedAlpn = config.alpn.split(',').map { it.trim() }.filter { it.isNotEmpty() }
            ssl.sslParameters = SSLParameters().apply { serverNames = listOf(SNIHostName(config.sni.ifBlank { config.host.ifBlank { config.originalHost } })); if (requestedAlpn.isNotEmpty()) applicationProtocols = requestedAlpn.toTypedArray() }
            ssl.soTimeout = stageTimeoutMs; ssl.startHandshake()
            val negotiated = try { ssl.applicationProtocol ?: "" } catch (_: Throwable) { "" }
            if (requestedAlpn.isNotEmpty() && negotiated.isNotEmpty() && !requestedAlpn.contains(negotiated)) { ssl.close(); return Stage1Probe(config.originalHost, false, -1, "ALPN_MISMATCH", 0, 0, true, "Negotiated $negotiated") }
            Quad(BufferedInputStream(ssl.inputStream), ssl.outputStream, negotiated, ssl as AutoCloseable)
        } else {
            Quad(BufferedInputStream(socket.getInputStream()), socket.getOutputStream(), "", socket as AutoCloseable)
        }
        quad.second.write(buildWebSocketHandshake(config).toByteArray()); quad.second.flush()
        val headerBytes = readHttpHeader(quad.first, stageTimeoutMs)
        val headerText = headerBytes.toString(Charsets.UTF_8)
        if (!headerText.startsWith("HTTP/1.1 101") && !headerText.startsWith("HTTP/1.0 101")) { quad.fourth.close(); return Stage1Probe(config.originalHost, false, -1, "WS_REJECTED", headerBytes.size, System.currentTimeMillis() - start, false, headerText.lineSequence().firstOrNull() ?: "No 101") }
        val pingFrame = byteArrayOf(0x89.toByte(), 0x80.toByte(), 0x11, 0x22, 0x33, 0x44)
        quad.second.write(pingFrame); quad.second.flush()
        var extraBytes = 0; val waitUntil = System.currentTimeMillis() + keepAliveMs
        while (System.currentTimeMillis() < waitUntil) { if (quad.first.available() > 0) extraBytes += quad.first.readNBytes(minOf(quad.first.available(), 1024)).size; delayBlocking(80) }
        quad.fourth.close(); Stage1Probe(config.originalHost, true, System.currentTimeMillis() - start, if (quad.third.isNotBlank()) "WS_OK/${quad.third}" else "WS_OK", headerBytes.size + extraBytes, keepAliveMs)
    } catch (t: Throwable) { try { socket.close() } catch (_: Throwable) {}; Stage1Probe(config.originalHost, false, -1, "FAILED", 0, 0, false, t.message ?: t::class.java.simpleName) }
}

private data class Quad<A, B, C, D>(val first: A, val second: B, val third: C, val fourth: D)

private fun readHttpHeader(input: BufferedInputStream, timeoutMs: Int): ByteArray {
    val buffer = ArrayList<Byte>(); val deadline = System.currentTimeMillis() + timeoutMs
    while (System.currentTimeMillis() < deadline) {
        val value = input.read(); if (value == -1) break; buffer.add(value.toByte())
        val size = buffer.size
        if (size >= 4 && buffer[size - 4] == '\r'.code.toByte() && buffer[size - 3] == '\n'.code.toByte() && buffer[size - 2] == '\r'.code.toByte() && buffer[size - 1] == '\n'.code.toByte()) break
    }
    return buffer.toByteArray()
}

private fun buildWebSocketHandshake(config: ParsedTunnelConfig): String {
    val hostHeader = config.host.ifBlank { config.sni.ifBlank { config.originalHost } }
    val path = config.path.ifBlank { "/" }
    val keyBytes = ByteArray(16).also { SecureRandom().nextBytes(it) }
    val key = android.util.Base64.encodeToString(keyBytes, android.util.Base64.NO_WRAP)
    return buildString {
        append("GET $path HTTP/1.1\r\n")
        append("Host: $hostHeader\r\n")
        append("User-Agent: Mozilla/5.0\r\n")
        append("Upgrade: websocket\r\n")
        append("Connection: Upgrade\r\n")
        append("Sec-WebSocket-Key: $key\r\n")
        append("Sec-WebSocket-Version: 13\r\n\r\n")
    }
}

private fun buildUri(base: ParsedTunnelConfig, candidateIp: String, status: String): String {
    val security = if (base.tls) "tls" else "none"
    val hostValue = base.host
    val query = buildList {
        add("encryption=none")
        if (base.protocol.equals("vless", true) && base.flow.isNotBlank()) add("flow=${urlEnc(base.flow)}")
        add("type=${urlEnc(base.transport)}")
        if (hostValue.isNotBlank()) add("host=${urlEnc(hostValue)}")
        add("path=${urlEnc(base.path.ifBlank { "/" })}")
        add("security=$security")
        if (base.fingerprint.isNotBlank()) add("fp=${urlEnc(base.fingerprint)}")
        if (base.sni.isNotBlank()) add("sni=${urlEnc(base.sni)}")
        if (base.alpn.isNotBlank()) add("alpn=${urlEnc(base.alpn)}")
        add("allowInsecure=${if (base.allowInsecure) 1 else 0}")
    }.joinToString("&")
    return "${base.protocol.lowercase()}://${base.userId}@${candidateIp}:${base.port}?$query#${urlEnc(status + "-" + candidateIp)}"
}

private fun urlEnc(value: String): String = URLEncoder.encode(value, "UTF-8")
private fun openInNetMod(context: Context, config: String) {
    val cb = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
    cb.setPrimaryClip(ClipData.newPlainText("config", config))
    try {
        val launchIntent = context.packageManager.getLaunchIntentForPackage("com.netmod.syna")
        if (launchIntent != null) {
            launchIntent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            context.startActivity(launchIntent)
            Toast.makeText(context, "Config copied • Opening NetMod", Toast.LENGTH_SHORT).show()
            return
        }
        context.startActivity(
            Intent(Intent.ACTION_VIEW, Uri.parse(config)).apply {
                setPackage("com.netmod.syna")
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            }
        )
        Toast.makeText(context, "Config copied • Opening NetMod", Toast.LENGTH_SHORT).show()
    } catch (_: Throwable) {
        Toast.makeText(context, "Config copied • NetMod not installed", Toast.LENGTH_SHORT).show()
    }
}
private fun delayBlocking(ms: Long) { try { Thread.sleep(ms) } catch (_: InterruptedException) {} }
