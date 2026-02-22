package com.example.hostextractor

import android.app.*
import android.content.*
import android.net.Uri
import android.os.*
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.LayoutDirection
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.app.NotificationCompat
import androidx.core.view.WindowCompat
import kotlinx.coroutines.*
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import java.net.InetSocketAddress
import java.net.Socket
import java.net.URLDecoder
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLParameters
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory
import java.net.URLEncoder

// --- Settings Manager (Based on git.txt) ---
class SettingsManager(context: Context) {
    private val prefs = context.getSharedPreferences("app_settings", Context.MODE_PRIVATE)
    var sni: String get() = prefs.getString("sni", "") ?: ""; set(value) = prefs.edit().putString("sni", value).apply()
    var path: String get() = prefs.getString("path", "") ?: ""; set(value) = prefs.edit().putString("path", value).apply()
    var uuid: String get() = prefs.getString("uuid", "") ?: ""; set(value) = prefs.edit().putString("uuid", value).apply()
    var port: String get() = prefs.getString("port", "443") ?: "443"; set(value) = prefs.edit().putString("port", value).apply()
    var alpn: String get() = prefs.getString("alpn", "h2,http/1.1") ?: "h2,http/1.1"; set(value) = prefs.edit().putString("alpn", value).apply()
    var transport: String get() = prefs.getString("transport", "ws") ?: "ws"; set(value) = prefs.edit().putString("transport", value).apply()
    var flow: String get() = prefs.getString("flow", "none") ?: "none"; set(value) = prefs.edit().putString("flow", value).apply()
    var fingerprint: String get() = prefs.getString("fingerprint", "chrome") ?: "chrome"; set(value) = prefs.edit().putString("fingerprint", value).apply()
    var tls: Boolean get() = prefs.getBoolean("tls", true); set(value) = prefs.edit().putBoolean("tls", value).apply()
    var insecure: Boolean get() = prefs.getBoolean("insecure", false); set(value) = prefs.edit().putBoolean("insecure", value).apply()
    
    fun clearAll() {
        prefs.edit().clear().apply()
    }
}

data class DisplayResult(
    val host: String,
    val latency: Long,
    val jitter: Long,
    val successCount: Int,
    var status: String,
    val workingPorts: List<Int>,
    val isSuccess: Boolean,
    var speed: MutableState<String> = mutableStateOf(""),
    var testProgress: MutableState<Float> = mutableStateOf(0f),
    var alpnError: Boolean = false
)

data class V2Config(val address: String, val port: Int, val path: String, val sni: String, val alpn: String)

object ConnectionState {
    var connectedHost = mutableStateOf<String?>(null)
}

class ScanService : Service() {
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val current = intent?.getIntExtra("CURRENT", 0) ?: 0
        val total = intent?.getIntExtra("TOTAL", 0) ?: 0
        val channelId = "scanner_channel"
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(channelId, "Advanced Scanner", NotificationManager.IMPORTANCE_LOW)
            (getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager).createNotificationChannel(channel)
        }
        val notification = NotificationCompat.Builder(this, channelId)
            .setContentTitle("Scanner Running...")
            .setContentText("Progress: $current / $total")
            .setSmallIcon(android.R.drawable.stat_notify_sync)
            .setProgress(total, current, false).setOngoing(true).build()
        startForeground(101, notification)
        return START_NOT_STICKY
    }
    override fun onBind(intent: Intent?): IBinder? = null
}

val CF_IPV4_RANGES = listOf("104.16.0.0/20", "172.64.0.0/20", "108.162.192.0/20", "162.158.0.0/20", "173.245.48.0/20", "188.114.96.0/20", "190.93.240.0/20", "197.234.240.0/22", "198.41.128.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22")

class MainActivity : ComponentActivity() {
    val activityScope = CoroutineScope(SupervisorJob() + Dispatchers.Main)
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        WindowCompat.setDecorFitsSystemWindows(window, false)
        setContent {
            MaterialTheme(colorScheme = darkColorScheme()) {
                Surface(modifier = Modifier.fillMaxSize(), color = Color(0xFF121212)) {
                    Box(modifier = Modifier.fillMaxSize()) {
                        Column(modifier = Modifier.fillMaxSize()) {
                            Spacer(modifier = Modifier.fillMaxWidth().statusBarsPadding().background(Color.Black))
                            Box(modifier = Modifier.fillMaxSize().navigationBarsPadding()) {
                                MainTabScreen(activityScope)
                            }
                        }
                        Text(
                            text = "v1.4.5",
                            color = Color.Gray.copy(alpha = 0.5f),
                            fontSize = 12.sp,
                            modifier = Modifier.align(Alignment.BottomEnd).padding(bottom = 16.dp, end = 16.dp).navigationBarsPadding()
                        )
                    }
                }
            }
        }
    }
    override fun onDestroy() { super.onDestroy(); activityScope.cancel() }
}

@Composable
fun MainTabScreen(activityScope: CoroutineScope) {
    val context = LocalContext.current
    val settings = remember { SettingsManager(context) }
    var selectedTab by rememberSaveable { mutableIntStateOf(0) }
    var configInput by rememberSaveable { mutableStateOf("") }
    var configResults by remember { mutableStateOf<List<DisplayResult>>(emptyList()) }
    var ipInput by rememberSaveable { mutableStateOf("") }
    var ipResults by remember { mutableStateOf<List<DisplayResult>>(emptyList()) }

    Column {
        TabRow(selectedTabIndex = selectedTab, containerColor = Color(0xFF1E1E1E), contentColor = Color.White) {
            Tab(selected = selectedTab == 0, onClick = { selectedTab = 0 }, text = { Text("INPUT", fontSize = 10.sp) })
            Tab(selected = selectedTab == 1, onClick = { selectedTab = 1 }, text = { Text("CONFIG", fontSize = 10.sp) })
            Tab(selected = selectedTab == 2, onClick = { selectedTab = 2 }, text = { Text("IP SCAN", fontSize = 10.sp) })
            Tab(selected = selectedTab == 3, onClick = { selectedTab = 3 }, text = { Text("HELP", fontSize = 10.sp) })
        }
        when (selectedTab) {
            0 -> InputTab(settings)
            1 -> ConfigScannerTab(settings, configInput, configResults, { configInput = it }, { configResults = it }, activityScope)
            2 -> IpScannerTab(settings, ipInput, ipResults, { ipInput = it }, { ipResults = it }, activityScope)
            3 -> HelpTab()
        }
    }
}

@Composable
fun HelpTab() {
    var isFarsi by rememberSaveable { mutableStateOf(false) }
    Column(Modifier.padding(20.dp).verticalScroll(rememberScrollState())) {
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween, verticalAlignment = Alignment.CenterVertically) {
            Text(if (isFarsi) "راهنمای کارکرد" else "Operation Guide", color = Color.Cyan, fontWeight = FontWeight.Bold, fontSize = 20.sp)
            Button(onClick = { isFarsi = !isFarsi }, colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF555555))) {
                Text(if (isFarsi) "English" else "فارسی", fontSize = 12.sp, color = Color.White)
            }
        }
        Spacer(Modifier.height(16.dp))
        Card(colors = CardDefaults.cardColors(containerColor = Color(0xFF1E1E1E))) {
            Column(Modifier.padding(16.dp)) {
                if (isFarsi) {
                    CompositionLocalProvider(LocalLayoutDirection provides LayoutDirection.Rtl) {
                        Text("• تنظیمات: مشخصات سرور را در تب Input وارد نمایید.\n• تحلیل: تست‌ها تا لایه ۷ و با هندشیک کامل انجام می‌شوند.", color = Color.White, lineHeight = 24.sp, fontSize = 14.sp)
                    }
                } else {
                    Text("• Settings: Set server details in Input.\n• Analysis: L7 Handshake based testing.", color = Color.White, lineHeight = 22.sp, fontSize = 14.sp)
                }
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun InputTab(settings: SettingsManager) {
    var sni by remember { mutableStateOf(settings.sni) }
    var path by remember { mutableStateOf(settings.path) }
    var uuid by remember { mutableStateOf(settings.uuid) }
    var selectedPort by remember { mutableStateOf(settings.port) }
    var selectedAlpn by remember { mutableStateOf(settings.alpn) }
    var selectedTransport by remember { mutableStateOf(settings.transport) }
    var selectedFlow by remember { mutableStateOf(settings.flow) }
    var selectedFingerprint by remember { mutableStateOf(settings.fingerprint) }
    var tlsEnabled by remember { mutableStateOf(settings.tls) }
    var allowInsecure by remember { mutableStateOf(settings.insecure) }
    var isAdvancedExpanded by remember { mutableStateOf(false) }
    var linkInput by remember { mutableStateOf("") }
    val context = LocalContext.current

    Column(Modifier.padding(16.dp).verticalScroll(rememberScrollState())) {
        Text("Smart Config Importer", color = Color.Yellow, fontWeight = FontWeight.Bold, fontSize = 14.sp)
        OutlinedTextField(
            value = linkInput,
            onValueChange = { input ->
                linkInput = input
                try {
                    val uri = Uri.parse(input)
                    if (uri.scheme == "vless" || uri.scheme == "trojan") {
                        uuid = uri.userInfo ?: uuid
                        selectedPort = uri.port.takeIf { it != -1 }?.toString() ?: selectedPort
                        sni = uri.getQueryParameter("sni") ?: uri.getQueryParameter("host") ?: sni
                        path = uri.getQueryParameter("path")?.let { URLDecoder.decode(it, "UTF-8") } ?: path
                        selectedAlpn = uri.getQueryParameter("alpn") ?: selectedAlpn
                        selectedFingerprint = uri.getQueryParameter("fp") ?: selectedFingerprint
                        selectedFlow = uri.getQueryParameter("flow") ?: selectedFlow
                        selectedTransport = uri.getQueryParameter("type") ?: selectedTransport
                        allowInsecure = uri.getQueryParameter("insecure") == "1" || uri.getQueryParameter("allowInsecure") == "1"
                        tlsEnabled = uri.getQueryParameter("security") == "tls"
                        Toast.makeText(context, "Link Data Extracted!", Toast.LENGTH_SHORT).show()
                    }
                } catch (e: Exception) {}
            },
            label = { Text("Paste VLESS/Trojan Link") },
            modifier = Modifier.fillMaxWidth(),
            maxLines = 1
        )
        
        Spacer(Modifier.height(16.dp))
        Text("Main Configuration", color = Color.Cyan, fontWeight = FontWeight.Bold, fontSize = 16.sp)
        Spacer(Modifier.height(8.dp))
        OutlinedTextField(value = sni, onValueChange = { sni = it }, label = { Text("SNI") }, modifier = Modifier.fillMaxWidth())
        OutlinedTextField(value = path, onValueChange = { path = it }, label = { Text("Path") }, modifier = Modifier.fillMaxWidth())
        OutlinedTextField(value = uuid, onValueChange = { uuid = it }, label = { Text("UUID") }, modifier = Modifier.fillMaxWidth())
        
        Spacer(Modifier.height(12.dp))
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            var portExp by remember { mutableStateOf(false) }
            ExposedDropdownMenuBox(expanded = portExp, onExpandedChange = { portExp = !portExp }, modifier = Modifier.weight(1f)) {
                OutlinedTextField(value = selectedPort, onValueChange = {}, readOnly = true, label = { Text("Port") }, modifier = Modifier.menuAnchor(), trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expanded = portExp) })
                ExposedDropdownMenu(expanded = portExp, onDismissRequest = { portExp = false }) {
                    listOf("443", "8443", "2053", "2083", "2096").forEach { p -> DropdownMenuItem(text = { Text(p) }, onClick = { selectedPort = p; portExp = false }) }
                }
            }
            var flowExp by remember { mutableStateOf(false) }
            ExposedDropdownMenuBox(expanded = flowExp, onExpandedChange = { flowExp = !flowExp }, modifier = Modifier.weight(1f)) {
                OutlinedTextField(value = selectedFlow, onValueChange = {}, readOnly = true, label = { Text("Flow") }, modifier = Modifier.menuAnchor(), trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expanded = flowExp) })
                ExposedDropdownMenu(expanded = flowExp, onDismissRequest = { flowExp = false }) {
                    listOf("none", "xtls-rprx-vision", "xtls-rprx-vision-tls").forEach { f -> DropdownMenuItem(text = { Text(f) }, onClick = { selectedFlow = f; flowExp = false }) }
                }
            }
        }

        Spacer(Modifier.height(16.dp))
        Row(
            Modifier.fillMaxWidth().clickable { isAdvancedExpanded = !isAdvancedExpanded }.padding(vertical = 8.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Icon(if (isAdvancedExpanded) Icons.Default.ExpandLess else Icons.Default.ExpandMore, null, tint = Color.Yellow)
            Spacer(Modifier.width(8.dp))
            Text("Advanced Settings", color = Color.Yellow, fontWeight = FontWeight.Bold)
        }

        if (isAdvancedExpanded) {
            Column(Modifier.fillMaxWidth().padding(start = 8.dp).border(1.dp, Color.DarkGray).padding(12.dp)) {
                Text("Transport protocol", color = Color.Gray, fontSize = 12.sp)
                var transportExp by remember { mutableStateOf(false) }
                ExposedDropdownMenuBox(expanded = transportExp, onExpandedChange = { transportExp = !transportExp }) {
                    OutlinedTextField(value = selectedTransport, onValueChange = {}, readOnly = true, modifier = Modifier.fillMaxWidth().menuAnchor(), trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expanded = transportExp) })
                    ExposedDropdownMenu(expanded = transportExp, onDismissRequest = { transportExp = false }) {
                        listOf("ws", "grpc", "tcp").forEach { t -> DropdownMenuItem(text = { Text(t) }, onClick = { selectedTransport = t; transportExp = false }) }
                    }
                }

                Spacer(Modifier.height(12.dp))
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text("TLS", Modifier.weight(1f), color = Color.White)
                    Switch(checked = tlsEnabled, onCheckedChange = { tlsEnabled = it })
                }

                if (tlsEnabled) {
                    Spacer(Modifier.height(8.dp))
                    Text("Fingerprint", color = Color.Gray, fontSize = 12.sp)
                    var fpExp by remember { mutableStateOf(false) }
                    ExposedDropdownMenuBox(expanded = fpExp, onExpandedChange = { fpExp = !fpExp }) {
                        OutlinedTextField(value = selectedFingerprint, onValueChange = {}, readOnly = true, modifier = Modifier.fillMaxWidth().menuAnchor(), trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expanded = fpExp) })
                        ExposedDropdownMenu(expanded = fpExp, onDismissRequest = { fpExp = false }) {
                            listOf("chrome", "firefox", "safari", "edge", "randomized").forEach { fp -> DropdownMenuItem(text = { Text(fp) }, onClick = { selectedFingerprint = fp; fpExp = false }) }
                        }
                    }

                    Spacer(Modifier.height(8.dp))
                    Text("ALPN", color = Color.Gray, fontSize = 12.sp)
                    var alpnExp by remember { mutableStateOf(false) }
                    ExposedDropdownMenuBox(expanded = alpnExp, onExpandedChange = { alpnExp = !alpnExp }) {
                        OutlinedTextField(value = selectedAlpn, onValueChange = {}, readOnly = true, modifier = Modifier.fillMaxWidth().menuAnchor(), trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expanded = alpnExp) })
                        ExposedDropdownMenu(expanded = alpnExp, onDismissRequest = { alpnExp = false }) {
                            listOf("h2,http/1.1", "h2", "http/1.1", "h3").forEach { a -> DropdownMenuItem(text = { Text(a) }, onClick = { selectedAlpn = a; alpnExp = false }) }
                        }
                    }

                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text("Allow Insecure", Modifier.weight(1f), color = Color.White)
                        Switch(checked = allowInsecure, onCheckedChange = { allowInsecure = it })
                    }
                }
            }
        }

        Spacer(Modifier.height(24.dp))
        Button(onClick = { 
            settings.sni = sni.trim(); settings.path = path.trim(); settings.uuid = uuid.trim()
            settings.port = selectedPort; settings.alpn = selectedAlpn
            settings.transport = selectedTransport; settings.flow = selectedFlow
            settings.fingerprint = selectedFingerprint; settings.tls = tlsEnabled
            settings.insecure = allowInsecure
            Toast.makeText(context, "Settings Saved!", Toast.LENGTH_SHORT).show()
        }, modifier = Modifier.fillMaxWidth(), colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF4CAF50))) { Text("SAVE SETTINGS") }

        Spacer(Modifier.height(8.dp))
        Button(onClick = { 
            settings.clearAll()
            sni = ""; path = ""; uuid = ""; selectedPort = "443"; selectedAlpn = "h2,http/1.1"
            selectedTransport = "ws"; selectedFlow = "none"; selectedFingerprint = "chrome"
            tlsEnabled = true; allowInsecure = false; linkInput = ""
            Toast.makeText(context, "All Settings Deleted!", Toast.LENGTH_SHORT).show()
        }, modifier = Modifier.fillMaxWidth(), colors = ButtonDefaults.buttonColors(containerColor = Color.Red)) { Text("DELETE ALL SETTINGS") }
    }
}

@Composable
fun ConfigScannerTab(settings: SettingsManager, input: String, results: List<DisplayResult>, onInputChange: (String) -> Unit, onResultsChange: (List<DisplayResult>) -> Unit, activityScope: CoroutineScope) {
    val context = LocalContext.current; val clipboard = LocalClipboardManager.current
    var isTesting by remember { mutableStateOf(false) }
    var progress by remember { mutableFloatStateOf(0f) }
    var scanJob by remember { mutableStateOf<Job?>(null) }

    Column(Modifier.padding(16.dp).verticalScroll(rememberScrollState())) {
        Box {
            OutlinedTextField(value = input, onValueChange = onInputChange, label = { Text("Configs...") }, modifier = Modifier.fillMaxWidth().height(140.dp))
            Row(Modifier.align(Alignment.TopEnd).padding(4.dp)) {
                IconButton(onClick = { clipboard.getText()?.let { onInputChange(it.text) } }) { Icon(Icons.Default.ContentPaste, null, tint = Color.Cyan) }
                IconButton(onClick = { onInputChange("") }) { Icon(Icons.Default.Delete, null, tint = Color.Red) }
            }
        }
        if (isTesting) LinearProgressIndicator(progress = { progress }, modifier = Modifier.fillMaxWidth().padding(vertical = 8.dp), color = Color.Cyan)

        Row(Modifier.fillMaxWidth().padding(vertical = 12.dp), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            if (!isTesting) {
                Button(onClick = {
                    val addresses = extractAddressesOnly(input)
                    if (addresses.isEmpty() || settings.sni.isBlank()) return@Button
                    isTesting = true; onResultsChange(emptyList())
                    scanJob = activityScope.launch(Dispatchers.Default) { runUnifiedParallelScan(context, addresses, settings, { temp, prog -> onResultsChange(temp); progress = prog }, { isTesting = false }) }
                }, modifier = Modifier.weight(1f)) { Text("START") }
            } else {
                Button(onClick = { scanJob?.cancel(); isTesting = false; context.stopService(Intent(context, ScanService::class.java)) }, modifier = Modifier.weight(1f), colors = ButtonDefaults.buttonColors(containerColor = Color.Red)) { Text("STOP") }
            }
            Button(onClick = { val greens = results.filter { it.isSuccess && !it.alpnError }.joinToString("\n") { buildVlessConfig(it, settings) }; clipboard.setText(AnnotatedString(greens)) }, modifier = Modifier.weight(1f), colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF2E7D32))) { Text("COPY ALL") }
        }

        if (!isTesting && results.isNotEmpty()) {
            Spacer(Modifier.height(8.dp))
            Button(
                onClick = { results.filter { it.isSuccess }.forEach { activityScope.launch { runQualityTest(it, settings) } } },
                modifier = Modifier.fillMaxWidth(),
                colors = ButtonDefaults.buttonColors(containerColor = Color.Yellow, contentColor = Color.Black)
            ) { Text("SPEED TEST ALL") }
        }

        results.forEach { ResultRow(it, settings, activityScope) }
        Spacer(Modifier.height(40.dp))
    }
}

@Composable
fun IpScannerTab(settings: SettingsManager, input: String, results: List<DisplayResult>, onInputChange: (String) -> Unit, onResultsChange: (List<DisplayResult>) -> Unit, activityScope: CoroutineScope) {
    val context = LocalContext.current; val clipboard = LocalClipboardManager.current
    var isTesting by remember { mutableStateOf(false) }
    var progress by remember { mutableFloatStateOf(0f) }
    var scanJob by remember { mutableStateOf<Job?>(null) }

    Column(Modifier.padding(16.dp).verticalScroll(rememberScrollState())) {
        Button(onClick = { onInputChange(CF_IPV4_RANGES.joinToString("\n")) }, modifier = Modifier.fillMaxWidth()) { Text("Load Default CF Ranges") }
        Box {
            OutlinedTextField(value = input, onValueChange = onInputChange, label = { Text("IPs...") }, modifier = Modifier.fillMaxWidth().height(140.dp))
            Row(Modifier.align(Alignment.TopEnd).padding(4.dp)) {
                IconButton(onClick = { clipboard.getText()?.let { onInputChange(it.text) } }) { Icon(Icons.Default.ContentPaste, null, tint = Color.Cyan) }
                IconButton(onClick = { onInputChange("") }) { Icon(Icons.Default.Delete, null, tint = Color.Red) }
            }
        }
        if (isTesting) LinearProgressIndicator(progress = { progress }, modifier = Modifier.fillMaxWidth().padding(vertical = 8.dp), color = Color.Cyan)

        Row(Modifier.fillMaxWidth().padding(vertical = 8.dp), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            if (!isTesting) {
                Button(onClick = {
                    if (settings.sni.isBlank()) return@Button
                    isTesting = true; onResultsChange(emptyList())
                    scanJob = activityScope.launch(Dispatchers.Default) {
                        val ips = input.lines().filter { it.isNotBlank() }.flatMap { if (it.contains("/")) generateFullIpsFromRange(it.trim()) else listOf(it.trim()) }.distinct()
                        runUnifiedParallelScan(context, ips, settings, { temp, prog -> onResultsChange(temp); progress = prog }, { isTesting = false })
                    }
                }, modifier = Modifier.weight(1f)) { Text("SCAN IPs") }
            } else {
                Button(onClick = { scanJob?.cancel(); isTesting = false; context.stopService(Intent(context, ScanService::class.java)) }, modifier = Modifier.weight(1f), colors = ButtonDefaults.buttonColors(containerColor = Color.Red)) { Text("STOP") }
            }
            Button(onClick = { val greens = results.filter { it.isSuccess && !it.alpnError }.joinToString("\n") { buildVlessConfig(it, settings) }; clipboard.setText(AnnotatedString(greens)) }, modifier = Modifier.weight(1f), colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF2E7D32))) { Text("COPY ALL") }
        }

        if (!isTesting && results.isNotEmpty()) {
            Spacer(Modifier.height(8.dp))
            Button(
                onClick = { results.filter { it.isSuccess }.forEach { activityScope.launch { runQualityTest(it, settings) } } },
                modifier = Modifier.fillMaxWidth(),
                colors = ButtonDefaults.buttonColors(containerColor = Color.Yellow, contentColor = Color.Black)
            ) { Text("SPEED TEST ALL") }
        }

        results.forEach { ResultRow(it, settings, activityScope) }
        Spacer(Modifier.height(40.dp))
    }
}

suspend fun CoroutineScope.runUnifiedParallelScan(context: Context, targets: List<String>, settings: SettingsManager, onUpdate: (List<DisplayResult>, Float) -> Unit, onComplete: () -> Unit) {
    val totalCount = targets.size; if (totalCount == 0) return
    val serviceIntent = Intent(context, ScanService::class.java).apply { putExtra("TOTAL", totalCount) }
    context.startForegroundService(serviceIntent)
    val temp = mutableListOf<DisplayResult>(); val semaphore = Semaphore(100); var completedCount = 0; var lastUiUpdateTime = 0L
    targets.forEach { ip ->
        if (!isActive) return@runUnifiedParallelScan
        launch {
            try {
                semaphore.withPermit {
                    val workingPorts = mutableListOf<Int>(); val portLatencies = mutableMapOf<Int, Long>()
                    val testPort = settings.port.toIntOrNull() ?: 443
                    val portsToTest = if (testPort == 443) listOf(443, 2053, 8443, 2096) else listOf(testPort)
                    
                    var detectedAlpnError = false
                    for (p in portsToTest) {
                        val handshakeRes = withContext(Dispatchers.IO) { performFullHandshake(V2Config(ip, p, settings.path, settings.sni, settings.alpn)) }
                        if (handshakeRes.latency > 0) { workingPorts.add(p); portLatencies[p] = handshakeRes.latency
                        } else if (handshakeRes.alpnError) { detectedAlpnError = true }
                    }
                    if (workingPorts.isNotEmpty()) {
                        val bestPort = portLatencies.minByOrNull { it.value }?.key ?: workingPorts[0]
                        val lats = mutableListOf<Long>().apply { add(portLatencies[bestPort]!!) }
                        for (i in 1..2) { delay(50); val l = withContext(Dispatchers.IO) { performFullHandshake(V2Config(ip, bestPort, settings.path, settings.sni, settings.alpn)).latency }; if (l > 0) lats.add(l) }
                        val finalLatency = lats.average().toLong()
                        val finalJitter = (lats.maxOrNull() ?: 0L) - (lats.minOrNull() ?: 0L)
                        val status = when { lats.size >= 3 && finalJitter < 200 -> "STABLE"; else -> "UNSTABLE" }
                        synchronized(temp) { temp.add(DisplayResult(ip, finalLatency, finalJitter, lats.size, status, workingPorts, true)) }
                    } else synchronized(temp) { temp.add(DisplayResult(ip, 0, 0, 0, if(detectedAlpnError) "ALPN WRONG" else "FAILED", emptyList(), false, alpnError = detectedAlpnError)) }
                }
            } catch (e: Exception) {}
            completedCount++
            val now = System.currentTimeMillis()
            if (now - lastUiUpdateTime > 400 || completedCount == totalCount) {
                lastUiUpdateTime = now
                val sorted = synchronized(temp) { temp.toList().sortedWith(compareByDescending<DisplayResult> { it.isSuccess }.thenBy { if (it.isSuccess) it.latency else Long.MAX_VALUE }) }
                onUpdate(sorted, completedCount.toFloat() / totalCount)
            }
            if (completedCount == totalCount) {
                val top10 = synchronized(temp) { temp.filter { it.isSuccess }.take(10) }
                top10.forEach { launch { runQualityTest(it, settings) } }
                onComplete(); context.stopService(serviceIntent)
            }
        }
    }
}

data class HandshakeResult(val latency: Long, val alpnError: Boolean)

private fun performFullHandshake(config: V2Config): HandshakeResult {
    val socket = Socket()
    return try {
        val start = System.currentTimeMillis()
        socket.connect(InetSocketAddress(config.address, config.port), 7000)
        val ssl = (SSLSocketFactory.getDefault() as SSLSocketFactory).createSocket(socket, config.address, config.port, true) as SSLSocket
        val userAlpns = config.alpn.split(",").map { it.trim() }
        ssl.sslParameters = SSLParameters().apply { serverNames = listOf(SNIHostName(config.sni)); applicationProtocols = userAlpns.toTypedArray() }
        ssl.soTimeout = 7000; ssl.startHandshake()
        val negotiatedAlpn = try { ssl.applicationProtocol } catch (e: Throwable) { "" }
        if (config.alpn.isNotEmpty() && negotiatedAlpn.isNotEmpty() && !userAlpns.contains(negotiatedAlpn)) { ssl.close(); return HandshakeResult(-1L, true) }
        val req = "GET ${config.path} HTTP/1.1\r\nHost: ${config.sni}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"
        ssl.outputStream.write(req.toByteArray())
        val isOk = ssl.inputStream.bufferedReader().readLine()?.contains("101") == true
        ssl.close()
        if (isOk) HandshakeResult(System.currentTimeMillis() - start, false) else HandshakeResult(-1L, false)
    } catch (e: Exception) { HandshakeResult(-1L, false) } finally { try { socket.close() } catch (e: Exception) {} }
}

suspend fun runQualityTest(res: DisplayResult, settings: SettingsManager) {
    if (res.alpnError) return
    res.speed.value = "Testing..."; res.testProgress.value = 0.01f
    val port = res.workingPorts.firstOrNull() ?: 443; val allLatencies = mutableListOf<Long>()
    withContext(Dispatchers.Default) {
        for (i in 1..10) {
            val l = withContext(Dispatchers.IO) { performFullHandshake(V2Config(res.host, port, settings.path, settings.sni, settings.alpn)).latency }
            if (l > 0) allLatencies.add(l); res.testProgress.value = i.toFloat() / 10; delay(100)
        }
    }
    if (allLatencies.isEmpty()) res.speed.value = "LOSS" else {
        val avg = allLatencies.average().toInt(); val jitter = (allLatencies.maxOrNull() ?: 0L) - (allLatencies.minOrNull() ?: 0L)
        res.speed.value = "AVG: ${avg}ms | J: $jitter"
    }
    delay(1000); res.testProgress.value = 0f
}

@Composable
fun ResultRow(res: DisplayResult, settings: SettingsManager, activityScope: CoroutineScope) {
    val context = LocalContext.current; val clipboard = LocalClipboardManager.current; val isThisActive = ConnectionState.connectedHost.value == res.host
    Card(Modifier.fillMaxWidth().padding(vertical = 4.dp), colors = CardDefaults.cardColors(containerColor = if (isThisActive) Color(0xFF004D40) else if (res.isSuccess) Color(0xFF1E1E1E) else Color(0xFFB71C1C).copy(alpha = 0.1f))) {
        Column {
            Row(Modifier.padding(12.dp), verticalAlignment = Alignment.CenterVertically) {
                Column(Modifier.weight(1f)) {
                    Text(res.host, fontWeight = FontWeight.Bold, color = Color.White)
                    Text(if (res.isSuccess) "${res.status} | ${res.latency}ms" else if (res.alpnError) "ALPN WRONG" else "FAILED", color = if(res.isSuccess) Color.Cyan else Color.Gray, fontSize = 11.sp)
                    if (res.speed.value.isNotEmpty()) Text(res.speed.value, color = Color.Yellow, fontSize = 10.sp)
                }
                if (res.isSuccess && !res.alpnError) {
                    IconButton(onClick = { activityScope.launch { runQualityTest(res, settings) } }) { Icon(Icons.Default.Speed, null, tint = Color.Yellow, modifier = Modifier.size(20.dp)) }
                    Button(onClick = { if (isThisActive) ConnectionState.connectedHost.value = null else { ConnectionState.connectedHost.value = res.host; copyAndOpenNetMod(context, buildVlessConfig(res, settings)) } }, colors = ButtonDefaults.buttonColors(containerColor = if (isThisActive) Color.Red else Color(0xFF2E7D32)), contentPadding = PaddingValues(horizontal = 8.dp)) { Text(if(isThisActive) "STOP" else "CONN", fontSize = 10.sp) }
                    IconButton(onClick = { clipboard.setText(AnnotatedString(buildVlessConfig(res, settings))); Toast.makeText(context, "Copied!", Toast.LENGTH_SHORT).show() }) { Icon(Icons.Default.ContentCopy, null, tint = Color.White, modifier = Modifier.size(20.dp)) }
                }
            }
            if (res.testProgress.value > 0f) LinearProgressIndicator(progress = { res.testProgress.value }, modifier = Modifier.fillMaxWidth().height(2.dp), color = Color.Yellow, trackColor = Color.Transparent)
        }
    }
}

private fun buildVlessConfig(res: DisplayResult, settings: SettingsManager): String { 
    val p = res.workingPorts.firstOrNull() ?: settings.port.toIntOrNull() ?: 443
    val tlsStr = if(settings.tls) "tls" else "none"
    val insecureStr = if(settings.insecure) "1" else "0"
    return "vless://${settings.uuid}@${res.host}:$p?encryption=none&flow=${settings.flow}&type=${settings.transport}&host=${settings.sni}&headerType=none&path=${URLEncoder.encode(settings.path, "UTF-8")}&security=$tlsStr&fp=${settings.fingerprint}&sni=${settings.sni}&alpn=${URLEncoder.encode(settings.alpn, "UTF-8")}&allowInsecure=$insecureStr#${res.status}-${res.host}"
}
private fun copyAndOpenNetMod(context: Context, config: String) { val cb = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager; cb.setPrimaryClip(ClipData.newPlainText("V2", config));
    try { context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(config)).apply { setPackage("com.netmod.syna"); addFlags(Intent.FLAG_ACTIVITY_NEW_TASK) }) } catch (e: Exception) { context.packageManager.getLaunchIntentForPackage("com.netmod.syna")?.let { context.startActivity(it) } } }
private fun generateFullIpsFromRange(cidr: String): List<String> = try { val pts = cidr.split("/"); val base = pts[0]; val pref = pts[1].toInt().coerceIn(20, 32); val num = (1L shl (32 - pref)).coerceAtMost(2000); val ipL = base.split(".").map { it.toLong() }.let { (it[0] shl 24) or (it[1] shl 16) or (it[2] shl 8) or it[3] }; (0 until num).map { i -> val c = ipL + i; "${(c shr 24) and 0xFF}.${(c shr 16) and 0xFF}.${(c shr 8) and 0xFF}.${c and 0xFF}" } } catch (e: Exception) { listOf(cidr) }
private fun extractAddressesOnly(input: String) = Regex("""(?:vless|trojan)://[^@]*@([^:/?#\s]+)""").findAll(input).map { it.groupValues[1] }.toList().distinct()