package com.example.hostextractor

import android.content.Context
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject

data class XrayValidationResult(
    val available: Boolean,
    val success: Boolean,
    val delayMs: Long,
    val message: String
)

object XrayLiteBridge {
    private val candidateClassNames = listOf(
        "libv2ray.Libv2ray",
        "go.libv2ray.Libv2ray"
    )

    private fun resolveBridgeClass(): Class<*>? {
        for (name in candidateClassNames) {
            try {
                return Class.forName(name)
            } catch (_: Throwable) {
            }
        }
        return null
    }

    fun isAvailable(): Boolean = resolveBridgeClass() != null

    fun versionOrNull(): String? {
        val clazz = resolveBridgeClass() ?: return null
        return try {
            clazz.getMethod("checkVersionX").invoke(null)?.toString()
        } catch (_: Throwable) {
            null
        }
    }

    suspend fun validateOutbound(
        context: Context,
        configJson: String,
        probeUrl: String = "https://www.gstatic.com/generate_204"
    ): XrayValidationResult = withContext(Dispatchers.IO) {
        val clazz = resolveBridgeClass()
            ?: return@withContext XrayValidationResult(false, false, -1, "libv2ray.aar not loaded")

        try {
            try {
                clazz.getMethod("initCoreEnv", String::class.java, String::class.java)
                    .invoke(null, context.filesDir.absolutePath, "")
            } catch (_: Throwable) {
            }

            val raw = clazz.getMethod("measureOutboundDelay", String::class.java, String::class.java)
                .invoke(null, configJson, probeUrl)
            val delay = (raw as? Number)?.toLong() ?: -1L
            if (delay >= 0) {
                XrayValidationResult(true, true, delay, "XRAY_OK")
            } else {
                XrayValidationResult(true, false, delay, "XRAY_DELAY_NEGATIVE")
            }
        } catch (t: Throwable) {
            XrayValidationResult(true, false, -1, t.message ?: "XRAY_ERROR")
        }
    }

    fun buildXrayConfig(base: ParsedTunnelConfig, candidateIp: String): String {
        val root = JSONObject()
        root.put("log", JSONObject().put("loglevel", "warning"))
        root.put("inbounds", JSONArray())

        val outbounds = JSONArray()
        outbounds.put(buildPrimaryOutbound(base, candidateIp))
        outbounds.put(JSONObject().put("protocol", "freedom").put("tag", "direct"))
        root.put("outbounds", outbounds)
        return root.toString()
    }

    private fun buildPrimaryOutbound(base: ParsedTunnelConfig, candidateIp: String): JSONObject {
        val outbound = JSONObject()
        outbound.put("tag", "proxy")
        outbound.put("protocol", base.protocol.lowercase())

        outbound.put("settings", when (base.protocol.lowercase()) {
            "trojan" -> buildTrojanSettings(base, candidateIp)
            else -> buildVlessSettings(base, candidateIp)
        })

        outbound.put("streamSettings", buildStreamSettings(base))
        return outbound
    }

    private fun buildVlessSettings(base: ParsedTunnelConfig, candidateIp: String): JSONObject {
        val user = JSONObject()
            .put("id", base.userId)
            .put("encryption", "none")
        if (base.flow.isNotBlank() && base.flow != "none") {
            user.put("flow", base.flow)
        }

        val server = JSONObject()
            .put("address", candidateIp)
            .put("port", base.port)
            .put("users", JSONArray().put(user))

        return JSONObject().put("vnext", JSONArray().put(server))
    }

    private fun buildTrojanSettings(base: ParsedTunnelConfig, candidateIp: String): JSONObject {
        val server = JSONObject()
            .put("address", candidateIp)
            .put("port", base.port)
            .put("password", base.userId)
        return JSONObject().put("servers", JSONArray().put(server))
    }

    private fun buildStreamSettings(base: ParsedTunnelConfig): JSONObject {
        val stream = JSONObject()
            .put("network", base.transport)
            .put("security", if (base.tls) "tls" else "none")

        if (base.transport.equals("ws", ignoreCase = true)) {
            val headers = JSONObject().put("Host", base.host.ifBlank { base.sni.ifBlank { base.originalHost } })
            stream.put("wsSettings", JSONObject().put("path", base.path.ifBlank { "/" }).put("headers", headers))
        }

        if (base.transport.equals("grpc", ignoreCase = true)) {
            stream.put("grpcSettings", JSONObject().put("serviceName", base.path.trim('/')))
        }

        if (base.tls) {
            val tls = JSONObject()
                .put("serverName", base.sni.ifBlank { base.host.ifBlank { base.originalHost } })
                .put("allowInsecure", base.allowInsecure)
            if (base.alpn.isNotBlank()) {
                val alpnArray = JSONArray()
                base.alpn.split(',').map { it.trim() }.filter { it.isNotEmpty() }.forEach { alpnArray.put(it) }
                tls.put("alpn", alpnArray)
            }
            if (base.fingerprint.isNotBlank()) {
                tls.put("fingerprint", base.fingerprint)
            }
            stream.put("tlsSettings", tls)
        }

        return stream
    }
}
