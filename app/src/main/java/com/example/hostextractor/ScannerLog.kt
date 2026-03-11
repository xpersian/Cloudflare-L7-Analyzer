package com.example.hostextractor

import android.util.Log
import org.json.JSONObject

object ScannerLog {

    private const val SCAN = "SCANDBG"
    private const val XRAY = "XRAYDBG"

    fun scan(msg: String) {
        Log.e(SCAN, msg)
    }

    fun scanJson(prefix: String, json: JSONObject) {
        Log.e(SCAN, "$prefix json=${json}")
    }

    fun xray(msg: String) {
        Log.e(XRAY, msg)
    }

    fun xrayJson(prefix: String, json: JSONObject) {
        Log.e(XRAY, "$prefix json=${json}")
    }
}