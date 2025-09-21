package com.driveby.nativeapp

import android.annotation.SuppressLint
import android.os.Bundle
import android.webkit.WebSettings
import android.webkit.WebView
import android.webkit.WebViewClient
import androidx.activity.ComponentActivity
import androidx.activity.enableEdgeToEdge
import com.driveby.nativeapp.BuildConfig
import com.driveby.nativeapp.databinding.ActivityMainBinding

class MainActivity : ComponentActivity() {

    private lateinit var binding: ActivityMainBinding

    @SuppressLint("SetJavaScriptEnabled")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        val webView: WebView = binding.webview
        with(webView.settings) {
            javaScriptEnabled = true
            domStorageEnabled = true
            databaseEnabled = true
            cacheMode = WebSettings.LOAD_DEFAULT
            allowContentAccess = true
            allowFileAccess = true
            mediaPlaybackRequiresUserGesture = false
            // Debug only
            @Suppress("KotlinConstantConditions")
            if (BuildConfig.DEBUG) {
                allowUniversalAccessFromFileURLs = true
                allowFileAccessFromFileURLs = true
            }
        }
        webView.webViewClient = WebViewClient()

        // Load local asset HTML
        webView.loadUrl("file:///android_asset/index.html")
    }
}
