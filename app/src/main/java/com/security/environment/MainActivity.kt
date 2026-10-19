package com.security.environment

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.viewModels
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.ui.Modifier
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import com.security.environment.data.jni.SecurityEngineNative
import com.security.environment.domain.DetectionCoordinator
import com.security.environment.domain.SecurityScorer
import com.security.environment.ui.SecurityDashboardViewModel
import com.security.environment.ui.screens.HomeScreen

class MainActivity : ComponentActivity() {

    private val viewModel: SecurityDashboardViewModel by viewModels {
        object : ViewModelProvider.Factory {
            @Suppress("UNCHECKED_CAST")
            override fun <T : ViewModel> create(modelClass: Class<T>): T {
                val nativeEngine = SecurityEngineNative()
                val coordinator = DetectionCoordinator(nativeEngine = nativeEngine)
                val scorer = SecurityScorer()
                return SecurityDashboardViewModel(
                    coordinator = coordinator,
                    scorer = scorer,
                    engineNative = nativeEngine,
                    autoScan = true,
                    context = applicationContext
                ) as T
            }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            MaterialTheme {
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = MaterialTheme.colorScheme.background
                ) {
                    HomeScreen(viewModel = viewModel)
                }
            }
        }
    }
}
