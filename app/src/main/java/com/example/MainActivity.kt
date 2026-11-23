package com.example

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import com.example.ui.theme.ShieldForgeTheme
import com.shieldforge.app.ui.navigation.ShieldForgeAppRoot

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            ShieldForgeTheme {
                ShieldForgeAppRoot()
            }
        }
    }
}
