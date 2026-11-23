package com.shieldforge.app.ui.settings

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.example.ui.theme.AmberCaution
import com.example.ui.theme.CyberViolet
import com.example.ui.theme.ElectricBlue
import com.example.ui.theme.EmeraldVerified
import com.example.ui.theme.ObsidianVoid
import com.example.ui.theme.TextPrimary
import com.example.ui.theme.TextSecondary
import com.shieldforge.app.forge.registry.ProtectionRegistry
import com.shieldforge.app.ui.components.GlassPanelCard
import com.shieldforge.app.ui.components.SectionHeader
import com.shieldforge.app.ui.components.StatusPill

@Composable
fun SettingsScreen(
    deterministicBuilds: Boolean,
    strictAbort: Boolean,
    onUpdateSettings: (Boolean, Boolean) -> Unit,
) {
    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .background(ObsidianVoid),
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        item {
            SectionHeader(
                title = "Workstation Settings & FORGE-X Registry",
                subtitle = "Ethical hardening guidelines & real engine capabilities",
            )
        }
        item {
            GlassPanelCard(accentColor = ElectricBlue) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text("Deterministic Structural Ordering", style = MaterialTheme.typography.titleSmall, color = TextPrimary)
                        Text("Sorted ZIP & DEX checksums for reproducible outputs", style = MaterialTheme.typography.bodySmall, color = TextSecondary)
                    }
                    Switch(
                        checked = deterministicBuilds,
                        onCheckedChange = { onUpdateSettings(it, strictAbort) },
                    )
                }
                Spacer(Modifier.height(8.dp))
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text("Strict APO Structural Abort", style = MaterialTheme.typography.titleSmall, color = TextPrimary)
                        Text("Halt pipeline automatically on unsupported DEX or invalid AXML", style = MaterialTheme.typography.bodySmall, color = TextSecondary)
                    }
                    Switch(
                        checked = strictAbort,
                        onCheckedChange = { onUpdateSettings(deterministicBuilds, it) },
                    )
                }
            }
        }
        item {
            GlassPanelCard(accentColor = CyberViolet) {
                Text("Authorized Use & Transparency Policy", style = MaterialTheme.typography.titleMedium, color = TextPrimary)
                Spacer(Modifier.height(4.dp))
                Text(
                    text = "ShieldForge is engineered exclusively for legitimate hardening of applications you own or are authorized to modify. Encryption, obfuscation, structural transformation, and integrity verification are reported transparently without claiming absolute irreversibility.",
                    style = MaterialTheme.typography.bodySmall,
                    color = TextSecondary,
                )
            }
        }
        item {
            SectionHeader(title = "7 FORGE-X Engine Specifications")
        }
        items(ProtectionRegistry.engines, key = { it.moduleId.name }) { desc ->
            GlassPanelCard {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                ) {
                    Text(desc.moduleId.displayName, style = MaterialTheme.typography.titleMedium, color = TextPrimary)
                    StatusPill(text = desc.moduleId.codeName, color = ElectricBlue)
                }
                Spacer(Modifier.height(6.dp))
                desc.modeACapabilities.forEach { cap ->
                    Text("• Mode A: $cap", style = MaterialTheme.typography.bodySmall, color = EmeraldVerified)
                }
                desc.modeBCapabilities.forEach { cap ->
                    Text("• Mode B: $cap", style = MaterialTheme.typography.bodySmall, color = ElectricBlue)
                }
                desc.modeALimitations.forEach { lim ->
                    Text("• Limit: $lim", style = MaterialTheme.typography.bodySmall, color = AmberCaution)
                }
            }
        }
    }
}
