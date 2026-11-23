package com.example.ui.theme

import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Shapes
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.unit.dp

private val ShieldForgeDarkColorScheme = darkColorScheme(
    primary = ElectricBlue,
    onPrimary = TextPrimary,
    primaryContainer = ElectricBlueContainer,
    onPrimaryContainer = ElectricBlueBright,
    secondary = CyberViolet,
    onSecondary = TextPrimary,
    secondaryContainer = CyberVioletContainer,
    onSecondaryContainer = CyberVioletBright,
    tertiary = CyanPulse,
    onTertiary = ObsidianVoid,
    background = ObsidianVoid,
    onBackground = TextPrimary,
    surface = ObsidianSurface,
    onSurface = TextPrimary,
    surfaceVariant = GraphiteLow,
    onSurfaceVariant = TextSecondary,
    surfaceContainerLowest = ObsidianVoid,
    surfaceContainerLow = GraphiteLow,
    surfaceContainer = GraphiteMid,
    surfaceContainerHigh = GraphiteHigh,
    surfaceContainerHighest = ColorTokens.ElevatedGraphite,
    outline = GraphiteBorder,
    outlineVariant = ColorTokens.SubtleBorder,
    error = CrimsonCritical,
    onError = TextPrimary,
)

private object ColorTokens {
    val ElevatedGraphite = androidx.compose.ui.graphics.Color(0xFF25304C)
    val SubtleBorder = androidx.compose.ui.graphics.Color(0xFF1C253B)
}

val ShieldForgeShapes = Shapes(
    extraSmall = RoundedCornerShape(6.dp),
    small = RoundedCornerShape(10.dp),
    medium = RoundedCornerShape(14.dp),
    large = RoundedCornerShape(18.dp),
    extraLarge = RoundedCornerShape(24.dp),
)

@Composable
fun ShieldForgeTheme(
    content: @Composable () -> Unit,
) {
    MaterialTheme(
        colorScheme = ShieldForgeDarkColorScheme,
        typography = ShieldForgeTypography,
        shapes = ShieldForgeShapes,
        content = content,
    )
}
