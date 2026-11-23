package com.shieldforge.app.ui.components

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.example.ui.theme.AmberCaution
import com.example.ui.theme.CrimsonCritical
import com.example.ui.theme.CyberViolet
import com.example.ui.theme.ElectricBlue
import com.example.ui.theme.EmeraldVerified
import com.example.ui.theme.GraphiteBorder
import com.example.ui.theme.GraphiteLow
import com.example.ui.theme.GraphiteMid
import com.example.ui.theme.JetBrainsMonoFamily
import com.example.ui.theme.TextMuted
import com.example.ui.theme.TextPrimary
import com.example.ui.theme.TextSecondary
import com.shieldforge.app.core.common.CompatibilityState
import com.shieldforge.app.core.common.ComponentStatus

@Composable
fun GlassPanelCard(
    modifier: Modifier = Modifier,
    accentColor: Color = GraphiteBorder,
    onClick: (() -> Unit)? = null,
    content: @Composable ColumnScope.() -> Unit,
) {
    val shape = RoundedCornerShape(16.dp)
    val bgBrush = Brush.verticalGradient(
        colors = listOf(
            GraphiteMid.copy(alpha = 0.88f),
            GraphiteLow.copy(alpha = 0.94f),
        ),
    )
    Box(
        modifier = modifier
            .clip(shape)
            .background(bgBrush)
            .border(1.dp, accentColor.copy(alpha = 0.45f), shape)
            .then(if (onClick != null) Modifier.clickable(onClick = onClick) else Modifier)
            .padding(16.dp),
    ) {
        Column(content = content)
    }
}

@Composable
fun TelemetryStatCard(
    label: String,
    value: String,
    icon: ImageVector,
    accent: Color,
    modifier: Modifier = Modifier,
) {
    GlassPanelCard(
        modifier = modifier,
        accentColor = accent.copy(alpha = 0.55f),
    ) {
        Row(
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween,
            modifier = Modifier.fillMaxWidth(),
        ) {
            Box(
                modifier = Modifier
                    .size(34.dp)
                    .clip(RoundedCornerShape(10.dp))
                    .background(accent.copy(alpha = 0.16f)),
                contentAlignment = Alignment.Center,
            ) {
                Icon(
                    imageVector = icon,
                    contentDescription = label,
                    tint = accent,
                    modifier = Modifier.size(18.dp),
                )
            }
            Text(
                text = value,
                style = MaterialTheme.typography.headlineSmall,
                color = TextPrimary,
                fontWeight = FontWeight.Bold,
            )
        }
        Spacer(Modifier.height(10.dp))
        Text(
            text = label,
            style = MaterialTheme.typography.labelMedium,
            color = TextSecondary,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
        )
    }
}

@Composable
fun StatusPill(
    text: String,
    color: Color,
    modifier: Modifier = Modifier,
) {
    Surface(
        modifier = modifier,
        color = color.copy(alpha = 0.14f),
        shape = RoundedCornerShape(8.dp),
        border = BorderStroke(1.dp, color.copy(alpha = 0.4f)),
    ) {
        Row(
            modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Box(
                modifier = Modifier
                    .size(6.dp)
                    .clip(CircleShape)
                    .background(color),
            )
            Spacer(Modifier.width(6.dp))
            Text(
                text = text,
                style = MaterialTheme.typography.labelSmall,
                color = color,
                maxLines = 1,
            )
        }
    }
}

@Composable
fun CompatibilityBadge(state: CompatibilityState) {
    val (label, color) = when (state) {
        CompatibilityState.COMPATIBLE -> "COMPAT" to EmeraldVerified
        CompatibilityState.CAUTION_REFLECTION -> "REFLECT" to AmberCaution
        CompatibilityState.CAUTION_FRAMEWORK_ENTRY -> "ENTRY" to ElectricBlue
        CompatibilityState.CAUTION_JNI -> "JNI" to CyberViolet
        CompatibilityState.REQUIRES_SOURCE_R8 -> "SRC/R8" to AmberCaution
        CompatibilityState.INCOMPATIBLE -> "UNSUPP" to CrimsonCritical
    }
    StatusPill(text = label, color = color)
}

@Composable
fun ComponentStatusBadge(status: ComponentStatus) {
    val (label, color) = when (status) {
        ComponentStatus.INSPECTABLE -> "INSPECT" to TextMuted
        ComponentStatus.SELECTABLE -> "SELECT" to ElectricBlue
        ComponentStatus.TRANSFORMABLE -> "TRANSFORM" to EmeraldVerified
        ComponentStatus.VERIFIED -> "VERIFIED" to EmeraldVerified
        ComponentStatus.UNSUPPORTED_PRECOMPILED -> "NO-PRE" to CrimsonCritical
        ComponentStatus.SOURCE_PROJECT_ONLY -> "SRC-ONLY" to AmberCaution
    }
    StatusPill(text = label, color = color)
}

@Composable
fun MonoCodeText(
    text: String,
    color: Color = TextSecondary,
    modifier: Modifier = Modifier,
    maxLines: Int = 2,
) {
    Text(
        text = text,
        style = MaterialTheme.typography.labelMedium.copy(fontFamily = JetBrainsMonoFamily),
        color = color,
        maxLines = maxLines,
        overflow = TextOverflow.Ellipsis,
        modifier = modifier,
    )
}

@Composable
fun SectionHeader(
    title: String,
    subtitle: String? = null,
    trailing: (@Composable () -> Unit)? = null,
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 4.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.SpaceBetween,
    ) {
        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = title,
                style = MaterialTheme.typography.titleLarge,
                color = TextPrimary,
            )
            if (!subtitle.isNullOrBlank()) {
                Text(
                    text = subtitle,
                    style = MaterialTheme.typography.bodySmall,
                    color = TextSecondary,
                )
            }
        }
        if (trailing != null) {
            Spacer(Modifier.width(8.dp))
            trailing()
        }
    }
}
