package com.security.environment.ui.screens

import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.drawscope.rotate
import androidx.compose.ui.unit.dp
import kotlin.math.cos
import kotlin.math.sin

/**
 * 高科技 Canvas 雷达扫描动效组件
 *
 * 具备同心多层标尺环、极坐标准线、360°旋转余辉扇面扫描、脉冲扩散波与雷达特征反射光点 (Blips)。
 */
@Composable
fun RadarScanView(
    isScanning: Boolean,
    modifier: Modifier = Modifier,
    scanProgress: Float = 0f,
    radarColor: Color = Color(0xFF00E676),
    accentColor: Color = Color(0xFF00B0FF)
) {
    val infiniteTransition = rememberInfiniteTransition(label = "RadarTransition")

    // 1. 旋转光束动画 (0° ~ 360°)
    val rotationAngle by infiniteTransition.animateFloat(
        initialValue = 0f,
        targetValue = 360f,
        animationSpec = infiniteRepeatable(
            animation = tween(durationMillis = 2400, easing = LinearEasing),
            repeatMode = RepeatMode.Restart
        ),
        label = "RadarRotation"
    )

    // 2. 扩散脉冲波纹动画 (0.0 ~ 1.0)
    val pulseProgress by infiniteTransition.animateFloat(
        initialValue = 0f,
        targetValue = 1f,
        animationSpec = infiniteRepeatable(
            animation = tween(durationMillis = 1800, easing = LinearEasing),
            repeatMode = RepeatMode.Restart
        ),
        label = "RadarPulse"
    )

    // 3. 次级反相脉冲波
    val pulseProgressSecondary by infiniteTransition.animateFloat(
        initialValue = 0.5f,
        targetValue = 1.5f,
        animationSpec = infiniteRepeatable(
            animation = tween(durationMillis = 1800, easing = LinearEasing),
            repeatMode = RepeatMode.Restart
        ),
        label = "RadarPulseSecondary"
    )

    // 4. 反射光点微弱呼吸频闪
    val blipAlpha by infiniteTransition.animateFloat(
        initialValue = 0.3f,
        targetValue = 0.95f,
        animationSpec = infiniteRepeatable(
            animation = tween(durationMillis = 900, easing = LinearEasing),
            repeatMode = RepeatMode.Reverse
        ),
        label = "BlipBlink"
    )

    Box(
        modifier = modifier,
        contentAlignment = Alignment.Center
    ) {
        Canvas(modifier = Modifier.fillMaxSize()) {
            val center = Offset(size.width / 2f, size.height / 2f)
            val maxRadius = (size.minDimension / 2f) * 0.92f

            if (maxRadius <= 0f) return@Canvas

            // 1. 绘制 4 层同心雷达刻度圆环
            val ringSteps = listOf(0.25f, 0.5f, 0.75f, 1.0f)
            for (step in ringSteps) {
                drawCircle(
                    color = radarColor.copy(alpha = if (step == 1.0f) 0.35f else 0.18f),
                    radius = maxRadius * step,
                    center = center,
                    style = Stroke(width = if (step == 1.0f) 1.5.dp.toPx() else 1.dp.toPx())
                )
            }

            // 2. 绘制十字刻度线与 45° 辅助极坐标线
            drawLine(
                color = radarColor.copy(alpha = 0.2f),
                start = Offset(center.x - maxRadius, center.y),
                end = Offset(center.x + maxRadius, center.y),
                strokeWidth = 1.dp.toPx()
            )
            drawLine(
                color = radarColor.copy(alpha = 0.2f),
                start = Offset(center.x, center.y - maxRadius),
                end = Offset(center.x, center.y + maxRadius),
                strokeWidth = 1.dp.toPx()
            )

            // 45 度角斜准线
            val cos45 = 0.7071f
            val r45 = maxRadius * 0.95f
            drawLine(
                color = radarColor.copy(alpha = 0.12f),
                start = Offset(center.x - r45 * cos45, center.y - r45 * cos45),
                end = Offset(center.x + r45 * cos45, center.y + r45 * cos45),
                strokeWidth = 0.8.dp.toPx()
            )
            drawLine(
                color = radarColor.copy(alpha = 0.12f),
                start = Offset(center.x - r45 * cos45, center.y + r45 * cos45),
                end = Offset(center.x + r45 * cos45, center.y - r45 * cos45),
                strokeWidth = 0.8.dp.toPx()
            )

            // 中心瞄准原点
            drawCircle(
                color = radarColor.copy(alpha = 0.7f),
                radius = 3.dp.toPx(),
                center = center
            )

            if (isScanning) {
                // 3. 绘制主扩散脉冲光环 (Pulse Wave 1)
                val p1Radius = maxRadius * (pulseProgress % 1f)
                val p1Alpha = (1f - (pulseProgress % 1f)).coerceIn(0f, 0.8f) * 0.5f
                drawCircle(
                    color = radarColor.copy(alpha = p1Alpha),
                    radius = p1Radius,
                    center = center,
                    style = Stroke(width = 2.dp.toPx())
                )

                // 次扩散脉冲光环 (Pulse Wave 2)
                val p2Norm = pulseProgressSecondary % 1f
                val p2Radius = maxRadius * p2Norm
                val p2Alpha = (1f - p2Norm).coerceIn(0f, 0.8f) * 0.35f
                drawCircle(
                    color = accentColor.copy(alpha = p2Alpha),
                    radius = p2Radius,
                    center = center,
                    style = Stroke(width = 1.5.dp.toPx())
                )

                // 4. 绘制旋转扫描渐变扇面 (Sweep Gradient Sector)
                rotate(degrees = rotationAngle, pivot = center) {
                    val sweepBrush = Brush.sweepGradient(
                        0.0f to Color.Transparent,
                        0.70f to Color.Transparent,
                        0.90f to radarColor.copy(alpha = 0.08f),
                        0.98f to radarColor.copy(alpha = 0.25f),
                        1.0f to radarColor.copy(alpha = 0.55f),
                        center = center
                    )
                    drawCircle(
                        brush = sweepBrush,
                        radius = maxRadius,
                        center = center
                    )

                    // 扫描头锋线 (Leading Beam Edge)
                    drawLine(
                        color = radarColor.copy(alpha = 0.95f),
                        start = center,
                        end = Offset(center.x + maxRadius, center.y),
                        strokeWidth = 2.2.dp.toPx(),
                        cap = StrokeCap.Round
                    )
                }

                // 5. 模拟探测到的动态反射光点 (Blips)
                val blipList = listOf(
                    Triple(center.x + maxRadius * 0.42f, center.y - maxRadius * 0.38f, 0.85f),
                    Triple(center.x - maxRadius * 0.52f, center.y + maxRadius * 0.28f, 0.65f),
                    Triple(center.x + maxRadius * 0.22f, center.y + maxRadius * 0.62f, 0.75f),
                    Triple(center.x - maxRadius * 0.30f, center.y - maxRadius * 0.50f, 0.55f)
                )

                for ((bx, by, factor) in blipList) {
                    val currentBlipAlpha = (blipAlpha * factor).coerceIn(0.1f, 1.0f)
                    // 光点光晕
                    drawCircle(
                        color = accentColor.copy(alpha = currentBlipAlpha * 0.4f),
                        radius = 5.dp.toPx(),
                        center = Offset(bx, by)
                    )
                    // 光点核心
                    drawCircle(
                        color = radarColor.copy(alpha = currentBlipAlpha),
                        radius = 2.5.dp.toPx(),
                        center = Offset(bx, by)
                    )
                }
            }
        }
    }
}
