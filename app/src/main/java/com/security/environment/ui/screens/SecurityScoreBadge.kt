package com.security.environment.ui.screens

import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.FastOutSlowInEasing
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.tween
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.security.environment.data.model.SecurityAssessment
import com.security.environment.data.model.SecurityLevel

@Composable
fun SecurityScoreBadge(
    score: Int,
    level: SecurityLevel,
    isScanning: Boolean,
    scanProgress: Float,
    assessment: SecurityAssessment?,
    isDirectSyscallSupported: Boolean,
    modifier: Modifier = Modifier
) {
    // 动态色彩映射
    val primaryColor = when (level) {
        SecurityLevel.SAFE -> Color(0xFF2E7D32)
        SecurityLevel.WARNING -> Color(0xFFE65100)
        SecurityLevel.DANGEROUS -> Color(0xFFC62828)
    }

    val secondaryColor = when (level) {
        SecurityLevel.SAFE -> Color(0xFF81C784)
        SecurityLevel.WARNING -> Color(0xFFFFB74D)
        SecurityLevel.DANGEROUS -> Color(0xFFE57373)
    }

    val cardBg = when (level) {
        SecurityLevel.SAFE -> Color(0xFFF1F8E9)
        SecurityLevel.WARNING -> Color(0xFFFFF8E1)
        SecurityLevel.DANGEROUS -> Color(0xFFFFEBEE)
    }

    val animatedScoreProgress by animateFloatAsState(
        targetValue = if (isScanning) scanProgress else (score / 100f),
        animationSpec = tween(durationMillis = 600, easing = FastOutSlowInEasing),
        label = "scoreProgress"
    )

    val animatedPrimaryColor by animateColorAsState(
        targetValue = primaryColor,
        animationSpec = tween(durationMillis = 400),
        label = "primaryColor"
    )

    Card(
        modifier = modifier.fillMaxWidth(),
        shape = RoundedCornerShape(20.dp),
        colors = CardDefaults.cardColors(containerColor = cardBg),
        elevation = CardDefaults.cardElevation(defaultElevation = 2.dp)
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(20.dp)
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                // 左侧：等级、统计、状态提示
                Column(modifier = Modifier.weight(1f)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Box(
                            modifier = Modifier
                                .size(10.dp)
                                .clip(CircleShape)
                                .background(animatedPrimaryColor)
                        )
                        Spacer(modifier = Modifier.width(8.dp))
                        Text(
                            text = when (level) {
                                SecurityLevel.SAFE -> "环境状态: 极度纯净 (SAFE)"
                                SecurityLevel.WARNING -> "环境状态: 存在隐患 (WARNING)"
                                SecurityLevel.DANGEROUS -> "环境状态: 严重风险 (DANGEROUS)"
                            },
                            fontWeight = FontWeight.Bold,
                            color = animatedPrimaryColor,
                            fontSize = 15.sp
                        )
                    }

                    Spacer(modifier = Modifier.height(8.dp))

                    Text(
                        text = assessment?.summary ?: if (isScanning) "正在进行全栈深度内核对抗检测..." else "环境安全防护评估中",
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurface,
                        fontWeight = FontWeight.Normal,
                        lineHeight = 20.sp
                    )

                    Spacer(modifier = Modifier.height(10.dp))

                    // 统计指示胶囊
                    Row(
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        CountPill(label = "高危", count = assessment?.dangerCount ?: 0, color = Color(0xFFC62828))
                        CountPill(label = "警告", count = assessment?.warnCount ?: 0, color = Color(0xFFE65100))
                        CountPill(label = "通过", count = assessment?.passCount ?: 0, color = Color(0xFF2E7D32))
                    }
                }

                Spacer(modifier = Modifier.width(16.dp))

                // 右侧：圆形分数仪表盘
                Box(
                    modifier = Modifier.size(96.dp),
                    contentAlignment = Alignment.Center
                ) {
                    // 背景圆环
                    CircularProgressIndicator(
                        progress = { 1.0f },
                        modifier = Modifier.size(96.dp),
                        color = animatedPrimaryColor.copy(alpha = 0.15f),
                        strokeWidth = 8.dp,
                        trackColor = Color.Transparent,
                        strokeCap = StrokeCap.Round
                    )

                    // 前景动态圆环
                    CircularProgressIndicator(
                        progress = { animatedScoreProgress },
                        modifier = Modifier.size(96.dp),
                        color = animatedPrimaryColor,
                        strokeWidth = 8.dp,
                        trackColor = Color.Transparent,
                        strokeCap = StrokeCap.Round
                    )

                    Column(horizontalAlignment = Alignment.CenterHorizontally) {
                        if (isScanning) {
                            Text(
                                text = "${(scanProgress * 100).toInt()}%",
                                fontSize = 22.sp,
                                fontWeight = FontWeight.Black,
                                color = animatedPrimaryColor,
                                fontFamily = FontFamily.Monospace
                            )
                            Text(
                                text = "扫描中",
                                fontSize = 11.sp,
                                color = animatedPrimaryColor.copy(alpha = 0.8f)
                            )
                        } else {
                            Text(
                                text = "$score",
                                fontSize = 28.sp,
                                fontWeight = FontWeight.Black,
                                color = animatedPrimaryColor,
                                fontFamily = FontFamily.Monospace
                            )
                            Text(
                                text = "安全分",
                                fontSize = 11.sp,
                                fontWeight = FontWeight.SemiBold,
                                color = animatedPrimaryColor.copy(alpha = 0.8f)
                            )
                        }
                    }
                }
            }

            Spacer(modifier = Modifier.height(12.dp))

            // 底部引擎状态栏
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .clip(RoundedCornerShape(8.dp))
                    .background(Color.White.copy(alpha = 0.6f))
                    .padding(horizontal = 10.dp, vertical = 6.dp),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    text = "底层探测引擎: NDK Inline Syscall",
                    fontSize = 11.sp,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Text(
                    text = if (isDirectSyscallSupported) "Syscall 就绪 ●" else "Libc 模式 ●",
                    fontSize = 11.sp,
                    fontWeight = FontWeight.Bold,
                    color = if (isDirectSyscallSupported) Color(0xFF2E7D32) else Color(0xFFE65100)
                )
            }
        }
    }
}

@Composable
private fun CountPill(label: String, count: Int, color: Color) {
    Box(
        modifier = Modifier
            .clip(RoundedCornerShape(6.dp))
            .background(color.copy(alpha = 0.12f))
            .border(width = 0.5.dp, color = color.copy(alpha = 0.3f), shape = RoundedCornerShape(6.dp))
            .padding(horizontal = 6.dp, vertical = 2.dp)
    ) {
        Text(
            text = "$label $count",
            color = color,
            fontSize = 11.sp,
            fontWeight = FontWeight.Bold
        )
    }
}
