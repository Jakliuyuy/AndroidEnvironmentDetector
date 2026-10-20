package com.security.environment.ui.screens

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.expandVertically
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.shrinkVertically
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
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
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.security.environment.data.snapshot.DetectionDiff
import com.security.environment.data.snapshot.ItemDiffType
import com.security.environment.data.snapshot.ScanComparisonResult

/**
 * 历史扫描快照比对横幅 (Scan Diff Banner)
 * 当检测到与上一次快照相比有变动项时高亮提示
 */
@Composable
fun ScanDiffBanner(
    comparison: ScanComparisonResult?,
    isExpanded: Boolean,
    onToggleExpand: () -> Unit,
    modifier: Modifier = Modifier
) {
    if (comparison == null || !comparison.hasChanges) return

    val bannerBg = Color(0xFFFFF8E1)
    val bannerBorder = Color(0xFFFFB300)
    val accentColor = Color(0xFFE65100)

    Box(
        modifier = modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(14.dp))
            .background(bannerBg)
            .border(width = 1.2.dp, color = bannerBorder, shape = RoundedCornerShape(14.dp))
            .clickable(onClick = onToggleExpand)
            .padding(14.dp)
    ) {
        Column {
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Row(
                    modifier = Modifier.weight(1f),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Box(
                        modifier = Modifier
                            .size(10.dp)
                            .clip(CircleShape)
                            .background(accentColor)
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(
                        text = "环境状态变动提醒 (Environment Diff)",
                        fontWeight = FontWeight.Bold,
                        color = accentColor,
                        fontSize = 14.sp
                    )
                }

                Box(
                    modifier = Modifier
                        .clip(RoundedCornerShape(6.dp))
                        .background(Color.White.copy(alpha = 0.8f))
                        .padding(horizontal = 8.dp, vertical = 3.dp)
                ) {
                    Text(
                        text = if (isExpanded) "收起 ▲" else "查看详情 (${comparison.diffItems.size}) ▼",
                        fontSize = 11.sp,
                        color = accentColor,
                        fontWeight = FontWeight.Bold
                    )
                }
            }

            Spacer(modifier = Modifier.height(6.dp))

            Text(
                text = comparison.changeSummary,
                fontSize = 12.sp,
                color = Color(0xFF4E342E),
                lineHeight = 16.sp
            )

            AnimatedVisibility(
                visible = isExpanded,
                enter = fadeIn() + expandVertically(),
                exit = fadeOut() + shrinkVertically()
            ) {
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(top = 10.dp),
                    verticalArrangement = Arrangement.spacedBy(6.dp)
                ) {
                    for (diff in comparison.diffItems) {
                        DiffItemRow(diff = diff)
                    }
                }
            }
        }
    }
}

@Composable
private fun DiffItemRow(diff: DetectionDiff) {
    val (tagText, tagBg, tagColor) = when (diff.diffType) {
        ItemDiffType.NEW_ABNORMAL -> Triple("新增风险", Color(0xFFFFCDD2), Color(0xFFC62828))
        ItemDiffType.STATUS_CHANGED -> Triple("状态变更", Color(0xFFFFE0B2), Color(0xFFE65100))
        ItemDiffType.RESOLVED -> Triple("风险解除", Color(0xFFC8E6C9), Color(0xFF2E7D32))
        ItemDiffType.UNCHANGED -> Triple("无变化", Color(0xFFE0E0E0), Color(0xFF757575))
    }

    Row(
        verticalAlignment = Alignment.CenterVertically,
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(8.dp))
            .background(Color.White.copy(alpha = 0.85f))
            .padding(horizontal = 10.dp, vertical = 6.dp)
    ) {
        Box(
            modifier = Modifier
                .clip(RoundedCornerShape(4.dp))
                .background(tagBg)
                .padding(horizontal = 6.dp, vertical = 2.dp)
        ) {
            Text(
                text = tagText,
                color = tagColor,
                fontSize = 10.sp,
                fontWeight = FontWeight.Bold
            )
        }

        Spacer(modifier = Modifier.width(8.dp))

        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = diff.name,
                fontSize = 12.sp,
                fontWeight = FontWeight.SemiBold,
                color = Color(0xFF212121)
            )
            Text(
                text = diff.description,
                fontSize = 11.sp,
                color = Color(0xFF546E7A)
            )
        }
    }
}

/**
 * 嵌入在检测卡片上的变动徽章
 */
@Composable
fun ItemDiffBadge(diff: DetectionDiff, modifier: Modifier = Modifier) {
    val (badgeText, badgeBg, badgeColor) = when (diff.diffType) {
        ItemDiffType.NEW_ABNORMAL -> Triple("新增风险", Color(0xFFFFEBEE), Color(0xFFC62828))
        ItemDiffType.STATUS_CHANGED -> Triple("状态变动", Color(0xFFFFF3E0), Color(0xFFE65100))
        ItemDiffType.RESOLVED -> Triple("风险解除", Color(0xFFE8F5E9), Color(0xFF2E7D32))
        ItemDiffType.UNCHANGED -> return
    }

    Box(
        modifier = modifier
            .clip(RoundedCornerShape(6.dp))
            .background(badgeBg)
            .border(width = 0.8.dp, color = badgeColor.copy(alpha = 0.4f), shape = RoundedCornerShape(6.dp))
            .padding(horizontal = 6.dp, vertical = 2.dp)
    ) {
        Text(
            text = badgeText,
            color = badgeColor,
            fontSize = 10.sp,
            fontWeight = FontWeight.Bold
        )
    }
}
