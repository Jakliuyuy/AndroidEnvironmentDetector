package com.security.environment.ui.screens

import androidx.compose.animation.animateColorAsState
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
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
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.security.environment.data.model.CategorySummary
import com.security.environment.data.model.DetectionCategory
import com.security.environment.data.model.DetectionStatus

@Composable
fun CategorySummaryGrid(
    categorySummaries: List<CategorySummary>,
    selectedCategory: DetectionCategory?,
    onCategorySelected: (DetectionCategory?) -> Unit,
    modifier: Modifier = Modifier
) {
    val scrollState = rememberScrollState()

    Column(modifier = modifier.fillMaxWidth()) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .horizontalScroll(scrollState),
            horizontalArrangement = Arrangement.spacedBy(10.dp)
        ) {
            // "全部" 类别选择卡
            AllFilterChip(
                isSelected = selectedCategory == null,
                onClick = { onCategorySelected(null) }
            )

            // 五大核心维度卡
            DetectionCategory.entries.forEach { category ->
                val summary = categorySummaries.find { it.category == category }
                CategoryCard(
                    category = category,
                    summary = summary,
                    isSelected = selectedCategory == category,
                    onClick = {
                        if (selectedCategory == category) {
                            onCategorySelected(null)
                        } else {
                            onCategorySelected(category)
                        }
                    }
                )
            }
        }
    }
}

@Composable
private fun AllFilterChip(
    isSelected: Boolean,
    onClick: () -> Unit
) {
    val bgColor by animateColorAsState(
        targetValue = if (isSelected) MaterialTheme.colorScheme.primaryContainer else MaterialTheme.colorScheme.surface,
        label = "allChipBg"
    )
    val borderColor by animateColorAsState(
        targetValue = if (isSelected) MaterialTheme.colorScheme.primary else Color(0xFFE0E0E0),
        label = "allChipBorder"
    )

    Card(
        shape = RoundedCornerShape(12.dp),
        colors = CardDefaults.cardColors(containerColor = bgColor),
        modifier = Modifier
            .border(width = if (isSelected) 1.5.dp else 1.dp, color = borderColor, shape = RoundedCornerShape(12.dp))
            .clickable(onClick = onClick)
    ) {
        Box(
            modifier = Modifier.padding(horizontal = 14.dp, vertical = 12.dp),
            contentAlignment = Alignment.Center
        ) {
            Text(
                text = "全量分类",
                fontWeight = if (isSelected) FontWeight.Bold else FontWeight.Medium,
                color = if (isSelected) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurface,
                fontSize = 13.sp
            )
        }
    }
}

@Composable
private fun CategoryCard(
    category: DetectionCategory,
    summary: CategorySummary?,
    isSelected: Boolean,
    onClick: () -> Unit
) {
    val hasDanger = (summary?.dangerCount ?: 0) > 0
    val hasWarn = (summary?.warnCount ?: 0) > 0

    val statusColor = when {
        hasDanger -> Color(0xFFC62828)
        hasWarn -> Color(0xFFE65100)
        else -> Color(0xFF2E7D32)
    }

    val statusText = when {
        hasDanger -> "高危 ${summary?.dangerCount}"
        hasWarn -> "警告 ${summary?.warnCount}"
        else -> "正常"
    }

    val shortTitle = when (category) {
        DetectionCategory.BOOTLOADER -> "Bootloader"
        DetectionCategory.ROOT -> "Root提权"
        DetectionCategory.HOOK -> "Hook注入"
        DetectionCategory.VIRTUALIZATION -> "多开虚拟化"
        DetectionCategory.DEBUGGING -> "调试追踪"
    }

    val bgColor by animateColorAsState(
        targetValue = if (isSelected) statusColor.copy(alpha = 0.12f) else MaterialTheme.colorScheme.surface,
        label = "catCardBg"
    )
    val borderColor by animateColorAsState(
        targetValue = if (isSelected) statusColor else Color(0xFFE0E0E0),
        label = "catCardBorder"
    )

    Card(
        shape = RoundedCornerShape(12.dp),
        colors = CardDefaults.cardColors(containerColor = bgColor),
        modifier = Modifier
            .width(132.dp)
            .border(width = if (isSelected) 1.5.dp else 1.dp, color = borderColor, shape = RoundedCornerShape(12.dp))
            .clickable(onClick = onClick)
    ) {
        Column(
            modifier = Modifier.padding(horizontal = 12.dp, vertical = 10.dp)
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Text(
                    text = shortTitle,
                    fontWeight = FontWeight.Bold,
                    fontSize = 13.sp,
                    color = MaterialTheme.colorScheme.onSurface
                )
                Box(
                    modifier = Modifier
                        .size(8.dp)
                        .clip(CircleShape)
                        .background(statusColor)
                )
            }

            Spacer(modifier = Modifier.height(6.dp))

            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Text(
                    text = "${summary?.totalCount ?: 0} 项",
                    fontSize = 11.sp,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Text(
                    text = statusText,
                    fontSize = 11.sp,
                    fontWeight = FontWeight.Bold,
                    color = statusColor
                )
            }
        }
    }
}
