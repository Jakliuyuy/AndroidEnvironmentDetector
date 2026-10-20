package com.security.environment.ui.screens

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.FilterChipDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TextFieldDefaults
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.security.environment.ui.SecurityDashboardViewModel

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun HomeScreen(
    viewModel: SecurityDashboardViewModel,
    modifier: Modifier = Modifier
) {
    val uiState by viewModel.uiState.collectAsState()
    val context = LocalContext.current

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Box(
                            modifier = Modifier
                                .size(12.dp)
                                .clip(CircleShape)
                                .background(Color(0xFF2E7D32))
                        )
                        Spacer(modifier = Modifier.width(8.dp))
                        Column {
                            Text(
                                text = "环境安全检测",
                                fontWeight = FontWeight.Bold,
                                fontSize = 18.sp
                            )
                            Text(
                                text = "Android Anti-Tamper Engine v1.0",
                                fontSize = 11.sp,
                                color = MaterialTheme.colorScheme.onPrimaryContainer.copy(alpha = 0.7f)
                            )
                        }
                    }
                },
                actions = {
                    TextButton(onClick = { viewModel.openExportDialog() }) {
                        Text("导出报告", fontWeight = FontWeight.Bold)
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.primaryContainer,
                    titleContentColor = MaterialTheme.colorScheme.onPrimaryContainer
                )
            )
        },
        bottomBar = {
            // 底部常驻一键重检操作栏
            Surface(
                modifier = Modifier.fillMaxWidth(),
                tonalElevation = 8.dp,
                shadowElevation = 8.dp,
                color = MaterialTheme.colorScheme.surface
            ) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 16.dp, vertical = 10.dp),
                    horizontalArrangement = Arrangement.spacedBy(12.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Button(
                        onClick = { viewModel.triggerScan(context) },
                        enabled = !uiState.isScanning,
                        modifier = Modifier
                            .weight(1f)
                            .height(48.dp),
                        shape = RoundedCornerShape(12.dp),
                        colors = ButtonDefaults.buttonColors(
                            containerColor = MaterialTheme.colorScheme.primary
                        )
                    ) {
                        if (uiState.isScanning) {
                            CircularProgressIndicator(
                                modifier = Modifier.size(20.dp),
                                color = MaterialTheme.colorScheme.onPrimary,
                                strokeWidth = 2.dp
                            )
                            Spacer(modifier = Modifier.width(8.dp))
                            Text("正在全栈检测 (${(uiState.scanProgress * 100).toInt()}%)", fontWeight = FontWeight.Bold)
                        } else {
                            Text("一键重新检测 (Re-Scan)", fontWeight = FontWeight.Bold, fontSize = 15.sp)
                        }
                    }
                }
            }
        }
    ) { innerPadding ->
        LazyColumn(
            modifier = modifier
                .padding(innerPadding)
                .fillMaxSize(),
            contentPadding = PaddingValues(16.dp),
            verticalArrangement = Arrangement.spacedBy(14.dp)
        ) {
            // 1. 顶部评分与总览卡片
            item(key = "score_badge") {
                SecurityScoreBadge(
                    score = uiState.overallScore,
                    level = uiState.securityLevel,
                    isScanning = uiState.isScanning,
                    scanProgress = uiState.scanProgress,
                    assessment = uiState.assessment,
                    isDirectSyscallSupported = uiState.isDirectSyscallSupported
                )
            }

            // 1.1 扫描进行中的高科技雷达扫描视觉反馈卡片
            if (uiState.isScanning) {
                item(key = "radar_scanning_view") {
                    Card(
                        modifier = Modifier.fillMaxWidth(),
                        shape = RoundedCornerShape(16.dp),
                        colors = CardDefaults.cardColors(containerColor = Color(0xFF0F1E19)),
                        border = BorderStroke(1.dp, Color(0xFF00E676).copy(alpha = 0.4f))
                    ) {
                        Column(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(16.dp),
                            horizontalAlignment = Alignment.CenterHorizontally
                        ) {
                            Box(
                                modifier = Modifier.size(160.dp),
                                contentAlignment = Alignment.Center
                            ) {
                                RadarScanView(
                                    isScanning = true,
                                    scanProgress = uiState.scanProgress,
                                    modifier = Modifier.size(160.dp)
                                )
                            }
                            Spacer(modifier = Modifier.height(10.dp))
                            Text(
                                text = "正在全量探测内核/Hook/Root/Bootloader特征...",
                                color = Color(0xFF00E676),
                                fontSize = 13.sp,
                                fontWeight = FontWeight.SemiBold
                            )
                            Spacer(modifier = Modifier.height(4.dp))
                            Text(
                                text = "实时进度: ${(uiState.scanProgress * 100).toInt()}% | 双向 Syscall 握手比对中",
                                color = Color(0xFF80CBC4),
                                fontSize = 11.sp
                            )
                        }
                    }
                }
            }

            // 1.2 历史检测快照变动比对提示横幅 (若有变动且扫描已完成)
            if (!uiState.isScanning && uiState.diffComparison?.hasChanges == true) {
                item(key = "scan_diff_banner") {
                    ScanDiffBanner(
                        comparison = uiState.diffComparison,
                        isExpanded = uiState.isDiffBannerExpanded,
                        onToggleExpand = { viewModel.toggleDiffBannerExpanded() }
                    )
                }
            }

            // 2. 五大维度快捷过滤器
            item(key = "category_grid") {
                Column {
                    Text(
                        text = "安全维度分类",
                        fontWeight = FontWeight.Bold,
                        fontSize = 15.sp,
                        color = MaterialTheme.colorScheme.onSurface
                    )
                    Spacer(modifier = Modifier.height(8.dp))
                    CategorySummaryGrid(
                        categorySummaries = uiState.categorySummaries,
                        selectedCategory = uiState.selectedCategory,
                        onCategorySelected = { viewModel.selectCategory(it) }
                    )
                }
            }

            // 3. 搜索与异常过滤行
            item(key = "filter_bar") {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    // 搜索框
                    OutlinedTextField(
                        value = uiState.searchQuery,
                        onValueChange = { viewModel.updateSearchQuery(it) },
                        modifier = Modifier.fillMaxWidth(),
                        placeholder = { Text("搜索检测项名称、证据关键字或规则ID...", fontSize = 13.sp) },
                        singleLine = true,
                        shape = RoundedCornerShape(10.dp),
                        colors = TextFieldDefaults.colors(
                            focusedContainerColor = MaterialTheme.colorScheme.surface,
                            unfocusedContainerColor = MaterialTheme.colorScheme.surface
                        )
                    )

                    // 过滤 Chips 与展开控制
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            FilterChip(
                                selected = uiState.onlyAbnormal,
                                onClick = { viewModel.toggleOnlyAbnormal(!uiState.onlyAbnormal) },
                                label = { Text("仅看异常项") },
                                colors = FilterChipDefaults.filterChipColors(
                                    selectedContainerColor = Color(0xFFFFEBEE),
                                    selectedLabelColor = Color(0xFFC62828)
                                )
                            )
                            if (uiState.selectedCategory != null) {
                                Spacer(modifier = Modifier.width(8.dp))
                                FilterChip(
                                    selected = true,
                                    onClick = { viewModel.selectCategory(null) },
                                    label = { Text("类别: ${uiState.selectedCategory?.title} ✕") }
                                )
                            }
                        }

                        Row {
                            TextButton(onClick = { viewModel.expandAllItems() }) {
                                Text("全部展开", fontSize = 12.sp)
                            }
                            TextButton(onClick = { viewModel.collapseAllItems() }) {
                                Text("折叠", fontSize = 12.sp)
                            }
                        }
                    }

                    // 结果计数统计
                    Text(
                        text = "检测项列表 (${uiState.filteredItems.size} / ${uiState.items.size} 项)",
                        fontSize = 13.sp,
                        fontWeight = FontWeight.SemiBold,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }

            // 4. 空态提示
            if (uiState.filteredItems.isEmpty()) {
                item(key = "empty_state") {
                    Box(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(vertical = 32.dp),
                        contentAlignment = Alignment.Center
                    ) {
                        Text(
                            text = if (uiState.isScanning) "正在探测内核环境特征，请稍候..." else "未找到符合筛选条件的检测项",
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            fontSize = 14.sp
                        )
                    }
                }
            }

            // 5. 详细检测项卡片列表
            items(
                items = uiState.filteredItems,
                key = { it.id }
            ) { item ->
                DetectionItemCard(
                    item = item,
                    isExpanded = uiState.expandedItemIds.contains(item.id),
                    onToggleExpand = { viewModel.toggleItemExpanded(item.id) },
                    diff = uiState.getDiffForItem(item.id)
                )
            }

            // 底部留白防止遮挡
            item(key = "bottom_spacer") {
                Spacer(modifier = Modifier.height(24.dp))
            }
        }
    }

    // 报告导出对话框
    if (uiState.showExportDialog) {
        ExportReportDialog(
            jsonReport = uiState.exportedJson,
            plainTextReport = uiState.exportedPlainText,
            onDismiss = { viewModel.dismissExportDialog() }
        )
    }
}
