package com.security.environment.domain.detectors

import android.content.Context
import android.hardware.Sensor
import android.hardware.SensorManager
import android.os.Process
import com.security.environment.data.model.DetectionCategory
import com.security.environment.data.model.DetectionItem
import com.security.environment.data.model.DetectionMethod
import com.security.environment.data.model.DetectionStatus
import com.security.environment.domain.DefaultSystemEnvironment
import com.security.environment.domain.SystemEnvironment

class VirtualEnvDetector(
    private val env: SystemEnvironment = DefaultSystemEnvironment()
) {

    companion object {
        val QEMU_DRIVERS = listOf(
            "/dev/qemu_pipe",
            "/dev/goldfish_pipe",
            "/dev/vboxguest",
            "/dev/vboxuser",
            "/system/lib/libc_malloc_debug_qemu.so",
            "/sys/qemu_trace",
            "/system/bin/nox-prop",
            "/system/bin/ttVM-prop"
        )

        val CONTAINER_PATH_KEYWORDS = listOf(
            "virtual/",
            "io.va.exposed/",
            "parallel/",
            "container/",
            "/data/user/999/"
        )
    }

    fun detect(context: Context? = null): List<DetectionItem> {
        val results = mutableListOf<DetectionItem>()
        results.add(checkEmulatorProperties())
        results.add(checkQemuDriverFiles())
        results.add(checkBatteryAndSensors(context))
        results.add(checkDualAppAndContainerRedirection(context))
        return results
    }

    /**
     * SEC-R4-01: 模拟器硬件属性与系统指纹特征
     */
    fun checkEmulatorProperties(): DetectionItem {
        val hardware = env.getSystemProperty("ro.hardware")?.lowercase() ?: ""
        val qemuKernel = env.getSystemProperty("ro.kernel.qemu") ?: ""
        val model = env.getSystemProperty("ro.product.model")?.lowercase() ?: ""
        val manufacturer = env.getSystemProperty("ro.product.manufacturer")?.lowercase() ?: ""
        val board = env.getSystemProperty("ro.product.board")?.lowercase() ?: ""
        val fingerprint = env.getSystemProperty("ro.build.fingerprint")?.lowercase() ?: ""

        val anomalies = mutableListOf<String>()

        if (hardware.contains("goldfish") || hardware.contains("ranchu") ||
            hardware.contains("vbox86") || hardware.contains("nox") || hardware.contains("ttvm")
        ) {
            anomalies.add("hardware=$hardware")
        }

        if (qemuKernel == "1") {
            anomalies.add("ro.kernel.qemu=1")
        }

        if (model.contains("sdk") || model.contains("emulator") || model.contains("google_sdk")) {
            anomalies.add("model=$model")
        }

        if (manufacturer.contains("genymotion") || manufacturer.contains("unknown")) {
            anomalies.add("manufacturer=$manufacturer")
        }

        if (board.contains("goldfish")) {
            anomalies.add("board=$board")
        }

        if (fingerprint.contains("generic") || fingerprint.contains("vbox")) {
            anomalies.add("fingerprint_generic")
        }

        val isFound = anomalies.isNotEmpty()
        val status = if (isFound) DetectionStatus.WARN else DetectionStatus.PASS

        val evidence = if (isFound) {
            "emulator_props: " + anomalies.joinToString(", ")
        } else {
            "hardware=$hardware, model=$model (clean)"
        }

        val desc = if (isFound) {
            "检测到模拟器系统指纹或 QEMU 虚拟平台硬件特征"
        } else {
            "硬件架构与设备指纹表现为真实物理机特征"
        }

        return DetectionItem(
            id = "SEC-R4-01",
            name = "模拟器硬件指纹检测",
            category = DetectionCategory.VIRTUALIZATION,
            status = status,
            evidence = evidence,
            method = DetectionMethod.JAVA,
            description = desc,
            remediation = if (isFound) "建议在真实物理 Android 设备上运行" else ""
        )
    }

    /**
     * SEC-R4-02: QEMU / VirtualBox 虚拟外设与驱动设备文件
     */
    fun checkQemuDriverFiles(): DetectionItem {
        val foundDrivers = mutableListOf<String>()

        for (driver in QEMU_DRIVERS) {
            if (env.fileExists(driver)) {
                foundDrivers.add(driver)
            }
        }

        val isFound = foundDrivers.isNotEmpty()
        val status = if (isFound) DetectionStatus.DANGER else DetectionStatus.PASS

        val evidence = if (isFound) {
            "drivers_found: " + foundDrivers.joinToString(", ")
        } else {
            "scanned_${QEMU_DRIVERS.size}_virtual_drivers_clean"
        }

        val desc = if (isFound) {
            "检测到虚拟仿真外设管道与 QEMU 虚拟驱动节点"
        } else {
            "未发现虚拟化驱动或模拟器外设管道文件"
        }

        return DetectionItem(
            id = "SEC-R4-02",
            name = "QEMU/VBox 虚拟驱动文件",
            category = DetectionCategory.VIRTUALIZATION,
            status = status,
            evidence = evidence,
            method = DetectionMethod.DIRECT_SYSCALL,
            description = desc,
            remediation = if (isFound) "检测到虚拟机驱动节点，请在真机环境运行" else ""
        )
    }

    /**
     * SEC-R4-03: 物理传感器与电池真实性检测
     */
    fun checkBatteryAndSensors(context: Context? = null, simulatedSensorCount: Int? = null): DetectionItem {
        var sensorCount = simulatedSensorCount
        var hasLightSensor = false
        var hasProximitySensor = false

        if (sensorCount == null && context != null) {
            try {
                val sensorManager = context.getSystemService(Context.SENSOR_SERVICE) as? SensorManager
                if (sensorManager != null) {
                    val sensors = sensorManager.getSensorList(Sensor.TYPE_ALL)
                    sensorCount = sensors.size
                    hasLightSensor = sensorManager.getDefaultSensor(Sensor.TYPE_LIGHT) != null
                    hasProximitySensor = sensorManager.getDefaultSensor(Sensor.TYPE_PROXIMITY) != null
                }
            } catch (_: Throwable) {
                // Ignore context access error
            }
        }

        // Check battery sysfs
        val battTemp = env.readFile("/sys/class/power_supply/battery/temp")?.trim()
        val battVolt = env.readFile("/sys/class/power_supply/battery/voltage_now")?.trim()

        val isAbnormal = if (sensorCount != null) {
            // Emulators typically have < 5 sensors or missing light/proximity
            sensorCount < 5 || (!hasLightSensor && !hasProximitySensor && sensorCount < 10)
        } else {
            // If in headless test or no sensor manager, check if battery nodes report zero
            battTemp == "0" && battVolt == "0"
        }

        val status = if (isAbnormal) DetectionStatus.WARN else DetectionStatus.PASS

        val evidence = buildString {
            if (sensorCount != null) {
                append("sensor_count=").append(sensorCount)
                append(", light=").append(hasLightSensor)
                append(", proximity=").append(hasProximitySensor)
            } else {
                append("batt_temp=").append(battTemp ?: "unknown")
                append(", volt=").append(battVolt ?: "unknown")
            }
        }

        val desc = if (isAbnormal) {
            "物理传感器数量极少或电池物理参数表现为模拟器特征"
        } else {
            "物理传感器与供电状态符合真机硬件特征"
        }

        return DetectionItem(
            id = "SEC-R4-03",
            name = "传感器与电池真实性",
            category = DetectionCategory.VIRTUALIZATION,
            status = status,
            evidence = evidence,
            method = DetectionMethod.JAVA,
            description = desc,
            remediation = if (isAbnormal) "检测到硬件环境缺失，疑似虚拟化宿主" else ""
        )
    }

    /**
     * SEC-R4-04: 双开/分身多开与私有目录重定向检测
     */
    fun checkDualAppAndContainerRedirection(
        context: Context? = null,
        simulatedPath: String? = null,
        simulatedUid: Int? = null
    ): DetectionItem {
        val appPath = simulatedPath ?: context?.filesDir?.absolutePath ?: ""
        val currentUid = simulatedUid ?: try { Process.myUid() } catch (_: Throwable) { 10000 }

        val anomalies = mutableListOf<String>()

        // 1. Check path redirection
        for (kw in CONTAINER_PATH_KEYWORDS) {
            if (appPath.contains(kw, ignoreCase = true)) {
                anomalies.add("path_keyword:$kw")
            }
        }

        // 2. Multi-user 999 sub-user check (MIUI/EMUI dual-app)
        val userId = currentUid / 100000
        if (userId == 999 || appPath.contains("/user/999/")) {
            anomalies.add("dual_user_999")
        }

        val isFound = anomalies.isNotEmpty()
        val status = if (isFound) DetectionStatus.WARN else DetectionStatus.PASS

        val evidence = if (isFound) {
            "container_traces: " + anomalies.joinToString(", ") + " [path=$appPath]"
        } else {
            "private_path_clean [uid=$currentUid, path=$appPath]"
        }

        val desc = if (isFound) {
            "检测到应用私有目录重定向或运行于多开分身容器 (User 999 / VirtualApp) 中"
        } else {
            "应用运行于主用户私有沙箱中，无路径重定向痕迹"
        }

        return DetectionItem(
            id = "SEC-R4-04",
            name = "双开多开与路径重定向",
            category = DetectionCategory.VIRTUALIZATION,
            status = status,
            evidence = evidence,
            method = DetectionMethod.JAVA,
            description = desc,
            remediation = if (isFound) "请在系统原生主空间直接运行本应用" else ""
        )
    }
}
