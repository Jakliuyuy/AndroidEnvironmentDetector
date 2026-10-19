package com.security.environment.domain

import com.security.environment.data.jni.SecurityEngineNative
import java.io.BufferedReader
import java.io.File
import java.io.InputStreamReader
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.TimeUnit

interface SystemEnvironment {
    fun getSystemProperty(key: String): String?
    fun fileExists(path: String): Boolean
    fun readFile(path: String): String?
    fun readLink(path: String): String?
    fun canExecute(path: String): Boolean
    fun executeCommand(command: List<String>, timeoutMs: Long = 500): CommandResult
    fun readProcFile(path: String): String?
    fun listDirectory(path: String): List<String>
    fun probeSocket(host: String, port: Int, payload: ByteArray, timeoutMs: Int = 300): ByteArray?
    fun getEnvironmentVariable(name: String): String?
    fun loadClassOrNull(className: String): Class<*>?
    fun getStackTrace(): Array<StackTraceElement>
}

data class CommandResult(
    val exitCode: Int,
    val stdout: String,
    val stderr: String,
    val timedOut: Boolean = false
)

open class DefaultSystemEnvironment : SystemEnvironment {

    private val nativeEngine = SecurityEngineNative()

    override fun getSystemProperty(key: String): String? {
        // Level 1: Native syscall / libc property reader if available
        if (SecurityEngineNative.isNativeAvailable()) {
            try {
                val nativeVal = nativeEngine.readSystemPropertyNative(key)
                if (!nativeVal.isNullOrEmpty()) {
                    return nativeVal
                }
            } catch (_: Throwable) {
                // Fallback to reflection / command
            }
        }

        // Level 2: Reflection on android.os.SystemProperties
        try {
            val c = Class.forName("android.os.SystemProperties")
            val m = c.getMethod("get", String::class.java)
            val res = m.invoke(null, key) as? String
            if (!res.isNullOrEmpty()) {
                return res
            }
        } catch (_: Throwable) {
            // Fallback to getprop command
        }

        // Level 3: Execute `getprop <key>` via process
        return try {
            val res = executeCommand(listOf("getprop", key), timeoutMs = 300)
            val out = res.stdout.trim()
            if (out.isNotEmpty()) out else null
        } catch (_: Throwable) {
            null
        }
    }

    override fun fileExists(path: String): Boolean {
        return try {
            File(path).exists()
        } catch (_: Throwable) {
            false
        }
    }

    override fun readFile(path: String): String? {
        return try {
            val file = File(path)
            if (file.exists() && file.canRead()) {
                val sb = StringBuilder()
                file.bufferedReader().use { reader ->
                    val buf = CharArray(8192)
                    var total = 0
                    var n: Int
                    while (reader.read(buf).also { n = it } != -1) {
                        sb.append(buf, 0, n)
                        total += n
                        if (total >= 512 * 1024) break // limit to 512KB to prevent OOM
                    }
                }
                sb.toString()
            } else {
                null
            }
        } catch (_: Throwable) {
            null
        }
    }

    override fun readLink(path: String): String? {
        return try {
            File(path).canonicalPath
        } catch (_: Throwable) {
            null
        }
    }

    override fun canExecute(path: String): Boolean {
        return try {
            val file = File(path)
            file.exists() && file.canExecute()
        } catch (_: Throwable) {
            false
        }
    }

    override fun executeCommand(command: List<String>, timeoutMs: Long): CommandResult {
        return try {
            val process = ProcessBuilder(command).start()
            val completed = process.waitFor(timeoutMs, TimeUnit.MILLISECONDS)
            if (!completed) {
                process.destroyForcibly()
                return CommandResult(
                    exitCode = -1,
                    stdout = "",
                    stderr = "Timeout of ${timeoutMs}ms exceeded",
                    timedOut = true
                )
            }
            val stdout = process.inputStream.bufferedReader().use(BufferedReader::readText)
            val stderr = process.errorStream.bufferedReader().use(BufferedReader::readText)
            CommandResult(
                exitCode = process.exitValue(),
                stdout = stdout,
                stderr = stderr,
                timedOut = false
            )
        } catch (e: Throwable) {
            CommandResult(
                exitCode = -1,
                stdout = "",
                stderr = e.message ?: "Execution failed",
                timedOut = false
            )
        }
    }

    override fun readProcFile(path: String): String? {
        return readFile(path)
    }

    override fun listDirectory(path: String): List<String> {
        return try {
            File(path).list()?.toList() ?: emptyList()
        } catch (_: Throwable) {
            emptyList()
        }
    }

    override fun probeSocket(host: String, port: Int, payload: ByteArray, timeoutMs: Int): ByteArray? {
        return try {
            Socket().use { socket ->
                socket.soTimeout = timeoutMs
                socket.connect(InetSocketAddress(host, port), timeoutMs)
                if (payload.isNotEmpty()) {
                    socket.getOutputStream().write(payload)
                    socket.getOutputStream().flush()
                }
                val buffer = ByteArray(256)
                val readLen = socket.getInputStream().read(buffer)
                if (readLen > 0) {
                    buffer.copyOf(readLen)
                } else {
                    ByteArray(0)
                }
            }
        } catch (_: Throwable) {
            null
        }
    }

    override fun getEnvironmentVariable(name: String): String? {
        return try {
            System.getenv(name)
        } catch (_: Throwable) {
            null
        }
    }

    override fun loadClassOrNull(className: String): Class<*>? {
        return try {
            Class.forName(className)
        } catch (_: Throwable) {
            null
        }
    }

    override fun getStackTrace(): Array<StackTraceElement> {
        return Throwable().stackTrace
    }
}
