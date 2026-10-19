package com.security.environment

import com.security.environment.domain.CommandResult
import com.security.environment.domain.SystemEnvironment

class MockSystemEnvironment : SystemEnvironment {

    val properties = mutableMapOf<String, String>()
    val files = mutableMapOf<String, String>()
    val existingFiles = mutableSetOf<String>()
    val executableFiles = mutableSetOf<String>()
    val commandHandlers = mutableMapOf<List<String>, CommandResult>()
    val directories = mutableMapOf<String, List<String>>()
    val socketResponses = mutableMapOf<Pair<String, Int>, ByteArray>()
    val envVariables = mutableMapOf<String, String>()
    val loadedClasses = mutableMapOf<String, Class<*>>()
    var mockStackTrace: Array<StackTraceElement> = emptyArray()

    override fun getSystemProperty(key: String): String? {
        return properties[key]
    }

    override fun fileExists(path: String): Boolean {
        return existingFiles.contains(path) || files.containsKey(path)
    }

    override fun readFile(path: String): String? {
        return files[path]
    }

    val linkTargets = mutableMapOf<String, String>()

    override fun readLink(path: String): String? {
        return linkTargets[path] ?: files[path]
    }

    override fun canExecute(path: String): Boolean {
        return executableFiles.contains(path)
    }

    override fun executeCommand(command: List<String>, timeoutMs: Long): CommandResult {
        return commandHandlers[command] ?: CommandResult(
            exitCode = 0,
            stdout = "",
            stderr = ""
        )
    }

    override fun readProcFile(path: String): String? {
        return readFile(path)
    }

    override fun listDirectory(path: String): List<String> {
        return directories[path] ?: emptyList()
    }

    override fun probeSocket(host: String, port: Int, payload: ByteArray, timeoutMs: Int): ByteArray? {
        return socketResponses[host to port]
    }

    override fun getEnvironmentVariable(name: String): String? {
        return envVariables[name]
    }

    override fun loadClassOrNull(className: String): Class<*>? {
        return loadedClasses[className]
    }

    override fun getStackTrace(): Array<StackTraceElement> {
        return mockStackTrace
    }
}
