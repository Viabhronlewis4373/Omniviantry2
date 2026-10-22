package com.example.engine.omniroot.service

import android.content.Context
import android.util.Base64
import java.io.File
import java.security.MessageDigest
import java.security.SecureRandom

/** Authentication for the loopback OpenAI-compatible proxy. */
object LocalApiAuth {
    private const val TOKEN_FILE_NAME = "omniroot_local_api_token"
    private val lock = Any()

    fun getOrCreateToken(context: Context): String = synchronized(lock) {
        val file = tokenFile(context)
        val existing = runCatching { file.readText(Charsets.UTF_8).trim() }.getOrNull()
        if (!existing.isNullOrBlank() && existing.length >= 40) existing else createAndStoreToken(file)
    }

    fun rotateToken(context: Context): String = synchronized(lock) {
        createAndStoreToken(tokenFile(context))
    }

    fun isAuthorized(context: Context, authorizationHeader: String?): Boolean {
        val expected = "Bearer ${getOrCreateToken(context)}".toByteArray(Charsets.UTF_8)
        val actual = (authorizationHeader ?: "").toByteArray(Charsets.UTF_8)
        return MessageDigest.isEqual(expected, actual)
    }

    private fun tokenFile(context: Context): File =
        File(context.applicationContext.noBackupFilesDir, TOKEN_FILE_NAME)

    private fun createAndStoreToken(file: File): String {
        val bytes = ByteArray(32)
        SecureRandom().nextBytes(bytes)
        val token = Base64.encodeToString(bytes, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
        file.parentFile?.mkdirs()
        file.writeText(token, Charsets.UTF_8)
        return token
    }
}