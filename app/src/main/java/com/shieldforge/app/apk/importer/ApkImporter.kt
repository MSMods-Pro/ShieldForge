package com.shieldforge.app.apk.importer

import android.content.Context
import android.net.Uri
import android.provider.OpenableColumns
import com.shieldforge.app.apk.parser.ApkAnalysisResult
import com.shieldforge.app.apk.parser.ApkArchiveParser
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File
import java.util.UUID

object ApkImporter {
    suspend fun importFromUri(
        context: Context,
        uri: Uri,
    ): ApkAnalysisResult = withContext(Dispatchers.IO) {
        val projectId = "APK_${UUID.randomUUID().toString().take(8)}"
        val displayName = resolveDisplayName(context, uri) ?: "imported_app.apk"
        val workspaceDir = File(context.filesDir, "workspaces/$projectId").apply { mkdirs() }
        val inputCopy = File(workspaceDir, "input.apk")

        context.contentResolver.openInputStream(uri)?.use { input ->
            inputCopy.outputStream().use { output ->
                input.copyTo(output, bufferSize = 65_536)
            }
        } ?: throw IllegalStateException("Unable to open selected APK stream")

        if (!inputCopy.exists() || inputCopy.length() < 64L) {
            throw IllegalArgumentException("Imported file is empty or invalid APK")
        }
        ApkArchiveParser.analyzeApk(projectId, displayName, inputCopy)
    }

    /**
     * Imports ShieldForge's own installed APK (zero extra permissions, useful for instant on-device
     * real DEX/AXML/ARSC inspection and hardening pipeline validation).
     */
    suspend fun importOwnApplicationApk(context: Context): ApkAnalysisResult = withContext(Dispatchers.IO) {
        val sourceApk = File(context.applicationInfo.sourceDir)
        if (!sourceApk.exists()) {
            throw IllegalStateException("Application base APK path not accessible")
        }
        val projectId = "SELF_${UUID.randomUUID().toString().take(8)}"
        val workspaceDir = File(context.filesDir, "workspaces/$projectId").apply { mkdirs() }
        val inputCopy = File(workspaceDir, "input.apk")
        sourceApk.copyTo(inputCopy, overwrite = true)
        ApkArchiveParser.analyzeApk(projectId, "ShieldForge-self.apk", inputCopy)
    }

    private fun resolveDisplayName(context: Context, uri: Uri): String? {
        return runCatching {
            context.contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)
                ?.use { cursor ->
                    if (cursor.moveToFirst()) {
                        val idx = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)
                        if (idx >= 0) cursor.getString(idx) else null
                    } else null
                }
        }.getOrNull() ?: uri.lastPathSegment?.substringAfterLast('/')
    }
}
