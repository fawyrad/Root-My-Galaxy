package dev.busung.s25uroot

import android.content.Context
import android.net.Uri
import android.system.Os
import java.io.File
import java.security.MessageDigest

data class CustomKernelSuInfo(
    val file: File,
    val displayName: String,
    val size: Long,
    val sha256: String,
    val importedAtMillis: Long,
)

/** Stores an optional user-imported ksud executable in app-private storage. */
object CustomKernelSuStore {
    private const val DIRECTORY = "custom_ksud"
    private const val KERNEL_SU_NAME = "ksud"
    private const val META_NAME = "ksud.meta"
    private const val MAX_KERNEL_SU_BYTES = 256L * 1024 * 1024
    private val ELF_MAGIC = byteArrayOf(0x7F, 'E'.code.toByte(), 'L'.code.toByte(), 'F'.code.toByte())

    fun current(context: Context): CustomKernelSuInfo? {
        val kernelSu = kernelSuFile(context)
        val meta = metaFile(context)
        if (!kernelSu.exists() || !meta.exists()) return null
        val fields = meta.readLines(Charsets.UTF_8)
            .mapNotNull { line ->
                val index = line.indexOf('=')
                if (index <= 0) null else line.substring(0, index) to line.substring(index + 1)
            }
            .toMap()
        val size = fields["size"]?.toLongOrNull() ?: return null
        val sha256 = fields["sha256"] ?: return null
        val displayName = fields["name"] ?: kernelSu.name
        val importedAt = fields["importedAt"]?.toLongOrNull() ?: 0L
        if (kernelSu.length() != size) return null
        return CustomKernelSuInfo(kernelSu, displayName, size, sha256, importedAt)
    }

    fun import(context: Context, uri: Uri, displayName: String): CustomKernelSuInfo {
        val directory = File(context.filesDir, DIRECTORY).apply { mkdirs() }
        val temporary = File(directory, "$KERNEL_SU_NAME.part")
        val digest = MessageDigest.getInstance("SHA-256")
        var total = 0L
        val magic = ByteArray(4)
        var magicFilled = 0
        context.contentResolver.openInputStream(uri).use { input ->
            require(input != null) { context.getString(R.string.custom_ksud_import_failed) }
            temporary.outputStream().use { output ->
                val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
                while (true) {
                    val count = input.read(buffer)
                    if (count < 0) break
                    if (magicFilled < 4) {
                        val take = minOf(4 - magicFilled, count)
                        System.arraycopy(buffer, 0, magic, magicFilled, take)
                        magicFilled += take
                    }
                    total += count
                    require(total <= MAX_KERNEL_SU_BYTES) {
                        context.getString(R.string.custom_ksud_import_failed)
                    }
                    digest.update(buffer, 0, count)
                    output.write(buffer, 0, count)
                }
                output.fd.sync()
            }
        }
        require(total > 0) { context.getString(R.string.custom_ksud_import_invalid) }
        require(magicFilled == 4 && magic.contentEquals(ELF_MAGIC)) {
            context.getString(R.string.custom_ksud_import_invalid)
        }
        val kernelSu = kernelSuFile(context)
        if (kernelSu.exists()) kernelSu.delete()
        require(temporary.renameTo(kernelSu)) { context.getString(R.string.custom_ksud_import_failed) }
        Os.chmod(kernelSu.absolutePath, 0b100100100)
        val sha256 = digest.digest().joinToString("") { "%02x".format(it) }
        val importedAt = System.currentTimeMillis()
        val resolvedName = displayName.ifBlank { kernelSu.name }
        metaFile(context).writeText(
            buildString {
                append("name=").append(resolvedName.replace('\n', ' ').replace('\r', ' ')).append('\n')
                append("size=").append(total).append('\n')
                append("sha256=").append(sha256).append('\n')
                append("importedAt=").append(importedAt).append('\n')
            },
            Charsets.UTF_8,
        )
        return CustomKernelSuInfo(kernelSu, resolvedName, total, sha256, importedAt)
    }

    fun clear(context: Context) {
        kernelSuFile(context).delete()
        metaFile(context).delete()
        File(context.filesDir, "$DIRECTORY/$KERNEL_SU_NAME.part").delete()
    }

    private fun kernelSuFile(context: Context) = File(context.filesDir, "$DIRECTORY/$KERNEL_SU_NAME")

    private fun metaFile(context: Context) = File(context.filesDir, "$DIRECTORY/$META_NAME")
}
