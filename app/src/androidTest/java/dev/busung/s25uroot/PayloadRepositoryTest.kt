package dev.busung.s25uroot

import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import java.io.File
import java.security.MessageDigest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class PayloadRepositoryTest {
    @Test
    fun customPairUsesExactImportedFiles() {
        val context = ApplicationProvider.getApplicationContext<android.content.Context>()
        val repository = PayloadRepository(context)
        val directory = context.cacheDir.resolve("custom-payload-test").apply { mkdirs() }
        val exploit = directory.resolve("payload.so").apply {
            writeBytes(byteArrayOf(0x7F, 'E'.code.toByte(), 'L'.code.toByte(), 'F'.code.toByte()))
        }
        val kernelSu = directory.resolve("ksud").apply {
            writeBytes(byteArrayOf(0x7F, 'E'.code.toByte(), 'L'.code.toByte(), 'F'.code.toByte()))
        }

        try {
            val snapshot = DeviceSnapshot.current()
            val customKernelSu = CustomKernelSuInfo(
                file = kernelSu,
                displayName = "ksud",
                size = kernelSu.length(),
                sha256 = "test",
                importedAtMillis = 0L,
            )
            val profile = repository.customTarget(snapshot, customKernelSu)
            var reportedDownloadProgress = false
            val payloads = repository.customPayloads(
                profile = profile,
                info = CustomPayloadInfo(
                    file = exploit,
                    displayName = "payload.so",
                    size = exploit.length(),
                    sha256 = "test",
                    importedAtMillis = 0L,
                ),
                customKernelSu = customKernelSu,
            ) { reportedDownloadProgress = true }

            assertEquals(exploit.canonicalFile, payloads.exploit.canonicalFile)
            assertEquals(kernelSu.canonicalFile, requireNotNull(payloads.kernelSu).canonicalFile)
            assertFalse(reportedDownloadProgress)
        } finally {
            exploit.delete()
            kernelSu.delete()
            directory.delete()
        }
    }

    @Test
    fun bundledPayloadExtractsVerifiedApkAssets() {
        val context = ApplicationProvider.getApplicationContext<android.content.Context>()
        val payloads = PayloadRepository(context).bundledPayloads(DeviceSnapshot.current())
        val kernelSu = requireNotNull(payloads.kernelSu)

        assertEquals(PayloadRepository.BUNDLED_PROFILE_ID, payloads.profile.profileId)
        assertEquals(104_128L, payloads.exploit.length())
        assertEquals(6_407_096L, kernelSu.length())
        assertEquals(
            "ba0894d1214e3c46305d8acb0ab065eb110833b4b9973c9250aca5bfcb98c214",
            payloads.exploit.sha256(),
        )
        assertEquals(
            "fa3edcc7d168637394877b30cb1f909d762dda788ec14051f4ae79edd6562d63",
            kernelSu.sha256(),
        )
        assertTrue(payloads.exploit.canRead())
        assertTrue(kernelSu.canRead())
    }

    @Test
    fun manifestMatchesDeviceAndArtifactsDownload() {
        val context = ApplicationProvider.getApplicationContext<android.content.Context>()
        val repository = PayloadRepository(context)
        val snapshot = DeviceSnapshot.current()
        val profile = repository.resolveTarget(snapshot)
        assertTrue(profile.matches(snapshot))

        val payloads = repository.download(profile) { }
        val kernelSu = requireNotNull(payloads.kernelSu)
        assertEquals(profile.exploit.size, payloads.exploit.length())
        assertEquals(profile.kernelSu.size, kernelSu.length())
        assertTrue(payloads.exploit.canRead())
        assertTrue(kernelSu.canRead())
    }

    private fun File.sha256(): String {
        val digest = MessageDigest.getInstance("SHA-256")
        inputStream().use { input ->
            val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
            while (true) {
                val count = input.read(buffer)
                if (count < 0) break
                digest.update(buffer, 0, count)
            }
        }
        return digest.digest().joinToString("") { "%02x".format(it) }
    }
}
