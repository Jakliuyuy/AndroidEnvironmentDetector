package com.security.environment.domain.attestation

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.SecureRandom
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import java.util.UUID

/**
 * 基于 AndroidKeyStore 的硬件密钥证明实现
 * 
 * 生成硬件隔离区 (TEE / StrongBox) EC secp256r1 密钥对并携带随机挑战值 (Attestation Challenge)，
 * 从 X.509 证书链中提取并解析 Key Attestation Extension (OID 1.3.6.1.4.1.11129.2.1.17)，
 * 并在操作完毕后立即销毁临时密钥别名 (Alias Cleanup)，防止 KeyStore 膨胀。
 */
class KeyStoreAttestationSource(
    private val useStrongBox: Boolean = false
) : KeyAttestationSource {

    companion object {
        private const val ANDROID_KEYSTORE_PROVIDER = "AndroidKeyStore"
        private const val EC_CURVE_NAME = "secp256r1"
        private const val DEFAULT_CHALLENGE_SIZE = 32
    }

    override fun getAttestationResult(challenge: ByteArray?): KeyAttestationResult {
        val alias = "sec_probe_${System.currentTimeMillis()}_${UUID.randomUUID().toString().replace("-", "").take(8)}"
        var keyStore: KeyStore? = null

        return try {
            keyStore = KeyStore.getInstance(ANDROID_KEYSTORE_PROVIDER).apply {
                load(null)
            }

            val actualChallenge = challenge ?: generateRandomChallenge()

            // 1. 初始化 KeyGenParameterSpec (EC secp256r1, setAttestationChallenge)
            val specBuilder = KeyGenParameterSpec.Builder(
                alias,
                KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
            )
                .setAlgorithmParameterSpec(ECGenParameterSpec(EC_CURVE_NAME))
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setAttestationChallenge(actualChallenge)

            if (useStrongBox && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                try {
                    specBuilder.setIsStrongBoxBacked(true)
                } catch (_: Throwable) {
                    // Fallback to standard TEE if StrongBox flag is unavailable
                }
            }

            val keyGenSpec = specBuilder.build()

            // 2. 生成密钥对
            val keyPairGenerator = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_EC,
                ANDROID_KEYSTORE_PROVIDER
            )
            keyPairGenerator.initialize(keyGenSpec)
            keyPairGenerator.generateKeyPair()

            // 3. 提取证书链
            val certificateChain = keyStore.getCertificateChain(alias)
            if (certificateChain.isNullOrEmpty()) {
                return KeyAttestationResult.Failed("Certificate chain is empty for alias: $alias")
            }

            val x509Chain = certificateChain.filterIsInstance<X509Certificate>()
            if (x509Chain.isEmpty()) {
                return KeyAttestationResult.Failed("No X509Certificates found in chain")
            }

            val leafCert = x509Chain.first()

            // 4. 解析 Key Attestation 证书扩展
            val record = KeyAttestationParser.parseFromCertificate(leafCert)
                ?: return KeyAttestationResult.Failed("Failed to parse OID 1.3.6.1.4.1.11129.2.1.17 from certificate")

            KeyAttestationResult.Success(
                record = record,
                certificateChain = x509Chain,
                isHardwareBacked = record.isHardwareBacked
            )
        } catch (e: ClassNotFoundException) {
            KeyAttestationResult.Unavailable("Android KeyStore classes not available (JVM testing environment)")
        } catch (e: NoClassDefFoundError) {
            KeyAttestationResult.Unavailable("Android KeyStore not found in classpath")
        } catch (e: java.security.NoSuchProviderException) {
            KeyAttestationResult.Unavailable("AndroidKeyStore provider not registered in environment")
        } catch (e: Throwable) {
            val msg = e.message ?: e.javaClass.simpleName
            if (msg.contains("AndroidKeyStore", ignoreCase = true) ||
                msg.contains("StrongBox", ignoreCase = true) ||
                msg.contains("keystore", ignoreCase = true)
            ) {
                KeyAttestationResult.Unavailable("KeyStore attestation unsupported: $msg")
            } else {
                KeyAttestationResult.Failed("Attestation generation error: $msg", e)
            }
        } finally {
            // 5. 立即清理临时密钥别名 (Immediate Alias Cleanup)
            try {
                if (keyStore != null && keyStore.containsAlias(alias)) {
                    keyStore.deleteEntry(alias)
                }
            } catch (_: Throwable) {
                // Best-effort cleanup
            }
        }
    }

    private fun generateRandomChallenge(): ByteArray {
        val bytes = ByteArray(DEFAULT_CHALLENGE_SIZE)
        SecureRandom().nextBytes(bytes)
        return bytes
    }
}
