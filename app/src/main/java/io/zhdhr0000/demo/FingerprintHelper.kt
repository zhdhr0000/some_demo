package io.zhdhr0000.demo

import android.content.Context
import android.os.Handler
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.support.annotation.IntDef
import android.support.annotation.StringDef
import android.support.v4.hardware.fingerprint.FingerprintManagerCompat
import android.support.v4.os.CancellationSignal
import android.util.Base64
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.IvParameterSpec

/**
 * Created by zhangyinghao on 2018/10/16.
 */
class FingerprintHelper(context: Context) {
    private val fingerprintManager by lazy { FingerprintManagerCompat.from(context.applicationContext) }
    private val keyStore by lazy { KeyStore.getInstance("AndroidKeyStore") }
    var cryptoCallBack: CryptoCallBack? = null
    fun isKeyProtectedEnforeceBySecureHardware(): Boolean {
        try {
            generateKey("temp")
            val key = keyStore.getKey("temp", null) as SecretKey?
            if (key == null) {
                return false
            }
            val factory = SecretKeyFactory.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
            val keyInfo = factory.getKeySpec(key, KeyInfo::class.java) as KeyInfo?
            return keyInfo?.isInsideSecureHardware == true && keyInfo.isUserAuthenticationRequirementEnforcedBySecureHardware
        } catch (e: Exception) {
            // not Android KeyStore Key
            return false
        }

    }

    fun generateKey(alias: String,
                    @KeyAlgorithmEnum keyAlgorithm: String = KeyProperties.KEY_ALGORITHM_AES,
                    @PurposeEnum purpose: Int = (KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT),
                    @BlockModeEnum blockMode: String = KeyProperties.BLOCK_MODE_CBC,
                    @EncryptionPaddingEnum encryptionPadding: String = KeyProperties.ENCRYPTION_PADDING_PKCS7
    ) {
        keyStore.load(null)
        val generator = KeyGenerator.getInstance(keyAlgorithm, "AndroidKeyStore")
        generator.init(KeyGenParameterSpec.Builder(alias, purpose)
                .setBlockModes(blockMode)
                .setUserAuthenticationRequired(true)
                .setEncryptionPaddings(encryptionPadding).build())
        generator.generateKey()
    }

    fun isGeneratedKey(alias: String): Boolean {
        keyStore.load(null)
        val key = keyStore.getKey(alias, null) as SecretKey?
        return (key != null)
    }

    fun checkHasEnrolledFingerprints(): Boolean {
        return fingerprintManager.hasEnrolledFingerprints()
    }

    fun checkHasFingerprintHardware(): Boolean {
        return fingerprintManager.isHardwareDetected
    }

    fun getCryptoObject(keyName: String, purpose: Int, iv: ByteArray?, @KeyAlgorithmEnum algorithm: String = KeyProperties.KEY_ALGORITHM_AES): FingerprintManagerCompat.CryptoObject? {
        try {
            keyStore.load(null)
            val key = keyStore.getKey(keyName, null) as SecretKey? ?: return null
            val cipher = Cipher.getInstance(algorithm +
                    "/" + KeyProperties.BLOCK_MODE_CBC +
                    "/" + KeyProperties.ENCRYPTION_PADDING_PKCS7)
            return when (purpose) {
                KeyProperties.PURPOSE_ENCRYPT -> {
                    cipher.init(purpose, key)
                    FingerprintManagerCompat.CryptoObject(cipher)
                }
                KeyProperties.PURPOSE_DECRYPT -> {
                    cipher.init(purpose, key, IvParameterSpec(iv))
                    FingerprintManagerCompat.CryptoObject(cipher)
                }
                else -> null
            }
        } catch (e: Exception) {
            return null
        }
    }

    fun encrypt(alias: String, cryptoContent: String, cancellationSignal: CancellationSignal = CancellationSignal(), handler: Handler = Handler()) {
        val cryptoObject = getCryptoObject(alias, Cipher.ENCRYPT_MODE, null)
        fingerprintManager.authenticate(cryptoObject,
                0,
                cancellationSignal,
                object : FingerprintManagerCompat.AuthenticationCallback() {
                    override fun onAuthenticationSucceeded(result: FingerprintManagerCompat.AuthenticationResult?) {
                        val cipher = result?.cryptoObject?.cipher
                        if (cipher == null) {
                            onAuthenticationFailed()
                            return
                        }
                        cryptoCallBack?.onAuthenticationSucceeded(result)

                        val encrypted = cipher.doFinal(Base64.encode(cryptoContent.toByteArray(Charsets.UTF_8), Base64.URL_SAFE))
                        val iv = cipher.iv
                        val encryptedStr = Base64.encodeToString(encrypted, Base64.URL_SAFE)
                        val ivStr = Base64.encodeToString(iv, Base64.URL_SAFE)
                        cryptoCallBack?.encrypted(encryptedStr, ivStr)
                    }

                    override fun onAuthenticationHelp(helpMsgId: Int, helpString: CharSequence?) {
                        cryptoCallBack?.onAuthenticationHelp(helpMsgId, helpString)
                    }

                    override fun onAuthenticationError(errMsgId: Int, errString: CharSequence?) {
                        cryptoCallBack?.onAuthenticationError(errMsgId, errString)
                    }

                    override fun onAuthenticationFailed() {
                        cryptoCallBack?.onAuthenticationFailed()
                    }
                }, Handler())
    }

    fun decrypt(alias: String, encrypted: String, iv: String, cancellationSignal: CancellationSignal = CancellationSignal(), handler: Handler = Handler()) {
        val ivByteArray = Base64.decode(iv, Base64.URL_SAFE)
        val cryptoObject = getCryptoObject(alias, Cipher.DECRYPT_MODE, ivByteArray)
        fingerprintManager.authenticate(cryptoObject,
                0,
                cancellationSignal,
                object : FingerprintManagerCompat.AuthenticationCallback() {
                    override fun onAuthenticationSucceeded(result: FingerprintManagerCompat.AuthenticationResult?) {
                        val cipher = result?.cryptoObject?.cipher
                        if (cipher == null) {
                            onAuthenticationFailed()
                            return
                        }
                        cryptoCallBack?.onAuthenticationSucceeded(result)

                        val encryptedByteArray = Base64.decode(encrypted, Base64.URL_SAFE)
                        val decrypted = cipher.doFinal(encryptedByteArray)
                        val decryptedStr = android.util.Base64.decode(decrypted, Base64.URL_SAFE).toString(Charsets.UTF_8)
                        cryptoCallBack?.decypted(decryptedStr)
                    }

                    override fun onAuthenticationHelp(helpMsgId: Int, helpString: CharSequence?) {
                        cryptoCallBack?.onAuthenticationHelp(helpMsgId, helpString)
                    }

                    override fun onAuthenticationError(errMsgId: Int, errString: CharSequence?) {
                        cryptoCallBack?.onAuthenticationError(errMsgId, errString)
                    }

                    override fun onAuthenticationFailed() {
                        cryptoCallBack?.onAuthenticationFailed()
                    }
                }, Handler())
    }

    @Retention(AnnotationRetention.SOURCE)
    @StringDef(KeyProperties.KEY_ALGORITHM_RSA,
            KeyProperties.KEY_ALGORITHM_EC,
            KeyProperties.KEY_ALGORITHM_AES,
            KeyProperties.KEY_ALGORITHM_HMAC_SHA1,
            KeyProperties.KEY_ALGORITHM_HMAC_SHA224,
            KeyProperties.KEY_ALGORITHM_HMAC_SHA256,
            KeyProperties.KEY_ALGORITHM_HMAC_SHA384,
            KeyProperties.KEY_ALGORITHM_HMAC_SHA512)
    annotation class KeyAlgorithmEnum

    @Retention(AnnotationRetention.SOURCE)
    @StringDef(KeyProperties.ENCRYPTION_PADDING_NONE,
            KeyProperties.ENCRYPTION_PADDING_PKCS7,
            KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1,
            KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
    annotation class EncryptionPaddingEnum


    @Retention(AnnotationRetention.SOURCE)
    @StringDef(KeyProperties.BLOCK_MODE_ECB,
            KeyProperties.BLOCK_MODE_CBC,
            KeyProperties.BLOCK_MODE_CTR,
            KeyProperties.BLOCK_MODE_GCM)
    annotation class BlockModeEnum

    @Retention(AnnotationRetention.SOURCE)
    @IntDef(flag = true, value = [
        KeyProperties.PURPOSE_ENCRYPT,
        KeyProperties.PURPOSE_DECRYPT,
        KeyProperties.PURPOSE_SIGN,
        KeyProperties.PURPOSE_VERIFY
    ])
    annotation class PurposeEnum

    interface CryptoCallBack {
        fun onAuthenticationSucceeded(result: FingerprintManagerCompat.AuthenticationResult?){}
        fun onAuthenticationHelp(helpMsgId: Int, helpString: CharSequence?){}
        fun onAuthenticationError(errMsgId: Int, errString: CharSequence?){}
        fun onAuthenticationFailed(){}
        fun decypted(decrypted: String){}
        fun encrypted(encrypted: String, iv: String){}
    }
}