package io.zhdhr0000.demo

import android.os.Bundle
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.support.v4.hardware.fingerprint.FingerprintManagerCompat
import android.support.v4.os.CancellationSignal
import android.support.v7.app.AppCompatActivity
import com.google.gson.Gson
import kotlinx.android.synthetic.main.activity_fingerprint.*
import java.security.KeyPairGenerator
import java.security.KeyStore
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec

/**
 * Created by zhangyinghao on 2018/10/13.
 */
class FingerprintActivity : AppCompatActivity() {
    val TAG = "Fingerprint"
    val fingerprintManager by lazy { FingerprintManagerCompat.from(this) }
    val mCancellationSignal = CancellationSignal()
    lateinit var keyStore: KeyStore
    val gson = Gson()
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_fingerprint)
        keyStore = KeyStore.getInstance("AndroidKeyStore")
        fingerprint.setOnClickListener {
            if (checkHasFingerprintHardware() && checkHasEnrolledFingerprints()) {
                fingerprintManager.authenticate(null,
                        0,
                        mCancellationSignal,
                        object : FingerprintManagerCompat.AuthenticationCallback() {
                            override fun onAuthenticationSucceeded(result: FingerprintManagerCompat.AuthenticationResult?) {
                                super.onAuthenticationSucceeded(result)
                                saveKeySpec()
                                content.text = content.text?.toString() + "\nAuthentication Succeeded : ${gson.toJson(result?.cryptoObject)}"
                            }

                            override fun onAuthenticationHelp(helpMsgId: Int, helpString: CharSequence?) {
                                super.onAuthenticationHelp(helpMsgId, helpString)
                                content.text = content.text?.toString() + "\nAuthentication Help : $helpMsgId , $helpString"
                            }

                            override fun onAuthenticationError(errMsgId: Int, errString: CharSequence?) {
                                super.onAuthenticationError(errMsgId, errString)
                                content.text = content.text?.toString() + "\nAuthentication Error : $errMsgId , $errString"
                            }

                            override fun onAuthenticationFailed() {
                                super.onAuthenticationFailed()
                                content.text = content.text?.toString() + "\nAuthentication Failed"
                            }
                        }, null)
            }
        }

        check.setOnClickListener {
            fingerprintManager.authenticate(null,
                    0,
                    mCancellationSignal,
                    object : FingerprintManagerCompat.AuthenticationCallback() {
                        override fun onAuthenticationSucceeded(result: FingerprintManagerCompat.AuthenticationResult?) {
                            super.onAuthenticationSucceeded(result)
                            val keySpec = getKeySpec()
                            content.text = content.text?.toString() + "\nAuthentication Succeeded : ${keySpec}"
                        }

                        override fun onAuthenticationHelp(helpMsgId: Int, helpString: CharSequence?) {
                            super.onAuthenticationHelp(helpMsgId, helpString)
                            content.text = content.text?.toString() + "\nAuthentication Help : $helpMsgId , $helpString"
                        }

                        override fun onAuthenticationError(errMsgId: Int, errString: CharSequence?) {
                            super.onAuthenticationError(errMsgId, errString)
                            content.text = content.text?.toString() + "\nAuthentication Error : $errMsgId , $errString"
                        }

                        override fun onAuthenticationFailed() {
                            super.onAuthenticationFailed()
                            content.text = content.text?.toString() + "\nAuthentication Failed"
                        }
                    }, null)
        }
    }

    private fun getKeySpec(): String {
        val secretKey = keyStore.getKey("alias", "psw".toCharArray())
        return secretKey.format
    }

    private fun saveKeySpec() {
        keyStore.load(null)
        val keyPairGenerator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
        keyPairGenerator.initialize(KeyGenParameterSpec.Builder(
                "alias",
                KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY)
                .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
                .build())
        val keyPair = keyPairGenerator.generateKeyPair()


        val pbeKeySpec = PBEKeySpec("this is a pin code".toCharArray())
        val secretKeyFactory = SecretKeyFactory.getInstance("PBEWITHSHA1ANDDES")
        val secretKey = secretKeyFactory.generateSecret(pbeKeySpec)
        val entry = KeyStore.SecretKeyEntry(secretKey)
        keyStore.setEntry("alias", entry, KeyStore.PasswordProtection("psw".toCharArray()))
    }

    private fun checkHasEnrolledFingerprints(): Boolean {
        if (!fingerprintManager.hasEnrolledFingerprints()) {
            content.text = "手机未录入指纹"
        }
        return fingerprintManager.hasEnrolledFingerprints()
    }


    private fun checkHasFingerprintHardware(): Boolean {
        if (!fingerprintManager.isHardwareDetected) {
            content.text = "手机不支持指纹识别功能"
        }
        return fingerprintManager.isHardwareDetected
    }

}