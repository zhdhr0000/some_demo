package io.zhdhr0000.demo

import android.content.Context
import android.os.Bundle
import android.support.v4.hardware.fingerprint.FingerprintManagerCompat
import android.support.v7.app.AppCompatActivity
import kotlinx.android.synthetic.main.activity_fingerprint.*

/**
 * Created by zhangyinghao on 2018/10/13.
 */
class FingerprintActivity : AppCompatActivity() {
    val TAG = "Fingerprint"

    val alias = "pin"
    val pinCode by lazy { getSharedPreferences(TAG, Context.MODE_PRIVATE).getString("pin1", String.format("%06d", (Math.random() * 999999).toInt())) }
    var encrypted = ""
    var iv = ""
    private val fingerprintHelper by lazy { FingerprintHelper(this) }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_fingerprint)
        content.text = "${content.text?.toString()}hasFingerprintHardware: ${fingerprintHelper.checkHasFingerprintHardware()}"
        content.text = "${content.text?.toString()}\nhasEnrolledFingerprint: ${fingerprintHelper.checkHasEnrolledFingerprints()}"
        content.text = "${content.text?.toString()}\nhasSecuredHardware: ${fingerprintHelper.isKeyProtectedEnforeceBySecureHardware()}"
        content.text = "${content.text?.toString()}\nThis Alias($alias) ${if (fingerprintHelper.isGeneratedKey(alias)) "have" else "dont have"} key"
        getSharedPreferences(TAG, Context.MODE_PRIVATE).edit().putString("pin1", pinCode).apply()
        encrypted = getSharedPreferences(TAG, Context.MODE_PRIVATE).getString("encrypted", "")
        iv = getSharedPreferences(TAG, Context.MODE_PRIVATE).getString("iv", "")

        if (!fingerprintHelper.isGeneratedKey(alias)) {
            fingerprintHelper.generateKey(alias)
        }

        fingerprint.setOnClickListener {
            content.text = content.text.toString() + "\nEncrypt Authentication Start"
            fingerprintHelper.encrypt(alias, pinCode)
        }

        check.setOnClickListener {
            content.text = content.text.toString() + "\nDecrypt Authentication Start"
            fingerprintHelper.decrypt(alias, encrypted, iv)
        }

        fingerprintHelper.cryptoCallBack = object : FingerprintHelper.CryptoCallBack {
            override fun encrypted(encrypted: String, iv: String) {
                content.text = content.text.toString() + "\nencrypted: $encrypted iv: ${iv}"

                this@FingerprintActivity.encrypted = encrypted
                this@FingerprintActivity.iv = iv

                getSharedPreferences(TAG, Context.MODE_PRIVATE).edit().putString("encrypted", encrypted).apply()
                getSharedPreferences(TAG, Context.MODE_PRIVATE).edit().putString("iv", iv).apply()
            }

            override fun decypted(decrypted: String) {
                content.text = content.text.toString() + "\ndecrypted: $decrypted"
                content.text = content.text.toString() + "\norigin pinCode: $pinCode "
            }

            override fun onAuthenticationHelp(helpMsgId: Int, helpString: CharSequence?) {
                content.text = content.text.toString() + "\nonAuthenticationHelp: $helpMsgId $helpString "
            }

            override fun onAuthenticationSucceeded(result: FingerprintManagerCompat.AuthenticationResult?) {
                content.text = content.text.toString() + "\nonAuthenticationSucceeded"
            }
        }
    }
}