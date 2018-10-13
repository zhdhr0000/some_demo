package io.zhdhr0000.demo

import android.Manifest
import android.app.PendingIntent
import android.app.Service
import android.content.Intent
import android.nfc.NfcAdapter
import android.nfc.NfcManager
import android.os.Build
import android.os.Bundle
import android.support.v7.app.AppCompatActivity
import com.google.gson.Gson
import kotlinx.android.synthetic.main.activity_nfc.*

class NFCActivity : AppCompatActivity() {

    var flag = false
    val gson = Gson()
    val nfcAdapter: NfcAdapter? by lazy { (getSystemService(Service.NFC_SERVICE) as NfcManager).defaultAdapter }

    val pendingIntent by lazy { PendingIntent.getActivity(this, 0, Intent(this, this.javaClass), 0) }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_nfc)
        nfcRead.setOnClickListener {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                requestPermissions(arrayOf(Manifest.permission.NFC), 0)
            }
            nfcAdapter?.enableForegroundDispatch(this, pendingIntent, null, null)
            content.text = "NfcAdapter isEnabled: ${nfcAdapter?.isEnabled}"
        }

    }

    override fun onNewIntent(intent: Intent?) {
        super.onNewIntent(intent)

        content.text = content.text?.toString() + "\n" + gson.toJson(intent)
    }

    override fun onStart() {
        super.onStart()
        if (nfcAdapter == null) {
            content.text = "没有找到NFC芯片"
        } else {
            content.text = "NfcAdapter isEnabled: ${nfcAdapter?.isEnabled}"
        }
    }

    override fun onResume() {
        super.onResume()
        nfcAdapter?.enableForegroundDispatch(this, pendingIntent, null, null)
        content.text = "NfcAdapter isEnabled: ${nfcAdapter?.isEnabled}"

    }

    override fun onPause() {
        super.onPause()
        nfcAdapter?.disableForegroundDispatch(this)
    }
}
