package io.zhdhr0000.demo

import android.app.Activity
import android.content.Intent
import android.os.Bundle
import kotlinx.android.synthetic.main.activity_main.*

/**
 * Created by zhangyinghao on 2018/10/13.
 */
class MainActivity : Activity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        nfcRead.setOnClickListener { startActivity(Intent(this, NFCActivity::class.java)) }
        fingerprint.setOnClickListener { startActivity(Intent(this, FingerprintActivity::class.java)) }
    }
}