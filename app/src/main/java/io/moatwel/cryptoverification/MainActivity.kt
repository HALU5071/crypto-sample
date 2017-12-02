package io.moatwel.cryptoverification

import android.os.Bundle
import android.support.v7.app.AppCompatActivity
import android.util.Base64
import android.util.Log
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import java.nio.charset.Charset
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec


class MainActivity : AppCompatActivity() {

  private lateinit var keyStore: KeyStore

  private val KEY_ALIAS = "SampleKey"

  private val KEY_PROVIDER = "AndroidOpenSSL"

  private val privateKey = "ifjsur8qiw9e0r0w"

  val button by lazy { findViewById<Button>(R.id.do_encrypt) }

  val editText by lazy { findViewById<EditText>(R.id.plain_text) }

  val encryptedTextView by lazy { findViewById<TextView>(R.id.encrypted_text) }

  val decryptedTextView by lazy { findViewById<TextView>(R.id.decrypted_text) }

  private lateinit var cipher: Cipher

  private lateinit var secretKeySpec: SecretKeySpec

  override fun onCreate(savedInstanceState: Bundle?) {
    super.onCreate(savedInstanceState)
    setContentView(R.layout.activity_main)

    cipher = Cipher.getInstance("AES/CBC/PKCS7Padding", KEY_PROVIDER)
    secretKeySpec = SecretKeySpec(privateKey.toByteArray(CHARSET), cipher.algorithm)

    button.setOnClickListener {
      val plainText = editText.text.toString()

      val encryptedString = encrypto(plainText)
      encryptedTextView.text = encryptedString

      val decryptedString = decrypto(encryptedString)
      decryptedTextView.text = decryptedString
    }

  }

  private fun encrypto(plainText: String): String {
    var encrypted: ByteArray = ByteArray(KEY_LENGTH)

    try {
      cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec)
      encrypted = cipher.doFinal(plainText.toByteArray(CHARSET))
    } catch (e: Exception) {
      Log.d("Main", e.toString())
    }
    val iv = cipher.iv
    val buffer = ByteArray(iv.size + encrypted.size)
    System.arraycopy(iv, 0, buffer, 0, iv.size)
    System.arraycopy(encrypted, 0, buffer, iv.size, encrypted.size)

    return Base64.encodeToString(buffer, Base64.DEFAULT)
  }

  private fun decrypto(encrypted: String): String {
    val buffer = Base64.decode(encrypted, Base64.DEFAULT)
    var decrypted: ByteArray = ByteArray(KEY_LENGTH)

    try {
      cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, IvParameterSpec(buffer, 0, KEY_LENGTH))
      decrypted = cipher.doFinal(buffer, KEY_LENGTH, buffer.size - KEY_LENGTH)
    } catch (e: Exception) {
      Log.d("Main", e.toString())
    } finally {
      return String(decrypted, CHARSET)
    }
  }

  companion object {
    val KEY_LENGTH = 128 / 8

    val CHARSET = Charset.forName("UTF-8")
  }
}
