package io.moatwel.cryptoverification

import android.os.Bundle
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.support.v7.app.AppCompatActivity
import android.util.Base64
import android.util.Log
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import javax.crypto.Cipher
import javax.crypto.CipherInputStream
import javax.crypto.CipherOutputStream


class MainActivity : AppCompatActivity() {

  private lateinit var keyStore: KeyStore

  private val KEY_ALIAS = "SampleKey"

  private val KEY_PROVIDER = "AndroidKeyStore"

  private val ALGORITHM = "RSA/ECB/NoPadding"
//  private val ALGORITHM = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding"
//  private val ALGORITHM = "RSA/ECB/OAEPWithSHA-512AndMGF1Padding"
//  private val ALGORITHM = "RSA/ECB/OAEPPadding"

  val button by lazy { findViewById<Button>(R.id.do_encrypt) }

  override fun onCreate(savedInstanceState: Bundle?) {
    super.onCreate(savedInstanceState)
    setContentView(R.layout.activity_main)

    createKeyStore()

    button.setOnClickListener {
      val encryptedText = findViewById<TextView>(R.id.encrypted_text)
      val decryptedText = findViewById<TextView>(R.id.decrypted_text)
      val editText = findViewById<EditText>(R.id.plain_text)

      val encryptedString = encryptString(keyStore, KEY_ALIAS, editText.text.toString())
      encryptedText.text = encryptedString

      val decryptedString = decryptString(keyStore, KEY_ALIAS, encryptedString)
      decryptedText.text = decryptedString
    }

  }

  private fun createKeyStore() {
    try {
      keyStore = KeyStore.getInstance(KEY_PROVIDER)
      keyStore.load(null)
      createKey(keyStore, KEY_ALIAS)
    } catch (e: Exception) {
      Log.d("MainActivity", e.toString())
    }
  }

  private fun createKey(keyStore: KeyStore, alias: String) {
    try {
      // Create new key if needed
      if (!keyStore.containsAlias(alias)) {
        val keyPairGenerator = KeyPairGenerator.getInstance(
          KeyProperties.KEY_ALGORITHM_RSA, KEY_PROVIDER)
        keyPairGenerator.initialize(
          KeyGenParameterSpec.Builder(
            alias,
            KeyProperties.PURPOSE_DECRYPT)
//            .setBlockModes(KeyProperties.BLOCK_MODE_ECB)
            .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
            .build())
        keyPairGenerator.generateKeyPair()
      }
    } catch (e: Exception) {
      Log.e("MainActivity", e.toString())
    }

  }

  private fun encryptString(keyStore: KeyStore, alias: String, plainText: String): String {
    var encryptedText: String = ""
    try {
      val publicKey = keyStore.getCertificate(alias).publicKey

      val cipher = Cipher.getInstance(ALGORITHM)
      cipher.init(Cipher.ENCRYPT_MODE, publicKey)

      val outputStream = ByteArrayOutputStream()
      val cipherOutputStream = CipherOutputStream(outputStream, cipher)
      cipherOutputStream.write(plainText.toByteArray(charset("UTF-8")))
      cipherOutputStream.close()

      val bytes = outputStream.toByteArray()
      encryptedText = Base64.encodeToString(bytes, Base64.DEFAULT)
    } catch (e: Exception) {
      Log.e("MainActivity", e.toString())
    }

    return encryptedText
  }

  private fun decryptString(keyStore: KeyStore, alias: String, encryptedText: String): String {
    var decryptText = ""
    try {
      val privateKey = keyStore.getKey(alias, null) as PrivateKey

      val cipher = Cipher.getInstance(ALGORITHM)
      cipher.init(Cipher.DECRYPT_MODE, privateKey)

      val cipherInputStream = CipherInputStream(
        ByteArrayInputStream(Base64.decode(encryptedText, Base64.DEFAULT)), cipher)

      val outputStream = ByteArrayOutputStream()
      var byte = cipherInputStream.read()
      while (byte != -1) {
        outputStream.write(byte)
        byte = cipherInputStream.read()
      }
      outputStream.close()
      decryptText = outputStream.toString("UTF-8")
    } catch (e: Exception) {
      Log.e("MainActivity", e.toString())
    }

    return decryptText
  }
}
