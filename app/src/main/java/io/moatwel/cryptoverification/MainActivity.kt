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
import se.simbio.encryption.Encryption
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import javax.crypto.Cipher
import javax.crypto.CipherInputStream
import javax.crypto.CipherOutputStream
import com.kazakago.cryptore.CipherAlgorithm
import com.kazakago.cryptore.Cryptore
import com.kazakago.cryptore.DecryptResult
import com.kazakago.cryptore.EncryptionPadding


class MainActivity : AppCompatActivity() {

  private lateinit var keyStore: KeyStore

  private val KEY_ALIAS = "SampleKey"

  private val KEY_PROVIDER = "AndroidKeyStore"

//  private val ALGORITHM = "RSA/ECB/NoPadding"
//  private val ALGORITHM = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding"
//  private val ALGORITHM = "RSA/ECB/OAEPWithSHA-512AndMGF1Padding"
  private val ALGORITHM = "RSA/ECB/OAEPPadding"
//  private val ALGORITHM = "AES/CBC/PKCS7Padding"

  val button by lazy { findViewById<Button>(R.id.do_encrypt) }

  override fun onCreate(savedInstanceState: Bundle?) {
    super.onCreate(savedInstanceState)
    setContentView(R.layout.activity_main)

    createKeyStore()

    val builder = Cryptore.Builder(KEY_ALIAS, CipherAlgorithm.RSA)
    val encryptor = builder.build()

    button.setOnClickListener {
      val encryptedText = findViewById<TextView>(R.id.encrypted_text)
      val decryptedText = findViewById<TextView>(R.id.decrypted_text)
      val editText = findViewById<EditText>(R.id.plain_text)

//      val encryptedString = encryptString(keyStore, KEY_ALIAS, editText.text.toString())
//      val encryptedString = encryption.encrypt(editText.text.toString())
      val encryptedStringResult = encryptor.encrypt(editText.text.toString().toByteArray())
      val encryptedString = Base64.encodeToString(encryptedStringResult.bytes, Base64.DEFAULT)
      encryptedText.text = encryptedString

      val decryptoResult = encryptor.decrypt(Base64.decode(encryptedString, Base64.DEFAULT))
      val decryptedString = decryptoResult.bytes.toString()
//      val decryptedString = decryptString(keyStore, KEY_ALIAS, encryptedString)
//      val decryptedString = encryption.decryptOrNull(encryptedString)
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
        val keyPairGenerator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, KEY_PROVIDER)
        keyPairGenerator.initialize(
          KeyGenParameterSpec.Builder(
            alias,
            KeyProperties.PURPOSE_SIGN)
            .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
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
