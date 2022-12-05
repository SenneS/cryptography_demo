package be.senne.util

import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.SecureRandom
import java.security.interfaces.ECPrivateKey
import java.security.spec.ECGenParameterSpec
import javax.crypto.Cipher
import javax.crypto.Cipher.DECRYPT_MODE
import javax.crypto.Cipher.ENCRYPT_MODE
import javax.crypto.KeyAgreement
import javax.crypto.SecretKey
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec


private fun createKey(key: ByteArray) : SecretKey {
    return SecretKeySpec(key, "AES")
}
private fun createIv(iv: ByteArray) : IvParameterSpec {
    return IvParameterSpec(iv)
}

fun ecbEncrypt(input: ByteArray, key: ByteArray) : ByteArray {
    val cipher = Cipher.getInstance("AES/ECB/ZeroBytePadding", "BC");
    cipher.init(ENCRYPT_MODE, createKey(key))
    return cipher.doFinal(input)
}
fun ecbDecrypt(input: ByteArray, key: ByteArray) : ByteArray {
    val cipher = Cipher.getInstance("AES/ECB/ZeroBytePadding", "BC");
    cipher.init(DECRYPT_MODE, createKey(key))
    return cipher.doFinal(input)
}

fun cbcEncrypt(input: ByteArray, key: ByteArray, iv: ByteArray) : ByteArray {
    val cipher = Cipher.getInstance("AES/CBC/ZeroBytePadding", "BC");
    cipher.init(ENCRYPT_MODE, createKey(key), createIv(iv))
    return cipher.doFinal(input)
}
fun cbcDecrypt(input: ByteArray, key: ByteArray, iv: ByteArray) : ByteArray {
    val cipher = Cipher.getInstance("AES/CBC/ZeroBytePadding", "BC");
    cipher.init(DECRYPT_MODE, createKey(key), createIv(iv))
    return cipher.doFinal(input)
}

private fun dumpKey(key : KeyPair) {

    println("   private: ${key.private.encoded.asUByteArray().joinToString { it.toString(16).padStart(2, '0') }}")
    println("   public: ${key.public.encoded.asUByteArray().joinToString { it.toString(16).padStart(2, '0') }}")
}

//DH test met 256 bit priem getallen => 256bit shared secret
//Dit is een manier om een gedeeld geheim te maken over een mogelijks onveilig kanaal
fun DiffieHellman() {
    println("DH Test")

    val ecParameter = ECGenParameterSpec("P-256")
    var keygen = KeyPairGenerator.getInstance("ECDH", "BC");
    keygen.initialize(ecParameter, SecureRandom())

    val key1 = keygen.genKeyPair()
    dumpKey(key1)

    val key2 = keygen.genKeyPair()
    dumpKey(key2)

    val keyAgreement = KeyAgreement.getInstance("ECDH", "BC")

    keyAgreement.init(key1.private)
    keyAgreement.doPhase(key2.public, true)
    val secret1 = keyAgreement.generateSecret()

    keyAgreement.init(key2.private)
    keyAgreement.doPhase(key1.public, true)
    val secret2 = keyAgreement.generateSecret()

    //asUByteArray() is nodig om geen negatieve getallen te hebben boven 0x7F
    println("   geheim 1: ${secret1.asUByteArray().joinToString { it.toString(16).padStart(2, '0') }}")
    println("   geheim 2: ${secret2.asUByteArray().joinToString { it.toString(16).padStart(2, '0') }}")
}