import be.senne.util.*
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.lang.Exception
import java.lang.StringBuilder
import java.security.SecureRandom
import java.security.Security
import javax.crypto.Cipher
import javax.crypto.Cipher.DECRYPT_MODE
import javax.crypto.Cipher.ENCRYPT_MODE
import javax.crypto.SecretKey
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec


fun main(args: Array<String>) {

    //AES -> blokken zijn 16 bytes
    //- ECB -> standaard
    //- CBC -> eerst de blok xor'en met de geencrypteerde bytes van de vorige blok (eerste blok gebruikt een iv initialisation vector)
    //-         -> hierdoor kan je het verschil niet zien door 2 identieke blokken geencrypteerd met dezelfde sleutel.
    //-         -> (16 00 bytes, 16 AA bytes, 16 00 bytes) gencrypteerd met ecb zullen identiek zijn voor posities 0x00 en 0x10 in CBC mode niet.
    //- GCM -> CBC heeft geen ingebouwd mechanisme om te verifieren of de gencrypteerde bytes aangepast worden en blokken zijn afhankelijk van de vorige blok
    //         GCM daarentegen is niet afhankelijk van de data van de vorige blok en heeft een manier om te verifieren of de data aangetast is geweest.

    //registreer bouncy castle als security provider
    Security.addProvider(BouncyCastleProvider())

    val aesKey = "CF 86 86 D5 2D 7B FA D1 83 64 6F 75 F6 DA 0B 45".hexStringToByteArray()
    val aesIv  = "4B 53 A9 92 F5 F7 34 7E 0E 2D 45 D9 04 25 C1 C4".hexStringToByteArray()
    val data   = "48 61 6C 6C 6F 20 3A 29 00 00 00 00 00 00 00 00".hexStringToByteArray()

    val encryptedEcb = ecbEncrypt(data, aesKey)
    val decryptedEcb = ecbDecrypt(encryptedEcb, aesKey)

    val encryptedCbc = cbcEncrypt(data, aesKey, aesIv)
    val decryptedCbc = cbcDecrypt(encryptedCbc, aesKey, aesIv)

    println("Aes Tests:")
    println("   ECB ENC: ${bytesToString(encryptedEcb)}")
    println("   ECB DEC: ${bytesToString(decryptedEcb)}")

    println("   CBC ENC: ${bytesToString(encryptedCbc)}")
    println("   CBC DEC: ${bytesToString(decryptedCbc)}")


    DiffieHellman()

}

fun bytesToString(bytes : ByteArray) : String {
    return bytes.joinToString { byte -> byte.toUByte().toString(16) }
}

fun String.hexStringToByteArray() : ByteArray {
    val hexString = this.filter { character -> !character.isWhitespace() }

    if((hexString.length % 2) != 0) {
        throw Exception()
    }

    //eerst naar int ipv byte omdat er geen unsigned is en zelfs hun parsers begrijpen niet wat een byte 0x80 >= is.
    return hexString.chunked(2).map {str -> str.toInt(16).toByte() }.toByteArray()
}