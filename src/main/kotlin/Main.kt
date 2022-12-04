import org.bouncycastle.jce.provider.BouncyCastleProvider
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

    val aesKey : SecretKey = SecretKeySpec("00112233445566778899AABBCCDDEEFF".hexStringToByteArray(), "AES")

    val encryptor = Cipher.getInstance("AES/ECB/NoPadding", "BC");
    encryptor.init(ENCRYPT_MODE, aesKey)

    val decryptor = Cipher.getInstance("AES/ECB/NoPadding", "BC");
    decryptor.init(DECRYPT_MODE, aesKey)

    val plaintext = "AABBCCDDAABBCCDDAABBCCDDAABBCCDD".hexStringToByteArray()

    val encrypted_bytes = encryptor.doFinal(plaintext)
    val decrypted_bytes = decryptor.doFinal(encrypted_bytes)

    println(encrypted_bytes.joinToString { byte -> "%02X".format(byte) })
    println(decrypted_bytes.joinToString { byte -> "%02X".format(byte) })
}

fun String.hexStringToByteArray() : ByteArray? {
    val hexString = this

    if((hexString.length % 2) != 0) {
        return null
    }

    //eerst naar int ipv byte omdat er geen unsigned is en zelfs hun parsers begrijpen niet wat een byte 0x80 >= is.
    return hexString.chunked(2).map {str -> str.toInt(16).toByte() }.toByteArray()

}