import algorithm.impl._

/**
  * @author Oleksandr Shevchenko
  * @since 30.09.17
  */
object Main {
  def main(args: Array[String]) {
    val MESSAGE = "This is secret message!!!"
    val KEY = "Secret key!!!!!!"

    println("------------DES------------")
    val des = new DES()
    val cipherDes = des.encrypt(Util.messageToBlockSize(MESSAGE, 64).getBytes().map(_.toInt), Util.keyToRightSize(KEY, 56).getBytes().map(_.toInt))
    println("Input: " + MESSAGE)
    println("Encrypted: " + new String(cipherDes.map(_.toByte)))
    println("Decrypted: " + Util.trimMessage(new String(des.decrypt(cipherDes, Util.keyToRightSize(KEY, 56).getBytes().map(_.toInt)).map(_.toByte)), '#'))

    println("------------AES------------")
    val aes = new AES()
    val cipherAes = aes.encrypt(Util.messageToBlockSize(MESSAGE, 16).getBytes().map(_.toInt), Util.keyToRightSize(KEY, 16).getBytes().map(_.toInt))
    val encryptedStr: String = new String(cipherAes.map(_.toByte))
    val decryptedStr = Util.trimMessage(new String(aes.decrypt(cipherAes, Util.keyToRightSize(KEY, 16).getBytes().map(_.toInt)).map(_.toByte)), '#')
    println("Input: " + MESSAGE)
    println("Encrypted: ")
    println(encryptedStr)
    println("Decrypted: " + decryptedStr)

    println("------------RSA------------")
    val rsa = new RSA(2048)
    val encRsa = rsa.encrypt(MESSAGE.getBytes)
    val decRsa = rsa.decrypt(encRsa)
    val decryptedRsa = new String(decRsa)
    println("Input: " + MESSAGE)
    println("Encrypted: " + encRsa.deep.mkString(", "))
    println("Decrypted: " + decryptedRsa)
    //println(rsa.toString())

    println("------------ElGamal------------")
    val elgamal = new ElGamal()
    val encElGamal = elgamal.encrypt(MESSAGE.getBytes())
    val decElGamal = elgamal.decrypt(encElGamal)
    val decryptedElGamal = new String(decElGamal)
    println("Input: " + MESSAGE)
    println("Encrypted: " + encElGamal.deep.mkString(", "))
    println("Decrypted: " + decryptedElGamal)

    println("------------MD5------------")
    val md = new MD5()
    val hashMD5 = md.hash(MESSAGE)
    println("Input: " + MESSAGE)
    println(s"Hash: $hashMD5")

    println("------------SHA3------------")
    val sha = new SHA3()
    val hashSHA = sha.hash(MESSAGE)
    println("Input: " + MESSAGE)
    println(s"Hash: $hashSHA")

    println("------------Kupyna------------")
    val kupyna = new Kupyna()
    val hashKupyna = kupyna.hash(MESSAGE)
    println("Input: " + MESSAGE)
    println(s"Hash: $hashKupyna")

    println("------------Digital signature------------")
    println("------------RSA with MD5------------")
    val digMd = new MD5()
    val digHashMD5 = digMd.hash(MESSAGE)
    val digRsa = new RSA(2048)
    val digEncRsa = digRsa.encrypt(digHashMD5.getBytes)

    val digDecRsa = digRsa.decrypt(digEncRsa)
    val clientDecrypted = new String(digDecRsa)
    val messageHash = digMd.hash(MESSAGE)

    val message = if (clientDecrypted.equals(messageHash)) "The digital signature is correct" else "The digital signature is forged!!!"
    println(s"$message\nclientDecrypted = $clientDecrypted\nmessageHash = $messageHash")

    println("------------ElGamal with SHA3------------")
    val digSha3ElGamal = new SHA3()
    val digHashSha3ElGamal = digSha3ElGamal.hash(MESSAGE)
    val digElGamal = new ElGamal()
    val digEncElGamal = digElGamal.encrypt(digHashSha3ElGamal.getBytes)

    val digDecElGamal = digElGamal.decrypt(digEncElGamal)
    val clientDecryptedElGamal = new String(digDecElGamal)
    val messageHashElGamal = digSha3ElGamal.hash(MESSAGE)

    val messageElGamal = if (clientDecryptedElGamal.equals(messageHashElGamal)) "The digital signature is correct" else "The digital signature is forged!!!"
    println(s"$messageElGamal\nclientDecrypted = $clientDecryptedElGamal\nmessageHash = $messageHashElGamal")

  }

}
