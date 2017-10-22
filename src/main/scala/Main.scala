import algorithm.impl.{Aes, Des, ElGamal, Rsa}

/**
  * @author Oleksandr Shevchenko
  * @since 30.09.17
  */
object Main {
  def main(args: Array[String]) {
    val MESSAGE = "This is secret message!!!"
    val KEY = "Secret key!!!!!!"

    println("------------DES------------")
    val des = new Des()
    val cipherDes = des.encrypt(Util.messageToBlockSize(MESSAGE, 64).getBytes().map(_.toInt), Util.keyToRightSize(KEY, 56).getBytes().map(_.toInt))
    println("Input: " + MESSAGE)
    println("Encrypted: " + new String(cipherDes.map(_.toByte)))
    println("Decrypted: " + Util.trimMessage(new String(des.decrypt(cipherDes, Util.keyToRightSize(KEY, 56).getBytes().map(_.toInt)).map(_.toByte)), '#'))

    println("------------AES------------")
    val aes = new Aes()
    val cipherAes = aes.encrypt(Util.messageToBlockSize(MESSAGE, 16).getBytes().map(_.toInt), Util.keyToRightSize(KEY, 16).getBytes().map(_.toInt))
    val encryptedStr: String = new String(cipherAes.map(_.toByte))
    val decryptedStr = Util.trimMessage(new String(aes.decrypt(cipherAes, Util.keyToRightSize(KEY, 16).getBytes().map(_.toInt)).map(_.toByte)), '#')
    println("Input: " + MESSAGE)
    println("Encrypted: ")
    println(encryptedStr)
    println("Decrypted: " + decryptedStr)

    println("------------RSA------------")
    val rsa = new Rsa(16)
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
  }

}
