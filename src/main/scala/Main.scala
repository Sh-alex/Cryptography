import algorithm.impl.{Aes, Des}

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
    println("Input: " + MESSAGE)

    val cipherDes = des.encrypt(Util.messageToBlockSize(MESSAGE, 64).getBytes().map(_.toInt), Util.keyToRightSize(KEY, 56).getBytes().map(_.toInt))
    println("Encrypted: " + new String(cipherDes.map(_.toByte)))
    println("Decrypted: " + Util.trimMessage(new String(des.decrypt(cipherDes, Util.keyToRightSize(KEY, 56).getBytes().map(_.toInt)).map(_.toByte)), '#'))

    println("------------AES------------")
    val aes = new Aes()
    println("Input: " + MESSAGE)
    val cipherAes = aes.encrypt(Util.messageToBlockSize(MESSAGE, 16).getBytes().map(_.toInt), Util.keyToRightSize(KEY, 16).getBytes().map(_.toInt))
    val encryptedStr: String = new String(cipherAes.map(_.toByte))
    println("Encrypted: ")
    println(encryptedStr)
    val decryptedStr = Util.trimMessage(new String(aes.decrypt(cipherAes, Util.keyToRightSize(KEY, 16).getBytes().map(_.toInt)).map(_.toByte)), '#')
    println("Decrypted: " + decryptedStr)
  }

}
