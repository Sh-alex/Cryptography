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
    val cipherDes = des.encrypt(MESSAGE, KEY)
    println("Encrypted: " + cipherDes)
    println("Decrypted: " + des.decrypt(cipherDes, KEY))

    println("------------AES------------")
    val aes = new Aes()
    println("Input: " + MESSAGE)
    val cipherAes = aes.encrypt(MESSAGE, KEY)
    val encryptedStr: String = new String(cipherAes.map(_.toByte))
    println("Encrypted: ")
    println(encryptedStr)
    val decryptedStr = new String(aes.decrypt(cipherAes, KEY.getBytes()).map(_.toByte))
      .filterNot((x: Char) => x.equals('#'))
    println("Decrypted: " + decryptedStr)
  }

}
