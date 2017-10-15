import algorithm.impl.Des

/**
  * @author Oleksandr Shevchenko
  * @since 30.09.17
  */
object Main {
  def main(args: Array[String]) {
    val MESSAGE = "This is secret message!!!"
    val KEY = "Secret key"
    val des = new Des()
    println("Input: " + MESSAGE)
    val cipher = des.encrypt(MESSAGE, KEY)
    println("Encrypted: " + cipher)
    println("Decrypted: " + des.decrypt(cipher, KEY))
  }

}
