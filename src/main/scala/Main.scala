import algorithm.impl.Des

/**
  * @author Oleksandr Shevchenko
  * @since 30.09.17
  */
object Main {
  def main(args: Array[String]) {
    val MESSAGE = "1234567890abcdefghkjmlno"
    val KEY = "asdasasdrfgt"
    val des = new Des()
    println(MESSAGE)
    println(des.encrypt(MESSAGE, KEY))
    println(des.decrypt(des.encrypt(MESSAGE, KEY), KEY))
  }

}
