package algorithm

/**
  * @author Oleksandr Shevchenko
  * @since 07.10.17
  */
trait Encryption {
  def encrypt(message: Array[Int], key: Array[Int]): Array[Int]

  def decrypt(message: Array[Int], key: Array[Int]): Array[Int]
}