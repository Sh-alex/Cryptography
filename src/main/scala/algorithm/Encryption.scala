package algorithm

/**
  * @author Oleksandr Shevchenko
  * @since 07.10.17
  */
trait Encryption {
  def encrypt(message: String, key: String): String

  def decrypt(message: String, key: String): String
}