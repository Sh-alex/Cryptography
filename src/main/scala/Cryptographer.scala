import java.io.File

import algorithm.Encryption

/**
  * @author Oleksandr Shevchenko
  * @since 07.10.17
  */
trait Cryptographer {
  def encrypt(encryption: Encryption)

  def encrypt(encryption: Encryption, key: Key)

  def encrypt(encryption: Encryption, key: Key, srcFile: File)

  def decrypt(encryption: Encryption)

  def decrypt(encryption: Encryption, key: Key)

  def decrypt(encryption: Encryption, key: Key, dstFile: File)
}