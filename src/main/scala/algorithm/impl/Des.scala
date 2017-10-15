package algorithm.impl

import algorithm.Encryption

/**
  * @author Oleksandr Shevchenko
  * @since 07.10.17
  */
class Des extends Encryption {

  val NUM_FEISTEL = 16

  override def encrypt(message: String, key: String): String = {
    val bytes = message.getBytes()
    var keyBytes = key.getBytes()


    var left = bytes.take(bytes.length / 2)
    var right = bytes.drop(bytes.length / 2)

    for (i <- 1 to NUM_FEISTEL) {
      val temp: Array[Byte] = left.clone()
      left = right.clone()
      right = temp.zip(feistelFunction(right, keyBytes)).map { case (x, y) => x ^ y }.map(_.toByte)

      keyBytes = keyBytes.last +: keyBytes.dropRight(1)
    }
    new String(left ++ right)
  }

  override def decrypt(message: String, key: String): String = {
    val bytes = message.getBytes()
    var keyBytes = key.getBytes()


    var right = bytes.take(bytes.length / 2)
    var left = bytes.drop(bytes.length / 2)


    for (i <- 1 until NUM_FEISTEL) {
      keyBytes = keyBytes.last +: keyBytes.dropRight(1)
    }
    for (i <- 1 to NUM_FEISTEL) {
      val temp: Array[Byte] = left.clone()
      left = right.clone()
      right = temp.zip(feistelFunction(right, keyBytes)).map { case (x, y) => x ^ y }.map(_.toByte)

      keyBytes = keyBytes.tail :+ keyBytes.head
    }
    new String(right ++ left)

  }

  private def feistelFunction(message: Array[Byte], key: Array[Byte]): Array[Byte] = {
    (message, key).zipped.map(_ ^ _).map(_.toByte)
  }
}
