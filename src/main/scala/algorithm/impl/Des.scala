package algorithm.impl

import algorithm.Encryption

/**
  * @author Oleksandr Shevchenko
  * @since 07.10.17
  */
class Des extends Encryption {

  private val NUM_FEISTEL = 16
  private val BLOCK_SIZE = 64
  private val KEY_SIZE = 56

  override def encrypt(message: String, key: String): String = {
    val messageForEncrypt = messageToBlockSize(message)
    val keyForEncrypt = keyToRightSize(key)
    encryptInternal(messageForEncrypt, keyForEncrypt, isEncrypt = true)
  }

  override def decrypt(message: String, key: String): String = {
    val messageForDecrypt = messageToBlockSize(message)
    val keyForDecrypt = keyToRightSize(key)
    encryptInternal(messageForDecrypt, keyForDecrypt, isEncrypt = false)
      .filterNot((x: Char) => x.equals('#'))
  }

  private def encryptInternal(message: String, key: String, isEncrypt: Boolean): String = {
    val bytes = message.getBytes()
    val keyBytes = key.getBytes()
    val result = new StringBuilder("")

    val blocks = bytes.sliding(BLOCK_SIZE, BLOCK_SIZE).toList
    for(block <- blocks) {

      var keyForBlock = keyBytes.clone()
      var right = block.take(block.length / 2)
      var left = block.drop(block.length / 2)

      if (!isEncrypt) {
        for (i <- 1 until NUM_FEISTEL) {
          keyForBlock = keyForBlock.last +: keyForBlock.dropRight(1)
        }
      }

      for (i <- 1 to NUM_FEISTEL) {
        val temp: Array[Byte] = left.clone()
        //L = R
        //R = L xor f(R, k)
        left = right.clone()
        right = temp.zip(feistelFunction(right, keyForBlock)).map { case (x, y) => x ^ y }.map(_.toByte)

        if (isEncrypt)
          keyForBlock = keyForBlock.last +: keyForBlock.dropRight(1) //right shift
        else
          keyForBlock = keyForBlock.tail :+ keyForBlock.head //left shift
      }

      result.append(new String(left ++ right))
    }
    result.toString()
  }

  private def messageToBlockSize(message: String): String = {
    val strBuilder = new StringBuilder(message)
    while (strBuilder.toString().length % BLOCK_SIZE != 0)
      strBuilder.append("#")

    strBuilder.toString()
  }

  private def keyToRightSize(key: String): String = {
    val strBuilder = new StringBuilder(key)
    while (strBuilder.toString().length % KEY_SIZE != 0)
      strBuilder.append("#")

    strBuilder.toString()
  }

  private def feistelFunction(message: Array[Byte], key: Array[Byte]): Array[Byte] = {
    //Ri xor ki
    (message, key).zipped.map(_ ^ _).map(_.toByte)
  }
}
