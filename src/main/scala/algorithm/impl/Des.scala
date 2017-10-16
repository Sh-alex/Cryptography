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

  override def encrypt(message: Array[Int], key: Array[Int]): Array[Int] = {
    encryptInternal(message, key, isEncrypt = true)
  }

  override def decrypt(message: Array[Int], key: Array[Int]): Array[Int] = {
    encryptInternal(message, key, isEncrypt = false)
  }

  private def encryptInternal(bytes: Array[Int], keyBytes: Array[Int], isEncrypt: Boolean): Array[Int] = {
    var result = Array.empty[Int]

    val blocks = bytes.sliding(BLOCK_SIZE, BLOCK_SIZE).toList
    for (block <- blocks) {
      var keyForBlock = keyBytes.clone()
      var right = block.take(block.length / 2)
      var left = block.drop(block.length / 2)

      if (!isEncrypt) {
        for (_ <- 1 until NUM_FEISTEL) {
          keyForBlock = keyForBlock.last +: keyForBlock.dropRight(1)
        }
      }

      for (_ <- 1 to NUM_FEISTEL) {
        val temp: Array[Int] = left.clone()
        //L = R
        //R = L xor f(R, k)
        left = right.clone()
        right = temp.zip(feistelFunction(right, keyForBlock)).map { case (x, y) => x ^ y }

        if (isEncrypt)
          keyForBlock = keyForBlock.last +: keyForBlock.dropRight(1) //right shift
        else
          keyForBlock = keyForBlock.tail :+ keyForBlock.head //left shift
      }

      result ++= left ++ right
    }
    result
  }


  private def feistelFunction(message: Array[Int], key: Array[Int]): Array[Int] = {
    //Ri xor ki
    (message, key).zipped.map(_ ^ _)
  }
}
