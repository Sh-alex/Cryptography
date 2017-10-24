package algorithm.impl

import org.bouncycastle.crypto.digests.DSTU7564Digest

/**
  * @author Oleksandr Shevchenko
  * @since 24.10.17
  */
//DSTU7564
class Kupyna {

  private val HASH_SIZE = 512

  def hash(s: String): String = {
    val dstu7564 = new DSTU7564Digest(HASH_SIZE)
    dstu7564.update(s.getBytes(), 0, s.getBytes().length)
    val bytes = new Array[Byte](HASH_SIZE / 8)
    dstu7564.doFinal(bytes, 0)

    new String(bytes)
  }
}
