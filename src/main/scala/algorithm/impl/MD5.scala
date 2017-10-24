package algorithm.impl

/**
  * @author Oleksandr Shevchenko
  * @since 24.10.17
  */
class MD5 {

  private val ALGORITHM = "MD5"

  def hash(s: String): String = {
    val m = java.security.MessageDigest.getInstance(ALGORITHM)
    val b = s.getBytes("UTF-8")
    m.update(b, 0, b.length)

    new java.math.BigInteger(1, m.digest()).toString(16)
  }

 }
