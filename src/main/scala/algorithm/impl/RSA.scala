package algorithm.impl

import scala.util.Random
import math._

/**
  * @author Oleksandr Shevchenko
  * @since 21.10.17
  */

class RSA(val keySize: Int) {

  require(keySize > 0)

  private val p = generatePrime(keySize / 2)
  private val q = generatePrime(keySize / 2)
  private val n = p * q
  private val phi = (p - 1)  * (q - 1)

  var publicKey = BigInt(3) // e=3 (open exp)
  publicKey = generatePublicKey()
  private val privateKey = publicKey.modInverse(phi) //d=e^{-1} mod phi

  def encrypt(message: BigInt): BigInt = {
    message.modPow(publicKey, n) //message^e mod n
  }

  def decrypt(cipher: BigInt): BigInt = {
    cipher.modPow(privateKey, n) //cipher^d mod n
  }

  def encrypt(message: Array[Byte]): Array[BigInt] = {
    message.map(x => Array[Byte](x)).map(enc)
  }

  def decrypt(cipher: Array[BigInt]): Array[Byte] = {
    cipher.map(decrypt).flatMap(_.toByteArray)
  }

  private def generatePublicKey(): BigInt = {
    while (phi.gcd(publicKey).intValue() > 1) {
      publicKey += 2
    }
    publicKey
  }

  private def generatePrime(bitLength: Int): BigInt = {
    BigInt.probablePrime(bitLength, Random)
  }

  /* Java accomplishes this by performing Miller-Rabin primality tests,
   * the number of which is based on certainty (and a Lucas-Lehmer test)
   */
  private def isPrime(number: Int, certainty: Int): Boolean = {
    BigInt(number).isProbablePrime(certainty)
  }


  private def enc(message: Array[Byte]): BigInt = {
    BigInt(message).modPow(publicKey, n)
  }

  override def toString(): String = {
    new String (s"p: $p\nq: $q\nphi: $phi\nn: $n\npublic: $publicKey\nprivate: $privateKey" )
  }
}