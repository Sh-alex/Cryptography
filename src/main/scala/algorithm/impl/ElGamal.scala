package algorithm.impl

import java.security.SecureRandom

import scala.math.BigInt
import scala.util.Random

/**
  * @author Oleksandr Shevchenko
  * @since 21.10.17
  */
class ElGamal {
  private val sc = new SecureRandom()
  private val prime = BigInt.probablePrime(64, Random)

  private val privateKey = BigInt(64, sc) //1 < x < p -> 1 < privateKey < prime

  def encrypt(message: Array[Byte]): Array[(BigInt, BigInt)] = {
    for (m <- message) yield encrypt(m.toInt)
  }

  def decrypt(cipher:Array[(BigInt, BigInt)]): Array[Byte] = {
    for (c <- cipher) yield decrypt(c).toByte
  }

  def encrypt(message: BigInt): (BigInt, BigInt) = {
    val g = BigInt(2).modPow(privateKey, prime)
    val y = g.modPow(privateKey, prime)
    val k = BigInt(64, sc) //1 < k < p -> 1 < k < prime

    val alpha = g.modPow(k, prime)
    val beta = y.modPow(k, prime).modInverse(prime) * message mod prime

    (alpha, beta)
  }

  def decrypt(cipher: (BigInt, BigInt)): BigInt = {
    // M=b(a^{-x}) mod p
    val message = cipher._2 * cipher._1.modPow(-privateKey, prime).modInverse(prime) mod prime
    message
  }
}
