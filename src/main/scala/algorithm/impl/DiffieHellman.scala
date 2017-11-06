package algorithm.impl

/**
  * @author Oleksandr Shevchenko
  * @since 06.11.17
  */
import scala.util.Random

class DiffieHellman (val p: BigInt, val g: Int, val name: String) {

  // private key is generated once and for always
  // (re-generating the private key breaks the algorithm)
  private val privateKey: BigInt = this.random(1024)

  // public key is g^privateKey mod p
  val publicKey: BigInt = expMod(g, privateKey, p)

  // initialize to public key
  var secret: BigInt = publicKey

  def resetSecret(): Unit =
    secret = publicKey

  // take what we have already and raise it to
  // the power of our private key modulo p.
  def combineSecretWithPrivateKey(): Unit =
    secret = expMod(secret, privateKey, p)

  // calculates a^b mod c
  private def expMod(a: BigInt, b: BigInt, c: BigInt): BigInt = a.modPow(b, c)

  // generates a random number for a given number of bits
  private def random(n: Int): BigInt = BigInt(n, new Random())
}

object DiffieHellman {
  def randomPrime(n: Int): BigInt = BigInt.probablePrime(n, new Random())

  def rotate[T](list: List[T]): List[T] = (list.head :: list.tail.reverse).reverse

  // share all public keys with all participants,
  // for any number of participants
  def doKeyExchange(participants: List[DiffieHellman]): Boolean = {

    // reset everything
    participants.foreach(p => p.resetSecret())

    for (_ <- 1 until participants.length) {

      // get and rotate the intermediates
      val intermediates = participants.map(p => p.secret)

      // rotate the intermediates
      val rotated = rotate(intermediates)

      // map them into the participants
      (participants, rotated).zipped.map((p, i) => p.secret = i)

      // mix with participant's private key
      participants.foreach(p => p.combineSecretWithPrivateKey())
    }

    // return true if all secret keys are equal
    participants.map(p => p.secret).distinct.length == 1
  }
}
