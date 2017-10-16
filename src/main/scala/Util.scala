/**
  * @author Oleksandr Shevchenko
  * @since 16.10.17
  */
object Util {
  def messageToBlockSize(message: String, blockSize: Int): String = {
    val strBuilder = new StringBuilder(message)
    while (strBuilder.toString().length % blockSize != 0)
      strBuilder.append("#")

    strBuilder.toString()
  }

  def keyToRightSize(key: String, keySize: Int): String = {
    val strBuilder = new StringBuilder(key)
    while (strBuilder.toString().length % keySize != 0)
      strBuilder.append("#")

    strBuilder.toString()
  }

  def trimMessage(message: String, symbol: Char): String = {
    message.filterNot((x: Char) => x.equals('#'))
  }
}
