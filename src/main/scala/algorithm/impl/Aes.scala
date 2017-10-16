package algorithm.impl

import algorithm.Encryption

/**
  * @author Oleksandr Shevchenko
  * @since 07.10.17
  */
class Aes extends Encryption {

  private val Nb = 4 //AES, Nb = 4 (block size 128)
  private val Nk = 4 //AES, Nk = 4, 6, or 8 (key size 128/192/256 )
  private val NUM_ROUNDS = 10 //AES, Nr = 10, 12, 14 (128/192/256 )
  private val BLOCK_SIZE = 16

  override def encrypt(bytes: Array[Int], keyBytes: Array[Int]): Array[Int] = {

    var result = Array.empty[Int]

    val blocks = bytes.sliding(BLOCK_SIZE, BLOCK_SIZE).toList
    var state = Array.ofDim[Int](4, Nb)
    for (block <- blocks) {
      state = Array.ofDim[Int](4, Nb)
      //State[r][c] = input[r + 4c], r = 0,1...4; c = 0,1..Nb.
      for (r <- 0 until 4; c <- 0 until Nb)
        state(r)(c) = block(r + 4 * c)

      val keySchedule = keyExpansion(keyBytes)

      state = addRoundKey(state, keySchedule)

      for (rnd <- 1 until NUM_ROUNDS) {
        state = subBytes(state)
        state = shiftRows(state)
        state = mixColumns(state)
        state = addRoundKey(state, keySchedule, rnd)
      }

      state = subBytes(state)
      state = shiftRows(state)
      state = addRoundKey(state, keySchedule, NUM_ROUNDS)

      val output: Array[Int] = Array.ofDim[Int](4 * Nb)
      for (r <- 0 until 4; c <- 0 until Nb) {
        output(r + 4 * c) = state(r)(c)
      }

      result ++= output
    }

    result
  }

  override def decrypt(bytes: Array[Int], keyBytes: Array[Int]): Array[Int] = {

    var result = Array.empty[Int]

    val blocks = bytes.sliding(BLOCK_SIZE, BLOCK_SIZE).toList
    var state = Array.ofDim[Int](4, Nb)

    for (block <- blocks) {
      //State[r][c] = input[r + 4c], r = 0,1...4; c = 0,1..Nb.
      for (r <- 0 until 4; c <- 0 until Nb)
        state(r)(c) = block(r + 4 * c)

      val keySchedule = keyExpansion(keyBytes)

      state = addRoundKey(state, keySchedule, NUM_ROUNDS)

      var rnd = NUM_ROUNDS - 1
      while (rnd >= 1) {
        state = shiftRows(state, isEncrypt = false)
        state = subBytes(state, isEncrypt = false)
        state = addRoundKey(state, keySchedule, rnd)
        state = mixColumns(state, isEncrypt = false)

        rnd -= 1
      }

      state = shiftRows(state, isEncrypt = false)
      state = subBytes(state, isEncrypt = false)
      state = addRoundKey(state, keySchedule, rnd)

      val output = Array.ofDim[Int](4 * Nb)
      for (r <- 0 until 4; c <- 0 until Nb)
        output(r + 4 * c) = state(r)(c)

      result ++= output
    }

    result
  }

  private def mixColumns(state: Array[Array[Int]], isEncrypt: Boolean = true) = {
    for (i <- 0 until Nb) {
      var s0, s1, s2, s3: Int = 0

      if (isEncrypt) {
        s0 = mul_by_02(state(0)(i)) ^ mul_by_03(state(1)(i)) ^ state(2)(i) ^ state(3)(i)
        s1 = state(0)(i) ^ mul_by_02(state(1)(i)) ^ mul_by_03(state(2)(i)) ^ state(3)(i)
        s2 = state(0)(i) ^ state(1)(i) ^ mul_by_02(state(2)(i)) ^ mul_by_03(state(3)(i))
        s3 = mul_by_03(state(0)(i)) ^ state(1)(i) ^ state(2)(i) ^ mul_by_02(state(3)(i))
      }
      else {
        s0 = mul_by_0e(state(0)(i)) ^ mul_by_0b(state(1)(i)) ^ mul_by_0d(state(2)(i)) ^ mul_by_09(state(3)(i))
        s1 = mul_by_09(state(0)(i)) ^ mul_by_0e(state(1)(i)) ^ mul_by_0b(state(2)(i)) ^ mul_by_0d(state(3)(i))
        s2 = mul_by_0d(state(0)(i)) ^ mul_by_09(state(1)(i)) ^ mul_by_0e(state(2)(i)) ^ mul_by_0b(state(3)(i))
        s3 = mul_by_0b(state(0)(i)) ^ mul_by_0d(state(1)(i)) ^ mul_by_09(state(2)(i)) ^ mul_by_0e(state(3)(i))
      }

      state(0)(i) = s0
      state(1)(i) = s1
      state(2)(i) = s2
      state(3)(i) = s3
    }

    state
  }

  private def shiftRows(state: Array[Array[Int]], isEncrypt: Boolean = true) = {

    var count = 1

    if (isEncrypt)
      for (i <- 1 until Nb) {
        state(i) = leftShift(state(i), count)
        count += 1
      }
    else
      for (i <- 1 until Nb) {
        state(i) = rightShift(state(i), count)
        count += 1
      }

    state
  }

  private def leftShift(state: Array[Int], count: Int) = {
    var res = state.clone()
    for (_ <- 0 until count) {
      res = res.tail :+ res.head
    }

    res
  }

  private def rightShift(state: Array[Int], count: Int) = {
    var res = state.clone()
    for (_ <- 0 until count) {
      res = res.last +: res.dropRight(1)
    }

    res
  }

  private def subBytes(state: Array[Array[Int]], isEncrypt: Boolean = true): Array[Array[Int]] = {
    val box = if (isEncrypt) sBox else invSbox

    for (i <- state.indices; j <- state(i).indices) {
      val row = state(i)(j) / 0x10
      val col = state(i)(j) % 0x10

      val boxElem = box(BLOCK_SIZE * row + col)
      state(i)(j) = boxElem
    }

    state
  }

  private def addRoundKey(state: Array[Array[Int]], keySchedule: Array[Array[Int]],
                          numRounds: Int = 0): Array[Array[Int]] = {
    for (col <- 0 until Nk) {
      // nb*round is a shift which indicates start of a part of the KeySchedule
      val s0 = state(0)(col) ^ keySchedule(0)(Nb * numRounds + col)
      val s1 = state(1)(col) ^ keySchedule(1)(Nb * numRounds + col)
      val s2 = state(2)(col) ^ keySchedule(2)(Nb * numRounds + col)
      val s3 = state(3)(col) ^ keySchedule(3)(Nb * numRounds + col)

      state(0)(col) = s0
      state(1)(col) = s1
      state(2)(col) = s2
      state(3)(col) = s3
    }
    state
  }

  private def keyExpansion(key: Array[Int]): Array[Array[Int]] = {
    val keySchedule = Array.ofDim[Int](4, 4)
    //make ChipherKey(which is base of KeySchedule)
    for (r <- 0 until 4; c <- 0 until Nb)
      keySchedule(r)(c) = key(r + 4 * c)

    //Continue to fill KeySchedule
    for (col <- Nk until (Nb * (NUM_ROUNDS + 1))) {
      if (col % Nk == 0) {
        //take shifted (col - 1)th column...
        var tmp = (for (row <- 1 until 4) yield keySchedule(row)(col - 1)).toArray
        tmp = tmp :+ keySchedule(0)(col - 1)

        //change its elements using Sbox-table like in SubBytes...
        for (j <- tmp.indices) {
          val sBoxRow = tmp(j) / 0x10
          val sBoxCol = tmp(j) % 0x10
          val sBoxElem = sBox(BLOCK_SIZE * sBoxRow + sBoxCol)
          tmp(j) = sBoxElem

          //and finally make XOR of 3 columns
          for (row <- 0 until 4) {
            val s = keySchedule(row)(col - 4) ^ tmp(row) ^ rCon(row)(col / Nk - 1)
            keySchedule(row) = keySchedule(row) :+ s
          }
        }

      } else {
        //just make XOR of 2 columns
        for (row <- 0 until 4) {
          val s = keySchedule(row)(col - 4) ^ keySchedule(row)(col - 1)
          keySchedule(row) :+ s
        }
      }
    }

    keySchedule
  }

  private def mul_by_02(num: Int): Int = {
    //The function multiplies by 3 in Galua space
    val res = if (num < 0x80) num << 1 else (num << 1) ^ 0x1b

    res % 0x100
  }

  private def mul_by_03(num: Int): Int = {
    /*The function multiplies by 3 in Galua space
    example: 0x03*num = (0x02 + 0x01)num = num*0x02 + num
    Addition in Galua field is oparetion XOR*/

    mul_by_02(num) ^ num
  }

  private def mul_by_09(num: Int): Int = {
    //return mul_by_03(num)^mul_by_03(num)^mul_by_03(num)
    mul_by_02(mul_by_02(mul_by_02(num))) ^ num
  }

  private def mul_by_0b(num: Int): Int = {
    // return mul_by_09(num)^mul_by_02(num)
    mul_by_02(mul_by_02(mul_by_02(num))) ^ mul_by_02(num) ^ num
  }

  private def mul_by_0d(num: Int): Int = {
    // return mul_by_0b(num)^mul_by_02(num)
    mul_by_02(mul_by_02(mul_by_02(num))) ^ mul_by_02(mul_by_02(num)) ^ num
  }

  private def mul_by_0e(num: Int): Int = {
    // return mul_by_0d(num)^num
    mul_by_02(mul_by_02(mul_by_02(num))) ^ mul_by_02(mul_by_02(num)) ^ mul_by_02(num)
  }

  private val sBox = Array(
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
  )

  private val invSbox = Array(
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
  )

  private val rCon = Array(
    Array(0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36),
    Array(0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00),
    Array(0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00),
    Array(0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
  )

}
