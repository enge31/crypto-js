const crypto = require('crypto')
const { WordArray, Hex, Base64, Utf8 } = require('./core')
const { Aes } = require('./aes')

function pkcs7Pad (data, blockSize) {
  const padLen = blockSize - (data.sigBytes % blockSize)
  const padByte = padLen & 0xff
  const words = data.words.slice()
  const oldSigBytes = data.sigBytes
  for (let i = 0; i < padLen; i++) {
    const idx = oldSigBytes + i
    words[idx >>> 2] |= padByte << (24 - (idx % 4) * 8)
  }
  return new WordArray(words, oldSigBytes + padLen)
}

function pkcs7Unpad (data) {
  const words = data.words
  const sigBytes = data.sigBytes
  const padByte = (words[(sigBytes - 1) >>> 2] >>> (24 - ((sigBytes - 1) % 4) * 8)) & 0xff
  const newSigBytes = sigBytes - padByte
  if (newSigBytes < 0) throw new Error('Invalid padding')
  for (let i = newSigBytes; i < sigBytes; i++) {
    const b = (words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff
    if (b !== padByte) throw new Error('Invalid padding')
  }
  return new WordArray(words, newSigBytes)
}

function cbcEncrypt (aes, plaintext, iv) {
  const blockSize = 16
  const padded = pkcs7Pad(plaintext, blockSize)
  const nBlocks = padded.sigBytes / blockSize
  const resultWords = []
  let prev = iv
  for (let i = 0; i < nBlocks; i++) {
    const offset = i * blockSize / 4
    const blockWords = padded.words.slice(offset, offset + blockSize / 4)
    const blockWA = new WordArray(blockWords, blockSize)
    const xored = new WordArray(
      [(blockWA.words[0] ^ prev.words[0]) >>> 0,
       (blockWA.words[1] ^ prev.words[1]) >>> 0,
       (blockWA.words[2] ^ prev.words[2]) >>> 0,
       (blockWA.words[3] ^ prev.words[3]) >>> 0],
      blockSize
    )
    const encrypted = aes.encryptBlock(xored)
    resultWords.push(encrypted.words[0], encrypted.words[1], encrypted.words[2], encrypted.words[3])
    prev = encrypted
  }
  return new WordArray(resultWords, nBlocks * blockSize)
}

function cbcDecrypt (aes, ciphertext, iv) {
  const blockSize = 16
  const nBlocks = ciphertext.sigBytes / blockSize
  const resultWords = []
  let prev = iv
  for (let i = 0; i < nBlocks; i++) {
    const offset = i * blockSize / 4
    const blockWords = ciphertext.words.slice(offset, offset + blockSize / 4)
    const blockWA = new WordArray(blockWords, blockSize)
    const decrypted = aes.decryptBlock(blockWA)
    const xored = new WordArray(
      [(decrypted.words[0] ^ prev.words[0]) >>> 0,
       (decrypted.words[1] ^ prev.words[1]) >>> 0,
       (decrypted.words[2] ^ prev.words[2]) >>> 0,
       (decrypted.words[3] ^ prev.words[3]) >>> 0],
      blockSize
    )
    resultWords.push(xored.words[0], xored.words[1], xored.words[2], xored.words[3])
    prev = blockWA
  }
  const padded = new WordArray(resultWords, nBlocks * blockSize)
  return pkcs7Unpad(padded)
}

const AES = {
  encrypt: function (plaintext, key, cfg) {
    cfg = cfg || {}
    const iv = cfg.iv || WordArray.random(16)
    const aesKey = new Aes(key)
    const ciphertext = cbcEncrypt(aesKey, plaintext, iv)
    return { ciphertext, iv }
  },
  decrypt: function (ciphertext, key, cfg) {
    cfg = cfg || {}
    const iv = cfg.iv
    if (!iv) throw new Error('IV required for decryption')
    const aesKey = new Aes(key)
    return cbcDecrypt(aesKey, ciphertext, iv)
  },
  encryptToString: function (plaintext, password) {
    const salt = WordArray.random(8)
    const key = _deriveKey(password, salt)
    const iv = WordArray.random(16)
    const result = AES.encrypt(plaintext, key, { iv })
    const concat = salt.clone().concat(iv).concat(result.ciphertext)
    return Base64.stringify(concat)
  },
  decryptFromString: function (ciphertextStr, password) {
    const data = Base64.parse(ciphertextStr)
    const salt = new WordArray(data.words.slice(0, 2), 8)
    const iv = new WordArray(data.words.slice(2, 6), 16)
    const ct = new WordArray(data.words.slice(6), data.sigBytes - 24)
    const key = _deriveKey(password, salt)
    return AES.decrypt(ct, key, { iv })
  }
}

function _deriveKey (password, salt) {
  const words = []
  for (let i = 0; i < password.length; i++) {
    words[i >>> 2] |= (password.charCodeAt(i) & 0xff) << (24 - (i % 4) * 8)
  }
  const pwdWA = new WordArray(words, password.length)
  const { Sha256 } = require('./sha256')
  const { Hmac } = require('./hmac')
  const hasher = new Sha256()
  let u = pwdWA.clone().concat(salt)
  for (let i = 0; i < 100; i++) {
    u = Hmac.hash(hasher, pwdWA, u)
    u = new WordArray(u.words.slice(), u.sigBytes)
  }
  return u
}

module.exports = { AES, pkcs7Pad, pkcs7Unpad, cbcEncrypt, cbcDecrypt }
