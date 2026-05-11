const { WordArray, Hex, Latin1, Utf8, Base64 } = require('./lib/core')
const { Sha256 } = require('./lib/sha256')
const { Hmac } = require('./lib/hmac')
const { PBKDF2 } = require('./lib/pbkdf2')
const { AES } = require('./lib/cipher')
const { Aes } = require('./lib/aes')

const sha256 = function (message) {
  return Sha256.hash(message)
}

const hmac = function (key, message) {
  if (typeof key === 'string') {
    const words = []
    for (let i = 0; i < key.length; i++) {
      words[i >>> 2] |= (key.charCodeAt(i) & 0xff) << (24 - (i % 4) * 8)
    }
    key = new WordArray(words, key.length)
  }
  if (typeof message === 'string') {
    const words = []
    for (let i = 0; i < message.length; i++) {
      words[i >>> 2] |= (message.charCodeAt(i) & 0xff) << (24 - (i % 4) * 8)
    }
    message = new WordArray(words, message.length)
  }
  return Hmac.hash(new Sha256(), key, message)
}

const pbkdf2 = function (password, salt, keySize, iterations) {
  return PBKDF2.compute(password, salt, keySize, iterations)
}

const encrypt = function (plaintext, password) {
  if (typeof plaintext === 'string') {
    plaintext = Utf8.parse(plaintext)
  }
  return AES.encryptToString(plaintext, password)
}

const decrypt = function (ciphertext, password) {
  const result = AES.decryptFromString(ciphertext, password)
  return Utf8.stringify(result)
}

module.exports = {
  WordArray,
  Hex,
  Latin1,
  Utf8,
  Base64,
  Sha256,
  sha256,
  Hmac,
  hmac,
  PBKDF2,
  pbkdf2,
  AES,
  Aes,
  encrypt,
  decrypt
}
