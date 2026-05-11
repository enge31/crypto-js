const { WordArray } = require('./core')
const { Hmac } = require('./hmac')

function PBKDF2 (hasher) {
  this._hasher = hasher
}

PBKDF2.prototype.compute = function (password, salt, keySize, iterations) {
  if (typeof password === 'string') {
    const words = []
    for (let i = 0; i < password.length; i++) {
      words[i >>> 2] |= (password.charCodeAt(i) & 0xff) << (24 - (i % 4) * 8)
    }
    password = new WordArray(words, password.length)
  }
  if (typeof salt === 'string') {
    const words = []
    for (let i = 0; i < salt.length; i++) {
      words[i >>> 2] |= (salt.charCodeAt(i) & 0xff) << (24 - (i % 4) * 8)
    }
    salt = new WordArray(words, salt.length)
  }
  const keySizeBytes = keySize * 4
  const hLen = 32
  const blocks = Math.ceil(keySizeBytes / hLen)
  const derivedWords = []
  const hasher = new this._hasher.constructor()
  for (let block = 1; block <= blocks; block++) {
    const blockWord = new WordArray([block], 4)
    let u = salt.concat(blockWord)
    for (let i = 0; i < iterations; i++) {
      u = Hmac.hash(hasher, password, u)
      u = new WordArray(u.words.slice(), u.sigBytes)
      if (i === 0) {
        for (let j = 0; j < u.words.length; j++) {
          derivedWords[((block - 1) * hLen / 4) + j] = u.words[j]
        }
      } else {
        const derivedOffset = ((block - 1) * hLen / 4)
        for (let j = 0; j < u.words.length; j++) {
          derivedWords[derivedOffset + j] ^= u.words[j]
        }
      }
    }
  }
  return new WordArray(derivedWords, keySizeBytes)
}

PBKDF2.compute = function (password, salt, keySize, iterations) {
  const { Sha256 } = require('./sha256')
  const pbkdf2 = new PBKDF2(new Sha256())
  return pbkdf2.compute(password, salt, keySize, iterations)
}

module.exports = { PBKDF2 }
