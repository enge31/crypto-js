const { WordArray } = require('./core')

const K = [
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
  0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
  0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
  0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
  0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
  0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
  0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]

const H_256 = [
  0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
  0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
]

function rotr (x, n) {
  return (x >>> n) | (x << (32 - n))
}

function shr (x, n) {
  return x >>> n
}

function sigma0 (x) {
  return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22)
}

function sigma1 (x) {
  return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25)
}

function gamma0 (x) {
  return rotr(x, 7) ^ rotr(x, 18) ^ shr(x, 3)
}

function gamma1 (x) {
  return rotr(x, 17) ^ rotr(x, 19) ^ shr(x, 10)
}

function Ch (x, y, z) {
  return (x & y) ^ (~x & z)
}

function Maj (x, y, z) {
  return (x & y) ^ (x & z) ^ (y & z)
}

function Sha256 () {
  this._hash = H_256.slice()
  this._buf = []
  this._len = 0
  this._buflen = 0
}

Sha256.prototype.reset = function () {
  this._hash = H_256.slice()
  this._buf = []
  this._len = 0
  this._buflen = 0
}

Sha256.prototype.update = function (message) {
  if (typeof message === 'string') {
    const bytes = []
    for (let i = 0; i < message.length; i++) {
      const c = message.charCodeAt(i)
      if (c < 0x80) {
        bytes.push(c)
      } else if (c < 0x800) {
        bytes.push(0xc0 | (c >> 6), 0x80 | (c & 0x3f))
      } else if (c < 0xd800 || c >= 0xe000) {
        bytes.push(0xe0 | (c >> 12), 0x80 | ((c >> 6) & 0x3f), 0x80 | (c & 0x3f))
      } else {
        i++
        c = 0x10000 + (((c & 0x3ff) << 10) | (message.charCodeAt(i) & 0x3ff))
        bytes.push(
          0xf0 | (c >> 18),
          0x80 | ((c >> 12) & 0x3f),
          0x80 | ((c >> 6) & 0x3f),
          0x80 | (c & 0x3f)
        )
      }
    }
    message = bytes
  }
  if (message instanceof WordArray) {
    const words = message.words
    const sigBytes = message.sigBytes
    const bytes = new Array(sigBytes)
    for (let i = 0; i < sigBytes; i++) {
      bytes[i] = (words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff
    }
    message = bytes
  }
  if (Array.isArray(message)) {
    return this._updateBuffer(message)
  }
  throw new Error('Unsupported message type')
}

Sha256.prototype._updateBuffer = function (data) {
  const len = data.length
  this._len += len
  let i = 0
  if (this._buflen) {
    const space = 64 - this._buflen
    const take = Math.min(space, len)
    for (let j = 0; j < take; j++) {
      this._buf[this._buflen + j] = data[j]
    }
    this._buflen += take
    i += take
    if (this._buflen === 64) {
      this._compress(this._buf)
      this._buflen = 0
    }
  }
  for (; i + 64 <= len; i += 64) {
    const block = data.slice(i, i + 64)
    this._compress(block)
  }
  if (i < len) {
    const remaining = data.slice(i)
    for (let j = 0; j < remaining.length; j++) {
      this._buf[this._buflen + j] = remaining[j]
    }
    this._buflen += remaining.length
  }
  return this
}

Sha256.prototype._compress = function (block) {
  const W = new Array(64)
  for (let t = 0; t < 16; t++) {
    W[t] = (block[t * 4] << 24) | (block[t * 4 + 1] << 16) |
           (block[t * 4 + 2] << 8) | block[t * 4 + 3]
  }
  for (let t = 16; t < 64; t++) {
    W[t] = (gamma1(W[t - 2]) + W[t - 7] + gamma0(W[t - 15]) + W[t - 16]) | 0
  }
  let a = this._hash[0] >>> 0
  let b = this._hash[1] >>> 0
  let c = this._hash[2] >>> 0
  let d = this._hash[3] >>> 0
  let e = this._hash[4] >>> 0
  let f = this._hash[5] >>> 0
  let g = this._hash[6] >>> 0
  let h = this._hash[7] >>> 0
  for (let t = 0; t < 64; t++) {
    const sigma1e = sigma1(e)
    const Ch_efg = Ch(e, f, g)
    const T1 = (h + sigma1e + Ch_efg + K[t] + W[t]) | 0
    const sigma0a = sigma0(a)
    const Maj_abc = Maj(a, b, c)
    const T2 = (sigma0a + Maj_abc) | 0
    h = g
    g = f
    f = e
    e = (d + T1) | 0
    d = c
    c = b
    b = a
    a = (T1 + T2) | 0
  }
  this._hash[0] = (this._hash[0] + a) | 0
  this._hash[1] = (this._hash[1] + b) | 0
  this._hash[2] = (this._hash[2] + c) | 0
  this._hash[3] = (this._hash[3] + d) | 0
  this._hash[4] = (this._hash[4] + e) | 0
  this._hash[5] = (this._hash[5] + f) | 0
  this._hash[6] = (this._hash[6] + g) | 0
  this._hash[7] = (this._hash[7] + h) | 0
}

Sha256.prototype.finalize = function () {
  const bitsLen = this._len * 8
  this.update([0x80])
  while (this._buflen !== 56) {
    this.update([0x00])
  }
  const lenBuf = [
    0, 0, 0, 0,
    (bitsLen >>> 24) & 0xff,
    (bitsLen >>> 16) & 0xff,
    (bitsLen >>> 8) & 0xff,
    bitsLen & 0xff
  ]
  this.update(lenBuf)
  const words = this._hash.slice()
  return new WordArray(words, 32)
}

Sha256.hash = function (message) {
  return new Sha256().update(message).finalize()
}

module.exports = { Sha256 }
