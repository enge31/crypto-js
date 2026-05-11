const crypto = require('crypto')

const WordArray = function (words, sigBytes) {
  this.words = words || []
  this.sigBytes = sigBytes === undefined ? (this.words.length * 4) : sigBytes
}

WordArray.create = function () {
  return new WordArray()
}

WordArray.random = function (nBytes) {
  const words = []
  for (let i = 0; i < nBytes; i += 4) {
    words.push(crypto.randomBytes(4).readUInt32BE(0))
  }
  return new WordArray(words, nBytes)
}

WordArray.prototype.toString = function (encoder) {
  encoder = encoder || Hex
  return encoder.stringify(this)
}

WordArray.prototype.concat = function (wordArray) {
  const thisWords = this.words
  const thatWords = wordArray.words
  const thisSigBytes = this.sigBytes
  const thatSigBytes = wordArray.sigBytes
  this.clamp()
  if (thisSigBytes % 4) {
    for (let i = 0; i < thatSigBytes; i++) {
      const thatByte = (thatWords[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff
      thisWords[(thisSigBytes + i) >>> 2] |= thatByte << (24 - ((thisSigBytes + i) % 4) * 8)
    }
  } else {
    for (let i = 0; i < thatSigBytes; i += 4) {
      thisWords[(thisSigBytes + i) >>> 2] = thatWords[i >>> 2]
    }
  }
  this.sigBytes += thatSigBytes
  return this
}

WordArray.prototype.clamp = function () {
  const words = this.words
  const sigBytes = this.sigBytes
  words[sigBytes >>> 2] &= 0xffffffff << (32 - (sigBytes % 4) * 8)
  words.length = Math.ceil(sigBytes / 4)
}

WordArray.prototype.clone = function () {
  return new WordArray(this.words.slice(0), this.sigBytes)
}

const Hex = {
  stringify: function (wordArray) {
    const words = wordArray.words
    const sigBytes = wordArray.sigBytes
    const hexChars = []
    for (let i = 0; i < sigBytes; i++) {
      const bite = (words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff
      hexChars.push((bite >>> 4).toString(16))
      hexChars.push((bite & 0x0f).toString(16))
    }
    return hexChars.join('')
  },
  parse: function (str) {
    const len = str.length
    const words = []
    for (let i = 0; i < len; i += 2) {
      words[i >>> 3] |= parseInt(str.substr(i, 2), 16) << (24 - (i % 8) * 4)
    }
    return new WordArray(words, len / 2)
  }
}

const Latin1 = {
  stringify: function (wordArray) {
    const words = wordArray.words
    const sigBytes = wordArray.sigBytes
    const map = []
    for (let i = 0; i < sigBytes; i++) {
      const bite = (words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff
      map.push(String.fromCharCode(bite))
    }
    return map.join('')
  },
  parse: function (str) {
    const len = str.length
    const words = []
    for (let i = 0; i < len; i++) {
      words[i >>> 2] |= (str.charCodeAt(i) & 0xff) << (24 - (i % 4) * 8)
    }
    return new WordArray(words, len)
  }
}

const Utf8 = {
  stringify: function (wordArray) {
    return decodeURIComponent(escape(Latin1.stringify(wordArray)))
  },
  parse: function (str) {
    return Latin1.parse(unescape(encodeURIComponent(str)))
  }
}

const Base64 = {
  _map: 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/',
  _reverseMap: null,
  stringify: function (wordArray) {
    const words = wordArray.words
    const sigBytes = wordArray.sigBytes
    const map = this._map
    wordArray.clamp()
    let base64Chars = []
    for (let i = 0; i < sigBytes; i += 3) {
      const b1 = (words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff
      const b2 = (words[(i + 1) >>> 2] >>> (24 - ((i + 1) % 4) * 8)) & 0xff
      const b3 = (words[(i + 2) >>> 2] >>> (24 - ((i + 2) % 4) * 8)) & 0xff
      const triple = (b1 << 16) | (b2 << 8) | b3
      for (let j = 0; j < 4; j++) {
        if (i * 8 + j * 6 <= sigBytes * 8) {
          base64Chars.push(map.charAt((triple >>> (6 * (3 - j))) & 0x3f))
        } else {
          base64Chars.push('=')
        }
      }
    }
    return base64Chars.join('')
  },
  parse: function (str) {
    if (!this._reverseMap) {
      this._reverseMap = {}
      for (let i = 0; i < this._map.length; i++) {
        this._reverseMap[this._map.charAt(i)] = i
      }
    }
    let sigBytes = 0
    for (let i = 0; i < str.length; i++) {
      const c = str.charAt(i)
      if (c === '=') break
      if (this._reverseMap[c] !== undefined) sigBytes++
    }
    sigBytes = Math.floor(sigBytes * 3 / 4)
    const words = []
    let byteIdx = 0
    for (let i = 0; i < str.length; i += 4) {
      const c0 = this._reverseMap[str[i]]
      const c1 = this._reverseMap[str[i + 1]]
      const c2 = this._reverseMap[str[i + 2]]
      const c3 = this._reverseMap[str[i + 3]]
      if (c0 === undefined || c1 === undefined) break
      let triple = (c0 << 18) | (c1 << 12)
      if (c2 !== undefined) triple |= (c2 << 6)
      if (c3 !== undefined) triple |= c3
      for (let j = 0; j < 3; j++) {
        if (byteIdx >= sigBytes) break
        const byteVal = (triple >>> (16 - j * 8)) & 0xff
        const wordIdx = byteIdx >>> 2
        const shift = 24 - (byteIdx % 4) * 8
        words[wordIdx] = (words[wordIdx] || 0) | (byteVal << shift)
        byteIdx++
      }
    }
    return new WordArray(words, sigBytes)
  }
}

module.exports = {
  WordArray,
  Hex,
  Latin1,
  Utf8,
  Base64
}
