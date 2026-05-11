const { WordArray } = require('./core')

function Hmac (hasher, key) {
  this._hasher = hasher
  this._key = key
}

Hmac.prototype.update = function (message) {
  this._message = this._hasher.update(message)
  return this
}

Hmac.prototype.finalize = function () {
  if (this._message) {
    const hash = this._message.finalize()
    const innerKey = this._key
    const outerKey = this._oKey
    return this._hasher.reset().update(outerKey).update(hash).finalize()
  }
  const hash = this._hasher.finalize()
  return this._hasher.reset().update(this._oKey).update(hash).finalize()
}

Hmac.hash = function (hasher, key, message) {
  const hmac = new Hmac(hasher, key)
  const ipad = WordArray.create()
  const opad = WordArray.create()
  const keyWords = key.words
  const keySigBytes = key.sigBytes
  for (let i = 0; i < 16; i++) {
    const word = i < (keySigBytes / 4 | 0) ? keyWords[i] : 0
    ipad.words[i] = word ^ 0x36363636
    opad.words[i] = word ^ 0x5c5c5c5c
  }
  ipad.sigBytes = 64
  opad.sigBytes = 64
  hmac._oKey = opad
  const instance = new hasher.constructor()
  instance.update(ipad)
  instance.update(message)
  const hash = instance.finalize()
  instance.reset()
  instance.update(opad)
  instance.update(hash)
  return instance.finalize()
}

module.exports = { Hmac }
