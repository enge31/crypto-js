const crypto = require('./index')
const assert = require('assert')

let passed = 0
let failed = 0

function test (name, fn) {
  try {
    fn()
    passed++
    console.log(`  PASS: ${name}`)
  } catch (e) {
    failed++
    console.log(`  FAIL: ${name}`)
    console.log(`        ${e.message}`)
  }
}

function assertEq (a, b, msg) {
  assert.strictEqual(a, b, msg || `expected ${JSON.stringify(a)} to equal ${JSON.stringify(b)}`)
}

function assertWordArrayEq (wa1, wa2, msg) {
  const h1 = crypto.Hex.stringify(wa1)
  const h2 = crypto.Hex.stringify(wa2)
  assertEq(h1, h2, msg)
}

console.log('\n=== Encoding Tests ===')
test('Hex stringify', () => {
  const wa = crypto.Hex.parse('48656c6c6f')
  assertEq(crypto.Hex.stringify(wa), '48656c6c6f')
})
test('Hex parse and stringify roundtrip', () => {
  const hex = 'deadbeef01020304'
  assertEq(crypto.Hex.stringify(crypto.Hex.parse(hex)), hex)
})
test('Base64 stringify', () => {
  const wa = crypto.Utf8.parse('hello')
  assertEq(crypto.Base64.stringify(wa), 'aGVsbG8=')
})
test('Base64 parse', () => {
  const wa = crypto.Base64.parse('aGVsbG8=')
  assertEq(crypto.Utf8.stringify(wa), 'hello')
})
test('Base64 roundtrip', () => {
  const original = 'Hello, World! 123'
  const wa = crypto.Utf8.parse(original)
  const b64 = crypto.Base64.stringify(wa)
  const back = crypto.Utf8.stringify(crypto.Base64.parse(b64))
  assertEq(back, original)
})
test('UTF-8 parse and stringify', () => {
  const str = 'Hello 世界 🌍'
  assertEq(crypto.Utf8.stringify(crypto.Utf8.parse(str)), str)
})

console.log('\n=== SHA-256 Tests ===')
test('SHA-256 empty string', () => {
  const h = crypto.sha256('')
  assertEq(crypto.Hex.stringify(h), 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')
})
test('SHA-256 "abc"', () => {
  const h = crypto.sha256('abc')
  assertEq(crypto.Hex.stringify(h), 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad')
})
test('SHA-256 "hello"', () => {
  const h = crypto.sha256('hello')
  assertEq(crypto.Hex.stringify(h), '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824')
})
test('SHA-256 longer string', () => {
  const h = crypto.sha256('The quick brown fox jumps over the lazy dog')
  assertEq(crypto.Hex.stringify(h), 'd7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592')
})

console.log('\n=== HMAC-SHA256 Tests ===')
test('HMAC-SHA256 RFC 4231 Test Case 2', () => {
  const key = 'Jefe'
  const msg = 'what do ya want for nothing?'
  const h = crypto.hmac(key, msg)
  assertEq(crypto.Hex.stringify(h), '5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843')
})
test('HMAC-SHA256 RFC 4231 Test Case 3', () => {
  const key = crypto.Hex.parse('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')
  const msg = crypto.Hex.parse('dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd')
  const h = crypto.hmac(key, msg)
  assertEq(crypto.Hex.stringify(h), '773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe')
})

console.log('\n=== PBKDF2 Tests ===')
test('PBKDF2 basic', () => {
  const key = crypto.pbkdf2('password', 'salt', 4, 1)
  assertEq(crypto.Hex.stringify(key), '120fb6cffcf8b32c43e7225256c4f837')
})
test('PBKDF2 100 iterations', () => {
  const key = crypto.pbkdf2('password', 'salt', 8, 100)
  assertEq(crypto.Hex.stringify(key), '07e6997180cf7f12904f04100d405d34888fdf62af6d506a0ecc23b196fe99d8')
})

console.log('\n=== AES-CBC Tests ===')
test('AES-128 encrypt/decrypt block', () => {
  const key = crypto.Hex.parse('2b7e151628aed2a6abf7158809cf4f3c')
  const plain = crypto.Hex.parse('6bc1bee22e409f96e93d7e117393172a')
  const aes = new crypto.Aes(key)
  const ct = aes.encryptBlock(plain)
  const pt = aes.decryptBlock(ct)
  assertWordArrayEq(pt, plain)
})
test('AES-256 encrypt/decrypt block', () => {
  const key = crypto.Hex.parse('603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4')
  const plain = crypto.Hex.parse('6bc1bee22e409f96e93d7e117393172a')
  const aes = new crypto.Aes(key)
  const ct = aes.encryptBlock(plain)
  const pt = aes.decryptBlock(ct)
  assertWordArrayEq(pt, plain)
})
test('AES-CBC encrypt/decrypt with IV', () => {
  const key = crypto.Hex.parse('2b7e151628aed2a6abf7158809cf4f3c')
  const iv = crypto.Hex.parse('000102030405060708090a0b0c0d0e0f')
  const plain = crypto.Utf8.parse('Hello, AES-CBC encryption!')
  const result = crypto.AES.encrypt(plain, key, { iv })
  const decrypted = crypto.AES.decrypt(result.ciphertext, key, { iv: result.iv })
  assertEq(crypto.Utf8.stringify(decrypted), 'Hello, AES-CBC encryption!')
})
test('AES-CBC roundtrip with random IV', () => {
  const key = crypto.WordArray.random(16)
  const plain = crypto.Utf8.parse('This is a secret message with some length to test.')
  const result = crypto.AES.encrypt(plain, key)
  const decrypted = crypto.AES.decrypt(result.ciphertext, key, { iv: result.iv })
  assertEq(crypto.Utf8.stringify(decrypted), 'This is a secret message with some length to test.')
})

console.log('\n=== OpenSSL-compatible encrypt/decrypt Tests ===')
test('encrypt/decrypt string roundtrip', () => {
  const ct = crypto.encrypt('Hello World!', 'mypassword')
  const pt = crypto.decrypt(ct, 'mypassword')
  assertEq(pt, 'Hello World!')
})
test('encrypt/decrypt with unicode', () => {
  const ct = crypto.encrypt('Hello 世界 🌍', 'pass123')
  const pt = crypto.decrypt(ct, 'pass123')
  assertEq(pt, 'Hello 世界 🌍')
})
test('encrypt/decrypt longer text', () => {
  const plain = 'The quick brown fox jumps over the lazy dog. '.repeat(5)
  const ct = crypto.encrypt(plain, 'a-strong-password!')
  const pt = crypto.decrypt(ct, 'a-strong-password!')
  assertEq(pt, plain)
})

console.log('\n=== Summary ===')
console.log(`  ${passed} passed, ${failed} failed, ${passed + failed} total\n`)
process.exit(failed > 0 ? 1 : 0)
