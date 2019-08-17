#!/usr/bin/env node

const {randomBytes} = require('crypto')

const suite = require('abstract-leveldown/test')
const memdown = require('memdown')
const test = require('tape')

const SecureStore = require('.')


const options =
{
  cipher:
  {
    algorithm: 'aes-192-cbc',
    iv: randomBytes(16)
  },
  keyHmac:
  {
    algorithm: 'sha512',
    key: 'keyHmac key'
  },
  valueHmac:
  {
    algorithm: 'sha512',
    key: 'valueHmac key'
  },
  valueScrypt:
  {
    keylen: 24,
    salt: 'valueScrypt salt'
  }
}


suite({
  createIfMissing: false,
  errorIfExists: false,
  factory: function()
  {
    return new SecureStore(memdown(), options)
  },
  iterator: false,
  test
})
