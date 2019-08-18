const {createCipheriv, createDecipheriv, createHmac, scrypt} = require('crypto')

const {AbstractLevelDOWN} = require('abstract-leveldown')
const map = require('async-each')
const merge = require('lodash.merge')


function calcCipherKey(key, valueHmac, valueScrypt, callback)
{
  const {preffix} = valueHmac
  const data = preffix != null ? Buffer.concat([preffix, key]) : key

  const password = calcHmac(data, valueHmac)

  scrypt(password, valueScrypt.salt, valueScrypt.keylen, valueScrypt.options,
    callback)
}

function calcDbKey(key, keyHmac)
{
  const {suffix} = keyHmac
  const data = suffix != null ? Buffer.concat([key, suffix]) : key

  return calcHmac(data, keyHmac)
}

function calcHmac(value, {algorithm, key})
{
  if(!Buffer.isBuffer(value)) value = Buffer.from(value)

  return createHmac(algorithm, key).update(value).digest()
}

function cipherValue(key, value, valueHmac, valueScrypt, cipher, callback)
{
  calcCipherKey(key, valueHmac, valueScrypt, function(error, cipherKey)
  {
    if(error) return callback(error)

    // TODO add CCM mode
    const cipherIv = createCipheriv(cipher.algorithm, cipherKey, cipher.iv,
      cipher.options)

    const encrypted = Buffer.concat([
      cipherIv.update(value),
      cipherIv.final()
    ])

    return callback(null, encrypted)
  })
}


module.exports = class SecureStore extends AbstractLevelDOWN
{
  constructor(db, options)
  {
    super()

    this.#db = db
    this.#options = options
  }


  // AbstractLevelDOWN API

  _batch(operations, options, callback)
  {
    const batchOptions = merge({}, options, this.#options)

    map(operations, function({key, options, type, value, ...operation}, callback)
    {
      const {
        cipher,
        keyHmac,
        suffix,
        valueHmac,
        valueScrypt
      } = merge({}, options, batchOptions)

      // Calc hashed key
      const dbKey = calcDbKey(key, keyHmac)

      if(type !== 'put')
        return callback(null, {...operation, key: dbKey, options, type, value})

      // Cipher value
      cipherValue(key, value, valueHmac, valueScrypt, cipher,
        function(error, value)
      {
        if(error) return callback(error)

        return callback(null, {...operation, key: dbKey, options, type, value})
      })
    }, (error, operations) =>
    {
      if(error) return callback(error)

      this.#db.batch(operations, options, callback)
    })
  }

  _del(key, options, callback)
  {
    const {keyHmac, suffix} = merge({}, options, this.#options)

    // Calc hashed key
    const dbKey = calcDbKey(key, keyHmac, suffix)

    this.#db.del(dbKey, callback)
  }

  _get(key, {asBuffer, ...options}, callback)
  {
    const {
      cipher,
      keyHmac,
      valueHmac,
      valueScrypt
    } = merge({}, options, this.#options)

    // Calc hashed key
    const dbKey = calcDbKey(key, keyHmac)

    // Get ciphered value
    this.#db.get(dbKey, function(error, encrypted)
    {
      if(error) return callback(error)

      // Decipher value
      calcCipherKey(key, valueHmac, valueScrypt, function(error, cipherKey)
      {
        if(error) return callback(error)

        // TODO add CCM mode
        const decipherIv = createDecipheriv(cipher.algorithm, cipherKey,
          cipher.iv, cipher.options)

        const outputencoding = asBuffer ? undefined : 'utf8'

        let decrypted = decipherIv.update(encrypted, undefined, outputencoding)

        let final
        try {
          final = decipherIv.final(outputencoding)
        } catch(e) {
          return callback(e)
        }

        decrypted = asBuffer
          ? Buffer.concat([decrypted, final])
          : decrypted + final

        // Return defiphered value
        callback(null, decrypted)
      })
    })
  }

  _put(key, value, options, callback)
  {
    const {
      cipher,
      keyHmac,
      valueHmac,
      valueScrypt
    } = merge({}, options, this.#options)

    // Cipher value
    cipherValue(key, value, valueHmac, valueScrypt, cipher, (error, value) =>
    {
      if(error) return callback(error)

      // Store ciphered value
      const dbKey = calcDbKey(key, keyHmac)

      this.#db.put(dbKey, value, callback)
    })
  }

  _serializeKey(key)
  {
    return Buffer.isBuffer(key) ? key : String(key)
  }

  _serializeValue(value)
  {
    return Buffer.isBuffer(value) ? value : String(value)
  }


  // Private API

  #db
  #options
}
