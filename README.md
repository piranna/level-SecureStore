![level badge](https://leveljs.org/img/badge.svg)

# level-SecureStore
Cryptographically secure storage for LevelDB

Secure data-store using hashed keys and encrypted values, focused to store user
credentials and access tokens for third-party services (AKA "secrets").

**Important note:** By design limits, this module don't implement iterators.
Being keys hashed and values encrypted with a per-entry encryption key makes it
the concept of next or prev entry no sense. Due to this issue,
[it's not `AbstractLevelDOWN` compliant](https://github.com/Level/abstract-leveldown/pull/347#issuecomment-522267389).
Besides that, it fully support on purposse the
[`AbstractLevelDOWN`](https://github.com/Level/abstract-leveldown#public-api-for-consumers)
API, so if you don't need to use iterators in your project, it's safe to
integrate this module in the [LevelJS](https://leveljs.org/) ecosystem.

## Alternatives

This module is similar to [encrypt-down](https://github.com/adorsys/encrypt-down)
and more specially to [level-encrypt](https://github.com/tradle/level-encrypt),
but first one don't use hashes as keys (although a wrapper module could have
implemented them and used separatelly), and second one is not designed as an
[AbstractLevelDOWN](https://github.com/Level/abstract-leveldown) object. In
addition to that, none of them uses a per-entry encryption key instead a global
per-instance one. This module achieve all these goals.

## Encryption scheme

- *keys*: keys are hashed with HMAC using the provided algorithm and key. An
  optional suffix can be provided, for example to add the platform or namespace
  where the plain text key belongs. It's done this way because probably the keys
  will be more random and have more entropy than the suffix, in case someone try
  to unhash it. You can use any of the hashing algorithms provided by Node.js
  [crypto](https://nodejs.org/api/crypto.html) module.
- *values*: values are ciphered using the provided algorithm, initialization
  vector, and cipher options. Cipher key is calculated from the HMAC hash of the
  original plain text key of the entry (ideally with a different configuration
  than the one used to calc the hashed key), that later is being salted with
  provided salt, key length and salt options. An optional preffix can be
  provided, for example a user provided password for that entry. It's done this
  way because (ideally) the preffix will be more impredecible and have more
  entropy than the plain text keys they are associated. The same as with keys
  hashes, you can use any of the hashing and cryptography algorithms provided by
  Node.js [crypto](https://nodejs.org/api/crypto.html) module.

This scheme has been designed so data can only be access in a single way,
reducing atacks surface to specific targeted objetives, so in case database gets
to be stolen, it's useless without the keys hashing key and the plain text key
and the key suffix to know what entry value needs to be decipher, and for a
specific entry, you still needs its decoded plain text key, the key for the
value encryption key hash, and the salt for the value encryption key. This is
secure enough to store third-party services tokens that needs to be accessed
from server side, but by using the (probably) user provided preffix, it makes
almost impossible to decipher the entry value also to the legitim owner of the
database (with all the encryption and hashing configurations), that could lead
to [plausible deniability](https://en.wikipedia.org/wiki/Plausible_deniability)
of the database content itself.

It is **heavily recommended** to not store any of the plain text keys or key
suffixes as part of the secrets stored in the ciphered value content. In normal
conditions they are already provided to identify the entry where to get the
ciphered value, so in case the secrets gets to be revealed, they would provide
their owner too. By doing it this way, owner of the secrets will be hidden
behind the key hash, leading the secrets to became almost useless.

## Install

```sh
npm install level-securestore
```

## Usage

```javascript
const SecureStore = require('level-securestore')

const levelup = require('levelup')
const memdown = require('memdown')

const db = levelup(new SecureStore(memdown(), options))
```

## API

`level-SecureStore` only provides a constructor that accept an
`AbstractLevelDOWN` database as first argument and an options bag as second
argument, and return a new `AbstractLevelDOWN` instance with no extra API
methods.

### options

Per-instance options can be provided as second argument of constructor. Per-call
options can be passed as argument of the `AbstractLevelDOWN` API methods that
accept an options bag, mixed with the options specific for each
`AbstractLevelDOWN` API call. This can be used for example to still allow access
using old credentials in case encryption algorithm gets changed. Per-instance
and per-call options will be merged for each call, overwriting this last ones to
the per-instance ones.

- `cipher`: config of values encryption
  - `algorithm`: algorithm to be used
  - `iv`: initialization vector
  - `[options]`: options used by Node.js encryption engine
- `keyHmac`: config for keys HMAC
  - `algorithm`: algorithm to be used
  - `key`: key used to generate the HMAC
  - `[suffix]`: optional suffix appended to each key (for example, a namespace)
- `valueHmac`: config for values HMAC
  - `algorithm`: algorithm to be used
  - `key`: key used to generate the HMAC
  - `[preffix]`: optional preffix prepended to each encryption key (for example,
    an user provided password)
- `valueScrypt`: config for salted crypt of values encryption key
  - `keylen`: final length of the salted key
  - `[options]`: options used by Node.js `scrypt`
  - `salt`: salt data to be used in the values encryption key

## TODO

- Allow to use a cipherKey not based on the queried entry (how to pass it?)
- Allow CCM mode encrypted keys
- Study if hashing of values encryption key is useful when using `scrypt` or a
  waste of CPU cycles.
