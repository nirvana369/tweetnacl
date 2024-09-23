[![mops](https://oknww-riaaa-aaaam-qaf6a-cai.raw.ic0.app/badge/mops/tweetnacl)](https://mops.one/tweetnacl) [![documentation](https://oknww-riaaa-aaaam-qaf6a-cai.raw.ic0.app/badge/documentation/tweetnacl)](https://mops.one/tweetnacl/docs)

tweetnacl.mo
============

Port of [TweetNaCl](http://tweetnacl.cr.yp.to) / [NaCl](http://nacl.cr.yp.to/)
to Motoko for icp canister (wasm runtime). Public domain.

Documentation
=============

* [Overview](#overview)
* [Security Considerations](#security-considerations)
* [Installation](#installation)
* [Examples](#examples)
* [Usage](#usage)
  * [Public-key authenticated encryption (box)](#public-key-authenticated-encryption-box)
  * [Secret-key authenticated encryption (secretbox)](#secret-key-authenticated-encryption-secretbox)
  * [Scalar multiplication](#scalar-multiplication)
  * [Signatures](#signatures)
  * [Hashing](#hashing)
  * [Random bytes generation](#random-bytes-generation)
  * [Constant-time comparison](#constant-time-comparison)
* [Testing](#testing)
* [Benchmarks](#benchmarks)
* [Contributors](#contributors)


Overview
--------

The primary goal of this project is to produce a translation of TweetNaCl to
Motoko which is as close as possible to the original C implementation. 
Some functions replaced with faster versions.

Security Considerations
-----------------------

It is important to note that tweetnacl.mo is a low-level library
that doesn't provide complete security protocols. When designing
protocols, you should carefully consider various properties of
underlying primitives.

### No secret key commitment

While XSalsa20-Poly1305, as used in `NACL.BOX.SECRET.box` and `NACL.BOX.box`,
meets the standard notions of privacy and authenticity for a secret-key
authenticated-encryption scheme using nonces, it is *not key-committing*,
which means that it is possible to find a ciphertext which decrypts to
valid plaintexts under two different keys. This may lead to vulnerabilities
if encrypted messages are used in a context where key commitment is expected.

### Signature malleability

While Ed25519 as originally defined and implemented in `NACL.SIGN.sign`
meets the standard notion of unforgeability for a public-key
signature scheme under chosen-message attacks, it is *malleable*:
given a signed message, it is possible, without knowing the secret key,
to create a different signature for the same message that will verify
under the same public key. This may lead to vulnerabilities if
signatures are used in a context where malleability is not expected.

### Hash length-extension attacks

The SHA-512 hash function, as implemented by `NACL.hash`, is *not
resistant* to length-extension attacks.

### Side-channel attacks

While tweetnacl.mo uses algorithmic constant-time operations,
it is impossible to guarantee that they are physically constant time
given wasm runtimes, and other factors.
It is also impossible to guarantee that secret data is physically
removed from memory during cleanup due to copying garbage
collectors and optimizing compilers.


Installation
------------

Install with mops

You need mops installed. In your project directory run 
[Mops](https://mops.one/):

    $ mops add tweetnacl

In the Motoko source file import the package as:

    $ import NACL "mo:tweetnacl";

or [download source code](https://github.com/nirvana369/tweetnacl/releases).


Examples
--------
You can find usage examples in our [Github](https://github.com/nirvana369/tweetnacl-example).


Usage
-----

All API functions accept and return bytes as `[Nat8]`s.


### Public-key authenticated encryption (box)

Implements *x25519-xsalsa20-poly1305*.

#### NACL.BOX.keyPair(pRNG : ?((Nat) -> ([Nat8])))

Generates a new random key pair for box and returns it as an object with
`publicKey` and `secretKey` members:

    {
       publicKey: ...,  // [Nat8] with 32-byte public key
       secretKey: ...   // [Nat8] with 32-byte secret key
    }
Function's params (pRNG) is optional (func randomBytes(byteLength : Nat) : [Nat8]) function,
in case you don't want use internal randomBytes function (set pRNG is null to use default setting).

#### NACL.BOX.KEYPAIR.fromSecretKey(secretKey)

Returns a key pair for box with public key corresponding to the given secret
key.

#### NACL.BOX.box(message, nonce, theirPublicKey, mySecretKey)

Encrypts and authenticates message using peer's public key, our secret key, and
the given nonce, which must be unique for each distinct message for a key pair.

Returns an encrypted and authenticated message, which is
`NACL.BOX.OVERHEAD_LENGTH` longer than the original message.

#### NACL.BOX.open(box, nonce, theirPublicKey, mySecretKey)

Authenticates and decrypts the given box with peer's public key, our secret
key, and the given nonce.

Returns the original message, or `null` if authentication fails.

#### NACL.BOX.BEFORE(theirPublicKey, mySecretKey)

Returns a precomputed shared key which can be used in `NACL.BOX.AFTER` and
`NACL.BOX.OPEN_AFTER`.

#### NACL.BOX.AFTER(message, nonce, sharedKey)

Same as `NACL.BOX.box`, but uses a shared key precomputed with `NACL.BOX.BEFORE`.

#### NACL.BOX.OPEN_AFTER(box, nonce, sharedKey)

Same as `NACL.BOX.open`, but uses a shared key precomputed with `NACL.BOX.BEFORE`.

#### Constants

##### NACL.BOX.PUBLIC_KEY_LENGTH = 32

Length of public key in bytes.

##### NACL.BOX.SECRET_KEY_LENGTH = 32

Length of secret key in bytes.

##### NACL.BOX.SHARED_KEY_LENGTH = 32

Length of precomputed shared key in bytes.

##### NACL.BOX.NONCE_LENGTH = 24

Length of nonce in bytes.

##### NACL.BOX.OVERHEAD_LENGTH = 16

Length of overhead added to box compared to original message.


### Secret-key authenticated encryption (secretbox)

Implements *xsalsa20-poly1305*.

#### NACL.BOX.SECRET.box(message, nonce, key)

Encrypts and authenticates message using the key and the nonce. The nonce must
be unique for each distinct message for this key.

Returns an encrypted and authenticated message, which is
`NACL.BOX.SECRET.OVERHEAD_LENGTH` longer than the original message.

#### NACL.BOX.SECRET.open(box, nonce, key)

Authenticates and decrypts the given secret box using the key and the nonce.

Returns the original message, or `null` if authentication fails.

#### Constants

##### NACL.BOX.SECRET.KEY_LENGTH = 32

Length of key in bytes.

##### NACL.BOX.SECRET.NONCE_LENGTH = 24

Length of nonce in bytes.

##### NACL.BOX.SECRET.OVERHEAD_LENGTH = 16

Length of overhead added to secret box compared to original message.


### Scalar multiplication

Implements *x25519*.

#### NACL.SCALARMULT.mult(n, p)

Multiplies an integer `n` by a group element `p` and returns the resulting
group element.

#### NACL.SCALARMULT.base(n)

Multiplies an integer `n` by a standard group element and returns the resulting
group element.

#### Constants

##### NACL.SCALARMULT.SCALAR_LENGTH = 32

Length of scalar in bytes.

##### NACL.SCALARMULT.GROUP_ELEMENT_LENGTH = 32

Length of group element in bytes.


### Signatures

Implements [ed25519](http://ed25519.cr.yp.to).

#### NACL.SIGN.keyPair(pRNG : ?((Nat) -> ([Nat8])))

Generates new random key pair for signing and returns it as an object with
`publicKey` and `secretKey` members:

    {
       publicKey: ...,  // [Nat8] with 32-byte public key
       secretKey: ...   // [Nat8] with 64-byte secret key
    }

Function's params (pRNG) is optional (func randomBytes(byteLength : Nat) : [Nat8]) function,
in case you don't want use internal randomBytes function (set pRNG is null to use default setting).

#### NACL.SIGN.KEYPAIR.fromSecretKey(secretKey)

Returns a signing key pair with public key corresponding to the given
64-byte secret key. The secret key must have been generated by
`NACL.SIGN.keyPair` or `NACL.SIGN.KEYPAIR.fromSeed`.

#### NACL.SIGN.KEYPAIR.fromSeed(seed)

Returns a new signing key pair generated deterministically from a 32-byte seed.
The seed must contain enough entropy to be secure. This method is not
recommended for general use: instead, use `NACL.SIGN.keyPair` to generate a new
key pair from a random seed.

#### NACL.SIGN.sign(message, secretKey)

Signs the message using the secret key and returns a signed message.

#### NACL.SIGN.open(signedMessage, publicKey)

Verifies the signed message and returns the message without signature.

Returns `null` if verification failed.

#### NACL.SIGN.DETACHED.detached(message, secretKey)

Signs the message using the secret key and returns a signature.

#### NACL.SIGN.DETACHED.verify(message, signature, publicKey)

Verifies the signature for the message and returns `true` if verification
succeeded or `false` if it failed.

#### Constants

##### NACL.SIGN.PUBLIC_KEY_LENGTH = 32

Length of signing public key in bytes.

##### NACL.SIGN.SECRET_KEY_LENGTH = 64

Length of signing secret key in bytes.

##### NACL.SIGN.SEED_LENGTH = 32

Length of seed for `NACL.SIGN.KEYPAIR.fromSeed` in bytes.

##### NACL.SIGN.SIGNATURE_LENGTH = 64

Length of signature in bytes.


### Hashing

Implements *SHA-512*.

#### NACL.hash(message)

Returns SHA-512 hash of the message.

#### Constants

##### NACL.HASH_LENGTH = 64

Length of hash in bytes.


### Random bytes generation

#### NACL.randomBytes(length)

Returns a `[Nat8]` of the given length containing random bytes of
cryptographic quality.

**Implementation note**

tweetnacl.mo uses the following lib to generate random bytes:

* https://github.com/ZenVoich/fuzz


### Constant-time comparison

#### NACL.verify(x, y)

Compares `x` and `y` in constant time and returns `true` if their lengths are
non-zero and equal, and their contents are equal.

Returns `false` if either of the arguments has zero length, or arguments have
different lengths, or their contents differ.

Testing
------------
Tesing with mops

You need mops installed. In your project directory run 
[Mops](https://mops.one/):

    $ mops test

Benchmarks
------------
Benchmarks with mops

You need mops installed. In your project directory run 
[Mops](https://mops.one/):

    $ mops bench

TweetTNaCl module benchmark

Instructions

||	1|	10|	50|
|---|---|---|---|
|NACL.SIGN.keypair| 	245_814_512|	2_458_100_529|	12_290_412_009|
|NACL.SIGN.KEYPAIR.fromSecretKey| 	1_325_777|	1_449_824|	1_992_240|
|NACL.SIGN.KEYPAIR.fromSeed| 	245_811_703|	2_452_182_933|	12_258_286_264|
|NACL.SIGN.sign| 	498_143_585|	4_981_456_572|	24_908_186_306|
|NACL.SIGN.open| 	990_069_856|	5_417_580_019|	25_095_326_075|
|NACL.SIGN.DETACHED.detached| 	7_820|	8_069|	8_069|
|NACL.SIGN.DETACHED.verify| 	990_083_376|	5_417_548_342|	25_093_337_457|
|NACL.BOX.keypair| 	121_800_446|	1_218_046_698|	6_089_900_580|
|NACL.BOX.KEYPAIR.fromSecretKey| 	121_797_070|	1_212_079_970|	6_057_745_038|
|NACL.BOX.box| 	246_713_481|	1_342_797_270|	6_214_283_560|
|NACL.BOX.open| 	368_606_846|	1_465_686_613|	6_341_507_292|
|NACL.BOX.SECRET.before| 	242_994_353|	1_333_710_393|	6_181_332_808|
|NACL.BOX.SECRET.box| 	246_703_621|	252_086_521|	275_921_549|
|NACL.BOX.SECRET.open| 	247_419_456|	253_757_297|	281_990_505|
|NACL.SCALARMULT.mult| 	122_455_341|	1_212_723_590|	6_058_390_508|
|NACL.SCALARMULT.base| 	121_802_394|	1_212_080_660|	6_057_741_604|
|NACL.hash| 	3_638_966|	12_612_758|	52_552_053|
|NACL.randomBytes| 	10_530_371|	105_087_105|	525_234_851|

Heap
||	1|	10|	50|
|---|---|---|---|
|NACL.SIGN.keypair| 	244 B|	280 B|	280 B|
|NACL.SIGN.KEYPAIR.fromSecretKey| 	244 B|	244 B|	244 B|
|NACL.SIGN.KEYPAIR.fromSeed| 	244 B|	280 B|	280 B|
|NACL.SIGN.sign| 	244 B|	280 B|	280 B|
|NACL.SIGN.open| 	316 B|	352 B|	352 B|
|NACL.SIGN.DETACHED.detached| 	316 B|	316 B|	316 B|
|NACL.SIGN.DETACHED.verify| 	316 B|	352 B|	352 B|
|NACL.BOX.keypair| 	316 B|	352 B|	352 B|
|NACL.BOX.KEYPAIR.fromSecretKey| 	316 B|	352 B|	352 B|
|NACL.BOX.box| 	316 B|	352 B|	352 B|
|NACL.BOX.open| 	316 B|	352 B|	352 B|
|NACL.BOX.SECRET.before| 	316 B|	352 B|	352 B|
|NACL.BOX.SECRET.box| 	316 B|	316 B|	316 B|
|NACL.BOX.SECRET.open| 	316 B|	316 B|	316 B|
|NACL.SCALARMULT.mult| 	316 B|	352 B|	352 B|
|NACL.SCALARMULT.base| 	316 B|	352 B|	352 B|
|NACL.hash| 	316 B|	316 B|	316 B|
|NACL.randomBytes| 	316 B|	316 B|	316 B|

Contributors
------------

[nirvana369](https://github.com/nirvana369/).

