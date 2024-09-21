tweetnacl.mo
============

Port of [TweetNaCl](http://tweetnacl.cr.yp.to) / [NaCl](http://nacl.cr.yp.to/)
to Motoko for icp canister (wasm runtime).

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

You need mops installed. In your project directory run:
[Mops](https://mops.one/):

    $ mops add tweetnacl

In the Motoko source file import the package as:

    $ import nacl "mo:nacl";

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


Contributors
------------

[nirvana369](https://github.com/nirvana369/).

