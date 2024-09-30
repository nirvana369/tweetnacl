/*******************************************************************
* Copyright         : 2024 nirvana369
* File Name         : lib.mo
* Description       : tweetnacl interface
*                    
* Revision History  :
* Date				Author    		Comments
* ---------------------------------------------------------------------------
* 09/21/2024		nirvana369 		Created
******************************************************************/

import NACL "./tweetnacl";
import Buffer "mo:base/Buffer";
import Array "mo:base/Array";

module {

    public let HASH_LENGTH = NACL.HASH_LENGTH;
    
    /**
    *   Hashing
    *   Implements SHA-512.
    *   
    *   nacl.hash(message)
    *   Returns SHA-512 hash of the message.
    **/
    public func hash(msg : [Nat8]) : [Nat8] {
        NACL.hash(msg);
    };

    public func verify(x : [Nat8], y : [Nat8]) : Bool {
        NACL.verify(x, y);
    };

    public func randomBytes(blength: Nat): [Nat8] {
        let x = Buffer.fromArray<Nat8>(Array.tabulate<Nat8>(blength, func i = 0));
        NACL.randomBytes(x, blength, null);
        Buffer.toArray(x);
    };

    public func asyncRandomBytes(blength: Nat): async [Nat8] {
        let x = Buffer.fromArray<Nat8>(Array.tabulate<Nat8>(blength, func i = 0));
        await NACL.asyncRandomBytes(x, blength, null);
        Buffer.toArray(x);
    };


    /**
    *   Public-key authenticated encryption (box)
    *   Implements x25519-xsalsa20-poly1305.
    **/
    public module BOX {

        //  Length of public key in bytes.
        public let PUBLIC_KEY_LENGTH = NACL.BOX.PUBLIC_KEY_LENGTH;
        //  Length of secret key in bytes.
        public let SECRET_KEY_LENGTH = NACL.BOX.SECRET_KEY_LENGTH;
        //  Length of precomputed shared key in bytes.
        public let SHARED_KEY_LENGTH = NACL.BOX.SHARED_KEY_LENGTH;
        //  Length of nonce in bytes.
        public let NONCE_LENGTH = NACL.BOX.NONCE_LENGTH;
        //  Length of overhead added to box compared to original message.
        public let OVERHEAD_LENGTH = NACL.BOX.OVERHEAD_LENGTH;

        /**
        *   nacl.box(message, nonce, theirPublicKey, mySecretKey)
        *   
        *   Encrypts and authenticates message using peer's public key, our secret key, and the given nonce, 
        *   which must be unique for each distinct message for a key pair.
        *   
        *   Returns an encrypted and authenticated message, which is nacl.box.overheadLength longer than the original message.
        **/
        public func box(msg : [Nat8], nonce : [Nat8], publicKey : [Nat8], secretKey : [Nat8]) : [Nat8] {
            NACL.BOX.box(msg, nonce, publicKey, secretKey);
        };

        /**
        *   nacl.box.open(box, nonce, theirPublicKey, mySecretKey)
        *
        *   Authenticates and decrypts the given box with peer's public key, our secret key, and the given nonce.
        *
        *   Returns the original message, or null if authentication fails.
        **/
        public func open(msg : [Nat8], nonce : [Nat8], publicKey : [Nat8], secretKey : [Nat8]) : ?[Nat8] {
            NACL.BOX.open(msg, nonce, publicKey, secretKey);
        };
        
        /**
        *   nacl.box.keyPair()
        *
        *   Generates a new random key pair for box and returns it as an object with publicKey and secretKey members:
        **/
        public func keyPair(pRNG : ?((Nat) -> ([Nat8]))) : {publicKey : [Nat8]; secretKey : [Nat8]} {
            NACL.BOX.keyPair(pRNG);
        };

        /**
        *   async nacl.box.keyPair()
        *
        *   Generates a new random key pair for box and returns it as an object with publicKey and secretKey members:
        **/
        public func asyncKeyPair(pRNG : ?((Nat) -> async ([Nat8]))) : async ({publicKey : [Nat8]; secretKey : [Nat8]}) {
            await NACL.BOX.asyncKeyPair(pRNG);
        };

        public module KEYPAIR {
            /**
            *   nacl.box.keyPair.fromSecretKey(secretKey)
            *   
            *   Returns a key pair for box with public key corresponding to the given secret key.
            **/
            public func fromSecretKey(secretKey : [Nat8]) : {publicKey : [Nat8]; secretKey : [Nat8]} {
                NACL.BOX.KEYPAIR.fromSecretKey(secretKey);
            };
        };


        /**
        *   Secret-key authenticated encryption (secretbox)
        *   Implements xsalsa20-poly1305.
        **/
        public module SECRET {

            // Length of precomputed shared key in bytes.
            public let KEY_LENGTH = NACL.BOX.SECRET.KEY_LENGTH;
            //  Length of nonce in bytes.
            public let NONCE_LENGTH = NACL.BOX.SECRET.NONCE_LENGTH;
            //  Length of overhead added to secret box compared to original message.
            public let OVERHEAD_LENGTH = NACL.BOX.SECRET.OVERHEAD_LENGTH;

            /**
            *   nacl.before(theirPublicKey, mySecretKey)
            *   Returns a precomputed shared key which can be used in nacl.serectbox and nacl.secretboxOpen.
            **/
            public func before(publicKey : [Nat8], secretKey : [Nat8]) : [Nat8] {
                NACL.BOX.SECRET.before(publicKey, secretKey);
            };

            /**
            *   nacl.secretbox(message, nonce, sharedKey)
            *   Same as nacl.box, but uses a shared key precomputed with nacl.before.
            *
            *   Encrypts and authenticates message using the key and the nonce. The nonce must be unique for each distinct message for this key.
            *
            *   Returns an encrypted and authenticated message, which is nacl.secretbox.overheadLength longer than the original message.
            **/
            public func box(msg : [Nat8], nonce : [Nat8], key : [Nat8]) : [Nat8] {
                NACL.BOX.SECRET.box(msg, nonce, key);
            };

            /**
            *   nacl.secretboxOpen(box, nonce, sharedKey)
            *   Same as nacl.boxOpen, but uses a shared key precomputed with nacl.before.
            *
            *   Authenticates and decrypts the given secret box using the key and the nonce.
            *
            *   Returns the original message, or null if authentication fails.
            **/
            public func open(box: [Nat8], nonce : [Nat8], key : [Nat8]) : ?[Nat8] {
                NACL.BOX.SECRET.open(box, nonce, key);
            };
        };

        public let BEFORE = SECRET.before;
        public let AFTER = SECRET.box;
        public let OPEN_AFTER = SECRET.open;
    };


    /**
    *   Signatures
    *   Implements ed25519.
    **/
    public module SIGN {

        //  Length of signing public key in bytes.
        public let PUBLIC_KEY_LENGTH = NACL.SIGN.PUBLIC_KEY_LENGTH;
        //  Length of signing secret key in bytes.
        public let SECRET_KEY_LENGTH = NACL.SIGN.SECRET_KEY_LENGTH;
        //  Length of seed for nacl.sign.keyPair.fromSeed in bytes.
        public let SEED_LENGTH = NACL.SIGN.SEED_LENGTH;
        //  Length of signature in bytes.
        public let SIGNATURE_LENGTH = NACL.SIGN.SIGNATURE_LENGTH;

        /**
        *   nacl.sign(message, secretKey)
        *   Signs the message using the secret key and returns a signed message.
        **/
        public func sign(msg : [Nat8], secretKey : [Nat8]) : [Nat8] {
            NACL.SIGN.sign(msg, secretKey);
        };

        /**
        *   nacl.sign.open(signedMessage, publicKey)
        *
        *   Verifies the signed message and returns the message without signature.
        *   Returns null if verification failed.
        **/
        public func open(signedMsg : [Nat8], publicKey : [Nat8]) : ?[Nat8] {
            NACL.SIGN.open(signedMsg, publicKey);
        };

        /**
        *   nacl.sign.keyPair()
        *
        *   Generates new random key pair for signing and returns it as an object with publicKey and secretKey members:
        **/
        public func keyPair(pRNG : ?((Nat) -> ([Nat8]))) : {publicKey : [Nat8]; secretKey : [Nat8]} {
            NACL.SIGN.keyPair(pRNG);
        };

        /**
        *   async nacl.sign.keyPair()
        *
        *   Generates new random key pair for signing and returns it as an object with publicKey and secretKey members:
        **/
        public func asyncKeyPair(pRNG : ?((Nat) -> async ([Nat8]))) : async ({publicKey : [Nat8]; secretKey : [Nat8]}) {
            await NACL.SIGN.asyncKeyPair(pRNG);
        };

        public module KEYPAIR {
            
            /**
            *   nacl.sign.keyPair.fromSecretKey(secretKey)
            *
            *   Returns a signing key pair with public key corresponding to the given 64-byte secret key.
            *   The secret key must have been generated by nacl.sign.keyPair or nacl.sign.keyPair.fromSeed.
            **/
            public func fromSecretKey(secretKey : [Nat8]) : {publicKey : [Nat8]; secretKey : [Nat8]} {
                NACL.SIGN.KEYPAIR.fromSecretKey(secretKey);
            };

            /**
            *   nacl.sign.keyPair.fromSeed(seed)
            *
            *   Returns a new signing key pair generated deterministically from a 32-byte seed. The seed must contain enough entropy to be secure.
            *   This method is not recommended for general use: instead, use nacl.sign.keyPair to generate a new key pair from a random seed.
            **/
            public func fromSeed(seed : [Nat8]) : {publicKey : [Nat8]; secretKey : [Nat8]} {
                NACL.SIGN.KEYPAIR.fromSeed(seed);
            };
        };

        public module DETACHED {
            
            /**
            *   nacl.sign.detached(message, secretKey)
            *   Signs the message using the secret key and returns a signature.
            **/
            public func detached(msg : [Nat8], secretKey : [Nat8]) : [Nat8] {
                NACL.SIGN.DETACHED.detached(msg, secretKey);
            };

            /**
            *   nacl.sign.detached.verify(message, signature, publicKey)
            *   Verifies the signature for the message and returns true if verification succeeded or false if it failed.
            **/
            public func verify(msg : [Nat8], sig : [Nat8], publicKey : [Nat8]) : Bool {
                NACL.SIGN.DETACHED.verify(msg, sig, publicKey);
            };
        };
    };


    /**
    *   Scalar multiplication
    *   Implements x25519.
    **/
    public module SCALARMULT {

        //  Length of scalar in bytes.
        public let SCALAR_LENGTH = NACL.SCALARMULT.SCALAR_LENGTH;
        //  Length of group element in bytes.
        public let GROUP_ELEMENT_LENGTH = NACL.SCALARMULT.GROUP_ELEMENT_LENGTH;

        /**
        *   nacl.scalarMult(n, p)
        *   Multiplies an integer n by a group element p and returns the resulting group element.
        **/
        public func mult(n : [Nat8], p : [Nat8]) : [Nat8] {
            NACL.SCALARMULT.mult(n, p);
        };

        /**
        *   nacl.scalarMult.base(n)
        *   Multiplies an integer n by a standard group element and returns the resulting group element.
        **/
        public func base(n : [Nat8]) : [Nat8] {
            NACL.SCALARMULT.base(n);
        };
    };
    // end module Nacl
};