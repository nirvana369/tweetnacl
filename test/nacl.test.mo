import {test; suite} "mo:test";
import Array "mo:base/Array";
import Bool "mo:base/Bool";
import Nat8 "mo:base/Nat8";
import Option "mo:base/Option";
import Iter "mo:base/Iter";
import NACL "../src/lib";

actor {


    public func runTests() : async () {
    
        suite("NACL.SIGN", func() {
            test("NACL.SIGN.keypair", func() {
                let kp = NACL.SIGN.keyPair(null);
                assert(kp.publicKey.size() == NACL.SIGN.PUBLIC_KEY_LENGTH);
                assert(kp.secretKey.size() == NACL.SIGN.SECRET_KEY_LENGTH);
            });

            test("NACL.SIGN.KEYPAIR.keyPairFromSecretKey", func() {
                let sk = NACL.randomBytes(NACL.SIGN.SECRET_KEY_LENGTH);
                let kp = NACL.SIGN.KEYPAIR.fromSecretKey(sk);
                assert(Array.equal(sk, kp.secretKey, Nat8.equal));

                let keypair = NACL.SIGN.keyPair(null);
                let {publicKey; secretKey} = NACL.SIGN.KEYPAIR.fromSecretKey(keypair.secretKey);
                assert(Array.equal(publicKey, keypair.publicKey, Nat8.equal));
                assert(Array.equal(secretKey, keypair.secretKey, Nat8.equal));
            });

            test("NACL.SIGN.KEYPAIR.keyPairFromSeed", func() {
                let seed = NACL.randomBytes(NACL.SIGN.SEED_LENGTH);
                let kp = NACL.SIGN.KEYPAIR.fromSeed(seed);
                assert(kp.publicKey.size() == NACL.SIGN.PUBLIC_KEY_LENGTH);
                assert(kp.secretKey.size() == NACL.SIGN.SECRET_KEY_LENGTH);
            });
            test("NACL.SIGN.sign", func() {
                let keypair = NACL.SIGN.keyPair(null);
                let msg = NACL.randomBytes(128);
                let sign = NACL.SIGN.sign(msg, keypair.secretKey);
                assert(sign.size() > 0);
            });
            test("NACL.SIGN.open", func() {
                let keypair = NACL.SIGN.keyPair(null);
                let msg = NACL.randomBytes(128);
                let msgSigned = NACL.SIGN.sign(msg, keypair.secretKey);
                let rawMsg = NACL.SIGN.open(msgSigned, keypair.publicKey);
                assert(rawMsg != null);
                assert(Array.equal(msg, Option.get(rawMsg, []), Nat8.equal));
            });
            test("NACL.SIGN.DETACHED.detached", func() {
                let keypair = NACL.SIGN.keyPair(null);
                let msg = NACL.randomBytes(128);
                let sig = NACL.SIGN.DETACHED.detached(msg, keypair.secretKey);
                assert(sig.size() > 0);
            });
            test("NACL.SIGN.DETACHED.verify", func() {
                let keypair = NACL.SIGN.keyPair(null);
                let msg = NACL.randomBytes(128);
                let signature = NACL.SIGN.DETACHED.detached(msg, keypair.secretKey);
                let vrf = NACL.SIGN.DETACHED.verify(msg, signature, keypair.publicKey);
                assert(vrf);
            });
        });

        suite("NACL.BOX", func() {
            test("NACL.BOX.keypair", func() {
                let kp = NACL.BOX.keyPair(null);
                assert(kp.publicKey.size() == NACL.BOX.PUBLIC_KEY_LENGTH);
                assert(kp.secretKey.size() == NACL.BOX.SECRET_KEY_LENGTH);
            });

            test("NACL.BOX.KEYPAIR.fromSecretKey", func() {
                let sk = NACL.randomBytes(NACL.BOX.SECRET_KEY_LENGTH);
                let kp = NACL.BOX.KEYPAIR.fromSecretKey(sk);
                assert(Array.equal(sk, kp.secretKey, Nat8.equal));

                let keypair = NACL.BOX.keyPair(null);
                let {publicKey; secretKey} = NACL.BOX.KEYPAIR.fromSecretKey(keypair.secretKey);
                assert(Array.equal(publicKey, keypair.publicKey, Nat8.equal));
                assert(Array.equal(secretKey, keypair.secretKey, Nat8.equal));
            });
            test("NACL.BOX.box", func() {
                let keypairBob = NACL.BOX.keyPair(null);
                for(i in Iter.range(0, 1000)) {()};
                let keypairAlice = NACL.BOX.keyPair(null);

                let nonce = NACL.randomBytes(NACL.BOX.NONCE_LENGTH);
                let msg = NACL.randomBytes(128);
                let boxedMsg = NACL.BOX.box(msg, nonce, keypairBob.publicKey, keypairAlice.secretKey);
                assert(boxedMsg.size() > 0);
            });
            test("NACL.BOX.open", func() {
                let keypairBob = NACL.BOX.keyPair(null);
                for(i in Iter.range(0, 1000)) {()};
                let keypairAlice = NACL.BOX.keyPair(null);

                let nonce = NACL.randomBytes(NACL.BOX.NONCE_LENGTH);
                let msg = NACL.randomBytes(128);
                let msgBox = NACL.BOX.box(msg, nonce, keypairBob.publicKey, keypairAlice.secretKey);
                let msgRaw = NACL.BOX.open(msgBox, nonce, keypairAlice.publicKey, keypairBob.secretKey);
                assert(msgRaw != null);
                assert(Array.equal(msg, Option.get(msgRaw, []), Nat8.equal));
            });
        });

        suite("NACL.BOX.SECRET", func() {
            test("NACL.BOX.SECRET.before", func() {
                let keypair = NACL.BOX.keyPair(null);
                let keyShared = NACL.BOX.SECRET.before(keypair.publicKey, keypair.secretKey);
                assert(keyShared.size() == NACL.BOX.SECRET.KEY_LENGTH);
            });
            test("NACL.BOX.SECRET.box", func() {
                let keypairBob = NACL.BOX.keyPair(null);
                for(i in Iter.range(0, 1000)) {()};
                let keypairAlice = NACL.BOX.keyPair(null);
                let sharedKey = NACL.BOX.SECRET.before(keypairBob.publicKey, keypairAlice.secretKey);

                let nonce = NACL.randomBytes(NACL.BOX.SECRET.NONCE_LENGTH);
                let msg = NACL.randomBytes(128);
                ignore NACL.BOX.SECRET.box(msg, nonce, sharedKey);
            });
            test("NACL.BOX.SECRET.open", func() {
                let keypairBob = NACL.BOX.keyPair(null);
                for(i in Iter.range(0, 1000)) {()};
                let keypairAlice = NACL.BOX.keyPair(null);
                let sharedKey = NACL.BOX.SECRET.before(keypairBob.publicKey, keypairAlice.secretKey);

                let nonce = NACL.randomBytes(NACL.BOX.SECRET.NONCE_LENGTH);
                let msg = NACL.randomBytes(128);
                let msgBox = NACL.BOX.SECRET.box(msg, nonce, sharedKey);
                
                let msgRaw = NACL.BOX.SECRET.open(msgBox, nonce, sharedKey);
                assert(msgRaw != null);
                assert(Array.equal(msg, Option.get(msgRaw, []), Nat8.equal));
            });
        });

        suite("NACL.SCALARMULT | NACL.randomBytes | NACL.hash", func() {
            test("NACL.SCALARMULT.mult", func() {
                let n = NACL.randomBytes(NACL.SCALARMULT.SCALAR_LENGTH);
                let m = NACL.randomBytes(NACL.SCALARMULT.GROUP_ELEMENT_LENGTH);
                let r = NACL.SCALARMULT.mult(n, m);
                assert(r.size() == NACL.SCALARMULT.GROUP_ELEMENT_LENGTH);
            });
            test("NACL.SCALARMULT.base", func() {
                let n = NACL.randomBytes(NACL.SCALARMULT.SCALAR_LENGTH);
                let r = NACL.SCALARMULT.base(n);
                assert(r.size() == NACL.SCALARMULT.GROUP_ELEMENT_LENGTH);
            });
            test("NACL.randomBytes", func() {
                let rnd = NACL.randomBytes(32);
                assert(rnd.size() == 32);
                let rnd64 = NACL.randomBytes(64);
                assert(rnd64.size() == 64);
                let rnd128 = NACL.randomBytes(128);
                assert(rnd128.size() == 128);
                let rnd256 = NACL.randomBytes(256);
                assert(rnd256.size() == 256);
                let rnd512 = NACL.randomBytes(512);
                assert(rnd512.size() == 512);
            });
            test("NACL.hash", func() {
                let msg = NACL.randomBytes(128);
                let x1 = NACL.hash(msg);
                assert(x1.size() == 64);
                let msg512 = NACL.randomBytes(512);
                let x2 = NACL.hash(msg512);
                assert(x2.size() == 64);
                let msg1024 = NACL.randomBytes(1024);
                let x3 = NACL.hash(msg1024);
                assert(x3.size() == 64);
            });
        });
    };
}