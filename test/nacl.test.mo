import {test; suite} "mo:test";
import Array "mo:base/Array";
import Nat8 "mo:base/Nat8";
import Option "mo:base/Option";
import Iter "mo:base/Iter";
import Text "mo:base/Text";
import Blob "mo:base/Blob";
import Char "mo:base/Char";
import NACL "../src/lib";

actor {

    func getHexes() : [Text] {
        let symbols = [
            '0', '1', '2', '3', '4', '5', '6', '7',
            '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
        ];
        let base : Nat8 = 0x10;
        func nat8ToText(u8: Nat8) : Text {
            let c1 = symbols[Nat8.toNat((u8/base))];
            let c2 = symbols[Nat8.toNat((u8%base))];
            return Char.toText(c1) # Char.toText(c2);
        };
        let array : [Text] = Array.tabulate<Text>(256, func i = nat8ToText(Nat8.fromNat(i)));
        return array;
    };

    func bytesToHex(uint8a: [Nat8]): Text {
        let hexes = getHexes();
        let hex = Array.foldRight<Nat8, Text>(uint8a, "", 
                                            func(x, acc) = hexes[Nat8.toNat(x)] # acc);
        return hex;
    };

    func randomBytesExternal(blength: Nat): [Nat8] {
        let x : [var Nat8] = Array.tabulateVar<Nat8>(blength, func i = 1);
        x[0] := 111;
        x[31] := 222;
        Array.freeze(x);
    };

    public func runTests() : async () {
    
        suite("NACL.SIGN", func() {
            test("NACL.SIGN.keypair", func() {
                let kp = NACL.SIGN.keyPair(null);
                let sumPkBytes = Array.foldLeft<Nat8, Nat>(kp.publicKey, 0, func (sum, xi) = sum + Nat8.toNat(xi));
                let sumSkBytes = Array.foldLeft<Nat8, Nat>(kp.secretKey, 0, func (sum, xi) = sum + Nat8.toNat(xi));
                assert(sumPkBytes > 0);
                assert(sumSkBytes > 0);
                assert(kp.publicKey.size() == NACL.SIGN.PUBLIC_KEY_LENGTH);
                assert(kp.secretKey.size() == NACL.SIGN.SECRET_KEY_LENGTH);
            });

            test("NACL.SIGN.keypair use external random func", func() {
                let kp = NACL.SIGN.keyPair(?randomBytesExternal);
                assert(kp.secretKey[0] == 111);
                assert(kp.secretKey[31] == 222);
                let sumPkBytes = Array.foldLeft<Nat8, Nat>(kp.publicKey, 0, func (sum, xi) = sum + Nat8.toNat(xi));
                let sumSkBytes = Array.foldLeft<Nat8, Nat>(kp.secretKey, 0, func (sum, xi) = sum + Nat8.toNat(xi));
                assert(sumPkBytes > 0);
                assert(sumSkBytes > 0);
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
                let msg = NACL.randomBytes(1024);
                let sign = NACL.SIGN.sign(msg, keypair.secretKey);
                assert(sign.size() > 0);
            });
            test("NACL.SIGN.open", func() {
                let keypair = NACL.SIGN.keyPair(null);
                let msg = NACL.randomBytes(1024);
                let msgSigned = NACL.SIGN.sign(msg, keypair.secretKey);
                let rawMsg = NACL.SIGN.open(msgSigned, keypair.publicKey);
                assert(rawMsg != null);
                assert(Array.equal(msg, Option.get(rawMsg, []), Nat8.equal));
            });
            test("NACL.SIGN.DETACHED.detached", func() {
                let keypair = NACL.SIGN.keyPair(null);
                let msg = NACL.randomBytes(1024);
                let sig = NACL.SIGN.DETACHED.detached(msg, keypair.secretKey);
                assert(sig.size() > 0);
            });
            test("NACL.SIGN.DETACHED.verify", func() {
                let keypair = NACL.SIGN.keyPair(null);
                let msg = NACL.randomBytes(1024);
                let signature = NACL.SIGN.DETACHED.detached(msg, keypair.secretKey);
                let vrf = NACL.SIGN.DETACHED.verify(msg, signature, keypair.publicKey);
                assert(vrf);
            });
        });

        suite("NACL.BOX", func() {
            test("NACL.BOX.keypair", func() {
                let kp = NACL.BOX.keyPair(null);
                let sumPkBytes = Array.foldLeft<Nat8, Nat>(kp.publicKey, 0, func (sum, xi) = sum + Nat8.toNat(xi));
                let sumSkBytes = Array.foldLeft<Nat8, Nat>(kp.secretKey, 0, func (sum, xi) = sum + Nat8.toNat(xi));
                assert(sumPkBytes > 0);
                assert(sumSkBytes > 0);
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
                let msg = NACL.randomBytes(1024);
                let boxedMsg = NACL.BOX.box(msg, nonce, keypairBob.publicKey, keypairAlice.secretKey);
                assert(boxedMsg.size() > 0);
            });
            test("NACL.BOX.open", func() {
                let keypairBob = NACL.BOX.keyPair(null);
                for(i in Iter.range(0, 1000)) {()};
                let keypairAlice = NACL.BOX.keyPair(null);

                let nonce = NACL.randomBytes(NACL.BOX.NONCE_LENGTH);
                let msg = NACL.randomBytes(1024);
                let msgBox = NACL.BOX.box(msg, nonce, keypairBob.publicKey, keypairAlice.secretKey);
                let msgRaw = NACL.BOX.open(msgBox, nonce, keypairAlice.publicKey, keypairBob.secretKey);
                assert(msgRaw != null);
                assert(Array.equal(msg, Option.get(msgRaw, []), Nat8.equal));
            });
            test("NACL.BOX.open (test with message size < 16)", func() {
                let keypairBob = NACL.BOX.keyPair(null);
                for(i in Iter.range(0, 1000)) {()};
                let keypairAlice = NACL.BOX.keyPair(null);
                for (i in Iter.range(1, 16)) {
                    let nonce = NACL.randomBytes(NACL.BOX.NONCE_LENGTH);
                    let msg = NACL.randomBytes(i);
                    let msgBox = NACL.BOX.box(msg, nonce, keypairBob.publicKey, keypairAlice.secretKey);
                    let msgRaw = NACL.BOX.open(msgBox, nonce, keypairAlice.publicKey, keypairBob.secretKey);
                    assert(msgRaw != null);
                    assert(Array.equal(msg, Option.get(msgRaw, []), Nat8.equal));
                }
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
                let msg = NACL.randomBytes(1024);
                ignore NACL.BOX.SECRET.box(msg, nonce, sharedKey);
            });
            test("NACL.BOX.SECRET.open", func() {
                let keypairBob = NACL.BOX.keyPair(null);
                for(i in Iter.range(0, 1000)) {()};
                let keypairAlice = NACL.BOX.keyPair(null);
                let sharedKey = NACL.BOX.SECRET.before(keypairBob.publicKey, keypairAlice.secretKey);

                let nonce = NACL.randomBytes(NACL.BOX.SECRET.NONCE_LENGTH);
                let msg = NACL.randomBytes(1024);
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
                var byteLength = 32;
                while (byteLength < 555) {
                    let rnd = NACL.randomBytes(byteLength);
                    let sumRndBytes = Array.foldLeft<Nat8, Nat>(rnd, 0, func (sum, xi) = sum + Nat8.toNat(xi));
                    assert(sumRndBytes > 0);
                    assert(rnd.size() == byteLength);
                    byteLength *= 2;
                };
            });

            let VECTORS = [
                { value = "abc"; output = "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f" },
                { value = ""; output = "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e" },
                { value = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"; output = "204a8fc6dda82f0a0ced7beb8e08a41657c16ef468b228a8279be331a703c33596fd15c13b1b07f9aa1d3bea57789ca031ad85c7a71dd70354ec631238ca3445" }
            ];

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

                for (x in VECTORS.vals()) {
                    let hash = NACL.hash(Blob.toArray(Text.encodeUtf8(x.value)));
                    let hex = bytesToHex(hash);
                    assert(x.output == hex);
                };
            });
        });
    };
}