import {test; suite} "mo:test/async";
import Utils "mo:test/expect/utils";
import Array "mo:base/Array";
import Nat8 "mo:base/Nat8";
import Blob "mo:base/Blob";
import Buffer "mo:base/Buffer";
import Random "mo:base/Random";
import Iter "mo:base/Iter";
import Option "mo:base/Option";
import Debug "mo:base/Debug";
import NACL "../src/lib";

actor {

    func asyncRandomBytesExternal(blength: Nat): async [Nat8] {
        let frandom = func () : async [Nat8] {Blob.toArray(await Random.blob())};
        var r = Buffer.fromArray<Nat8>(await frandom());
        if (r.size() > blength) {
            r := Buffer.subBuffer(r, 0, blength);
        };
        while (r.size() < blength) {
            let moreBytes = Buffer.fromArray<Nat8>(await frandom());
            var i = 0;
            while (r.size() < blength and i < moreBytes.size()) {
                r.add(moreBytes.get(i));
                i += 1;
            };
        };
        r.put(0, 111);
        r.put(31, 222);
        Buffer.toArray(r);
    };

    public func runTests() : async () {
    
        await suite("NACL.SIGN", func() : async () {
            await test("NACL.SIGN.asyncKeyPair", func() : async () {
                let kp = await NACL.SIGN.asyncKeyPair(null);
                let sumPkBytes = Array.foldLeft<Nat8, Nat>(kp.publicKey, 0, func (sum, xi) = sum + Nat8.toNat(xi));
                let sumSkBytes = Array.foldLeft<Nat8, Nat>(kp.secretKey, 0, func (sum, xi) = sum + Nat8.toNat(xi));
                assert(sumPkBytes > 0);
                assert(sumSkBytes > 0);
                assert(kp.publicKey.size() == NACL.SIGN.PUBLIC_KEY_LENGTH);
                assert(kp.secretKey.size() == NACL.SIGN.SECRET_KEY_LENGTH);
            });
        });

        await suite("NACL.SIGN", func() : async () {
            await test("NACL.SIGN.asyncKeyPair with external random function", func() : async () {
                let kp = await NACL.SIGN.asyncKeyPair(?asyncRandomBytesExternal);
                assert(kp.secretKey[0] == 111);  // defined in asyncRandomBytesExternal
                assert(kp.secretKey[31] == 222); // defined in asyncRandomBytesExternal
                let sumPkBytes = Array.foldLeft<Nat8, Nat>(kp.publicKey, 0, func (sum, xi) = sum + Nat8.toNat(xi));
                let sumSkBytes = Array.foldLeft<Nat8, Nat>(kp.secretKey, 0, func (sum, xi) = sum + Nat8.toNat(xi));
                assert(sumPkBytes > 0);
                assert(sumSkBytes > 0);
                assert(kp.publicKey.size() == NACL.SIGN.PUBLIC_KEY_LENGTH);
                assert(kp.secretKey.size() == NACL.SIGN.SECRET_KEY_LENGTH);
            });

            for (i in Iter.range(0, 5)) {
                await test("NACL.SIGN.open", func() : async () {
                    
                        let keypair = await NACL.SIGN.asyncKeyPair(null);
                        let msg = await NACL.asyncRandomBytes(1024);
                        let msgSigned = NACL.SIGN.sign(msg, keypair.secretKey);
                        let rawMsg = NACL.SIGN.open(msgSigned, keypair.publicKey);
                        assert(rawMsg != null);
                        assert(Array.equal(msg, Option.get(rawMsg, []), Nat8.equal));
                    
                });
            };
            
            for (i in Iter.range(0, 5)) {
                await test("NACL.SIGN.DETACHED.verify", func() : async () {
                        let keypair = await NACL.SIGN.asyncKeyPair(null);
                        let msg = await NACL.asyncRandomBytes(1024);
                        let signature = NACL.SIGN.DETACHED.detached(msg, keypair.secretKey);
                        let vrf = NACL.SIGN.DETACHED.verify(msg, signature, keypair.publicKey);
                        assert(vrf);
                    
                });
            };
        });

        await suite("NACL.BOX", func() : async () {
            await test("NACL.BOX.keypair", func() : async () {
                let kp = await NACL.BOX.asyncKeyPair(null);
                let sumPkBytes = Array.foldLeft<Nat8, Nat>(kp.publicKey, 0, func (sum, xi) = sum + Nat8.toNat(xi));
                let sumSkBytes = Array.foldLeft<Nat8, Nat>(kp.secretKey, 0, func (sum, xi) = sum + Nat8.toNat(xi));
                assert(sumPkBytes > 0);
                assert(sumSkBytes > 0);
                assert(kp.publicKey.size() == NACL.BOX.PUBLIC_KEY_LENGTH);
                assert(kp.secretKey.size() == NACL.BOX.SECRET_KEY_LENGTH);
            });

            for (i in Iter.range(0, 5)) {
                await test("NACL.BOX.open", func() : async () {
                    
                        let keypairBob = await NACL.BOX.asyncKeyPair(null);
                        let keypairAlice = await NACL.BOX.asyncKeyPair(null);

                        let nonce = await NACL.asyncRandomBytes(NACL.BOX.NONCE_LENGTH);
                        let msg = await NACL.asyncRandomBytes(1024);
                        let msgBox = NACL.BOX.box(msg, nonce, keypairBob.publicKey, keypairAlice.secretKey);
                        let msgRaw = NACL.BOX.open(msgBox, nonce, keypairAlice.publicKey, keypairBob.secretKey);
                        assert(msgRaw != null);
                        assert(Array.equal(msg, Option.get(msgRaw, []), Nat8.equal));
                    
                });
            };
            
            for (i in Iter.range(0, 5)) {
                await test("NACL.BOX.open (test with message size < 16)", func() : async () {
                    
                        for (i in Iter.range(1, 16)) {
                            let keypairBob = await NACL.BOX.asyncKeyPair(null);
                            let keypairAlice = await NACL.BOX.asyncKeyPair(null);
                            let nonce = await NACL.asyncRandomBytes(NACL.BOX.NONCE_LENGTH);
                            let msg = await NACL.asyncRandomBytes(i);
                            let msgBox = NACL.BOX.box(msg, nonce, keypairBob.publicKey, keypairAlice.secretKey);
                            let msgRaw = NACL.BOX.open(msgBox, nonce, keypairAlice.publicKey, keypairBob.secretKey);
                            assert(msgRaw != null);
                            assert(Array.equal(msg, Option.get(msgRaw, []), Nat8.equal));
                        };
                    
                });
            };
        });

        await suite("NACL.asyncRandomBytes", func() : async () {
            await test("NACL.randomBytes", func() : async () {
                var byteLength = 32;
                while (byteLength < 555) {
                    let rnd = await NACL.asyncRandomBytes(byteLength);
                    let sumRndBytes = Array.foldLeft<Nat8, Nat>(rnd, 0, func (sum, xi) = sum + Nat8.toNat(xi));
                    assert(sumRndBytes > 0);
                    assert(rnd.size() == byteLength);
                    byteLength *= 2;
                };
            });
        });

    };
}