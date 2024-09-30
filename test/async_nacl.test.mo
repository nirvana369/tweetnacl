import {test; suite} "mo:test/async";
import Array "mo:base/Array";
import Nat8 "mo:base/Nat8";
import Blob "mo:base/Blob";
import Buffer "mo:base/Buffer";
import Random "mo:base/Random";
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