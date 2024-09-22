import Bench "mo:bench";
import Nat "mo:base/Nat";
import Iter "mo:base/Iter";

import NACL "../src/lib";

module {
    public func init() : Bench.Bench {
        let bench = Bench.Bench();

        bench.name("TWEETNACL");
        bench.description("TweetTNaCl module benchmark");

        bench.rows(["NACL.SIGN.keypair",
                    "NACL.SIGN.KEYPAIR.fromSecretKey",
                    "NACL.SIGN.KEYPAIR.fromSeed",
                    "NACL.SIGN.sign",
                    "NACL.SIGN.open",
                    "NACL.SIGN.DETACHED.detached",
                    "NACL.SIGN.DETACHED.verify",

                    "NACL.BOX.keypair",
                    "NACL.BOX.KEYPAIR.fromSecretKey",
                    "NACL.BOX.box",
                    "NACL.BOX.open",
                    "NACL.BOX.SECRET.before",
                    "NACL.BOX.SECRET.box",
                    "NACL.BOX.SECRET.open",
                    
                    "NACL.SCALARMULT.mult",
                    "NACL.SCALARMULT.base",
                    "NACL.hash",
                    "NACL.randomBytes"
                    ]);
        bench.cols(["1", "10", "50" /*"100", "1000"*/]);
        
        
        bench.runner(func(row, col) {
            let ?n = Nat.fromText(col);

            switch (row) {
                // NACL.SIGN test
                case ("NACL.SIGN.keypair") {
                    for (i in Iter.range(1, n)) {
                        ignore NACL.SIGN.keyPair(null);
                    };
                };
                case ("NACL.SIGN.KEYPAIR.fromSecretKey") {
                    let secretKey = NACL.randomBytes(NACL.SIGN.SECRET_KEY_LENGTH);
                    for (i in Iter.range(1, n)) {
                        ignore NACL.SIGN.KEYPAIR.fromSecretKey(secretKey);
                    };
                };
                case ("NACL.SIGN.KEYPAIR.fromSeed") {
                    let seed = NACL.randomBytes(NACL.SIGN.SEED_LENGTH);
                    for (i in Iter.range(1, n)) {
                        ignore NACL.SIGN.KEYPAIR.fromSeed(seed);
                    };
                };
                case ("NACL.SIGN.sign") {
                    for (i in Iter.range(1, n)) {
                        let keypair = NACL.SIGN.keyPair(null);
                        let msg = NACL.randomBytes(128);
                        ignore NACL.SIGN.sign(msg, keypair.secretKey);
                    };
                };
                case ("NACL.SIGN.open") {
                    let keypair = NACL.SIGN.keyPair(null);
                    let msg = NACL.randomBytes(128);
                    let msgSigned = NACL.SIGN.sign(msg, keypair.secretKey);
                    for (i in Iter.range(1, n)) {
                        ignore NACL.SIGN.open(msgSigned, keypair.publicKey);
                    };
                };
                case ("NACL.SIGN.DETACHED") {
                    let keypair = NACL.SIGN.keyPair(null);
                    let msg = NACL.randomBytes(128);
                    ignore NACL.SIGN.DETACHED.detached(msg, keypair.secretKey);
                };
                case ("NACL.SIGN.DETACHED.verify") {
                    let keypair = NACL.SIGN.keyPair(null);
                    let msg = NACL.randomBytes(128);
                    let signature = NACL.SIGN.DETACHED.detached(msg, keypair.secretKey);
                    for (i in Iter.range(1, n)) {
                        ignore NACL.SIGN.DETACHED.verify(msg, signature, keypair.publicKey);
                    };
                    
                };
                // NACL.BOX test
                case ("NACL.BOX.keypair") {
                    for (i in Iter.range(1, n)) {
                        ignore NACL.BOX.keyPair(null);
                    };
                };
                case ("NACL.BOX.KEYPAIR.fromSecretKey") {
                    let secretKey = NACL.randomBytes(NACL.BOX.SECRET_KEY_LENGTH);
                    for (i in Iter.range(1, n)) {
                        ignore NACL.BOX.KEYPAIR.fromSecretKey(secretKey);
                    };
                };
                case ("NACL.BOX.box") {
                    let keypair = NACL.BOX.keyPair(null);
                    let nonce = NACL.randomBytes(NACL.BOX.NONCE_LENGTH);
                    let msg = NACL.randomBytes(128);
                    for (i in Iter.range(1, n)) {
                        ignore NACL.BOX.box(msg, nonce, keypair.publicKey, keypair.secretKey);
                    };
                };
                case ("NACL.BOX.open") {
                    let keypair = NACL.BOX.keyPair(null);
                    let nonce = NACL.randomBytes(NACL.BOX.NONCE_LENGTH);
                    let msg = NACL.randomBytes(128);
                    let msgBox = NACL.BOX.box(msg, nonce, keypair.publicKey, keypair.secretKey);
                    for (i in Iter.range(1, n)) {
                        ignore NACL.BOX.open(msgBox, nonce, keypair.publicKey, keypair.secretKey);
                    };
                };
                case ("NACL.BOX.SECRET.before") {
                    let keypair = NACL.BOX.keyPair(null);
                    
                    for (i in Iter.range(1, n)) {
                        ignore NACL.BOX.SECRET.before(keypair.publicKey, keypair.secretKey);
                    };
                };
                case ("NACL.BOX.SECRET.box") {
                    let keypair = NACL.BOX.keyPair(null);
                    let sharedKey = NACL.BOX.SECRET.before(keypair.publicKey, keypair.secretKey);
                    let nonce = NACL.randomBytes(NACL.BOX.SECRET.NONCE_LENGTH);
                    let msg = NACL.randomBytes(128);
                    
                    for (i in Iter.range(1, n)) {
                        ignore NACL.BOX.SECRET.box(msg, nonce, sharedKey);
                    };
                };
                case ("NACL.BOX.SECRET.open") {
                    let keypair = NACL.BOX.keyPair(null);
                    let sharedKey = NACL.BOX.SECRET.before(keypair.publicKey, keypair.secretKey);
                    let nonce = NACL.randomBytes(NACL.BOX.SECRET.NONCE_LENGTH);
                    let msg = NACL.randomBytes(128);
                    let msgBox = NACL.BOX.SECRET.box(msg, nonce, sharedKey);
                    
                    for (i in Iter.range(1, n)) {
                        ignore NACL.BOX.SECRET.open(msgBox, nonce, sharedKey);
                    };
                };
                // NACL.SCALARMULT | NACL.randomBytes | NACL.hash
                case ("NACL.SCALARMULT.mult") {
                    let x = NACL.randomBytes(NACL.SCALARMULT.SCALAR_LENGTH);
                    let y = NACL.randomBytes(NACL.SCALARMULT.GROUP_ELEMENT_LENGTH);
                    for (i in Iter.range(1, n)) {
                        ignore NACL.SCALARMULT.mult(x, y);
                    };
                };
                case ("NACL.SCALARMULT.base") {
                    let x = NACL.randomBytes(NACL.SCALARMULT.SCALAR_LENGTH);
                    for (i in Iter.range(1, n)) {
                        ignore NACL.SCALARMULT.base(x);
                    };
                };
                case ("NACL.hash") {
                    let msg = NACL.randomBytes(128);
                    for (i in Iter.range(1, n)) {
                        ignore NACL.hash(msg);
                    };
                };
                case ("NACL.randomBytes") {
                    for (i in Iter.range(1, n)) {
                        ignore NACL.randomBytes(512);
                    };
                };
                case _ {};
            };
        });

        bench;
  };
};