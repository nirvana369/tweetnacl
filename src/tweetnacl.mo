/*******************************************************************
* Copyright         : 2024 nirvana369
* File Name         : tweetnacl.mo
* Description       : This library is porting version of Nacl.
*                    
* Revision History  :
* Date				Author    		Comments
* ---------------------------------------------------------------------------
* 08/31/2024		nirvana369 		Created.
* 09/01/2024		nirvana369 		Added core functions.
* 09/04/2024        nirvana369      Implement func crypto_hashblocks_hl
*                                   use int64 to process instead int32
* 09/05/2024        nirvana369      Relax.. ~_~
* 09/11/2024        nirvana369      Yagi typhoon landing... ~_~
* 09/16/2024        nirvana369      Implement func modL, reduce, crypto_sign
* 09/17/2024        nirvana369      Implement unpackneg, crypto_sign_open, high-level API
* 09/18/2024        nirvana369      Unit test : module sign
* 09/19/2024        nirvana369      Unit test : module sign, fix bug func crypto_sign() -> modL not assign subbuffer to main param
* 09/20/2024        nirvana369      Unit test : module box
*                                   Fix bug Poly1305 : arithmetic overflow -> change nat16 to int64
* 09/22/2024        nirvana369      Fix bug array index out of bound (Poly1305 (NACL.BOX module) - tag #22092024) when : 3 < message size < 16
*                                   Update test
* 10/24/2014        nirvana369      Refactor some func: change [Int64] -> Buffer<Int64>
******************************************************************/

import Float "mo:base/Float";
import Array "mo:base/Array";
import Nat64 "mo:base/Nat64";
import Nat8 "mo:base/Nat8";
import Iter "mo:base/Iter";
import Int "mo:base/Int";
import Int64 "mo:base/Int64";
import Buffer "mo:base/Buffer";
import Debug "mo:base/Debug";
import Nat "mo:base/Nat";
import Blob "mo:base/Blob";
import Time "mo:base/Time";
import Random "mo:base/Random";

module TweetNaCl {

    public let crypto_secretbox_KEYBYTES = 32;
    public let crypto_secretbox_NONCEBYTES = 24;
    public let crypto_secretbox_ZEROBYTES = 32;
    public let crypto_secretbox_BOXZEROBYTES = 16;
    public let crypto_scalarmult_BYTES = 32;
    public let crypto_scalarmult_SCALARBYTES = 32;
    public let crypto_box_PUBLICKEYBYTES = 32;
    public let crypto_box_SECRETKEYBYTES = 32;
    public let crypto_box_BEFORENMBYTES = 32;
    public let crypto_box_NONCEBYTES = crypto_secretbox_NONCEBYTES;
    public let crypto_box_ZEROBYTES = crypto_secretbox_ZEROBYTES;
    public let crypto_box_BOXZEROBYTES = crypto_secretbox_BOXZEROBYTES;
    public let crypto_sign_BYTES = 64;
    public let crypto_sign_PUBLICKEYBYTES = 32;
    public let crypto_sign_SECRETKEYBYTES = 64;
    public let crypto_sign_SEEDBYTES = 32;
    public let crypto_hash_BYTES = 64;

    let _0 : [Nat8] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let _9 : [Nat8] = [9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

    let gf0 : [Int64] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let gf1 : [Int64] = [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let _121665 : [Int64] = [0xdb41, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let D : [Int64] = [0x78a3, 0x1359, 0x4dca, 0x75eb, 0xd8ab, 0x4141, 0x0a4d, 0x0070, 0xe898, 0x7779, 0x4079, 0x8cc7, 0xfe73, 0x2b6f, 0x6cee, 0x5203];
    let D2 : [Int64] = [0xf159, 0x26b2, 0x9b94, 0xebd6, 0xb156, 0x8283, 0x149a, 0x00e0, 0xd130, 0xeef3, 0x80f2, 0x198e, 0xfce7, 0x56df, 0xd9dc, 0x2406];
    let X : [Int64] = [0xd51a, 0x8f25, 0x2d60, 0xc956, 0xa7b2, 0x9525, 0xc760, 0x692c, 0xdc5c, 0xfdd6, 0xe231, 0xc0a4, 0x53fe, 0xcd6e, 0x36d3, 0x2169];
    let Y : [Int64] = [0x6658, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666];
    let I : [Int64] = [0xa0b0, 0x4a0e, 0x1b27, 0xc4ee, 0xe478, 0xad2f, 0x1806, 0x2f43, 0xd7a7, 0x3dfb, 0x0099, 0x2b4d, 0xdf0b, 0x4fc1, 0x2480, 0x2b83];

    let sigma : [Nat8] = [101, 120, 112, 97, 110, 100, 32, 51, 50, 45, 98, 121, 116, 101, 32, 107];

    let K : [Int64] = [
        0x428a2f98, 0xd728ae22, 0x71374491, 0x23ef65cd,
        0xb5c0fbcf, 0xec4d3b2f, 0xe9b5dba5, 0x8189dbbc,
        0x3956c25b, 0xf348b538, 0x59f111f1, 0xb605d019,
        0x923f82a4, 0xaf194f9b, 0xab1c5ed5, 0xda6d8118,
        0xd807aa98, 0xa3030242, 0x12835b01, 0x45706fbe,
        0x243185be, 0x4ee4b28c, 0x550c7dc3, 0xd5ffb4e2,
        0x72be5d74, 0xf27b896f, 0x80deb1fe, 0x3b1696b1,
        0x9bdc06a7, 0x25c71235, 0xc19bf174, 0xcf692694,
        0xe49b69c1, 0x9ef14ad2, 0xefbe4786, 0x384f25e3,
        0x0fc19dc6, 0x8b8cd5b5, 0x240ca1cc, 0x77ac9c65,
        0x2de92c6f, 0x592b0275, 0x4a7484aa, 0x6ea6e483,
        0x5cb0a9dc, 0xbd41fbd4, 0x76f988da, 0x831153b5,
        0x983e5152, 0xee66dfab, 0xa831c66d, 0x2db43210,
        0xb00327c8, 0x98fb213f, 0xbf597fc7, 0xbeef0ee4,
        0xc6e00bf3, 0x3da88fc2, 0xd5a79147, 0x930aa725,
        0x06ca6351, 0xe003826f, 0x14292967, 0x0a0e6e70,
        0x27b70a85, 0x46d22ffc, 0x2e1b2138, 0x5c26c926,
        0x4d2c6dfc, 0x5ac42aed, 0x53380d13, 0x9d95b3df,
        0x650a7354, 0x8baf63de, 0x766a0abb, 0x3c77b2a8,
        0x81c2c92e, 0x47edaee6, 0x92722c85, 0x1482353b,
        0xa2bfe8a1, 0x4cf10364, 0xa81a664b, 0xbc423001,
        0xc24b8b70, 0xd0f89791, 0xc76c51a3, 0x0654be30,
        0xd192e819, 0xd6ef5218, 0xd6990624, 0x5565a910,
        0xf40e3585, 0x5771202a, 0x106aa070, 0x32bbd1b8,
        0x19a4c116, 0xb8d2d0c8, 0x1e376c08, 0x5141ab53,
        0x2748774c, 0xdf8eeb99, 0x34b0bcb5, 0xe19b48a8,
        0x391c0cb3, 0xc5c95a63, 0x4ed8aa4a, 0xe3418acb,
        0x5b9cca4f, 0x7763e373, 0x682e6ff3, 0xd6b2b8a3,
        0x748f82ee, 0x5defb2fc, 0x78a5636f, 0x43172f60,
        0x84c87814, 0xa1f0ab72, 0x8cc70208, 0x1a6439ec,
        0x90befffa, 0x23631e28, 0xa4506ceb, 0xde82bde9,
        0xbef9a3f7, 0xb2c67915, 0xc67178f2, 0xe372532b,
        0xca273ece, 0xea26619c, 0xd186b8c7, 0x21c0c207,
        0xeada7dd6, 0xcde0eb1e, 0xf57d4f7f, 0xee6ed178,
        0x06f067aa, 0x72176fba, 0x0a637dc5, 0xa2c898a6,
        0x113f9804, 0xbef90dae, 0x1b710b35, 0x131c471b,
        0x28db77f5, 0x23047d84, 0x32caab7b, 0x40c72493,
        0x3c9ebe0a, 0x15c9bebc, 0x431d67c4, 0x9c100d4c,
        0x4cc5d4be, 0xcb3e42b6, 0x597f299c, 0xfc657e2a,
        0x5fcb6fab, 0x3ad6faec, 0x6c44198c, 0x4a475817
    ];

    let L : [Int64] = [0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10];

    module BitsPrc {

        public func nat8toInt64(n : Nat8) : Int64 {
            Int64.fromNat64(Nat64.fromNat(Nat8.toNat(n)));
        };

        public func int64toNat8(n : Int64) : Nat8 {
            Nat8.fromIntWrap(Int64.toInt(n));
        };
    };

    public func buffer_i64(bLength : Nat) : Buffer.Buffer<Int64> {
        Buffer.fromArray(Array.tabulate<Int64>(bLength, func i = 0));
    };

    func ts64(x : Buffer.Buffer<Nat8>, i : Nat, h : Int64, l : Int64) {
        x.put(i, BitsPrc.int64toNat8((h >> 24) & 0xff));
        x.put(i+1, BitsPrc.int64toNat8((h >> 16) & 0xff));
        x.put(i+2, BitsPrc.int64toNat8((h >>  8) & 0xff));
        x.put(i+3, BitsPrc.int64toNat8(h & 0xff));
        x.put(i+4, BitsPrc.int64toNat8((l >> 24)  & 0xff));
        x.put(i+5, BitsPrc.int64toNat8((l >> 16)  & 0xff));
        x.put(i+6, BitsPrc.int64toNat8((l >>  8)  & 0xff));
        x.put(i+7, BitsPrc.int64toNat8(l & 0xff));
    };

    // verify n bytes
    func vn(x : [Nat8], xi : Nat, y : [Nat8], yi : Nat, n : Nat) : Int {
        var i = 0;
        var d : Int64 = 0;
        while (i < n) {
            d |= (BitsPrc.nat8toInt64(x[xi+i]) ^ BitsPrc.nat8toInt64(y[yi+i]));
            i += 1;
        };
        // success = 0
        return Int64.toInt((1 & ((d - 1) >> 8)) - 1);
    };

    public func crypto_verify_16(x : [Nat8], xi : Nat, y : [Nat8], yi : Nat) : Int {
        return vn(x, xi, y, yi, 16);
    };

    public func crypto_verify_32(x : [Nat8], xi : Nat, y : [Nat8], yi : Nat) : Int {
        return vn(x, xi, y, yi, 32);
    };

    func core_salsa20(o : Buffer.Buffer<Nat8>, p : [Nat8], k : [Nat8], c : [Nat8]) {
        var j0  = BitsPrc.nat8toInt64(c[ 0] & 0xff) | (BitsPrc.nat8toInt64(c[ 1] & 0xff)<<8) | (BitsPrc.nat8toInt64(c[ 2] & 0xff)<<16) | (BitsPrc.nat8toInt64(c[ 3] & 0xff)<<24);
        var j1  = BitsPrc.nat8toInt64(k[ 0] & 0xff) | (BitsPrc.nat8toInt64(k[ 1] & 0xff)<<8) | (BitsPrc.nat8toInt64(k[ 2] & 0xff)<<16) | (BitsPrc.nat8toInt64(k[ 3] & 0xff)<<24);
        var j2  = BitsPrc.nat8toInt64(k[ 4] & 0xff) | (BitsPrc.nat8toInt64(k[ 5] & 0xff)<<8) | (BitsPrc.nat8toInt64(k[ 6] & 0xff)<<16) | (BitsPrc.nat8toInt64(k[ 7] & 0xff)<<24);
        var j3  = BitsPrc.nat8toInt64(k[ 8] & 0xff) | (BitsPrc.nat8toInt64(k[ 9] & 0xff)<<8) | (BitsPrc.nat8toInt64(k[10] & 0xff)<<16) | (BitsPrc.nat8toInt64(k[11] & 0xff)<<24);
        var j4  = BitsPrc.nat8toInt64(k[12] & 0xff) | (BitsPrc.nat8toInt64(k[13] & 0xff)<<8) | (BitsPrc.nat8toInt64(k[14] & 0xff)<<16) | (BitsPrc.nat8toInt64(k[15] & 0xff)<<24);
        var j5  = BitsPrc.nat8toInt64(c[ 4] & 0xff) | (BitsPrc.nat8toInt64(c[ 5] & 0xff)<<8) | (BitsPrc.nat8toInt64(c[ 6] & 0xff)<<16) | (BitsPrc.nat8toInt64(c[ 7] & 0xff)<<24);
        var j6  = BitsPrc.nat8toInt64(p[ 0] & 0xff) | (BitsPrc.nat8toInt64(p[ 1] & 0xff)<<8) | (BitsPrc.nat8toInt64(p[ 2] & 0xff)<<16) | (BitsPrc.nat8toInt64(p[ 3] & 0xff)<<24);
        var j7  = BitsPrc.nat8toInt64(p[ 4] & 0xff) | (BitsPrc.nat8toInt64(p[ 5] & 0xff)<<8) | (BitsPrc.nat8toInt64(p[ 6] & 0xff)<<16) | (BitsPrc.nat8toInt64(p[ 7] & 0xff)<<24);
        var j8  = BitsPrc.nat8toInt64(p[ 8] & 0xff) | (BitsPrc.nat8toInt64(p[ 9] & 0xff)<<8) | (BitsPrc.nat8toInt64(p[10] & 0xff)<<16) | (BitsPrc.nat8toInt64(p[11] & 0xff)<<24);
        var j9  = BitsPrc.nat8toInt64(p[12] & 0xff) | (BitsPrc.nat8toInt64(p[13] & 0xff)<<8) | (BitsPrc.nat8toInt64(p[14] & 0xff)<<16) | (BitsPrc.nat8toInt64(p[15] & 0xff)<<24);
        var j10 = BitsPrc.nat8toInt64(c[ 8] & 0xff) | (BitsPrc.nat8toInt64(c[ 9] & 0xff)<<8) | (BitsPrc.nat8toInt64(c[10] & 0xff)<<16) | (BitsPrc.nat8toInt64(c[11] & 0xff)<<24);
        var j11 = BitsPrc.nat8toInt64(k[16] & 0xff) | (BitsPrc.nat8toInt64(k[17] & 0xff)<<8) | (BitsPrc.nat8toInt64(k[18] & 0xff)<<16) | (BitsPrc.nat8toInt64(k[19] & 0xff)<<24);
        var j12 = BitsPrc.nat8toInt64(k[20] & 0xff) | (BitsPrc.nat8toInt64(k[21] & 0xff)<<8) | (BitsPrc.nat8toInt64(k[22] & 0xff)<<16) | (BitsPrc.nat8toInt64(k[23] & 0xff)<<24);
        var j13 = BitsPrc.nat8toInt64(k[24] & 0xff) | (BitsPrc.nat8toInt64(k[25] & 0xff)<<8) | (BitsPrc.nat8toInt64(k[26] & 0xff)<<16) | (BitsPrc.nat8toInt64(k[27] & 0xff)<<24);
        var j14 = BitsPrc.nat8toInt64(k[28] & 0xff) | (BitsPrc.nat8toInt64(k[29] & 0xff)<<8) | (BitsPrc.nat8toInt64(k[30] & 0xff)<<16) | (BitsPrc.nat8toInt64(k[31] & 0xff)<<24);
        var j15 = BitsPrc.nat8toInt64(c[12] & 0xff) | (BitsPrc.nat8toInt64(c[13] & 0xff)<<8) | (BitsPrc.nat8toInt64(c[14] & 0xff)<<16) | (BitsPrc.nat8toInt64(c[15] & 0xff)<<24);

        var x0 = j0;
        var x1 = j1;
        var x2 = j2;
        var x3 = j3;
        var x4 = j4;
        var x5 = j5;
        var x6 = j6;
        var x7 = j7;
        var x8 = j8;
        var x9 = j9;
        var x10 = j10;
        var x11 = j11;
        var x12 = j12;
        var x13 = j13;
        var x14 = j14;
        var x15 = j15;
        var u : Int64 = 0;
        var i = 0;

        while (i < 20) {
            u := (x0 + x12 | 0) & 0xffffffff;
            x4 ^= ((u << 7) | (u >> (32-7))) & 0xffffffff;
            u := (x4 + x0 | 0) & 0xffffffff;
            x8 ^= ((u << 9) | (u >> (32-9))) & 0xffffffff;
            u := (x8 + x4 | 0) & 0xffffffff;
            x12 ^= ((u << 13) | (u >> (32-13))) & 0xffffffff;
            u := (x12 + x8 | 0) & 0xffffffff;
            x0 ^= ((u << 18) | (u >> (32-18))) & 0xffffffff;

            u := (x5 + x1 | 0) & 0xffffffff;
            x9 ^= ((u << 7) | (u >> (32-7))) & 0xffffffff;
            u := (x9 + x5 | 0) & 0xffffffff;
            x13 ^= ((u << 9) | (u >> (32-9))) & 0xffffffff;
            u := (x13 + x9 | 0) & 0xffffffff;
            x1 ^= ((u << 13) | (u >> (32-13))) & 0xffffffff;
            u := (x1 + x13 | 0) & 0xffffffff;
            x5 ^= ((u << 18) | (u >> (32-18))) & 0xffffffff;

            u := (x10 + x6 | 0) & 0xffffffff;
            x14 ^= ((u << 7) | (u >> (32-7))) & 0xffffffff;
            u := (x14 + x10 | 0) & 0xffffffff;
            x2 ^= ((u << 9) | (u >> (32-9))) & 0xffffffff;
            u := (x2 + x14 | 0) & 0xffffffff;
            x6 ^= ((u << 13) | (u >> (32-13))) & 0xffffffff;
            u := (x6 + x2 | 0) & 0xffffffff;
            x10 ^= ((u << 18) | (u >> (32-18))) & 0xffffffff;

            u := (x15 + x11 | 0) & 0xffffffff;
            x3 ^= ((u << 7) | (u >> (32-7))) & 0xffffffff;
            u := (x3 + x15 | 0) & 0xffffffff;
            x7 ^= ((u << 9) | (u >> (32-9))) & 0xffffffff;
            u := (x7 + x3 | 0) & 0xffffffff;
            x11 ^= ((u << 13) | (u >> (32-13))) & 0xffffffff;
            u := (x11 + x7 | 0) & 0xffffffff;
            x15 ^= ((u << 18) | (u >> (32-18))) & 0xffffffff;

            u := (x0 + x3 | 0) & 0xffffffff;
            x1 ^= ((u << 7) | (u >> (32-7))) & 0xffffffff;
            u := (x1 + x0 | 0) & 0xffffffff;
            x2 ^= ((u << 9) | (u >> (32-9))) & 0xffffffff;
            u := (x2 + x1 | 0) & 0xffffffff;
            x3 ^= ((u << 13) | (u >> (32-13))) & 0xffffffff;
            u := (x3 + x2 | 0) & 0xffffffff;
            x0 ^= ((u << 18) | (u >> (32-18))) & 0xffffffff;

            u := (x5 + x4 | 0) & 0xffffffff;
            x6 ^= ((u << 7) | (u >> (32-7))) & 0xffffffff;
            u := (x6 + x5 | 0) & 0xffffffff;
            x7 ^= ((u << 9) | (u >> (32-9))) & 0xffffffff;
            u := (x7 + x6 | 0) & 0xffffffff;
            x4 ^= ((u << 13) | (u >> (32-13))) & 0xffffffff;
            u := (x4 + x7 | 0) & 0xffffffff;
            x5 ^= ((u << 18) | (u >> (32-18))) & 0xffffffff;

            u := (x10 + x9 | 0) & 0xffffffff;
            x11 ^= ((u << 7) | (u >> (32-7))) & 0xffffffff;
            u := (x11 + x10 | 0) & 0xffffffff;
            x8 ^= ((u << 9) | (u >> (32-9))) & 0xffffffff;
            u := (x8 + x11 | 0) & 0xffffffff;
            x9 ^= ((u << 13) | (u >> (32-13))) & 0xffffffff;
            u := (x9 + x8 | 0) & 0xffffffff;
            x10 ^= ((u << 18) | (u >> (32-18))) & 0xffffffff;

            u := (x15 + x14 | 0) & 0xffffffff;
            x12 ^= ((u << 7) | (u >> (32-7))) & 0xffffffff;
            u := (x12 + x15 | 0) & 0xffffffff;
            x13 ^= ((u << 9) | (u >> (32-9))) & 0xffffffff;
            u := (x13 + x12 | 0) & 0xffffffff;
            x14 ^= ((u << 13) | (u >> (32-13))) & 0xffffffff;
            u := (x14 + x13 | 0) & 0xffffffff;
            x15 ^= ((u << 18) | (u >> (32-18))) & 0xffffffff;
            
            i += 2;
        };

        x0 :=  x0 +  j0 | 0;
        x1 :=  x1 +  j1 | 0;
        x2 :=  x2 +  j2 | 0;
        x3 :=  x3 +  j3 | 0;
        x4 :=  x4 +  j4 | 0;
        x5 :=  x5 +  j5 | 0;
        x6 :=  x6 +  j6 | 0;
        x7 :=  x7 +  j7 | 0;
        x8 :=  x8 +  j8 | 0;
        x9 :=  x9 +  j9 | 0;
        x10 := x10 + j10 | 0;
        x11 := x11 + j11 | 0;
        x12 := x12 + j12 | 0;
        x13 := x13 + j13 | 0;
        x14 := x14 + j14 | 0;
        x15 := x15 + j15 | 0;

        o.put( 0, BitsPrc.int64toNat8(x0 >>  0 & 0xff));
        o.put( 1, BitsPrc.int64toNat8(x0 >>  8 & 0xff));
        o.put( 2, BitsPrc.int64toNat8(x0 >> 16 & 0xff));
        o.put( 3, BitsPrc.int64toNat8(x0 >> 24 & 0xff));

        o.put( 4, BitsPrc.int64toNat8(x1 >>  0 & 0xff));
        o.put( 5, BitsPrc.int64toNat8(x1 >>  8 & 0xff));
        o.put( 6, BitsPrc.int64toNat8(x1 >> 16 & 0xff));
        o.put( 7, BitsPrc.int64toNat8(x1 >> 24 & 0xff));

        o.put( 8, BitsPrc.int64toNat8(x2 >>  0 & 0xff));
        o.put( 9, BitsPrc.int64toNat8(x2 >>  8 & 0xff));
        o.put(10, BitsPrc.int64toNat8(x2 >> 16 & 0xff));
        o.put(11, BitsPrc.int64toNat8(x2 >> 24 & 0xff));

        o.put(12, BitsPrc.int64toNat8(x3 >>  0 & 0xff));
        o.put(13, BitsPrc.int64toNat8(x3 >>  8 & 0xff));
        o.put(14, BitsPrc.int64toNat8(x3 >> 16 & 0xff));
        o.put(15, BitsPrc.int64toNat8(x3 >> 24 & 0xff));

        o.put(16, BitsPrc.int64toNat8(x4 >>  0 & 0xff));
        o.put(17, BitsPrc.int64toNat8(x4 >>  8 & 0xff));
        o.put(18, BitsPrc.int64toNat8(x4 >> 16 & 0xff));
        o.put(19, BitsPrc.int64toNat8(x4 >> 24 & 0xff));

        o.put(20, BitsPrc.int64toNat8(x5 >>  0 & 0xff));
        o.put(21, BitsPrc.int64toNat8(x5 >>  8 & 0xff));
        o.put(22, BitsPrc.int64toNat8(x5 >> 16 & 0xff));
        o.put(23, BitsPrc.int64toNat8(x5 >> 24 & 0xff));

        o.put(24, BitsPrc.int64toNat8(x6 >>  0 & 0xff));
        o.put(25, BitsPrc.int64toNat8(x6 >>  8 & 0xff));
        o.put(26, BitsPrc.int64toNat8(x6 >> 16 & 0xff));
        o.put(27, BitsPrc.int64toNat8(x6 >> 24 & 0xff));

        o.put(28, BitsPrc.int64toNat8(x7 >>  0 & 0xff));
        o.put(29, BitsPrc.int64toNat8(x7 >>  8 & 0xff));
        o.put(30, BitsPrc.int64toNat8(x7 >> 16 & 0xff));
        o.put(31, BitsPrc.int64toNat8(x7 >> 24 & 0xff));

        o.put(32, BitsPrc.int64toNat8(x8 >>  0 & 0xff));
        o.put(33, BitsPrc.int64toNat8(x8 >>  8 & 0xff));
        o.put(34, BitsPrc.int64toNat8(x8 >> 16 & 0xff));
        o.put(35, BitsPrc.int64toNat8(x8 >> 24 & 0xff));

        o.put(36, BitsPrc.int64toNat8(x9 >>  0 & 0xff));
        o.put(37, BitsPrc.int64toNat8(x9 >>  8 & 0xff));
        o.put(38, BitsPrc.int64toNat8(x9 >> 16 & 0xff));
        o.put(39, BitsPrc.int64toNat8(x9 >> 24 & 0xff));

        o.put(40, BitsPrc.int64toNat8(x10 >>  0 & 0xff));
        o.put(41, BitsPrc.int64toNat8(x10 >>  8 & 0xff));
        o.put(42, BitsPrc.int64toNat8(x10 >> 16 & 0xff));
        o.put(43, BitsPrc.int64toNat8(x10 >> 24 & 0xff));

        o.put(44, BitsPrc.int64toNat8(x11 >>  0 & 0xff));
        o.put(45, BitsPrc.int64toNat8(x11 >>  8 & 0xff));
        o.put(46, BitsPrc.int64toNat8(x11 >> 16 & 0xff));
        o.put(47, BitsPrc.int64toNat8(x11 >> 24 & 0xff));

        o.put(48, BitsPrc.int64toNat8(x12 >>  0 & 0xff));
        o.put(49, BitsPrc.int64toNat8(x12 >>  8 & 0xff));
        o.put(50, BitsPrc.int64toNat8(x12 >> 16 & 0xff));
        o.put(51, BitsPrc.int64toNat8(x12 >> 24 & 0xff));

        o.put(52, BitsPrc.int64toNat8(x13 >>  0 & 0xff));
        o.put(53, BitsPrc.int64toNat8(x13 >>  8 & 0xff));
        o.put(54, BitsPrc.int64toNat8(x13 >> 16 & 0xff));
        o.put(55, BitsPrc.int64toNat8(x13 >> 24 & 0xff));

        o.put(56, BitsPrc.int64toNat8(x14 >>  0 & 0xff));
        o.put(57, BitsPrc.int64toNat8(x14 >>  8 & 0xff));
        o.put(58, BitsPrc.int64toNat8(x14 >> 16 & 0xff));
        o.put(59, BitsPrc.int64toNat8(x14 >> 24 & 0xff));

        o.put(60, BitsPrc.int64toNat8(x15 >>  0 & 0xff));
        o.put(61, BitsPrc.int64toNat8(x15 >>  8 & 0xff));
        o.put(62, BitsPrc.int64toNat8(x15 >> 16 & 0xff));
        o.put(63, BitsPrc.int64toNat8(x15 >> 24 & 0xff));
    };

    func core_hsalsa20(o : Buffer.Buffer<Nat8>, p : [Nat8], k : [Nat8], c : [Nat8]) {
        var j0  = BitsPrc.nat8toInt64(c[ 0] & 0xff) | (BitsPrc.nat8toInt64(c[ 1] & 0xff)<<8) | (BitsPrc.nat8toInt64(c[ 2] & 0xff)<<16) | (BitsPrc.nat8toInt64(c[ 3] & 0xff)<<24);
        var j1  = BitsPrc.nat8toInt64(k[ 0] & 0xff) | (BitsPrc.nat8toInt64(k[ 1] & 0xff)<<8) | (BitsPrc.nat8toInt64(k[ 2] & 0xff)<<16) | (BitsPrc.nat8toInt64(k[ 3] & 0xff)<<24);
        var j2  = BitsPrc.nat8toInt64(k[ 4] & 0xff) | (BitsPrc.nat8toInt64(k[ 5] & 0xff)<<8) | (BitsPrc.nat8toInt64(k[ 6] & 0xff)<<16) | (BitsPrc.nat8toInt64(k[ 7] & 0xff)<<24);
        var j3  = BitsPrc.nat8toInt64(k[ 8] & 0xff) | (BitsPrc.nat8toInt64(k[ 9] & 0xff)<<8) | (BitsPrc.nat8toInt64(k[10] & 0xff)<<16) | (BitsPrc.nat8toInt64(k[11] & 0xff)<<24);
        var j4  = BitsPrc.nat8toInt64(k[12] & 0xff) | (BitsPrc.nat8toInt64(k[13] & 0xff)<<8) | (BitsPrc.nat8toInt64(k[14] & 0xff)<<16) | (BitsPrc.nat8toInt64(k[15] & 0xff)<<24);
        var j5  = BitsPrc.nat8toInt64(c[ 4] & 0xff) | (BitsPrc.nat8toInt64(c[ 5] & 0xff)<<8) | (BitsPrc.nat8toInt64(c[ 6] & 0xff)<<16) | (BitsPrc.nat8toInt64(c[ 7] & 0xff)<<24);
        var j6  = BitsPrc.nat8toInt64(p[ 0] & 0xff) | (BitsPrc.nat8toInt64(p[ 1] & 0xff)<<8) | (BitsPrc.nat8toInt64(p[ 2] & 0xff)<<16) | (BitsPrc.nat8toInt64(p[ 3] & 0xff)<<24);
        var j7  = BitsPrc.nat8toInt64(p[ 4] & 0xff) | (BitsPrc.nat8toInt64(p[ 5] & 0xff)<<8) | (BitsPrc.nat8toInt64(p[ 6] & 0xff)<<16) | (BitsPrc.nat8toInt64(p[ 7] & 0xff)<<24);
        var j8  = BitsPrc.nat8toInt64(p[ 8] & 0xff) | (BitsPrc.nat8toInt64(p[ 9] & 0xff)<<8) | (BitsPrc.nat8toInt64(p[10] & 0xff)<<16) | (BitsPrc.nat8toInt64(p[11] & 0xff)<<24);
        var j9  = BitsPrc.nat8toInt64(p[12] & 0xff) | (BitsPrc.nat8toInt64(p[13] & 0xff)<<8) | (BitsPrc.nat8toInt64(p[14] & 0xff)<<16) | (BitsPrc.nat8toInt64(p[15] & 0xff)<<24);
        var j10 = BitsPrc.nat8toInt64(c[ 8] & 0xff) | (BitsPrc.nat8toInt64(c[ 9] & 0xff)<<8) | (BitsPrc.nat8toInt64(c[10] & 0xff)<<16) | (BitsPrc.nat8toInt64(c[11] & 0xff)<<24);
        var j11 = BitsPrc.nat8toInt64(k[16] & 0xff) | (BitsPrc.nat8toInt64(k[17] & 0xff)<<8) | (BitsPrc.nat8toInt64(k[18] & 0xff)<<16) | (BitsPrc.nat8toInt64(k[19] & 0xff)<<24);
        var j12 = BitsPrc.nat8toInt64(k[20] & 0xff) | (BitsPrc.nat8toInt64(k[21] & 0xff)<<8) | (BitsPrc.nat8toInt64(k[22] & 0xff)<<16) | (BitsPrc.nat8toInt64(k[23] & 0xff)<<24);
        var j13 = BitsPrc.nat8toInt64(k[24] & 0xff) | (BitsPrc.nat8toInt64(k[25] & 0xff)<<8) | (BitsPrc.nat8toInt64(k[26] & 0xff)<<16) | (BitsPrc.nat8toInt64(k[27] & 0xff)<<24);
        var j14 = BitsPrc.nat8toInt64(k[28] & 0xff) | (BitsPrc.nat8toInt64(k[29] & 0xff)<<8) | (BitsPrc.nat8toInt64(k[30] & 0xff)<<16) | (BitsPrc.nat8toInt64(k[31] & 0xff)<<24);
        var j15 = BitsPrc.nat8toInt64(c[12] & 0xff) | (BitsPrc.nat8toInt64(c[13] & 0xff)<<8) | (BitsPrc.nat8toInt64(c[14] & 0xff)<<16) | (BitsPrc.nat8toInt64(c[15] & 0xff)<<24);

        var x0 = j0;
        var x1 = j1;
        var x2 = j2;
        var x3 = j3;
        var x4 = j4;
        var x5 = j5;
        var x6 = j6;
        var x7 = j7;
        var x8 = j8;
        var x9 = j9;
        var x10 = j10;
        var x11 = j11;
        var x12 = j12;
        var x13 = j13;
        var x14 = j14;
        var x15 = j15;
        var u : Int64 = 0;
        var i = 0;
        while (i < 20) {
            u := (x0 + x12 | 0) & 0xffffffff;
            x4 ^= ((u << 7) | (u >> (32-7))) & 0xffffffff;
            u := (x4 + x0 | 0) & 0xffffffff;
            x8 ^= ((u << 9) | (u >> (32-9))) & 0xffffffff;
            u := (x8 + x4 | 0) & 0xffffffff;
            x12 ^= ((u << 13) | (u >> (32-13))) & 0xffffffff;
            u := (x12 + x8 | 0) & 0xffffffff;
            x0 ^= ((u << 18) | (u >> (32-18))) & 0xffffffff;

            u := (x5 + x1 | 0) & 0xffffffff;
            x9 ^= ((u << 7) | (u >> (32-7))) & 0xffffffff;
            u := (x9 + x5 | 0) & 0xffffffff;
            x13 ^= ((u << 9) | (u >> (32-9))) & 0xffffffff;
            u := (x13 + x9 | 0) & 0xffffffff;
            x1 ^= ((u << 13) | (u >> (32-13))) & 0xffffffff;
            u := (x1 + x13 | 0) & 0xffffffff;
            x5 ^= ((u << 18) | (u >> (32-18))) & 0xffffffff;

            u := (x10 + x6 | 0) & 0xffffffff;
            x14 ^= ((u << 7) | (u >> (32-7))) & 0xffffffff;
            u := (x14 + x10 | 0) & 0xffffffff;
            x2 ^= ((u << 9) | (u >> (32-9))) & 0xffffffff;
            u := (x2 + x14 | 0) & 0xffffffff;
            x6 ^= ((u << 13) | (u >> (32-13))) & 0xffffffff;
            u := (x6 + x2 | 0) & 0xffffffff;
            x10 ^= ((u << 18) | (u >> (32-18))) & 0xffffffff;

            u := (x15 + x11 | 0) & 0xffffffff;
            x3 ^= ((u << 7) | (u >> (32-7))) & 0xffffffff;
            u := (x3 + x15 | 0) & 0xffffffff;
            x7 ^= ((u << 9) | (u >> (32-9))) & 0xffffffff;
            u := (x7 + x3 | 0) & 0xffffffff;
            x11 ^= ((u << 13) | (u >> (32-13))) & 0xffffffff;
            u := (x11 + x7 | 0) & 0xffffffff;
            x15 ^= ((u << 18) | (u >> (32-18))) & 0xffffffff;

            u := (x0 + x3 | 0) & 0xffffffff;
            x1 ^= ((u << 7) | (u >> (32-7))) & 0xffffffff;
            u := (x1 + x0 | 0) & 0xffffffff;
            x2 ^= ((u << 9) | (u >> (32-9))) & 0xffffffff;
            u := (x2 + x1 | 0) & 0xffffffff;
            x3 ^= ((u << 13) | (u >> (32-13))) & 0xffffffff;
            u := (x3 + x2 | 0) & 0xffffffff;
            x0 ^= ((u << 18) | (u >> (32-18))) & 0xffffffff;

            u := (x5 + x4 | 0) & 0xffffffff;
            x6 ^= ((u << 7) | (u >> (32-7))) & 0xffffffff;
            u := (x6 + x5 | 0) & 0xffffffff;
            x7 ^= ((u << 9) | (u >> (32-9))) & 0xffffffff;
            u := (x7 + x6 | 0) & 0xffffffff;
            x4 ^= ((u << 13) | (u >> (32-13))) & 0xffffffff;
            u := (x4 + x7 | 0) & 0xffffffff;
            x5 ^= ((u << 18) | (u >> (32-18))) & 0xffffffff;

            u := (x10 + x9 | 0) & 0xffffffff;
            x11 ^= ((u << 7) | (u >> (32-7))) & 0xffffffff;
            u := (x11 + x10 | 0) & 0xffffffff;
            x8 ^= ((u << 9) | (u >> (32-9))) & 0xffffffff;
            u := (x8 + x11 | 0) & 0xffffffff;
            x9 ^= ((u << 13) | (u >> (32-13))) & 0xffffffff;
            u := (x9 + x8 | 0) & 0xffffffff;
            x10 ^= ((u << 18) | (u >> (32-18))) & 0xffffffff;

            u := (x15 + x14 | 0) & 0xffffffff;
            x12 ^= ((u << 7) | (u >> (32-7))) & 0xffffffff;
            u := (x12 + x15 | 0) & 0xffffffff;
            x13 ^= ((u << 9) | (u >> (32-9))) & 0xffffffff;
            u := (x13 + x12 | 0) & 0xffffffff;
            x14 ^= ((u << 13) | (u >> (32-13))) & 0xffffffff;
            u := (x14 + x13 | 0) & 0xffffffff;
            x15 ^= ((u << 18) | (u >> (32-18))) & 0xffffffff;

            i += 2;
        };

        o.put( 0, BitsPrc.int64toNat8(x0 >>  0 & 0xff));
        o.put( 1, BitsPrc.int64toNat8(x0 >>  8 & 0xff));
        o.put( 2, BitsPrc.int64toNat8(x0 >> 16 & 0xff));
        o.put( 3, BitsPrc.int64toNat8(x0 >> 24 & 0xff));

        o.put( 4, BitsPrc.int64toNat8(x5 >>  0 & 0xff));
        o.put( 5, BitsPrc.int64toNat8(x5 >>  8 & 0xff));
        o.put( 6, BitsPrc.int64toNat8(x5 >> 16 & 0xff));
        o.put( 7, BitsPrc.int64toNat8(x5 >> 24 & 0xff));

        o.put( 8, BitsPrc.int64toNat8(x10 >>  0 & 0xff));
        o.put( 9, BitsPrc.int64toNat8(x10 >>  8 & 0xff));
        o.put(10, BitsPrc.int64toNat8(x10 >> 16 & 0xff));
        o.put(11, BitsPrc.int64toNat8(x10 >> 24 & 0xff));

        o.put(12, BitsPrc.int64toNat8(x15 >>  0 & 0xff));
        o.put(13, BitsPrc.int64toNat8(x15 >>  8 & 0xff));
        o.put(14, BitsPrc.int64toNat8(x15 >> 16 & 0xff));
        o.put(15, BitsPrc.int64toNat8(x15 >> 24 & 0xff));

        o.put(16, BitsPrc.int64toNat8(x6 >>  0 & 0xff));
        o.put(17, BitsPrc.int64toNat8(x6 >>  8 & 0xff));
        o.put(18, BitsPrc.int64toNat8(x6 >> 16 & 0xff));
        o.put(19, BitsPrc.int64toNat8(x6 >> 24 & 0xff));

        o.put(20, BitsPrc.int64toNat8(x7 >>  0 & 0xff));
        o.put(21, BitsPrc.int64toNat8(x7 >>  8 & 0xff));
        o.put(22, BitsPrc.int64toNat8(x7 >> 16 & 0xff));
        o.put(23, BitsPrc.int64toNat8(x7 >> 24 & 0xff));

        o.put(24, BitsPrc.int64toNat8(x8 >>  0 & 0xff));
        o.put(25, BitsPrc.int64toNat8(x8 >>  8 & 0xff));
        o.put(26, BitsPrc.int64toNat8(x8 >> 16 & 0xff));
        o.put(27, BitsPrc.int64toNat8(x8 >> 24 & 0xff));

        o.put(28, BitsPrc.int64toNat8(x9 >>  0 & 0xff));
        o.put(29, BitsPrc.int64toNat8(x9 >>  8 & 0xff));
        o.put(30, BitsPrc.int64toNat8(x9 >> 16 & 0xff));
        o.put(31, BitsPrc.int64toNat8(x9 >> 24 & 0xff));

    };

    func crypto_core_salsa20(out : Buffer.Buffer<Nat8>, inp : [Nat8], k : [Nat8], c : [Nat8]) {
        core_salsa20(out, inp, k, c);
    };

    public func crypto_core_hsalsa20(out : Buffer.Buffer<Nat8>, inp : [Nat8], k : [Nat8], c : [Nat8]) {
        core_hsalsa20(out, inp, k, c);
    };

    public func crypto_stream_salsa20_xor(c : Buffer.Buffer<Nat8>, cposInput : Nat, m : [Nat8], mposInput : Nat, b : Nat, n : [Nat8], k : [Nat8]) : Nat {
        var z : Buffer.Buffer<Nat8> = Buffer.fromArray(Array.tabulate<Nat8>(16, func (i) {
                                                                if (i < 8) {
                                                                    n[i];
                                                                } else {
                                                                    0;
                                                                };
                                                            }));
        var x : Buffer.Buffer<Nat8> = Buffer.fromArray(Array.tabulate<Nat8>(64, func (i) {0}));
        var u : Int64 = 0;
        var i : Int = 0;
        var bIndex = Int64.toInt(Int64.fromNat64(Nat64.fromNat(b)));
        var cpos = cposInput;
        var mpos = mposInput;
        while (bIndex >= 64) {
            crypto_core_salsa20(x, Buffer.toArray(z), k, sigma);
            i := 0;
            while (i < 64) {
                c.put(cpos + Int.abs(i), m[mpos + Int.abs(i)] ^ x.get(Int.abs(i)));
                i += 1;
            };
            u := 1;
            i := 8;
            while (i < 16) {
                u := u + BitsPrc.nat8toInt64(z.get(Int.abs(i)) & 0xff) | 0;
                z.put(Int.abs(i), BitsPrc.int64toNat8(u & 0xff));
                u >>= 8;
                i += 1;
            };
            bIndex -= 64;
            cpos += 64;
            mpos += 64;
        };
        if (bIndex > 0) {
            crypto_core_salsa20(x, Buffer.toArray(z), k, sigma);
            i := 0;
            while (i < bIndex) {
                c.put(cpos + Int.abs(i), m[mpos + Int.abs(i)] ^ x.get(Int.abs(i)));
                i += 1;
            };
        };
        return 0;
    };

    public func crypto_stream_salsa20(c : Buffer.Buffer<Nat8>, cpos : Nat, b : Nat, n : [Nat8], k : [Nat8]) : Nat8 {
        var z : Buffer.Buffer<Nat8> = Buffer.fromArray(Array.tabulate<Nat8>(16, func (i) {
                                                                                            if (i < 8) {
                                                                                                n[i];
                                                                                            } else {
                                                                                                0;
                                                                                            };
                                                                                        }));
        var x : Buffer.Buffer<Nat8> = Buffer.fromArray(Array.tabulate<Nat8>(64, func (i) {0}));
        var u : Int64 = 0;
        var i : Int = 0;
        var bIndex = Int64.toInt(Int64.fromNat64(Nat64.fromNat(b)));
        var cposIndex = cpos;
        while (bIndex >= 64) {
            crypto_core_salsa20(x, Buffer.toArray(z), k, sigma);
            i := 0;
            while (i < 64) {
                c.put(cposIndex + Int.abs(i), x.get(Int.abs(i)));
                i += 1;
            };
            u := 1;
            i := 8;
            while (i < 16) {
                u := u + BitsPrc.nat8toInt64(z.get(Int.abs(i)) & 0xff) | 0;
                z.put(Int.abs(i), BitsPrc.int64toNat8(u & 0xff));
                u >>= 8;
                i += 1;
            };
            bIndex -= 64;
            cposIndex += 64;
        };
        if (bIndex > 0) {
            crypto_core_salsa20(x, Buffer.toArray(z), k, sigma);
            i := 0;
            while (i < bIndex) {
                c.put(cposIndex + Int.abs(i), x.get(Int.abs(i)));
                i += 1;
            };
        };
        return 0;
    };

    public func crypto_stream(c : Buffer.Buffer<Nat8>,cpos : Nat, d : Nat, n : [Nat8],k : [Nat8]) : Nat8 {
        var s = Buffer.fromArray<Nat8>(Array.tabulate<Nat8>(32, func (i) {0}));
        crypto_core_hsalsa20(s, n, k, sigma);
        var sn = Array.tabulate<Nat8>(8, func (i) {n[i + 16]});
        return crypto_stream_salsa20(c, cpos, d, sn, Buffer.toArray(s));
    };
    
    public func crypto_stream_xor(c : Buffer.Buffer<Nat8>, cpos : Nat, m : [Nat8], mpos : Nat, d : Nat, n : [Nat8], k : [Nat8]) : Nat {
        var s = Buffer.fromArray<Nat8>(Array.tabulate<Nat8>(32, func (i) {0}));
        crypto_core_hsalsa20(s, n, k, sigma);
        var sn = Array.tabulate<Nat8>(8, func (i) {n[i + 16]});
        return crypto_stream_salsa20_xor(c, cpos, m, mpos, d, sn, Buffer.toArray(s));
    };

    /*
    * Port of Andrew Moon's Poly1305-donna-16. Public domain.
    * https://github.com/floodyberry/poly1305-donna
    */

    class Poly1305(key : [Nat8] /**key = 32 bytes**/) {

        let buffer = Array.tabulateVar<Nat8>(16, func i = 0);
        let r = Array.tabulateVar<Int64>(10, func i = 0);
        let h = Array.tabulateVar<Int64>(10, func i = 0);
        let pad = Array.tabulateVar<Int64>(8, func i = 0);
        var leftover = 0;
        var fin = 0;

        var t0 : Int64 = BitsPrc.nat8toInt64(key[ 0] & 0xff) | (BitsPrc.nat8toInt64(key[ 1] & 0xff) << 8); 
        r[0] := t0 & 0x1fff;
        var t1 : Int64 = BitsPrc.nat8toInt64(key[ 2] & 0xff) | (BitsPrc.nat8toInt64(key[ 3] & 0xff) << 8); 
        r[1] := ((t0 >> 13) | (t1 <<  3)) & 0x1fff;
        var t2 : Int64 = BitsPrc.nat8toInt64(key[ 4] & 0xff) | (BitsPrc.nat8toInt64(key[ 5] & 0xff) << 8);
        r[2] := ((t1 >> 10) | (t2 <<  6)) & 0x1f03;
        var t3 : Int64 = BitsPrc.nat8toInt64(key[ 6] & 0xff) | (BitsPrc.nat8toInt64(key[ 7] & 0xff) << 8);
        r[3] := ((t2 >>  7) | (t3 <<  9)) & 0x1fff;
        var t4 : Int64 = BitsPrc.nat8toInt64(key[ 8] & 0xff) | (BitsPrc.nat8toInt64(key[ 9] & 0xff) << 8);
        r[4] := ((t3 >>  4) | (t4 << 12)) & 0x00ff;
        r[5] := ((t4 >>  1)) & 0x1ffe;
        var t5 : Int64 = BitsPrc.nat8toInt64(key[10] & 0xff) | (BitsPrc.nat8toInt64(key[11] & 0xff) << 8);
        r[6] := ((t4 >> 14) | (t5 << 2)) & 0x1fff;
        var t6 : Int64 = BitsPrc.nat8toInt64(key[12] & 0xff) | (BitsPrc.nat8toInt64(key[13] & 0xff) << 8);
        r[7] := ((t5 >> 11) | (t6 <<  5)) & 0x1f81;
        var t7 : Int64 = BitsPrc.nat8toInt64(key[14] & 0xff) | (BitsPrc.nat8toInt64(key[15] & 0xff) << 8);
        r[8] := ((t6 >>  8) | (t7 <<  8)) & 0x1fff;
        r[9] := ((t7 >>  5)) & 0x007f;

        pad[0] := BitsPrc.nat8toInt64(key[16] & 0xff) | (BitsPrc.nat8toInt64(key[17] & 0xff) << 8);
        pad[1] := BitsPrc.nat8toInt64(key[18] & 0xff) | (BitsPrc.nat8toInt64(key[19] & 0xff) << 8);
        pad[2] := BitsPrc.nat8toInt64(key[20] & 0xff) | (BitsPrc.nat8toInt64(key[21] & 0xff) << 8);
        pad[3] := BitsPrc.nat8toInt64(key[22] & 0xff) | (BitsPrc.nat8toInt64(key[23] & 0xff) << 8);
        pad[4] := BitsPrc.nat8toInt64(key[24] & 0xff) | (BitsPrc.nat8toInt64(key[25] & 0xff) << 8);
        pad[5] := BitsPrc.nat8toInt64(key[26] & 0xff) | (BitsPrc.nat8toInt64(key[27] & 0xff) << 8);
        pad[6] := BitsPrc.nat8toInt64(key[28] & 0xff) | (BitsPrc.nat8toInt64(key[29] & 0xff) << 8);
        pad[7] := BitsPrc.nat8toInt64(key[30] & 0xff) | (BitsPrc.nat8toInt64(key[31] & 0xff) << 8);

        private func blocks(m : [Nat8], mposInput : Nat, bytesInput : Nat) {
            var hibit : Int64 = switch(fin) {
                case 0 {
                    (1 << 11);
                };
                case _ {
                    0;
                };
            };
            var mpos = mposInput;
            var bytes = bytesInput;

            var t0 : Int64 = 0;
            var t1 : Int64 = 0;
            var t2 : Int64 = 0;
            var t3 : Int64 = 0;
            var t4 : Int64 = 0;
            var t5 : Int64 = 0;
            var t6 : Int64 = 0;
            var t7 : Int64 = 0;
            var c : Int64 = 0;

            var d0 : Int64 = 0;
            var d1 : Int64 = 0;
            var d2 : Int64 = 0;
            var d3 : Int64 = 0;
            var d4 : Int64 = 0;
            var d5 : Int64 = 0;
            var d6 : Int64 = 0;
            var d7 : Int64 = 0;
            var d8 : Int64 = 0;
            var d9 : Int64 = 0;

            var h0 = h[0];
            var h1 = h[1];
            var h2 = h[2];
            var h3 = h[3];
            var h4 = h[4];
            var h5 = h[5];
            var h6 = h[6];
            var h7 = h[7];
            var h8 = h[8];
            var h9 = h[9];

            var r0 = r[0];
            var r1 = r[1];
            var r2 = r[2];
            var r3 = r[3];
            var r4 = r[4];
            var r5 = r[5];
            var r6 = r[6];
            var r7 = r[7];
            var r8 = r[8];
            var r9 = r[9];

            while (bytes >= 16) {
                t0 :=  BitsPrc.nat8toInt64(m[mpos+ 0] & 0xff) | (BitsPrc.nat8toInt64(m[mpos+ 1] & 0xff) << 8); 
                h0 += t0 & 0x1fff;
                t1 := BitsPrc.nat8toInt64(m[mpos+ 2] & 0xff) | (BitsPrc.nat8toInt64(m[mpos+ 3] & 0xff) << 8); 
                h1 += ((t0 >> 13) | (t1 <<  3)) & 0x1fff;
                t2 := BitsPrc.nat8toInt64(m[mpos+ 4] & 0xff) | (BitsPrc.nat8toInt64(m[mpos+ 5] & 0xff) << 8); 
                h2 += ((t1 >> 10) | (t2 <<  6)) & 0x1fff;
                t3 := BitsPrc.nat8toInt64(m[mpos+ 6] & 0xff) | (BitsPrc.nat8toInt64(m[mpos+ 7] & 0xff) << 8); 
                h3 += ((t2 >>  7) | (t3 <<  9)) & 0x1fff;
                t4 := BitsPrc.nat8toInt64(m[mpos+ 8] & 0xff) | (BitsPrc.nat8toInt64(m[mpos+ 9] & 0xff) << 8); 
                h4 += ((t3 >>  4) | (t4 << 12)) & 0x1fff;
                h5 += ((t4 >> 1)) & 0x1fff;
                t5 := BitsPrc.nat8toInt64(m[mpos+10] & 0xff) | (BitsPrc.nat8toInt64(m[mpos+11] & 0xff) << 8); 
                h6 += ((t4 >> 14) | (t5 <<  2)) & 0x1fff;
                t6 := BitsPrc.nat8toInt64(m[mpos+12] & 0xff) | (BitsPrc.nat8toInt64(m[mpos+13] & 0xff) << 8); 
                h7 += ((t5 >> 11) | (t6 <<  5)) & 0x1fff;
                t7 := BitsPrc.nat8toInt64(m[mpos+14] & 0xff) | (BitsPrc.nat8toInt64(m[mpos+15] & 0xff) << 8); 
                h8 += ((t6 >>  8) | (t7 <<  8)) & 0x1fff;
                h9 += ((t7 >> 5)) | hibit;

                c := 0;

                d0 := c;
                d0 += h0 * r0;
                d0 += h1 * (5 * r9);
                d0 += h2 * (5 * r8);
                d0 += h3 * (5 * r7);
                d0 += h4 * (5 * r6);
                c := (d0 >> 13); 
                d0 &= 0x1fff;

                d0 += h5 * (5 * r5);
                d0 += h6 * (5 * r4);
                d0 += h7 * (5 * r3);
                d0 += h8 * (5 * r2);
                d0 += h9 * (5 * r1);
                c += (d0 >> 13); 
                d0 &= 0x1fff;

                d1 := c;
                d1 += h0 * r1;
                d1 += h1 * r0;
                d1 += h2 * (5 * r9);
                d1 += h3 * (5 * r8);
                d1 += h4 * (5 * r7);
                c := (d1 >> 13);
                d1 &= 0x1fff;
                
                d1 += h5 * (5 * r6);
                d1 += h6 * (5 * r5);
                d1 += h7 * (5 * r4);
                d1 += h8 * (5 * r3);
                d1 += h9 * (5 * r2);
                c += (d1 >> 13);
                d1 &= 0x1fff;

                d2 := c;
                d2 += h0 * r2;
                d2 += h1 * r1;
                d2 += h2 * r0;
                d2 += h3 * (5 * r9);
                d2 += h4 * (5 * r8);
                c := (d2 >> 13);
                d2 &= 0x1fff;
                
                d2 += h5 * (5 * r7);
                d2 += h6 * (5 * r6);
                d2 += h7 * (5 * r5);
                d2 += h8 * (5 * r4);
                d2 += h9 * (5 * r3);
                c += (d2 >> 13);
                d2 &= 0x1fff;

                d3 := c;
                d3 += h0 * r3;
                d3 += h1 * r2;
                d3 += h2 * r1;
                d3 += h3 * r0;
                d3 += h4 * (5 * r9);
                c := (d3 >> 13);
                d3 &= 0x1fff;

                d3 += h5 * (5 * r8);
                d3 += h6 * (5 * r7);
                d3 += h7 * (5 * r6);
                d3 += h8 * (5 * r5);
                d3 += h9 * (5 * r4);
                c += (d3 >> 13);
                d3 &= 0x1fff;

                d4 := c;
                d4 += h0 * r4;
                d4 += h1 * r3;
                d4 += h2 * r2;
                d4 += h3 * r1;
                d4 += h4 * r0;
                c := (d4 >> 13);
                d4 &= 0x1fff;
                
                d4 += h5 * (5 * r9);
                d4 += h6 * (5 * r8);
                d4 += h7 * (5 * r7);
                d4 += h8 * (5 * r6);
                d4 += h9 * (5 * r5);
                c += (d4 >> 13);
                d4 &= 0x1fff;

                d5 := c;
                d5 += h0 * r5;
                d5 += h1 * r4;
                d5 += h2 * r3;
                d5 += h3 * r2;
                d5 += h4 * r1;
                c := (d5 >> 13);
                d5 &= 0x1fff;

                d5 += h5 * r0;
                d5 += h6 * (5 * r9);
                d5 += h7 * (5 * r8);
                d5 += h8 * (5 * r7);
                d5 += h9 * (5 * r6);
                c += (d5 >> 13);
                d5 &= 0x1fff;

                d6 := c;
                d6 += h0 * r6;
                d6 += h1 * r5;
                d6 += h2 * r4;
                d6 += h3 * r3;
                d6 += h4 * r2;
                c := (d6 >> 13);
                d6 &= 0x1fff;
                
                d6 += h5 * r1;
                d6 += h6 * r0;
                d6 += h7 * (5 * r9);
                d6 += h8 * (5 * r8);
                d6 += h9 * (5 * r7);
                c += (d6 >> 13);
                d6 &= 0x1fff;

                d7 := c;
                d7 += h0 * r7;
                d7 += h1 * r6;
                d7 += h2 * r5;
                d7 += h3 * r4;
                d7 += h4 * r3;
                c := (d7 >> 13);
                d7 &= 0x1fff;
                
                d7 += h5 * r2;
                d7 += h6 * r1;
                d7 += h7 * r0;
                d7 += h8 * (5 * r9);
                d7 += h9 * (5 * r8);
                c += (d7 >> 13);
                d7 &= 0x1fff;

                d8 := c;
                d8 += h0 * r8;
                d8 += h1 * r7;
                d8 += h2 * r6;
                d8 += h3 * r5;
                d8 += h4 * r4;
                c := (d8 >> 13);
                d8 &= 0x1fff;
                
                d8 += h5 * r3;
                d8 += h6 * r2;
                d8 += h7 * r1;
                d8 += h8 * r0;
                d8 += h9 * (5 * r9);
                c += (d8 >> 13);
                d8 &= 0x1fff;

                d9 := c;
                d9 += h0 * r9;
                d9 += h1 * r8;
                d9 += h2 * r7;
                d9 += h3 * r6;
                d9 += h4 * r5;
                c := (d9 >> 13); d9 &= 0x1fff;

                d9 += h5 * r4;
                d9 += h6 * r3;
                d9 += h7 * r2;
                d9 += h8 * r1;
                d9 += h9 * r0;
                c += (d9 >> 13); d9 &= 0x1fff;

                c := (((c << 2) + c)) | 0;
                c := (c + d0) | 0;
                d0 := c & 0x1fff;
                c := (c >> 13);
                d1 += c;

                h0 := d0;
                h1 := d1;
                h2 := d2;
                h3 := d3;
                h4 := d4;
                h5 := d5;
                h6 := d6;
                h7 := d7;
                h8 := d8;
                h9 := d9;

                mpos += 16;
                bytes -= 16;
            };
            h[0] := h0 & 0xffff;
            h[1] := h1 & 0xffff;
            h[2] := h2 & 0xffff;
            h[3] := h3 & 0xffff;
            h[4] := h4 & 0xffff;
            h[5] := h5 & 0xffff;
            h[6] := h6 & 0xffff;
            h[7] := h7 & 0xffff;
            h[8] := h8 & 0xffff;
            h[9] := h9 & 0xffff;
        };

        public func finish(mac : Buffer.Buffer<Nat8>, macpos : Nat) {
            var g = Array.tabulateVar<Int64>(10, func i = 0);
            var c : Int64 = 0;
            var mask : Int64 = 0;
            var f : Int64 = 0;
            var i = 0;
            switch (leftover) {
                case 0 {

                };
                case _ {
                    if (i < 16) {   // #22092024
                        i := leftover;
                        buffer[i] := 1;
                        i += 1;
                        while(i < 16) {
                            buffer[i] := 0;
                            i += 1;  
                        }; 
                    };
                    fin := 1;
                    blocks(Array.freeze(buffer), 0, 16);
                };
            };

            c := h[1] >> 13;
            h[1] &= 0x1fff;
            i := 2;
            while (i < 10) {
                h[i] += c;
                c := h[i] >> 13;
                h[i] &= 0x1fff;
                i += 1;
            };
            h[0] += (c * 5);
            c := h[0] >> 13;
            h[0] &= 0x1fff;
            h[1] += c;
            c := h[1] >> 13;
            h[1] &= 0x1fff;
            h[2] += c;

            g[0] := h[0] + 5;
            c := g[0] >> 13;
            g[0] &= 0x1fff;
            i := 1;
            while (i < 10) {
                g[i] := h[i] + c;
                c := g[i] >> 13;
                g[i] &= 0x1fff;
                i += 1;
            };
            g[9] -= (1 << 13);

            /** Logic in case use Nat16:
            // g[9] := switch (g[9] & 0xe000) { // mask with 0xe000 because if (1110000000000000 & g[9]) != 0 => g[9] >= 0x1fff = g[9] >= (1 << 13) 
            //     case 0 { 0 };
            //     case _ {  g[9] - (1 << 13); };
            // };
            **/

            mask := (c ^ 1) - 1;
            i := 0;
            while (i < 10) {
                g[i] &= mask;
                i += 1;
            };
            // mask = ~mask;
            mask := Int64.bitnot(mask);
            i := 0;
            while (i < 10) {
                h[i] := (h[i] & mask) | g[i];
                i += 1;                
            };

            h[0] := ((h[0]       ) | (h[1] << 13)                    ) & 0xffff;
            h[1] := ((h[1] >>  3) | (h[2] << 10)                    ) & 0xffff;
            h[2] := ((h[2] >>  6) | (h[3] <<  7)                    ) & 0xffff;
            h[3] := ((h[3] >>  9) | (h[4] <<  4)                    ) & 0xffff;
            h[4] := ((h[4] >> 12) | (h[5] <<  1) | (h[6] << 14)) & 0xffff;
            h[5] := ((h[6] >>  2) | (h[7] << 11)                    ) & 0xffff;
            h[6] := ((h[7] >>  5) | (h[8] <<  8)                    ) & 0xffff;
            h[7] := ((h[8] >>  8) | (h[9] <<  5)                    ) & 0xffff;

            f := h[0] + pad[0];
            h[0] := f & 0xffff;
            i := 1;
            while (i < 8) {
                f := (((h[i] + pad[i]) | 0) + (f >> 16)) | 0;
                h[i] := f & 0xffff;
                i += 1;
            };

            mac.put(macpos+ 0, BitsPrc.int64toNat8((h[0] >> 0) & 0xff));
            mac.put(macpos+ 1, BitsPrc.int64toNat8((h[0] >> 8) & 0xff));
            mac.put(macpos+ 2, BitsPrc.int64toNat8((h[1] >> 0) & 0xff));
            mac.put(macpos+ 3, BitsPrc.int64toNat8((h[1] >> 8) & 0xff));
            mac.put(macpos+ 4, BitsPrc.int64toNat8((h[2] >> 0) & 0xff));
            mac.put(macpos+ 5, BitsPrc.int64toNat8((h[2] >> 8) & 0xff));
            mac.put(macpos+ 6, BitsPrc.int64toNat8((h[3] >> 0) & 0xff));
            mac.put(macpos+ 7, BitsPrc.int64toNat8((h[3] >> 8) & 0xff));
            mac.put(macpos+ 8, BitsPrc.int64toNat8((h[4] >> 0) & 0xff));
            mac.put(macpos+ 9, BitsPrc.int64toNat8((h[4] >> 8) & 0xff));
            mac.put(macpos+10, BitsPrc.int64toNat8((h[5] >> 0) & 0xff));
            mac.put(macpos+11, BitsPrc.int64toNat8((h[5] >> 8) & 0xff));
            mac.put(macpos+12, BitsPrc.int64toNat8((h[6] >> 0) & 0xff));
            mac.put(macpos+13, BitsPrc.int64toNat8((h[6] >> 8) & 0xff));
            mac.put(macpos+14, BitsPrc.int64toNat8((h[7] >> 0) & 0xff));
            mac.put(macpos+15, BitsPrc.int64toNat8((h[7] >> 8) & 0xff));
        };

        public func update(m : [Nat8], mposInput : Nat, bytesInput : Nat) {
            var i = 0;
            var want = 0;
            var mpos = mposInput;
            var bytes = bytesInput;

            switch (leftover) {
                case 0 {};
                case _ {
                    want := (16 - leftover);
                    if (want > bytes) {
                        want := bytes;
                    };

                    i := 0;
                    while (i < want) {
                        buffer[leftover + i] := m[mpos+i];
                        i += 1;
                    };
                    
                    bytes -= want;
                    mpos += want;
                    leftover += want;
                    if (leftover < 16) {return};
                    blocks(Array.freeze(buffer), 0, 16);
                    leftover := 0;
                };
            };

            if (bytes >= 16) {
                want := bytes - (bytes % 16);
                blocks(m, mpos, want);
                mpos += want;
                bytes -= want;
            };

            switch (bytes) {
                case 0 {};
                case _ {
                    i := 0;
                    while (i < bytes) {
                        buffer[leftover + i] := m[mpos+i];
                        i += 1;
                    };
                    leftover += bytes;  // #22092024
                };
            };
        };

        // end class Poly1305
    };


    public func crypto_onetimeauth(out : Buffer.Buffer<Nat8>, outpos : Nat, m : [Nat8], mpos : Nat, n : Nat, k : [Nat8]) : Int {
        let s = Poly1305(k);
        s.update(m, mpos, n);
        s.finish(out, outpos);
        return 0;
    };

    public func crypto_onetimeauth_verify(h : [Nat8], hpos : Nat, m : [Nat8], mpos : Nat, n : Nat, k : [Nat8]) : Int {
        let x = Buffer.fromArray<Nat8>(Array.tabulate<Nat8>(16, func i = 0));
        ignore crypto_onetimeauth(x, 0, m, mpos, n, k);
        let rs = crypto_verify_16(h,hpos, Buffer.toArray(x), 0);
        return rs;
    };

    public func crypto_secretbox(c : Buffer.Buffer<Nat8>, m : [Nat8], d : Nat, n : [Nat8], k : [Nat8]) : Int {
        if (d < 32) return -1;
        ignore crypto_stream_xor(c, 0, m, 0, d, n, k);
        ignore crypto_onetimeauth(c, 16, Buffer.toArray(c), 32, d - 32, Buffer.toArray(c));
        for (i in Iter.range(0, 15)) { c.put(i, 0) };
        return 0;
    };

    public func crypto_secretbox_open(m : Buffer.Buffer<Nat8>, c : [Nat8], d : Nat, n : [Nat8], k : [Nat8]) : Int {
        var x = Buffer.fromArray<Nat8>(Array.tabulate<Nat8>(32, func i = 0));
        if (d < 32) return -1;
        ignore crypto_stream(x, 0, 32, n, k);
        if (crypto_onetimeauth_verify(c, 16, c, 32,d - 32, Buffer.toArray(x)) != 0) return -1;
        ignore crypto_stream_xor(m, 0, c, 0, d, n, k);
        for (i in Iter.range(0, 31)) m.put(i, 0);
        return 0;
    };
    
    public func set25519(r : Buffer.Buffer<Int64>, a : Buffer.Buffer<Int64>) {
        for (i in Iter.range(0, 15)) r.put(i, a.get(i) | 0);
    };

    func car25519(o : Buffer.Buffer<Int64>) {
        var c : Float = 1;
        for (i in Iter.range(0, 15)) {
            let v : Int64 = o.get(i) + Float.toInt64(c) + 65535;
            c := Float.floor(Float.fromInt64(v) / 65536);
            o.put(i, v - Float.toInt64(c) * 65536);
        };
        o.put(0, o.get(0) + (Float.toInt64(c)-1 + 37 * (Float.toInt64(c)-1)));
    };

    func sel25519(p : Buffer.Buffer<Int64>, q : Buffer.Buffer<Int64>, b : Int64) {
        var c : Int64 = Int64.bitnot(b-1);
        for (i in Iter.range(0, 15)) {
            let t = c & (p.get(i) ^ q.get(i));
            p.put(i, p.get(i) ^ t);
            q.put(i, q.get(i) ^ t);
        }
    };

    public func pack25519(o : Buffer.Buffer<Nat8>, n : Buffer.Buffer<Int64>) {
        var b : Int64 = 0;
        var m = buffer_i64(16);
        var t = buffer_i64(16);
        for (i in Iter.range(0, 15)) t.put(i, n.get(i));
        car25519(t);
        car25519(t);
        car25519(t);
        for (j in Iter.range(0, 1)) {
            m.put(0, t.get(0) - 0xffed);
            for (i in Iter.range(1, 14)) {
                m.put(i, t.get(i) - 0xffff - ((m.get(i-1) >> 16) & 1));
                m.put(i-1, m.get(i-1) & 0xffff);
            };
            m.put(15, t.get(15) - 0x7fff - ((m.get(14) >> 16) & 1));
            b := (m.get(15) >> 16) & 1;
            m.put(14, m.get(14) & 0xffff);
            sel25519(t, m, 1-b);
        };
        for (i in Iter.range(0, 15)) {
            o.put(2*i, BitsPrc.int64toNat8(t.get(i) & 0xff));
            o.put(2*i+1, BitsPrc.int64toNat8((t.get(i) >> 8) & 0xff));
        };
    };

    func neq25519(a : Buffer.Buffer<Int64>, b : Buffer.Buffer<Int64>) : Int {
        let c = Buffer.fromArray<Nat8>(Array.tabulate<Nat8>(32, func i = 0));
        var d = Buffer.fromArray<Nat8>(Array.tabulate<Nat8>(32, func i = 0));
        pack25519(c, a);
        pack25519(d, b);
        return crypto_verify_32(Buffer.toArray(c), 0, Buffer.toArray(d), 0);
    };

    func par25519(a : Buffer.Buffer<Int64>) : Nat8 {
        var d = Buffer.fromArray<Nat8>(Array.tabulate<Nat8>(32, func i = 0));
        pack25519(d, a);
        return d.get(0) & 1;
    };

    public func unpack25519(o : Buffer.Buffer<Int64>, n : [Nat8]) {
        for (i in Iter.range(0, 15)) o.put(i, BitsPrc.nat8toInt64(n[2*i]) + (BitsPrc.nat8toInt64(n[2*i+1]) << 8));
        o.put(15, o.get(15) & 0x7fff);
    };

    public func A(o : Buffer.Buffer<Int64>, a : Buffer.Buffer<Int64>, b : Buffer.Buffer<Int64>) {
        for (i in Iter.range(0, 15)) o.put(i, a.get(i) + b.get(i));
    };

    public func Z(o : Buffer.Buffer<Int64>, a : Buffer.Buffer<Int64>, b : Buffer.Buffer<Int64>) {
        for (i in Iter.range(0, 15)) o.put(i, a.get(i) - b.get(i));
    };

    public func M(o : Buffer.Buffer<Int64>, a : Buffer.Buffer<Int64>, b : Buffer.Buffer<Int64>) {
        var t0 : Int64 = 0;
        var t1 : Int64 = 0;
        var t2 : Int64 = 0;
        var t3 : Int64 = 0;
        var t4 : Int64 = 0;
        var t5 : Int64 = 0;
        var t6 : Int64 = 0;
        var t7 : Int64 = 0;

        var t8 : Int64 = 0;
        var t9 : Int64 = 0;
        var t10 : Int64 = 0;
        var t11 : Int64 = 0;
        var t12 : Int64 = 0;
        var t13 : Int64 = 0;
        var t14 : Int64 = 0;
        var t15 : Int64 = 0;

        var t16 : Int64 = 0;
        var t17 : Int64 = 0;
        var t18 : Int64 = 0;
        var t19 : Int64 = 0;
        var t20 : Int64 = 0;
        var t21 : Int64 = 0;
        var t22 : Int64 = 0;
        var t23 : Int64 = 0;

        var t24 : Int64 = 0;
        var t25 : Int64 = 0;
        var t26 : Int64 = 0;
        var t27 : Int64 = 0;
        var t28 : Int64 = 0;
        var t29 : Int64 = 0;
        var t30 : Int64 = 0;

        var b0 = b.get(0);
        var b1 = b.get(1);
        var b2 = b.get(2);
        var b3 = b.get(3);
        var b4 = b.get(4);
        var b5 = b.get(5);
        var b6 = b.get(6);
        var b7 = b.get(7);
        var b8 = b.get(8);
        var b9 = b.get(9);
        var b10 = b.get(10);
        var b11 = b.get(11);
        var b12 = b.get(12);
        var b13 = b.get(13);
        var b14 = b.get(14);
        var b15 = b.get(15);

        var v : Int64 = a.get(0);
        t0 += v * b0;
        t1 += v * b1;
        t2 += v * b2;
        t3 += v * b3;
        t4 += v * b4;
        t5 += v * b5;
        t6 += v * b6;
        t7 += v * b7;
        t8 += v * b8;
        t9 += v * b9;
        t10 += v * b10;
        t11 += v * b11;
        t12 += v * b12;
        t13 += v * b13;
        t14 += v * b14;
        t15 += v * b15;
        v := a.get(1);
        t1 += v * b0;
        t2 += v * b1;
        t3 += v * b2;
        t4 += v * b3;
        t5 += v * b4;
        t6 += v * b5;
        t7 += v * b6;
        t8 += v * b7;
        t9 += v * b8;
        t10 += v * b9;
        t11 += v * b10;
        t12 += v * b11;
        t13 += v * b12;
        t14 += v * b13;
        t15 += v * b14;
        t16 += v * b15;
        v := a.get(2);
        t2 += v * b0;
        t3 += v * b1;
        t4 += v * b2;
        t5 += v * b3;
        t6 += v * b4;
        t7 += v * b5;
        t8 += v * b6;
        t9 += v * b7;
        t10 += v * b8;
        t11 += v * b9;
        t12 += v * b10;
        t13 += v * b11;
        t14 += v * b12;
        t15 += v * b13;
        t16 += v * b14;
        t17 += v * b15;
        v := a.get(3);
        t3 += v * b0;
        t4 += v * b1;
        t5 += v * b2;
        t6 += v * b3;
        t7 += v * b4;
        t8 += v * b5;
        t9 += v * b6;
        t10 += v * b7;
        t11 += v * b8;
        t12 += v * b9;
        t13 += v * b10;
        t14 += v * b11;
        t15 += v * b12;
        t16 += v * b13;
        t17 += v * b14;
        t18 += v * b15;
        v := a.get(4);
        t4 += v * b0;
        t5 += v * b1;
        t6 += v * b2;
        t7 += v * b3;
        t8 += v * b4;
        t9 += v * b5;
        t10 += v * b6;
        t11 += v * b7;
        t12 += v * b8;
        t13 += v * b9;
        t14 += v * b10;
        t15 += v * b11;
        t16 += v * b12;
        t17 += v * b13;
        t18 += v * b14;
        t19 += v * b15;
        v := a.get(5);
        t5 += v * b0;
        t6 += v * b1;
        t7 += v * b2;
        t8 += v * b3;
        t9 += v * b4;
        t10 += v * b5;
        t11 += v * b6;
        t12 += v * b7;
        t13 += v * b8;
        t14 += v * b9;
        t15 += v * b10;
        t16 += v * b11;
        t17 += v * b12;
        t18 += v * b13;
        t19 += v * b14;
        t20 += v * b15;
        v := a.get(6);
        t6 += v * b0;
        t7 += v * b1;
        t8 += v * b2;
        t9 += v * b3;
        t10 += v * b4;
        t11 += v * b5;
        t12 += v * b6;
        t13 += v * b7;
        t14 += v * b8;
        t15 += v * b9;
        t16 += v * b10;
        t17 += v * b11;
        t18 += v * b12;
        t19 += v * b13;
        t20 += v * b14;
        t21 += v * b15;
        v := a.get(7);
        t7 += v * b0;
        t8 += v * b1;
        t9 += v * b2;
        t10 += v * b3;
        t11 += v * b4;
        t12 += v * b5;
        t13 += v * b6;
        t14 += v * b7;
        t15 += v * b8;
        t16 += v * b9;
        t17 += v * b10;
        t18 += v * b11;
        t19 += v * b12;
        t20 += v * b13;
        t21 += v * b14;
        t22 += v * b15;
        v := a.get(8);
        t8 += v * b0;
        t9 += v * b1;
        t10 += v * b2;
        t11 += v * b3;
        t12 += v * b4;
        t13 += v * b5;
        t14 += v * b6;
        t15 += v * b7;
        t16 += v * b8;
        t17 += v * b9;
        t18 += v * b10;
        t19 += v * b11;
        t20 += v * b12;
        t21 += v * b13;
        t22 += v * b14;
        t23 += v * b15;
        v := a.get(9);
        t9 += v * b0;
        t10 += v * b1;
        t11 += v * b2;
        t12 += v * b3;
        t13 += v * b4;
        t14 += v * b5;
        t15 += v * b6;
        t16 += v * b7;
        t17 += v * b8;
        t18 += v * b9;
        t19 += v * b10;
        t20 += v * b11;
        t21 += v * b12;
        t22 += v * b13;
        t23 += v * b14;
        t24 += v * b15;
        v := a.get(10);
        t10 += v * b0;
        t11 += v * b1;
        t12 += v * b2;
        t13 += v * b3;
        t14 += v * b4;
        t15 += v * b5;
        t16 += v * b6;
        t17 += v * b7;
        t18 += v * b8;
        t19 += v * b9;
        t20 += v * b10;
        t21 += v * b11;
        t22 += v * b12;
        t23 += v * b13;
        t24 += v * b14;
        t25 += v * b15;
        v := a.get(11);
        t11 += v * b0;
        t12 += v * b1;
        t13 += v * b2;
        t14 += v * b3;
        t15 += v * b4;
        t16 += v * b5;
        t17 += v * b6;
        t18 += v * b7;
        t19 += v * b8;
        t20 += v * b9;
        t21 += v * b10;
        t22 += v * b11;
        t23 += v * b12;
        t24 += v * b13;
        t25 += v * b14;
        t26 += v * b15;
        v := a.get(12);
        t12 += v * b0;
        t13 += v * b1;
        t14 += v * b2;
        t15 += v * b3;
        t16 += v * b4;
        t17 += v * b5;
        t18 += v * b6;
        t19 += v * b7;
        t20 += v * b8;
        t21 += v * b9;
        t22 += v * b10;
        t23 += v * b11;
        t24 += v * b12;
        t25 += v * b13;
        t26 += v * b14;
        t27 += v * b15;
        v := a.get(13);
        t13 += v * b0;
        t14 += v * b1;
        t15 += v * b2;
        t16 += v * b3;
        t17 += v * b4;
        t18 += v * b5;
        t19 += v * b6;
        t20 += v * b7;
        t21 += v * b8;
        t22 += v * b9;
        t23 += v * b10;
        t24 += v * b11;
        t25 += v * b12;
        t26 += v * b13;
        t27 += v * b14;
        t28 += v * b15;
        v := a.get(14);
        t14 += v * b0;
        t15 += v * b1;
        t16 += v * b2;
        t17 += v * b3;
        t18 += v * b4;
        t19 += v * b5;
        t20 += v * b6;
        t21 += v * b7;
        t22 += v * b8;
        t23 += v * b9;
        t24 += v * b10;
        t25 += v * b11;
        t26 += v * b12;
        t27 += v * b13;
        t28 += v * b14;
        t29 += v * b15;
        v := a.get(15);
        t15 += v * b0;
        t16 += v * b1;
        t17 += v * b2;
        t18 += v * b3;
        t19 += v * b4;
        t20 += v * b5;
        t21 += v * b6;
        t22 += v * b7;
        t23 += v * b8;
        t24 += v * b9;
        t25 += v * b10;
        t26 += v * b11;
        t27 += v * b12;
        t28 += v * b13;
        t29 += v * b14;
        t30 += v * b15;

        t0  += 38 * t16;
        t1  += 38 * t17;
        t2  += 38 * t18;
        t3  += 38 * t19;
        t4  += 38 * t20;
        t5  += 38 * t21;
        t6  += 38 * t22;
        t7  += 38 * t23;
        t8  += 38 * t24;
        t9  += 38 * t25;
        t10 += 38 * t26;
        t11 += 38 * t27;
        t12 += 38 * t28;
        t13 += 38 * t29;
        t14 += 38 * t30;
        // t15 left as is

        // first car
        var c : Float = 1;
        v :=  t0 + Float.toInt64(c) + 65535; c := Float.floor(Float.fromInt64(v) / 65536);  t0 := v - Float.toInt64(c) * 65536;
        v :=  t1 + Float.toInt64(c) + 65535; c := Float.floor(Float.fromInt64(v) / 65536);  t1 := v - Float.toInt64(c) * 65536;
        v :=  t2 + Float.toInt64(c) + 65535; c := Float.floor(Float.fromInt64(v) / 65536);  t2 := v - Float.toInt64(c) * 65536;
        v :=  t3 + Float.toInt64(c) + 65535; c := Float.floor(Float.fromInt64(v) / 65536);  t3 := v - Float.toInt64(c) * 65536;
        v :=  t4 + Float.toInt64(c) + 65535; c := Float.floor(Float.fromInt64(v) / 65536);  t4 := v - Float.toInt64(c) * 65536;
        v :=  t5 + Float.toInt64(c) + 65535; c := Float.floor(Float.fromInt64(v) / 65536);  t5 := v - Float.toInt64(c) * 65536;
        v :=  t6 + Float.toInt64(c) + 65535; c := Float.floor(Float.fromInt64(v) / 65536);  t6 := v - Float.toInt64(c) * 65536;
        v :=  t7 + Float.toInt64(c) + 65535; c := Float.floor(Float.fromInt64(v) / 65536);  t7 := v - Float.toInt64(c) * 65536;
        v :=  t8 + Float.toInt64(c) + 65535; c := Float.floor(Float.fromInt64(v) / 65536);  t8 := v - Float.toInt64(c) * 65536;
        v :=  t9 + Float.toInt64(c) + 65535; c := Float.floor(Float.fromInt64(v) / 65536);  t9 := v - Float.toInt64(c) * 65536;
        v := t10 + Float.toInt64(c) + 65535; c := Float.floor(Float.fromInt64(v) / 65536); t10 := v - Float.toInt64(c) * 65536;
        v := t11 + Float.toInt64(c) + 65535; c := Float.floor(Float.fromInt64(v) / 65536); t11 := v - Float.toInt64(c) * 65536;
        v := t12 + Float.toInt64(c) + 65535; c := Float.floor(Float.fromInt64(v) / 65536); t12 := v - Float.toInt64(c) * 65536;
        v := t13 + Float.toInt64(c) + 65535; c := Float.floor(Float.fromInt64(v) / 65536); t13 := v - Float.toInt64(c) * 65536;
        v := t14 + Float.toInt64(c) + 65535; c := Float.floor(Float.fromInt64(v) / 65536); t14 := v - Float.toInt64(c) * 65536;
        v := t15 + Float.toInt64(c) + 65535; c := Float.floor(Float.fromInt64(v) / 65536); t15 := v - Float.toInt64(c) * 65536;
        t0 += Float.toInt64(c)-1 + 37 * (Float.toInt64(c)-1);

        // second car
        c := 1;
        v :=  t0 + Float.toInt64(c) + 65535; c := Float.floor(Float.fromInt64(v) / 65536);  t0 := v - Float.toInt64(c) * 65536;
        v :=  t1 + Float.toInt64(c) + 65535; c := Float.floor(Float.fromInt64(v) / 65536);  t1 := v - Float.toInt64(c) * 65536;
        v :=  t2 + Float.toInt64(c) + 65535; c := Float.floor(Float.fromInt64(v) / 65536);  t2 := v - Float.toInt64(c) * 65536;
        v :=  t3 + Float.toInt64(c) + 65535; c := Float.floor(Float.fromInt64(v) / 65536);  t3 := v - Float.toInt64(c) * 65536;
        v :=  t4 + Float.toInt64(c) + 65535; c := Float.floor(Float.fromInt64(v) / 65536);  t4 := v - Float.toInt64(c) * 65536;
        v :=  t5 + Float.toInt64(c) + 65535; c := Float.floor(Float.fromInt64(v) / 65536);  t5 := v - Float.toInt64(c) * 65536;
        v :=  t6 + Float.toInt64(c) + 65535; c := Float.floor(Float.fromInt64(v) / 65536);  t6 := v - Float.toInt64(c) * 65536;
        v :=  t7 + Float.toInt64(c) + 65535; c := Float.floor(Float.fromInt64(v) / 65536);  t7 := v - Float.toInt64(c) * 65536;
        v :=  t8 + Float.toInt64(c) + 65535; c := Float.floor(Float.fromInt64(v) / 65536);  t8 := v - Float.toInt64(c) * 65536;
        v :=  t9 + Float.toInt64(c) + 65535; c := Float.floor(Float.fromInt64(v) / 65536);  t9 := v - Float.toInt64(c) * 65536;
        v := t10 + Float.toInt64(c) + 65535; c := Float.floor(Float.fromInt64(v) / 65536); t10 := v - Float.toInt64(c) * 65536;
        v := t11 + Float.toInt64(c) + 65535; c := Float.floor(Float.fromInt64(v) / 65536); t11 := v - Float.toInt64(c) * 65536;
        v := t12 + Float.toInt64(c) + 65535; c := Float.floor(Float.fromInt64(v) / 65536); t12 := v - Float.toInt64(c) * 65536;
        v := t13 + Float.toInt64(c) + 65535; c := Float.floor(Float.fromInt64(v) / 65536); t13 := v - Float.toInt64(c) * 65536;
        v := t14 + Float.toInt64(c) + 65535; c := Float.floor(Float.fromInt64(v) / 65536); t14 := v - Float.toInt64(c) * 65536;
        v := t15 + Float.toInt64(c) + 65535; c := Float.floor(Float.fromInt64(v) / 65536); t15 := v - Float.toInt64(c) * 65536;
        t0 += Float.toInt64(c)-1 + 37 * (Float.toInt64(c)-1);

        o.put( 0, t0);
        o.put( 1, t1);
        o.put( 2, t2);
        o.put( 3, t3);
        o.put( 4, t4);
        o.put( 5, t5);
        o.put( 6, t6);
        o.put( 7, t7);
        o.put( 8, t8);
        o.put( 9, t9);
        o.put(10, t10);
        o.put(11, t11);
        o.put(12, t12);
        o.put(13, t13);
        o.put(14, t14);
        o.put(15, t15);
        
    };

    public func S(o : Buffer.Buffer<Int64>, a : Buffer.Buffer<Int64>) {
        M(o, a, a);
    };

    func inv25519(o : Buffer.Buffer<Int64>, i : Buffer.Buffer<Int64>) {
        var c = buffer_i64(16);
        for (a in Iter.range(0, 15)) c.put(a, i.get(a));
        for (a in Iter.revRange(253, 0)) {
            S(c, c);
            if(a != 2 and a != 4) M(c, c, i);
        };
        for (a in Iter.range(0, 15)) o.put(a, c.get(a));
    };

    public func pow2523(o : Buffer.Buffer<Int64>, i : Buffer.Buffer<Int64>) {
        var c = buffer_i64(16);
        for (a in Iter.range(0, 15)) c.put(a, i.get(a));
        for (a in Iter.revRange(250, 0)) {
            S(c, c);
            if(a != 1) M(c, c, i);
        };
        for (a in Iter.range(0, 15)) o.put(a, c.get(a));
    };

    public func crypto_scalarmult(q : Buffer.Buffer<Nat8>, n : [Nat8], p : [Nat8]) : Int {
        let z = Array.tabulateVar<Nat8>(32, func i = 0);
        let x = Buffer.fromArray<Int64>(Array.tabulate<Int64>(80, func i = 0));
        let a = buffer_i64(16);
        let b = buffer_i64(16);
        let c = buffer_i64(16);
        let d = buffer_i64(16);
        let e = buffer_i64(16);
        let f = buffer_i64(16);
        for (i in Iter.range(0, 30)) z[i] := n[i];
        z[31] := (n[31] & 127) | 64;
        z[0] &= 248;
        unpack25519(x, p);
        for (i in Iter.range(0, 15)) {
            b.put(i, x.get(i));
        };
        a.put(0, 1);
        d.put(0, 1);
        for (i in Iter.revRange(254, 0)) {
            let r : Int64 = (BitsPrc.nat8toInt64(z[Nat64.toNat(Int64.toNat64(Int64.fromInt(i) >> 3))]) >> (Int64.fromInt(i) & 7)) & 1;
            sel25519(a,b,r);
            sel25519(c,d,r);
            A(e, a, c);
            Z(a, a, c);
            A(c, b, d);
            Z(b, b, d);
            S(d, e);
            S(f, a);
            M(a, c, a);
            M(c, b, e);
            A(e, a, c);
            Z(a, a, c);
            S(b, a);
            Z(c, d, f);
            M(a, c, Buffer.fromArray(_121665));
            A(a, a, d);
            M(c, c, a);
            M(a, d, f);
            M(d, b, x);
            S(b, e);
            sel25519(a, b, r);
            sel25519(c, d, r);
        };
        for (i in Iter.range(0, 15)) {
            x.put(i+16, a.get(i));
            x.put(i+32, c.get(i));
            x.put(i+48, b.get(i));
            x.put(i+64, d.get(i));
        };
        let x32 = Buffer.subBuffer<Int64>(x, 32, x.size() - 32);
        let x16 = Buffer.subBuffer<Int64>(x, 16, x.size() - 16);
        inv25519(x32, x32);
        M(x16, x16, x32);
        pack25519(q, x16);
        return 0;
    };

    public func crypto_scalarmult_base(q : Buffer.Buffer<Nat8>, n : [Nat8]) : Int {
        return crypto_scalarmult(q, n, _9);
    };

    public func randomBytes(r : Buffer.Buffer<Nat8>, byteNum : Nat, pRNG : ?((Nat) -> ([Nat8]))) {
        switch (pRNG) {
            case (?f) {
                let x = f(byteNum);
                for (i in Iter.range(0, byteNum - 1)) {
                    r.put(i, x[i]);
                };
            };
            case null {
                // process local
                let x = randomBytesInternal(byteNum);
                for (i in Iter.range(0, byteNum - 1)) {
                    r.put(i, x[i]);
                };
            };
        };
    };

    public func asyncRandomBytes(r : Buffer.Buffer<Nat8>, byteNum : Nat, pRNG : ?((Nat) -> async ([Nat8]))) : async () {
        switch (pRNG) {
            case (?f) {
                let x = await f(byteNum);
                for (i in Iter.range(0, byteNum - 1)) {
                    r.put(i, x[i]);
                };
            };
            case null {
                // process local
                let x = await asyncRandomBytesInternal(byteNum);
                for (i in Iter.range(0, byteNum - 1)) {
                    r.put(i, x[i]);
                };
            };
        };
    };

    public func crypto_box_keypair(y : Buffer.Buffer<Nat8>, x : Buffer.Buffer<Nat8>, pRNG : ?((Nat) -> ([Nat8]))) : Int {
        randomBytes(x, crypto_box_SECRETKEYBYTES, pRNG);
        return crypto_scalarmult_base(y, Buffer.toArray(x));
    };

    public func async_crypto_box_keypair(y : Buffer.Buffer<Nat8>, x : Buffer.Buffer<Nat8>, pRNG : ?((Nat) -> async ([Nat8]))) : async (Int) {
        await asyncRandomBytes(x, crypto_box_SECRETKEYBYTES, pRNG);
        return crypto_scalarmult_base(y, Buffer.toArray(x));
    };

    public func crypto_box_beforenm(k : Buffer.Buffer<Nat8>, y : [Nat8], x : [Nat8]) {
        var s = Buffer.fromArray<Nat8>(Array.tabulate<Nat8>(32, func i = 0));
        ignore crypto_scalarmult(s, x, y);
        return crypto_core_hsalsa20(k, _0, Buffer.toArray(s), sigma);
    };

    public let crypto_box_afternm = crypto_secretbox;
    public let crypto_box_open_afternm = crypto_secretbox_open;

    public func crypto_box(c : Buffer.Buffer<Nat8>, m : [Nat8], d : Nat, n : [Nat8], y : [Nat8], x : [Nat8]) : Int {
        var k = Buffer.fromArray<Nat8>(Array.tabulate<Nat8>(32, func i = 0));
        crypto_box_beforenm(k, y, x);
        return crypto_box_afternm(c, m, d, n, Buffer.toArray(k));
    };

    public func crypto_box_open(m : Buffer.Buffer<Nat8>, c : [Nat8], d : Nat, n : [Nat8], y : [Nat8], x : [Nat8]) : Int {
        var k = Buffer.fromArray<Nat8>(Array.tabulate<Nat8>(32, func i = 0));
        crypto_box_beforenm(k, y, x);
        return crypto_box_open_afternm(m, c, d, n, Buffer.toArray(k));
    };

    func crypto_hashblocks_hl(hh : Buffer.Buffer<Int64>, hl : Buffer.Buffer<Int64>, m : [Nat8], nInput : Nat) : Int {
        let wh = Array.tabulateVar<Int64>(16, func i = 0);
        let wl = Array.tabulateVar<Int64>(16, func i = 0);
        var n = nInput;

        var bh0 : Int64 = 0;
        var bh1 : Int64 = 0;
        var bh2 : Int64 = 0;
        var bh3 : Int64 = 0;
        var bh4 : Int64 = 0;
        var bh5 : Int64 = 0;
        var bh6 : Int64 = 0;
        var bh7 : Int64 = 0;

        var bl0 : Int64 = 0;
        var bl1 : Int64 = 0;
        var bl2 : Int64 = 0;
        var bl3 : Int64 = 0;
        var bl4 : Int64 = 0;
        var bl5 : Int64 = 0;
        var bl6 : Int64 = 0;
        var bl7 : Int64 = 0;

        var th : Int64 = 0;
        var tl : Int64 = 0;
        var h : Int64 = 0;
        var l : Int64 = 0;
        var a : Int64 = 0;
        var b : Int64 = 0;
        var c : Int64 = 0;
        var d : Int64 = 0;

        var ah0 : Int64 = hh.get(0);
        var ah1 : Int64 = hh.get(1);
        var ah2 : Int64 = hh.get(2);
        var ah3 : Int64 = hh.get(3);
        var ah4 : Int64 = hh.get(4);
        var ah5 : Int64 = hh.get(5);
        var ah6 : Int64 = hh.get(6);
        var ah7 : Int64 = hh.get(7);

        var al0 : Int64 = hl.get(0);
        var al1 : Int64 = hl.get(1);
        var al2 : Int64 = hl.get(2);
        var al3 : Int64 = hl.get(3);
        var al4 : Int64 = hl.get(4);
        var al5 : Int64 = hl.get(5);
        var al6 : Int64 = hl.get(6);
        var al7 : Int64 = hl.get(7);

        var pos = 0;
        while (n >= 128) {
            for (i in Iter.range(0, 15)) {
                let j = 8 * i + pos;
                wh[i] := (BitsPrc.nat8toInt64(m.get(j+0)) << 24) | (BitsPrc.nat8toInt64(m.get(j+1)) << 16) | (BitsPrc.nat8toInt64(m.get(j+2)) << 8) | BitsPrc.nat8toInt64(m.get(j+3));
                wl[i] := (BitsPrc.nat8toInt64(m.get(j+4)) << 24) | (BitsPrc.nat8toInt64(m.get(j+5)) << 16) | (BitsPrc.nat8toInt64(m.get(j+6)) << 8) | BitsPrc.nat8toInt64(m.get(j+7));
            };
            for (i in Iter.range(0, 79)) {
                bh0 := ah0 & 0xffffffff;
                bh1 := ah1 & 0xffffffff;
                bh2 := ah2 & 0xffffffff;
                bh3 := ah3 & 0xffffffff;
                bh4 := ah4 & 0xffffffff;
                bh5 := ah5 & 0xffffffff;
                bh6 := ah6 & 0xffffffff;
                bh7 := ah7 & 0xffffffff;

                bl0 := al0 & 0xffffffff;
                bl1 := al1 & 0xffffffff;
                bl2 := al2 & 0xffffffff;
                bl3 := al3 & 0xffffffff;
                bl4 := al4 & 0xffffffff;
                bl5 := al5 & 0xffffffff;
                bl6 := al6 & 0xffffffff;
                bl7 := al7 & 0xffffffff;

                // add
                h := ah7;
                l := al7;

                a := l & 0xffff; b := (l >> 16) & 0xffff;
                c := h & 0xffff; d := (h >> 16) & 0xffff;

                // Sigma1
                
                h := ((ah4 >> 14) | (al4 << (32-14))) ^ ((ah4 >> 18) | (al4 << (32-18))) ^ ((al4 >> (41-32)) | (ah4 << (32-(41-32))));
                l := ((al4 >> 14) | (ah4 << (32-14))) ^ ((al4 >> 18) | (ah4 << (32-18))) ^ ((ah4 >> (41-32)) | (al4 << (32-(41-32))));

                a += l & 0xffff; b += (l >> 16) & 0xffff;
                c += h & 0xffff; d += (h >> 16) & 0xffff;

                // Ch
                h := (ah4 & ah5) ^ (Int64.bitnot(ah4) & ah6);
                l := (al4 & al5) ^ (Int64.bitnot(al4) & al6);

                a += l & 0xffff; b += (l >> 16) & 0xffff;
                c += h & 0xffff; d += (h >> 16) & 0xffff;

                // K
                h := K[i*2];
                l := K[i*2+1];

                a += l & 0xffff; b += (l >> 16) & 0xffff;
                c += h & 0xffff; d += (h >> 16) & 0xffff;

                // w
                h := wh[i%16];
                l := wl[i%16];

                a += l & 0xffff; b += (l >> 16) & 0xffff;
                c += h & 0xffff; d += (h >> 16) & 0xffff;

                b += a >> 16;
                c += b >> 16;
                d += c >> 16;

                th := (c & 0xffff) | (d << 16) & 0xffffffff;
                tl := (a & 0xffff) | (b << 16) & 0xffffffff;

                // add
                h := th;
                l := tl;

                a := l & 0xffff; b := (l >> 16) & 0xffff;
                c := h & 0xffff; d := (h >> 16) & 0xffff;

                // Sigma0
                h := (ah0 >> 28 | (al0 << (32-28))) ^ (al0 >> (34-32) | (ah0 << (32-(34-32)))) ^ (al0 >> (39-32) | (ah0 << (32-(39-32))));
                l := (al0 >> 28 | (ah0 << (32-28))) ^ (ah0 >> (34-32) | (al0 << (32-(34-32)))) ^ (ah0 >> (39-32) | (al0 << (32-(39-32))));

                a += l & 0xffff; b += (l >> 16) & 0xffff;
                c += h & 0xffff; d += (h >> 16) & 0xffff;

                // Maj
                h := (ah0 & ah1) ^ (ah0 & ah2) ^ (ah1 & ah2);
                l := (al0 & al1) ^ (al0 & al2) ^ (al1 & al2);

                a += l & 0xffff; b += (l >> 16) & 0xffff;
                c += h & 0xffff; d += (h >> 16) & 0xffff;

                b += a >> 16;
                c += b >> 16;
                d += c >> 16;

                bh7 := (c & 0xffff) | (d << 16) & 0xffffffff;
                bl7 := (a & 0xffff) | (b << 16) & 0xffffffff;

                // add
                h := bh3;
                l := bl3;

                a := l & 0xffff; b := (l >> 16) & 0xffff;
                c := h & 0xffff; d := (h >> 16) & 0xffff;

                h := th;
                l := tl;

                a += l & 0xffff; b += (l >> 16) & 0xffff;
                c += h & 0xffff; d += (h >> 16) & 0xffff;

                b += a >> 16;
                c += b >> 16;
                d += c >> 16;

                bh3 := (c & 0xffff) | (d << 16) & 0xffffffff;
                bl3 := (a & 0xffff) | (b << 16) & 0xffffffff;

                ah1 := bh0 & 0xffffffff;
                ah2 := bh1 & 0xffffffff;
                ah3 := bh2 & 0xffffffff;
                ah4 := bh3 & 0xffffffff;
                ah5 := bh4 & 0xffffffff;
                ah6 := bh5 & 0xffffffff;
                ah7 := bh6 & 0xffffffff;
                ah0 := bh7 & 0xffffffff;

                al1 := bl0 & 0xffffffff;
                al2 := bl1 & 0xffffffff;
                al3 := bl2 & 0xffffffff;
                al4 := bl3 & 0xffffffff;
                al5 := bl4 & 0xffffffff;
                al6 := bl5 & 0xffffffff;
                al7 := bl6 & 0xffffffff;
                al0 := bl7 & 0xffffffff;

                if (i % 16 == 15) {
                    for (j in Iter.range(0, 15)) {
                        // add
                        h := wh[j];
                        l := wl[j];

                        a := l & 0xffff; b := (l >> 16) & 0xffff;
                        c := h & 0xffff; d := (h >> 16) & 0xffff;

                        h := wh[(j+9)%16] & 0xffffffff;
                        l := wl[(j+9)%16] & 0xffffffff;

                        a += l & 0xffff; b += (l >> 16) & 0xffff;
                        c += h & 0xffff; d += (h >> 16) & 0xffff;

                        // sigma0
                        th := wh[(j+1)%16] & 0xffffffff;
                        tl := wl[(j+1)%16] & 0xffffffff;
                        h := (th >> 1 | (tl << (32-1))) ^ (th >> 8 | (tl << (32-8))) ^ th >> 7;
                        l := (tl >> 1 | (th << (32-1))) ^ (tl >> 8 | (th << (32-8))) ^ (tl >> 7 | (th << (32-7)));

                        a += l & 0xffff; b += (l >> 16) & 0xffff;
                        c += h & 0xffff; d += (h >> 16) & 0xffff;

                        // sigma1
                        th := wh[(j+14)%16] & 0xffffffff;
                        tl := wl[(j+14)%16] & 0xffffffff;
                        h := (th >> 19 | (tl << (32-19))) ^ (tl >> (61-32) | (th << (32-(61-32)))) ^ (th >> 6);
                        l := (tl >> 19 | (th << (32-19))) ^ (th >> (61-32) | (tl << (32-(61-32)))) ^ (tl >> 6 | (th << (32-6)));

                        a += l & 0xffff; b += (l >> 16) & 0xffff;
                        c += h & 0xffff; d += (h >> 16) & 0xffff;

                        b += a >> 16;
                        c += b >> 16;
                        d += c >> 16;

                        wh[j] := (c & 0xffff) | (d << 16) & 0xffffffff;
                        wl[j] := (a & 0xffff) | (b << 16) & 0xffffffff;
                    };
                };
            
            };

            // add
            h := ah0;
            l := al0;

            a := l & 0xffff; b := (l >> 16) & 0xffff;
            c := h & 0xffff; d := (h >> 16) & 0xffff;

            h := hh.get(0);
            l := hl.get(0);

            a += l & 0xffff; b += (l >> 16) & 0xffff;
            c += h & 0xffff; d += (h >> 16) & 0xffff;

            b += a >> 16;
            c += b >> 16;
            d += c >> 16;

            ah0 := (c & 0xffff) | (d << 16) & 0xffffffff;
            al0 := (a & 0xffff) | (b << 16) & 0xffffffff;
            hh.put(0, ah0);
            hl.put(0, al0);

            h := ah1;
            l := al1;

            a := l & 0xffff; b := (l >> 16) & 0xffff;
            c := h & 0xffff; d := (h >> 16) & 0xffff;

            h := hh.get(1);
            l := hl.get(1);

            a += l & 0xffff; b += (l >> 16) & 0xffff;
            c += h & 0xffff; d += (h >> 16) & 0xffff;

            b += a >> 16;
            c += b >> 16;
            d += c >> 16;

            ah1 := (c & 0xffff) | (d << 16) & 0xffffffff;
            al1 := (a & 0xffff) | (b << 16) & 0xffffffff;
            hh.put(1, ah1);
            hl.put(1, al1);

            h := ah2;
            l := al2;

            a := l & 0xffff; b := (l >> 16) & 0xffff;
            c := h & 0xffff; d := (h >> 16) & 0xffff;

            h := hh.get(2);
            l := hl.get(2);

            a += l & 0xffff; b += (l >> 16) & 0xffff;
            c += h & 0xffff; d += (h >> 16) & 0xffff;

            b += a >> 16;
            c += b >> 16;
            d += c >> 16;

            ah2 := (c & 0xffff) | (d << 16) & 0xffffffff;
            al2 := (a & 0xffff) | (b << 16) & 0xffffffff;
            hh.put(2, ah2);
            hl.put(2, al2);

            h := ah3;
            l := al3;

            a := l & 0xffff; b := (l >> 16) & 0xffff;
            c := h & 0xffff; d := (h >> 16) & 0xffff;

            h := hh.get(3);
            l := hl.get(3);

            a += l & 0xffff; b += (l >> 16) & 0xffff;
            c += h & 0xffff; d += (h >> 16) & 0xffff;

            b += a >> 16;
            c += b >> 16;
            d += c >> 16;

            ah3 := (c & 0xffff) | (d << 16) & 0xffffffff;
            al3 := (a & 0xffff) | (b << 16) & 0xffffffff;
            hh.put(3, ah3);
            hl.put(3, al3);

            h := ah4;
            l := al4;

            a := l & 0xffff; b := (l >> 16) & 0xffff;
            c := h & 0xffff; d := (h >> 16) & 0xffff;

            h := hh.get(4);
            l := hl.get(4);

            a += l & 0xffff; b += (l >> 16) & 0xffff;
            c += h & 0xffff; d += (h >> 16) & 0xffff;

            b += a >> 16;
            c += b >> 16;
            d += c >> 16;

            ah4 := (c & 0xffff) | (d << 16) & 0xffffffff;
            al4 := (a & 0xffff) | (b << 16) & 0xffffffff;
            hh.put(4, ah4);
            hl.put(4, al4);

            h := ah5;
            l := al5;

            a := l & 0xffff; b := (l >> 16) & 0xffff;
            c := h & 0xffff; d := (h >> 16) & 0xffff;

            h := hh.get(5);
            l := hl.get(5);

            a += l & 0xffff; b += (l >> 16) & 0xffff;
            c += h & 0xffff; d += (h >> 16) & 0xffff;

            b += a >> 16;
            c += b >> 16;
            d += c >> 16;

            ah5 := (c & 0xffff) | (d << 16) & 0xffffffff;
            al5 := (a & 0xffff) | (b << 16) & 0xffffffff;
            hh.put(5, ah5);
            hl.put(5, al5);

            h := ah6;
            l := al6;

            a := l & 0xffff; b := (l >> 16) & 0xffff;
            c := h & 0xffff; d := (h >> 16) & 0xffff;

            h := hh.get(6);
            l := hl.get(6);

            a += l & 0xffff; b += (l >> 16) & 0xffff;
            c += h & 0xffff; d += (h >> 16) & 0xffff;

            b += a >> 16;
            c += b >> 16;
            d += c >> 16;

            ah6 := (c & 0xffff) | (d << 16) & 0xffffffff;
            al6 := (a & 0xffff) | (b << 16) & 0xffffffff;
            hh.put(6, ah6);
            hl.put(6, al6);

            h := ah7;
            l := al7;

            a := l & 0xffff; b := (l >> 16) & 0xffff;
            c := h & 0xffff; d := (h >> 16) & 0xffff;

            h := hh.get(7);
            l := hl.get(7);

            a += l & 0xffff; b += (l >> 16) & 0xffff;
            c += h & 0xffff; d += (h >> 16) & 0xffff;

            b += a >> 16;
            c += b >> 16;
            d += c >> 16;

            ah7 := (c & 0xffff) | (d << 16) & 0xffffffff;
            al7 := (a & 0xffff) | (b << 16) & 0xffffffff;
            hh.put(7, ah7);
            hl.put(7, al7);

            pos += 128;
            n -= 128;
        };

        return n;
    };

    public func crypto_hash(out : Buffer.Buffer<Nat8>, m : [Nat8], nInput : Nat) : Int {
        var x = Buffer.fromArray<Nat8>(Array.tabulate<Nat8>(256, func i = 0));
        
        let hh = Buffer.fromArray<Int64>([0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]);
        let hl = Buffer.fromArray<Int64>([0xf3bcc908, 0x84caa73b, 0xfe94f82b, 0x5f1d36f1 , 0xade682d1, 0x2b3e6c1f, 0xfb41bd6b, 0x137e2179]);
        
        var n = nInput;
        var b = n;

        ignore crypto_hashblocks_hl(hh, hl, m, n);
        n %= 128;
        
        for (i in Iter.range(0, n - 1)) { x.put(i, m[b - n + i]) };
        
        x.put(n, 128);

        n := 256 - 128 * (if (n < 112) 1 else 0);
        x.put(n-9, 0);
        ts64(x, n-8,  (Int64.fromNat64(Nat64.fromNat(b)) / 0x20000000) | 0, Int64.fromNat64(Nat64.fromNat(b) << 3));
        ignore crypto_hashblocks_hl(hh, hl, Buffer.toArray(x), n);

        for (i in Iter.range(0, 7)) {ts64(out, 8 * i, hh.get(i), hl.get(i))};
        return 0;
    };

    public func add(p : [Buffer.Buffer<Int64>], q : [Buffer.Buffer<Int64>]) {
        let a = buffer_i64(16); 
        let b = buffer_i64(16);
        let c = buffer_i64(16);
        let d = buffer_i64(16);
        let e = buffer_i64(16);
        let f = buffer_i64(16);
        let g = buffer_i64(16);
        let h = buffer_i64(16);
        let t = buffer_i64(16);

        Z(a, p[1], p[0]);
        Z(t, q[1], q[0]);
        M(a, a, t);
        A(b, p[0], p[1]);
        A(t, q[0], q[1]);
        M(b, b, t);
        M(c, p[3], q[3]);
        M(c, c, Buffer.fromArray(D2));
        M(d, p[2], q[2]);
        A(d, d, d);
        Z(e, b, a);
        Z(f, d, c);
        A(g, d, c);
        A(h, b, a);

        M(p[0], e, f);
        M(p[1], h, g);
        M(p[2], g, f);
        M(p[3], e, h);
    };

    func cswap(p : [Buffer.Buffer<Int64>], q : [Buffer.Buffer<Int64>], b : Int64) {
        for (i in Iter.range(0, 3)) {
            sel25519(p[i], q[i], b);
        };
    };

    func pack(r : Buffer.Buffer<Nat8>, p : [Buffer.Buffer<Int64>]) {
        var tx = buffer_i64(16);
        let ty = buffer_i64(16);
        let zi = buffer_i64(16);
        inv25519(zi, p[2]);
        M(tx, p[0], zi);
        M(ty, p[1], zi);
        pack25519(r, ty);
        r.put(31, r.get(31) ^ (par25519(tx) << 7));
    };

    public func scalarmult(p : [Buffer.Buffer<Int64>], q : [Buffer.Buffer<Int64>], s : [Nat8]) {
        set25519(p[0], Buffer.fromArray(gf0));
        set25519(p[1], Buffer.fromArray(gf1));
        set25519(p[2], Buffer.fromArray(gf1));
        set25519(p[3], Buffer.fromArray(gf0));
        for (i in Iter.revRange(255, 0)) {
            let b = (BitsPrc.nat8toInt64(s[Nat8.toNat((Nat8.fromNat(Int.abs(i))/8) | 0)]) >> (Int64.fromInt(i) & 7)) & 1;
            cswap(p, q, b);
            add(q, p);
            add(p, p);
            cswap(p, q, b);
        };
    };

    public func scalarbase(p : [Buffer.Buffer<Int64>], s : [Nat8]) {
        var q = [buffer_i64(16), buffer_i64(16), buffer_i64(16), buffer_i64(16)];
        set25519(q[0], Buffer.fromArray(X));
        set25519(q[1], Buffer.fromArray(Y));
        set25519(q[2], Buffer.fromArray(gf1));
        M(q[3], Buffer.fromArray(X), Buffer.fromArray(Y));
        scalarmult(p, q, s);
    };

    public func crypto_sign_keypair(pk : Buffer.Buffer<Nat8>, sk : Buffer.Buffer<Nat8>, seeded : Bool, pRNG : ?((Nat) -> ([Nat8]))) : Int {
        var d = Buffer.fromArray<Nat8>(Array.tabulate<Nat8>(64, func i = 0));
        var p = [buffer_i64(16), buffer_i64(16), buffer_i64(16), buffer_i64(16)];

        if (seeded == false) randomBytes(sk, crypto_sign_SEEDBYTES, pRNG);
        ignore crypto_hash(d, Buffer.toArray(sk), 32);
        d.put(0, d.get(0) & 248);
        d.put(31, d.get(31) & 127);
        d.put(31, d.get(31) | 64);

        scalarbase(p, Buffer.toArray(d));
        pack(pk, p);

        for (i in Iter.range(0, 31)) sk.put(i+32, pk.get(i));
        return 0;
    };

    public func async_crypto_sign_keypair(pk : Buffer.Buffer<Nat8>, sk : Buffer.Buffer<Nat8>, seeded : Bool, pRNG : ?((Nat) -> async ([Nat8]))) : async (Int) {
        var d = Buffer.fromArray<Nat8>(Array.tabulate<Nat8>(64, func i = 0));
        var p = [buffer_i64(16), buffer_i64(16), buffer_i64(16), buffer_i64(16)];

        if (seeded == false) await asyncRandomBytes(sk, crypto_sign_SEEDBYTES, pRNG);
        ignore crypto_hash(d, Buffer.toArray(sk), 32);
        d.put(0, d.get(0) & 248);
        d.put(31, d.get(31) & 127);
        d.put(31, d.get(31) | 64);

        scalarbase(p, Buffer.toArray(d));
        pack(pk, p);

        for (i in Iter.range(0, 31)) sk.put(i+32, pk.get(i));
        return 0;
    };

    public func modL(r : Buffer.Buffer<Nat8>, x : [var Int64]) {
        var carry : Int64 = 0;
        for (i in Iter.revRange(63, 32)) {
            carry := 0;
            for (j in Iter.range(Int.abs(i) - 32, i - 13)) {
                x[j] += carry - 16 * x[Int.abs(i)] * L[j - (Int.abs(i) - 32)];
                carry := Float.toInt64(Float.floor((Float.fromInt64(x[Int.abs(j)]) + 128) / 256));
                x[j] -= carry * 256;
            };
            x[Int.abs(i) - 12] += carry;
            x[Int.abs(i)] := 0;
        };
        carry := 0;
        for (j in Iter.range(0, 31)) {
            x[j] += carry - (x[31] >> 4) * L[j];
            carry := x[j] >> 8;
            x[j] &= 255;
        };
        for (j in Iter.range(0, 31)) x[j] -= carry * L[j];
        for (i in Iter.range(0, 31)) {
            x[i+1] += x[i] >> 8;
            r.put(i, BitsPrc.int64toNat8(x[i] & 255));
        };
    };

    func reduce(r : Buffer.Buffer<Nat8>) {
        let x = Array.tabulateVar<Int64>(64, func i = 0);
        for (i in Iter.range(0, 63)) {
            x[i] := BitsPrc.nat8toInt64(r.get(i));
            r.put(i, 0);
        };
        modL(r, x);
    };

    public func crypto_sign(sm : Buffer.Buffer<Nat8>, m : [Nat8], n : Nat, sk : [Nat8]) : Int {
        let d = Buffer.fromArray<Nat8>(Array.tabulate<Nat8>(64, func i = 0));
        let h = Buffer.fromArray<Nat8>(Array.tabulate<Nat8>(64, func i = 0));
        let r = Buffer.fromArray<Nat8>(Array.tabulate<Nat8>(64, func i = 0));
        let x = Array.tabulateVar<Int64>(64, func i = 0);
        var p = [buffer_i64(16), buffer_i64(16), buffer_i64(16), buffer_i64(16)];

        ignore crypto_hash(d, sk, 32);
        d.put(0, d.get(0) & 248);
        d.put(31, d.get(31) & 127);
        d.put(31, d.get(31) | 64);

        var smlen = n + 64;
        for (i in Iter.range(0, n - 1)) sm.put(64 + i, m[i]);
        for (i in Iter.range(0, 31)) sm.put(32 + i, d.get(32 + i));

        ignore crypto_hash(r, Buffer.toArray(Buffer.subBuffer<Nat8>(sm, 32, sm.size() - 32)), n + 32);
        reduce(r);
        scalarbase(p, Buffer.toArray(r));
        pack(sm, p);

        for (i in Iter.range(32, 63)) sm.put(i, sk[i]);
        ignore crypto_hash(h, Buffer.toArray(sm), n + 64);
        reduce(h);

        for (i in Iter.range(0, 31)) x[i] := BitsPrc.nat8toInt64(r.get(i));
        for (i in Iter.range(0, 31)) {
            for (j in Iter.range(0, 31)) {
                x[i+j] += BitsPrc.nat8toInt64(h.get(i)) * BitsPrc.nat8toInt64(d.get(j));
            };
        };
        let tmp = Buffer.subBuffer<Nat8>(sm, 32, sm.size() - 32);
        modL(tmp, x);
        for (i in Iter.range(0, tmp.size() - 1)) {
            sm.put(i + 32, tmp.get(i));
        };
        return smlen;
    };

    func unpackneg(r : [Buffer.Buffer<Int64>], p : [Nat8]) : Int {
        let t = buffer_i64(16);
        let chk = buffer_i64(16);
        let num = buffer_i64(16);
        let den = buffer_i64(16);
        let den2 = buffer_i64(16);
        let den4 = buffer_i64(16);
        let den6 = buffer_i64(16);

        set25519(r[2], Buffer.fromArray(gf1));
        unpack25519(r[1], p);
        S(num, r[1]);
        M(den, num, Buffer.fromArray(D));
        Z(num, num, r[2]);
        A(den, r[2], den);

        S(den2, den);
        S(den4, den2);
        M(den6, den4, den2);
        M(t, den6, num);
        M(t, t, den);

        pow2523(t, t);
        M(t, t, num);
        M(t, t, den);
        M(t, t, den);
        M(r[0], t, den);

        S(chk, r[0]);
        M(chk, chk, den);
        if (neq25519(chk, num) != 0) M(r[0], r[0], Buffer.fromArray(I));
        S(chk, r[0]);
        M(chk, chk, den);
        if (neq25519(chk, num) != 0) return -1;

        if (par25519(r[0]) == (p[31] >> 7)) Z(r[0], Buffer.fromArray(gf0), r[0]);

        M(r[3], r[0], r[1]);
        return 0;
    };

    public func crypto_sign_open(m : Buffer.Buffer<Nat8>, sm : [Nat8], nInput : Nat, pk : [Nat8]) : Int {
        let t = Buffer.fromArray<Nat8>(Array.tabulate<Nat8>(32, func i = 0));
        let h = Buffer.fromArray<Nat8>(Array.tabulate<Nat8>(64, func i = 0));
        let p = [buffer_i64(16), buffer_i64(16), buffer_i64(16), buffer_i64(16)];
        let q = [buffer_i64(16), buffer_i64(16), buffer_i64(16), buffer_i64(16)];
        var n = nInput;
        if (n < 64) return -1;

        if (unpackneg(q, pk) != 0) return -1;

        for (i in Iter.range(0, n-1)) m.put(i, sm[i]);
        for (i in Iter.range(0, 31)) m.put(i+32, pk[i]);
        ignore crypto_hash(h, Buffer.toArray(m), n);
        reduce(h);
        scalarmult(p, q, Buffer.toArray(h));

        scalarbase(q, Array.subArray<Nat8>(sm, 32, sm.size() - 32));
        add(p, q);
        pack(t, p);

        n -= 64;
        if (crypto_verify_32(sm, 0, Buffer.toArray(t), 0) != 0) {
            for (i in Iter.range(0, n-1)) m.put(i, 0);
            return -1;
        };

        for (i in Iter.range(0, n-1)) m.put(i, sm[i + 64]);
        return n;
    };

    // NaCl high-level API
    public func checkLengths(k : [Nat8], n : [Nat8]) {
        if (k.size() != crypto_secretbox_KEYBYTES) Debug.trap("bad key size");
        if (n.size() != crypto_secretbox_NONCEBYTES) Debug.trap("bad nonce size");
    };

    public func checkBoxLengths(pk : [Nat8], sk : [Nat8]) {
        if (pk.size() != crypto_box_PUBLICKEYBYTES) Debug.trap("bad public key size");
        if (sk.size() != crypto_box_SECRETKEYBYTES) Debug.trap("bad secret key size");
    };

    //  Length of hash in bytes.
    public let HASH_LENGTH = crypto_hash_BYTES;
    
    /**
    *   Hashing
    *   Implements SHA-512.
    *   
    *   nacl.hash(message)
    *   Returns SHA-512 hash of the message.
    **/
    public func hash(msg : [Nat8]) : [Nat8] {
        let h = Buffer.fromArray<Nat8>(Array.tabulate<Nat8>(crypto_hash_BYTES, func i = 0));
        ignore crypto_hash(h, msg, msg.size());
        return Buffer.toArray(h);
    };

    public func verify(x : [Nat8], y : [Nat8]) : Bool {
        // Zero length arguments are considered not equal.
        if (x.size() == 0 or y.size() == 0) return false;
        if (x.size() != y.size()) return false;
        return (vn(x, 0, y, 0, x.size()) == 0);
    };

    /**
    *  Generator func base on current Time
    */
    func nat8Generator(): {next : () -> (Nat8)} {
      let seed: Nat = Int.abs(Time.now());
      let prime = 456209410580464648418198177201;
      let prime2 = 4451889979529614097557895687536048212109;
      var prev = seed;
      {
        next = func(): Nat8 {
          let cur = (prev * prime + 5) % prime2;
          prev := cur;
          Nat8.fromIntWrap(cur);
        };
      };
    };

    func randomBytesInternal(blength: Nat): [Nat8] {
        let randomNat8 = nat8Generator();
        Array.tabulate<Nat8>(blength, func i = randomNat8.next());
    };

    func asyncRandomBytesInternal(blength: Nat): async [Nat8] {
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
        Buffer.toArray(r);
    };


    /**
    *   Public-key authenticated encryption (box)
    *   Implements x25519-xsalsa20-poly1305.
    **/
    public module BOX {

        //  Length of public key in bytes.
        public let PUBLIC_KEY_LENGTH = crypto_box_PUBLICKEYBYTES;
        //  Length of secret key in bytes.
        public let SECRET_KEY_LENGTH = crypto_box_SECRETKEYBYTES;
        //  Length of precomputed shared key in bytes.
        public let SHARED_KEY_LENGTH = crypto_box_BEFORENMBYTES;
        //  Length of nonce in bytes.
        public let NONCE_LENGTH = crypto_box_NONCEBYTES;
        //  Length of overhead added to box compared to original message.
        public let OVERHEAD_LENGTH = crypto_secretbox_BOXZEROBYTES;

        /**
        *   nacl.box(message, nonce, theirPublicKey, mySecretKey)
        *   
        *   Encrypts and authenticates message using peer's public key, our secret key, and the given nonce, 
        *   which must be unique for each distinct message for a key pair.
        *   
        *   Returns an encrypted and authenticated message, which is nacl.box.overheadLength longer than the original message.
        **/
        public func box(msg : [Nat8], nonce : [Nat8], publicKey : [Nat8], secretKey : [Nat8]) : [Nat8] {
            let k = SECRET.before(publicKey, secretKey);
            return SECRET.box(msg, nonce, k);
        };

        /**
        *   nacl.box.open(box, nonce, theirPublicKey, mySecretKey)
        *
        *   Authenticates and decrypts the given box with peer's public key, our secret key, and the given nonce.
        *
        *   Returns the original message, or null if authentication fails.
        **/
        public func open(msg : [Nat8], nonce : [Nat8], publicKey : [Nat8], secretKey : [Nat8]) : ?[Nat8] {
            var k = SECRET.before(publicKey, secretKey);
            return SECRET.open(msg, nonce, k);
        };
        
        /**
        *   nacl.box.keyPair()
        *
        *   Generates a new random key pair for box and returns it as an object with publicKey and secretKey members:
        **/
        public func keyPair(pRNG : ?((Nat) -> ([Nat8]))) : {publicKey : [Nat8]; secretKey : [Nat8]} {
            let pk = Buffer.fromArray<Nat8>(Array.tabulate<Nat8>(crypto_box_PUBLICKEYBYTES, func i = 0));
            let sk = Buffer.fromArray<Nat8>(Array.tabulate<Nat8>(crypto_box_SECRETKEYBYTES, func i = 0));
            ignore crypto_box_keypair(pk, sk, pRNG);
            return {publicKey = Buffer.toArray(pk); secretKey = Buffer.toArray(sk)};
        };

        /**
        *   async nacl.box.keyPair()
        *
        *   Generates a new random key pair for box and returns it as an object with publicKey and secretKey members:
        **/
        public func asyncKeyPair(pRNG : ?((Nat) -> async ([Nat8]))) : async ({publicKey : [Nat8]; secretKey : [Nat8]}) {
            let pk = Buffer.fromArray<Nat8>(Array.tabulate<Nat8>(crypto_box_PUBLICKEYBYTES, func i = 0));
            let sk = Buffer.fromArray<Nat8>(Array.tabulate<Nat8>(crypto_box_SECRETKEYBYTES, func i = 0));
            ignore await async_crypto_box_keypair(pk, sk, pRNG);
            return {publicKey = Buffer.toArray(pk); secretKey = Buffer.toArray(sk)};
        };

        public module KEYPAIR {
            /**
            *   nacl.box.keyPair.fromSecretKey(secretKey)
            *   
            *   Returns a key pair for box with public key corresponding to the given secret key.
            **/
            public func fromSecretKey(secretKey : [Nat8]) : {publicKey : [Nat8]; secretKey : [Nat8]} {
                if (secretKey.size() != crypto_box_SECRETKEYBYTES)  Debug.trap("bad secret key size");
                let pk = Buffer.fromArray<Nat8>(Array.tabulate<Nat8>(crypto_box_PUBLICKEYBYTES, func i = 0));
                ignore crypto_scalarmult_base(pk, secretKey);
                return {publicKey = Buffer.toArray(pk); secretKey = secretKey};
            };
        };


        /**
        *   Secret-key authenticated encryption (secretbox)
        *   Implements xsalsa20-poly1305.
        **/
        public module SECRET {

            // Length of precomputed shared key in bytes.
            public let KEY_LENGTH = crypto_secretbox_KEYBYTES;
            //  Length of nonce in bytes.
            public let NONCE_LENGTH = crypto_secretbox_NONCEBYTES;
            //  Length of overhead added to secret box compared to original message.
            public let OVERHEAD_LENGTH = crypto_secretbox_BOXZEROBYTES;

            /**
            *   nacl.before(theirPublicKey, mySecretKey)
            *   Returns a precomputed shared key which can be used in nacl.serectbox and nacl.secretboxOpen.
            **/
            public func before(publicKey : [Nat8], secretKey : [Nat8]) : [Nat8] {
                checkBoxLengths(publicKey, secretKey);
                let k = Buffer.fromArray<Nat8>(Array.tabulate<Nat8>(crypto_box_BEFORENMBYTES, func i = 0));
                crypto_box_beforenm(k, publicKey, secretKey);
                return Buffer.toArray(k);
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
                checkLengths(key, nonce);
                let m = Array.tabulateVar<Nat8>(crypto_secretbox_ZEROBYTES + msg.size(), func i = 0);
                let c = Buffer.fromArray<Nat8>(Array.tabulate<Nat8>(m.size(), func i = 0));
                for (i in Iter.range(0, msg.size() - 1)) m[i + crypto_secretbox_ZEROBYTES] := msg[i];
                ignore crypto_secretbox(c, Array.freeze(m), m.size(), nonce, key);
                return Buffer.toArray(Buffer.subBuffer<Nat8>(c, crypto_secretbox_BOXZEROBYTES, c.size() - crypto_secretbox_BOXZEROBYTES));
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
                checkLengths(key, nonce);
                let c = Array.tabulateVar<Nat8>(crypto_secretbox_BOXZEROBYTES + box.size(), func i = 0);
                let m = Buffer.fromArray<Nat8>(Array.tabulate<Nat8>(c.size(), func i = 0));
                for (i in Iter.range(0, box.size() - 1)) c[i + crypto_secretbox_BOXZEROBYTES] := box[i];
                if (c.size() < 32) return null;
                if (crypto_secretbox_open(m, Array.freeze(c), c.size(), nonce, key) != 0) return null;
                return ?Buffer.toArray(Buffer.subBuffer<Nat8>(m, crypto_secretbox_ZEROBYTES, m.size() - crypto_secretbox_ZEROBYTES));
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
        public let PUBLIC_KEY_LENGTH = crypto_sign_PUBLICKEYBYTES;
        //  Length of signing secret key in bytes.
        public let SECRET_KEY_LENGTH = crypto_sign_SECRETKEYBYTES;
        //  Length of seed for nacl.sign.keyPair.fromSeed in bytes.
        public let SEED_LENGTH = crypto_sign_SEEDBYTES;
        //  Length of signature in bytes.
        public let SIGNATURE_LENGTH = crypto_sign_BYTES;

        /**
        *   nacl.sign(message, secretKey)
        *   Signs the message using the secret key and returns a signed message.
        **/
        public func sign(msg : [Nat8], secretKey : [Nat8]) : [Nat8] {
            if (secretKey.size() != crypto_sign_SECRETKEYBYTES) Debug.trap("bad secret key size");
            let signedMsg = Buffer.fromArray<Nat8>(Array.tabulate<Nat8>(crypto_sign_BYTES + msg.size(), func i = 0));
            ignore crypto_sign(signedMsg, msg, msg.size(), secretKey);
            return Buffer.toArray(signedMsg);
        };

        /**
        *   nacl.sign.open(signedMessage, publicKey)
        *
        *   Verifies the signed message and returns the message without signature.
        *   Returns null if verification failed.
        **/
        public func open(signedMsg : [Nat8], publicKey : [Nat8]) : ?[Nat8] {
            if (publicKey.size() != crypto_sign_PUBLICKEYBYTES) Debug.trap("bad public key size");
            let tmp = Buffer.fromArray<Nat8>(Array.tabulate<Nat8>(signedMsg.size(), func i = 0));
            let mlen = crypto_sign_open(tmp, signedMsg, signedMsg.size(), publicKey);
            if (mlen < 0) return null;
            let m = Buffer.fromArray<Nat8>(Array.tabulate<Nat8>(Int.abs(mlen), func i = 0));
            for (i in Iter.range(0, m.size() - 1)) m.put(i, tmp.get(i));
            return ?Buffer.toArray(m);
        };

        /**
        *   nacl.sign.keyPair()
        *
        *   Generates new random key pair for signing and returns it as an object with publicKey and secretKey members:
        **/
        public func keyPair(pRNG : ?((Nat) -> ([Nat8]))) : {publicKey : [Nat8]; secretKey : [Nat8]} {
            let pk = Buffer.fromArray<Nat8>(Array.tabulate<Nat8>(crypto_sign_PUBLICKEYBYTES, func i = 0));
            let sk = Buffer.fromArray<Nat8>(Array.tabulate<Nat8>(crypto_sign_SECRETKEYBYTES, func i = 0));
            ignore crypto_sign_keypair(pk, sk, false, pRNG);
            return {publicKey = Buffer.toArray(pk); secretKey = Buffer.toArray(sk)};
        };

        /**
        *   async nacl.sign.keyPair()
        *
        *   Generates new random key pair for signing and returns it as an object with publicKey and secretKey members:
        **/
        public func asyncKeyPair(pRNG : ?((Nat) -> async ([Nat8]))) : async ({publicKey : [Nat8]; secretKey : [Nat8]}) {
            let pk = Buffer.fromArray<Nat8>(Array.tabulate<Nat8>(crypto_sign_PUBLICKEYBYTES, func i = 0));
            let sk = Buffer.fromArray<Nat8>(Array.tabulate<Nat8>(crypto_sign_SECRETKEYBYTES, func i = 0));
            ignore await async_crypto_sign_keypair(pk, sk, false, pRNG);
            return {publicKey = Buffer.toArray(pk); secretKey = Buffer.toArray(sk)};
        };


        public module KEYPAIR {
            
            /**
            *   nacl.sign.keyPair.fromSecretKey(secretKey)
            *
            *   Returns a signing key pair with public key corresponding to the given 64-byte secret key.
            *   The secret key must have been generated by nacl.sign.keyPair or nacl.sign.keyPair.fromSeed.
            **/
            public func fromSecretKey(secretKey : [Nat8]) : {publicKey : [Nat8]; secretKey : [Nat8]} {
                if (secretKey.size() != crypto_sign_SECRETKEYBYTES) Debug.trap("bad secret key size");
                let pk = Array.tabulateVar<Nat8>(crypto_sign_PUBLICKEYBYTES, func i = 0);
                for (i in Iter.range(0, pk.size() - 1)) pk[i] := secretKey[32+i];
                return {publicKey = Array.freeze(pk); secretKey = secretKey};
            };

            /**
            *   nacl.sign.keyPair.fromSeed(seed)
            *
            *   Returns a new signing key pair generated deterministically from a 32-byte seed. The seed must contain enough entropy to be secure.
            *   This method is not recommended for general use: instead, use nacl.sign.keyPair to generate a new key pair from a random seed.
            **/
            public func fromSeed(seed : [Nat8]) : {publicKey : [Nat8]; secretKey : [Nat8]} {
                if (seed.size() != crypto_sign_SEEDBYTES)  Debug.trap("bad seed size");
                let pk = Buffer.fromArray<Nat8>(Array.tabulate<Nat8>(crypto_sign_PUBLICKEYBYTES, func i = 0));
                let sk = Buffer.fromArray<Nat8>(Array.tabulate<Nat8>(crypto_sign_SECRETKEYBYTES, func i = 0));
                for (i in Iter.range(0, 31)) sk.put(i, seed[i]);
                ignore crypto_sign_keypair(pk, sk, true, null);
                return {publicKey = Buffer.toArray(pk); secretKey = Buffer.toArray(sk)};
            };
        };

        public module DETACHED {
            
            /**
            *   nacl.sign.detached(message, secretKey)
            *   Signs the message using the secret key and returns a signature.
            **/
            public func detached(msg : [Nat8], secretKey : [Nat8]) : [Nat8] {
                let signedMsg = sign(msg, secretKey);
            let sig = Buffer.fromArray<Nat8>(Array.tabulate<Nat8>(crypto_sign_BYTES, func i = 0));
            for (i in Iter.range(0, sig.size() - 1)) sig.put(i, signedMsg[i]);
            return Buffer.toArray(sig);
            };

            /**
            *   nacl.sign.detached.verify(message, signature, publicKey)
            *   Verifies the signature for the message and returns true if verification succeeded or false if it failed.
            **/
            public func verify(msg : [Nat8], sig : [Nat8], publicKey : [Nat8]) : Bool {
                if (sig.size() != crypto_sign_BYTES)    Debug.trap("bad signature size");
                if (publicKey.size() != crypto_sign_PUBLICKEYBYTES) Debug.trap("bad public key size");
                let sm = Array.tabulateVar<Nat8>(crypto_sign_BYTES + msg.size(), func i = 0);
                let m = Buffer.fromArray<Nat8>(Array.tabulate<Nat8>(crypto_sign_BYTES + msg.size(), func i = 0));
                for (i in Iter.range(0, crypto_sign_BYTES - 1)) sm[i] := sig[i];
                for (i in Iter.range(0, msg.size() - 1)) sm[i+crypto_sign_BYTES] := msg[i];
                return (crypto_sign_open(m, Array.freeze(sm), sm.size(), publicKey) >= 0);
            };
        };
    };


    /**
    *   Scalar multiplication
    *   Implements x25519.
    **/
    public module SCALARMULT {

        //  Length of scalar in bytes.
        public let SCALAR_LENGTH = crypto_scalarmult_SCALARBYTES;
        //  Length of group element in bytes.
        public let GROUP_ELEMENT_LENGTH = crypto_scalarmult_BYTES;

        /**
        *   nacl.scalarMult(n, p)
        *   Multiplies an integer n by a group element p and returns the resulting group element.
        **/
        public func mult(n : [Nat8], p : [Nat8]) : [Nat8] {
            if (n.size() != crypto_scalarmult_SCALARBYTES) Debug.trap("bad n size");
            if (p.size() != crypto_scalarmult_BYTES) Debug.trap("bad p size");
            let q = Buffer.fromArray<Nat8>(Array.tabulate<Nat8>(crypto_scalarmult_BYTES, func i = 0));
            ignore crypto_scalarmult(q, n, p);
            return Buffer.toArray(q);
        };

        /**
        *   nacl.scalarMult.base(n)
        *   Multiplies an integer n by a standard group element and returns the resulting group element.
        **/
        public func base(n : [Nat8]) : [Nat8] {
            if (n.size() != crypto_scalarmult_SCALARBYTES) Debug.trap("bad n size");
            let q = Buffer.fromArray<Nat8>(Array.tabulate<Nat8>(crypto_scalarmult_BYTES, func i = 0));
            ignore crypto_scalarmult_base(q, n);
            return Buffer.toArray(q);
        };
    };
    // end module Nacl
};