/*******************************************************************
* Copyright         : 2024 nirvana369
* File Name         : tweetnacl.mo
* Description       : This library is porting version of library tweetnacl.
*                    
* Revision History  :
* Date				Author    		Comments
* ---------------------------------------------------------------------------
* 08/31/2024		nirvana369 		Created.
* 09/01/2024		nirvana369 		Added core function.
* 09/04/2024        nirvana369      Implement func crypto_hashblocks_hl
*                                   use 64int to process instead 32int
******************************************************************/

import Float "mo:base/Float";
import Array "mo:base/Array";
import Nat64 "mo:base/Nat64";
import Nat32 "mo:base/Nat32";
import Nat16 "mo:base/Nat16";
import Nat8 "mo:base/Nat8";
import Iter "mo:base/Iter";
import Int "mo:base/Int";
import Int64 "mo:base/Int64";
import Int8 "mo:base/Int8";
import Buffer "mo:base/Buffer";
import Int16 "mo:base/Int16";
import Int32 "mo:base/Int32";


class TweetNaCl() {

    private func gf(init : ?[Int64]) : Buffer.Buffer<Int64> {
        switch (init) {
            case (?arr) {
                Buffer.fromArray(arr);
            };
            case null {
                Buffer.fromArray(Array.tabulate<Int64>(16, func i = 0));
            };
        };
    };

    var randomBytesFuncShared : ?((Nat) -> ([Nat8])) = null;

    public let setRandomBytesFunc = func (f : (Nat) -> ([Nat8])) {
        randomBytesFuncShared := ?f;
    };

    let _0 : [Nat8] = Array.tabulate<Nat8>(16, func (i) : Nat8 {0});
    let _9 : [Nat8] = Array.tabulate<Nat8>(32, func (i) : Nat8 {if (i == 0) 9 else 0});

    let gf0 = Buffer.toArray(gf(null));
    let gf1 = Buffer.toArray(gf(?[1]));
    let _121665 : [Int64] = [0xdb41, 1];
    let D : [Int64] = [0x78a3, 0x1359, 0x4dca, 0x75eb, 0xd8ab, 0x4141, 0x0a4d, 0x0070, 0xe898, 0x7779, 0x4079, 0x8cc7, 0xfe73, 0x2b6f, 0x6cee, 0x5203];
    let D2 : [Int64] = [0xf159, 0x26b2, 0x9b94, 0xebd6, 0xb156, 0x8283, 0x149a, 0x00e0, 0xd130, 0xeef3, 0x80f2, 0x198e, 0xfce7, 0x56df, 0xd9dc, 0x2406];
    let X : [Int64] = [0xd51a, 0x8f25, 0x2d60, 0xc956, 0xa7b2, 0x9525, 0xc760, 0x692c, 0xdc5c, 0xfdd6, 0xe231, 0xc0a4, 0x53fe, 0xcd6e, 0x36d3, 0x2169];
    let Y : [Int64] = [0x6658, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666];
    let I : [Int64] = [0xa0b0, 0x4a0e, 0x1b27, 0xc4ee, 0xe478, 0xad2f, 0x1806, 0x2f43, 0xd7a7, 0x3dfb, 0x0099, 0x2b4d, 0xdf0b, 0x4fc1, 0x2480, 0x2b83];

    module BitsPrc {
        public func nat32toNat8(n : Nat32) : Nat8 {
            Nat8.fromNat(Nat32.toNat(n));
        };

        public func nat8toNat32(n : Nat8) : Nat32 {
            Nat32.fromNat(Nat8.toNat(n));
        };

        public func nat16toNat8(n : Nat16) : Nat8 {
            Nat8.fromNat(Nat16.toNat(n));
        };

        public func nat8toNat16(n : Nat8) : Nat16 {
            Nat16.fromNat(Nat8.toNat(n));
        };

        public func nat8toInt64(n : Nat8) : Int64 {
            Int64.fromNat64(Nat64.fromNat(Nat8.toNat(n)));
        };

        public func nat8toInt32(n : Nat8) : Int32 {
            Int32.fromNat32(Nat32.fromNat(Nat8.toNat(n)));
        };

        public func int64toInt32(n : Int64) : Int32 {
            Int32.fromIntWrap(Int64.toInt(n));
        };

        public func int64toNat8(n : Int64) : Nat8 {
            Nat8.fromIntWrap(Int64.toInt(n));
        };

        public func int32toNat8(n : Int32) : Nat8 {
            Nat8.fromIntWrap(Int32.toInt(n));
        };

        public func int8toNat8(n : Int8) : Nat8 {
            Int8.toNat8(n);
        };

        public func unsigned32ShiftRight(val : Int32, shiftBy : Int32) : Int32 {
            let n = Int.abs(Int32.toInt(shiftBy));
            var r = val >> (shiftBy % 32);
                for (i in Iter.range(31 - n + 1, 31)) {
                    r := Int32.bitclear(r, i);
                };
            r;
        };
    };

    func ts64(x : Buffer.Buffer<Nat8>, i : Nat, h : Int32, l : Int32) {
        x.put(i, BitsPrc.int32toNat8((h >> 24) & 0xff));
        x.put(i+1, BitsPrc.int32toNat8((h >> 16) & 0xff));
        x.put(i+2, BitsPrc.int32toNat8((h >>  8) & 0xff));
        x.put(i+3, BitsPrc.int32toNat8(h & 0xff));
        x.put(i+4, BitsPrc.int32toNat8((l >> 24)  & 0xff));
        x.put(i+5, BitsPrc.int32toNat8((l >> 16)  & 0xff));
        x.put(i+6, BitsPrc.int32toNat8((l >>  8)  & 0xff));
        x.put(i+7, BitsPrc.int32toNat8(l & 0xff));
    };

    // verify 32 bytes
    func vn(x : [Nat8], xi : Nat, y : [Nat8], yi : Nat, n : Nat) : Nat8 {
        var i = 0;
        var d : Nat8 = 0;
        while (i < n) {
            d := d | (x[xi+i] ^ y[yi+i]);
            i += 1;
        };
        // success = 0
        return (1 & ((d - 1) >> 8)) - 1;
    };

    func crypto_verify_16(x : [Nat8], xi : Nat, y : [Nat8], yi : Nat) : Nat8 {
        return vn(x, xi, y, yi, 16);
    };

    func crypto_verify_32(x : [Nat8], xi : Nat, y : [Nat8], yi : Nat) : Nat8 {
        return vn(x, xi, y, yi, 32);
    };

    func core_salsa20(o : Buffer.Buffer<Nat8>, p : [Nat8], k : [Nat8], c : [Nat8]) {
        var j0  = BitsPrc.nat8toNat32(c[ 0] & 0xff) | (BitsPrc.nat8toNat32(c[ 1] & 0xff)<<8) | (BitsPrc.nat8toNat32(c[ 2] & 0xff)<<16) | (BitsPrc.nat8toNat32(c[ 3] & 0xff)<<24);
        var j1  = BitsPrc.nat8toNat32(k[ 0] & 0xff) | (BitsPrc.nat8toNat32(k[ 1] & 0xff)<<8) | (BitsPrc.nat8toNat32(k[ 2] & 0xff)<<16) | (BitsPrc.nat8toNat32(k[ 3] & 0xff)<<24);
        var j2  = BitsPrc.nat8toNat32(k[ 4] & 0xff) | (BitsPrc.nat8toNat32(k[ 5] & 0xff)<<8) | (BitsPrc.nat8toNat32(k[ 6] & 0xff)<<16) | (BitsPrc.nat8toNat32(k[ 7] & 0xff)<<24);
        var j3  = BitsPrc.nat8toNat32(k[ 8] & 0xff) | (BitsPrc.nat8toNat32(k[ 9] & 0xff)<<8) | (BitsPrc.nat8toNat32(k[10] & 0xff)<<16) | (BitsPrc.nat8toNat32(k[11] & 0xff)<<24);
        var j4  = BitsPrc.nat8toNat32(k[12] & 0xff) | (BitsPrc.nat8toNat32(k[13] & 0xff)<<8) | (BitsPrc.nat8toNat32(k[14] & 0xff)<<16) | (BitsPrc.nat8toNat32(k[15] & 0xff)<<24);
        var j5  = BitsPrc.nat8toNat32(c[ 4] & 0xff) | (BitsPrc.nat8toNat32(c[ 5] & 0xff)<<8) | (BitsPrc.nat8toNat32(c[ 6] & 0xff)<<16) | (BitsPrc.nat8toNat32(c[ 7] & 0xff)<<24);
        var j6  = BitsPrc.nat8toNat32(p[ 0] & 0xff) | (BitsPrc.nat8toNat32(p[ 1] & 0xff)<<8) | (BitsPrc.nat8toNat32(p[ 2] & 0xff)<<16) | (BitsPrc.nat8toNat32(p[ 3] & 0xff)<<24);
        var j7  = BitsPrc.nat8toNat32(p[ 4] & 0xff) | (BitsPrc.nat8toNat32(p[ 5] & 0xff)<<8) | (BitsPrc.nat8toNat32(p[ 6] & 0xff)<<16) | (BitsPrc.nat8toNat32(p[ 7] & 0xff)<<24);
        var j8  = BitsPrc.nat8toNat32(p[ 8] & 0xff) | (BitsPrc.nat8toNat32(p[ 9] & 0xff)<<8) | (BitsPrc.nat8toNat32(p[10] & 0xff)<<16) | (BitsPrc.nat8toNat32(p[11] & 0xff)<<24);
        var j9  = BitsPrc.nat8toNat32(p[12] & 0xff) | (BitsPrc.nat8toNat32(p[13] & 0xff)<<8) | (BitsPrc.nat8toNat32(p[14] & 0xff)<<16) | (BitsPrc.nat8toNat32(p[15] & 0xff)<<24);
        var j10 = BitsPrc.nat8toNat32(c[ 8] & 0xff) | (BitsPrc.nat8toNat32(c[ 9] & 0xff)<<8) | (BitsPrc.nat8toNat32(c[10] & 0xff)<<16) | (BitsPrc.nat8toNat32(c[11] & 0xff)<<24);
        var j11 = BitsPrc.nat8toNat32(k[16] & 0xff) | (BitsPrc.nat8toNat32(k[17] & 0xff)<<8) | (BitsPrc.nat8toNat32(k[18] & 0xff)<<16) | (BitsPrc.nat8toNat32(k[19] & 0xff)<<24);
        var j12 = BitsPrc.nat8toNat32(k[20] & 0xff) | (BitsPrc.nat8toNat32(k[21] & 0xff)<<8) | (BitsPrc.nat8toNat32(k[22] & 0xff)<<16) | (BitsPrc.nat8toNat32(k[23] & 0xff)<<24);
        var j13 = BitsPrc.nat8toNat32(k[24] & 0xff) | (BitsPrc.nat8toNat32(k[25] & 0xff)<<8) | (BitsPrc.nat8toNat32(k[26] & 0xff)<<16) | (BitsPrc.nat8toNat32(k[27] & 0xff)<<24);
        var j14 = BitsPrc.nat8toNat32(k[28] & 0xff) | (BitsPrc.nat8toNat32(k[29] & 0xff)<<8) | (BitsPrc.nat8toNat32(k[30] & 0xff)<<16) | (BitsPrc.nat8toNat32(k[31] & 0xff)<<24);
        var j15 = BitsPrc.nat8toNat32(c[12] & 0xff) | (BitsPrc.nat8toNat32(c[13] & 0xff)<<8) | (BitsPrc.nat8toNat32(c[14] & 0xff)<<16) | (BitsPrc.nat8toNat32(c[15] & 0xff)<<24);

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
        var u : Nat32 = 0;
        var i = 0;
        while (i < 20) {
            u := x0 + x12 | 0;
            x4 ^= u <<> 7;
            u := x4 + x0 | 0;
            x8 ^= u <<> 9;
            u := x8 + x4 | 0;
            x12 ^= u <<> 13;
            u := x12 + x8 | 0;
            x0 ^= u <<> 18;

            u := x5 + x1 | 0;
            x9 ^= u <<> 7;
            u := x9 + x5 | 0;
            x13 ^= u <<> 9;
            u := x13 + x9 | 0;
            x1 ^= u <<> 13;
            u := x1 + x13 | 0;
            x5 ^= u <<> 18;

            u := x10 + x6 | 0;
            x14 ^= u <<> 7;
            u := x14 + x10 | 0;
            x2 ^= u <<> 9;
            u := x2 + x14 | 0;
            x6 ^= u <<> 13;
            u := x6 + x2 | 0;
            x10 ^= u <<> 18;

            u := x15 + x11 | 0;
            x3 ^= u <<> 7;
            u := x3 + x15 | 0;
            x7 ^= u <<> 9;
            u := x7 + x3 | 0;
            x11 ^= u <<> 13;
            u := x11 + x7 | 0;
            x15 ^= u <<> 18;

            u := x0 + x3 | 0;
            x1 ^= u <<> 7;
            u := x1 + x0 | 0;
            x2 ^= u <<> 9;
            u := x2 + x1 | 0;
            x3 ^= u <<> 13;
            u := x3 + x2 | 0;
            x0 ^= u <<> 18;

            u := x5 + x4 | 0;
            x6 ^= u <<> 7;
            u := x6 + x5 | 0;
            x7 ^= u <<> 9;
            u := x7 + x6 | 0;
            x4 ^= u <<> 13;
            u := x4 + x7 | 0;
            x5 ^= u <<> 18;

            u := x10 + x9 | 0;
            x11 ^= u <<> 7;
            u := x11 + x10 | 0;
            x8 ^= u <<> 9;
            u := x8 + x11 | 0;
            x9 ^= u <<> 13;
            u := x9 + x8 | 0;
            x10 ^= u <<> 18;

            u := x15 + x14 | 0;
            x12 ^= u <<> 7;
            u := x12 + x15 | 0;
            x13 ^= u <<> 9;
            u := x13 + x12 | 0;
            x14 ^= u <<> 13;
            u := x14 + x13 | 0;
            x15 ^= u <<> 18;
            
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

        o.put( 0, BitsPrc.nat32toNat8(x0 >>  0 & 0xff));
        o.put( 1, BitsPrc.nat32toNat8(x0 >>  8 & 0xff));
        o.put( 2, BitsPrc.nat32toNat8(x0 >> 16 & 0xff));
        o.put( 3, BitsPrc.nat32toNat8(x0 >> 24 & 0xff));

        o.put( 4, BitsPrc.nat32toNat8(x1 >>  0 & 0xff));
        o.put( 5, BitsPrc.nat32toNat8(x1 >>  8 & 0xff));
        o.put( 6, BitsPrc.nat32toNat8(x1 >> 16 & 0xff));
        o.put( 7, BitsPrc.nat32toNat8(x1 >> 24 & 0xff));

        o.put( 8, BitsPrc.nat32toNat8(x2 >>  0 & 0xff));
        o.put( 9, BitsPrc.nat32toNat8(x2 >>  8 & 0xff));
        o.put(10, BitsPrc.nat32toNat8(x2 >> 16 & 0xff));
        o.put(11, BitsPrc.nat32toNat8(x2 >> 24 & 0xff));

        o.put(12, BitsPrc.nat32toNat8(x3 >>  0 & 0xff));
        o.put(13, BitsPrc.nat32toNat8(x3 >>  8 & 0xff));
        o.put(14, BitsPrc.nat32toNat8(x3 >> 16 & 0xff));
        o.put(15, BitsPrc.nat32toNat8(x3 >> 24 & 0xff));

        o.put(16, BitsPrc.nat32toNat8(x4 >>  0 & 0xff));
        o.put(17, BitsPrc.nat32toNat8(x4 >>  8 & 0xff));
        o.put(18, BitsPrc.nat32toNat8(x4 >> 16 & 0xff));
        o.put(19, BitsPrc.nat32toNat8(x4 >> 24 & 0xff));

        o.put(20, BitsPrc.nat32toNat8(x5 >>  0 & 0xff));
        o.put(21, BitsPrc.nat32toNat8(x5 >>  8 & 0xff));
        o.put(22, BitsPrc.nat32toNat8(x5 >> 16 & 0xff));
        o.put(23, BitsPrc.nat32toNat8(x5 >> 24 & 0xff));

        o.put(24, BitsPrc.nat32toNat8(x6 >>  0 & 0xff));
        o.put(25, BitsPrc.nat32toNat8(x6 >>  8 & 0xff));
        o.put(26, BitsPrc.nat32toNat8(x6 >> 16 & 0xff));
        o.put(27, BitsPrc.nat32toNat8(x6 >> 24 & 0xff));

        o.put(28, BitsPrc.nat32toNat8(x7 >>  0 & 0xff));
        o.put(29, BitsPrc.nat32toNat8(x7 >>  8 & 0xff));
        o.put(30, BitsPrc.nat32toNat8(x7 >> 16 & 0xff));
        o.put(31, BitsPrc.nat32toNat8(x7 >> 24 & 0xff));

        o.put(32, BitsPrc.nat32toNat8(x8 >>  0 & 0xff));
        o.put(33, BitsPrc.nat32toNat8(x8 >>  8 & 0xff));
        o.put(34, BitsPrc.nat32toNat8(x8 >> 16 & 0xff));
        o.put(35, BitsPrc.nat32toNat8(x8 >> 24 & 0xff));

        o.put(36, BitsPrc.nat32toNat8(x9 >>  0 & 0xff));
        o.put(37, BitsPrc.nat32toNat8(x9 >>  8 & 0xff));
        o.put(38, BitsPrc.nat32toNat8(x9 >> 16 & 0xff));
        o.put(39, BitsPrc.nat32toNat8(x9 >> 24 & 0xff));

        o.put(40, BitsPrc.nat32toNat8(x10 >>  0 & 0xff));
        o.put(41, BitsPrc.nat32toNat8(x10 >>  8 & 0xff));
        o.put(42, BitsPrc.nat32toNat8(x10 >> 16 & 0xff));
        o.put(43, BitsPrc.nat32toNat8(x10 >> 24 & 0xff));

        o.put(44, BitsPrc.nat32toNat8(x11 >>  0 & 0xff));
        o.put(45, BitsPrc.nat32toNat8(x11 >>  8 & 0xff));
        o.put(46, BitsPrc.nat32toNat8(x11 >> 16 & 0xff));
        o.put(47, BitsPrc.nat32toNat8(x11 >> 24 & 0xff));

        o.put(48, BitsPrc.nat32toNat8(x12 >>  0 & 0xff));
        o.put(49, BitsPrc.nat32toNat8(x12 >>  8 & 0xff));
        o.put(50, BitsPrc.nat32toNat8(x12 >> 16 & 0xff));
        o.put(51, BitsPrc.nat32toNat8(x12 >> 24 & 0xff));

        o.put(52, BitsPrc.nat32toNat8(x13 >>  0 & 0xff));
        o.put(53, BitsPrc.nat32toNat8(x13 >>  8 & 0xff));
        o.put(54, BitsPrc.nat32toNat8(x13 >> 16 & 0xff));
        o.put(55, BitsPrc.nat32toNat8(x13 >> 24 & 0xff));

        o.put(56, BitsPrc.nat32toNat8(x14 >>  0 & 0xff));
        o.put(57, BitsPrc.nat32toNat8(x14 >>  8 & 0xff));
        o.put(58, BitsPrc.nat32toNat8(x14 >> 16 & 0xff));
        o.put(59, BitsPrc.nat32toNat8(x14 >> 24 & 0xff));

        o.put(60, BitsPrc.nat32toNat8(x15 >>  0 & 0xff));
        o.put(61, BitsPrc.nat32toNat8(x15 >>  8 & 0xff));
        o.put(62, BitsPrc.nat32toNat8(x15 >> 16 & 0xff));
        o.put(63, BitsPrc.nat32toNat8(x15 >> 24 & 0xff));
    };

    func core_hsalsa20(o : Buffer.Buffer<Nat8>, p : [Nat8], k : [Nat8], c : [Nat8]) {
        var j0  = BitsPrc.nat8toNat32(c[ 0] & 0xff) | (BitsPrc.nat8toNat32(c[ 1] & 0xff)<<8) | (BitsPrc.nat8toNat32(c[ 2] & 0xff)<<16) | (BitsPrc.nat8toNat32(c[ 3] & 0xff)<<24);
        var j1  = BitsPrc.nat8toNat32(k[ 0] & 0xff) | (BitsPrc.nat8toNat32(k[ 1] & 0xff)<<8) | (BitsPrc.nat8toNat32(k[ 2] & 0xff)<<16) | (BitsPrc.nat8toNat32(k[ 3] & 0xff)<<24);
        var j2  = BitsPrc.nat8toNat32(k[ 4] & 0xff) | (BitsPrc.nat8toNat32(k[ 5] & 0xff)<<8) | (BitsPrc.nat8toNat32(k[ 6] & 0xff)<<16) | (BitsPrc.nat8toNat32(k[ 7] & 0xff)<<24);
        var j3  = BitsPrc.nat8toNat32(k[ 8] & 0xff) | (BitsPrc.nat8toNat32(k[ 9] & 0xff)<<8) | (BitsPrc.nat8toNat32(k[10] & 0xff)<<16) | (BitsPrc.nat8toNat32(k[11] & 0xff)<<24);
        var j4  = BitsPrc.nat8toNat32(k[12] & 0xff) | (BitsPrc.nat8toNat32(k[13] & 0xff)<<8) | (BitsPrc.nat8toNat32(k[14] & 0xff)<<16) | (BitsPrc.nat8toNat32(k[15] & 0xff)<<24);
        var j5  = BitsPrc.nat8toNat32(c[ 4] & 0xff) | (BitsPrc.nat8toNat32(c[ 5] & 0xff)<<8) | (BitsPrc.nat8toNat32(c[ 6] & 0xff)<<16) | (BitsPrc.nat8toNat32(c[ 7] & 0xff)<<24);
        var j6  = BitsPrc.nat8toNat32(p[ 0] & 0xff) | (BitsPrc.nat8toNat32(p[ 1] & 0xff)<<8) | (BitsPrc.nat8toNat32(p[ 2] & 0xff)<<16) | (BitsPrc.nat8toNat32(p[ 3] & 0xff)<<24);
        var j7  = BitsPrc.nat8toNat32(p[ 4] & 0xff) | (BitsPrc.nat8toNat32(p[ 5] & 0xff)<<8) | (BitsPrc.nat8toNat32(p[ 6] & 0xff)<<16) | (BitsPrc.nat8toNat32(p[ 7] & 0xff)<<24);
        var j8  = BitsPrc.nat8toNat32(p[ 8] & 0xff) | (BitsPrc.nat8toNat32(p[ 9] & 0xff)<<8) | (BitsPrc.nat8toNat32(p[10] & 0xff)<<16) | (BitsPrc.nat8toNat32(p[11] & 0xff)<<24);
        var j9  = BitsPrc.nat8toNat32(p[12] & 0xff) | (BitsPrc.nat8toNat32(p[13] & 0xff)<<8) | (BitsPrc.nat8toNat32(p[14] & 0xff)<<16) | (BitsPrc.nat8toNat32(p[15] & 0xff)<<24);
        var j10 = BitsPrc.nat8toNat32(c[ 8] & 0xff) | (BitsPrc.nat8toNat32(c[ 9] & 0xff)<<8) | (BitsPrc.nat8toNat32(c[10] & 0xff)<<16) | (BitsPrc.nat8toNat32(c[11] & 0xff)<<24);
        var j11 = BitsPrc.nat8toNat32(k[16] & 0xff) | (BitsPrc.nat8toNat32(k[17] & 0xff)<<8) | (BitsPrc.nat8toNat32(k[18] & 0xff)<<16) | (BitsPrc.nat8toNat32(k[19] & 0xff)<<24);
        var j12 = BitsPrc.nat8toNat32(k[20] & 0xff) | (BitsPrc.nat8toNat32(k[21] & 0xff)<<8) | (BitsPrc.nat8toNat32(k[22] & 0xff)<<16) | (BitsPrc.nat8toNat32(k[23] & 0xff)<<24);
        var j13 = BitsPrc.nat8toNat32(k[24] & 0xff) | (BitsPrc.nat8toNat32(k[25] & 0xff)<<8) | (BitsPrc.nat8toNat32(k[26] & 0xff)<<16) | (BitsPrc.nat8toNat32(k[27] & 0xff)<<24);
        var j14 = BitsPrc.nat8toNat32(k[28] & 0xff) | (BitsPrc.nat8toNat32(k[29] & 0xff)<<8) | (BitsPrc.nat8toNat32(k[30] & 0xff)<<16) | (BitsPrc.nat8toNat32(k[31] & 0xff)<<24);
        var j15 = BitsPrc.nat8toNat32(c[12] & 0xff) | (BitsPrc.nat8toNat32(c[13] & 0xff)<<8) | (BitsPrc.nat8toNat32(c[14] & 0xff)<<16) | (BitsPrc.nat8toNat32(c[15] & 0xff)<<24);

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
        var u : Nat32 = 0;
        var i = 0;
        while (i < 20) {
            u := x0 + x12 | 0;
            x4 ^= u <<> 7;
            u := x4 + x0 | 0;
            x8 ^= u <<> 9;
            u := x8 + x4 | 0;
            x12 ^= u <<> 13;
            u := x12 + x8 | 0;
            x0 ^= u <<> 18;

            u := x5 + x1 | 0;
            x9 ^= u <<> 7;
            u := x9 + x5 | 0;
            x13 ^= u <<> 9;
            u := x13 + x9 | 0;
            x1 ^= u <<> 13;
            u := x1 + x13 | 0;
            x5 ^= u <<> 18;

            u := x10 + x6 | 0;
            x14 ^= u <<> 7;
            u := x14 + x10 | 0;
            x2 ^= u <<> 9;
            u := x2 + x14 | 0;
            x6 ^= u <<> 13;
            u := x6 + x2 | 0;
            x10 ^= u <<> 18;

            u := x15 + x11 | 0;
            x3 ^= u <<> 7;
            u := x3 + x15 | 0;
            x7 ^= u <<> 9;
            u := x7 + x3 | 0;
            x11 ^= u <<> 13;
            u := x11 + x7 | 0;
            x15 ^= u <<> 18;

            u := x0 + x3 | 0;
            x1 ^= u <<> 7;
            u := x1 + x0 | 0;
            x2 ^= u <<> 9;
            u := x2 + x1 | 0;
            x3 ^= u <<> 13;
            u := x3 + x2 | 0;
            x0 ^= u <<> 18;

            u := x5 + x4 | 0;
            x6 ^= u <<> 7;
            u := x6 + x5 | 0;
            x7 ^= u <<> 9;
            u := x7 + x6 | 0;
            x4 ^= u <<> 13;
            u := x4 + x7 | 0;
            x5 ^= u <<> 18;

            u := x10 + x9 | 0;
            x11 ^= u <<> 7;
            u := x11 + x10 | 0;
            x8 ^= u <<> 9;
            u := x8 + x11 | 0;
            x9 ^= u <<> 13;
            u := x9 + x8 | 0;
            x10 ^= u <<> 18;

            u := x15 + x14 | 0;
            x12 ^= u <<> 7;
            u := x12 + x15 | 0;
            x13 ^= u <<> 9;
            u := x13 + x12 | 0;
            x14 ^= u <<> 13;
            u := x14 + x13 | 0;
            x15 ^= u <<> 18;

            i += 2;
        };

        o.put( 0, BitsPrc.nat32toNat8(x0 >>  0 & 0xff));
        o.put( 1, BitsPrc.nat32toNat8(x0 >>  8 & 0xff));
        o.put( 2, BitsPrc.nat32toNat8(x0 >> 16 & 0xff));
        o.put( 3, BitsPrc.nat32toNat8(x0 >> 24 & 0xff));

        o.put( 4, BitsPrc.nat32toNat8(x5 >>  0 & 0xff));
        o.put( 5, BitsPrc.nat32toNat8(x5 >>  8 & 0xff));
        o.put( 6, BitsPrc.nat32toNat8(x5 >> 16 & 0xff));
        o.put( 7, BitsPrc.nat32toNat8(x5 >> 24 & 0xff));

        o.put( 8, BitsPrc.nat32toNat8(x10 >>  0 & 0xff));
        o.put( 9, BitsPrc.nat32toNat8(x10 >>  8 & 0xff));
        o.put(10, BitsPrc.nat32toNat8(x10 >> 16 & 0xff));
        o.put(11, BitsPrc.nat32toNat8(x10 >> 24 & 0xff));

        o.put(12, BitsPrc.nat32toNat8(x15 >>  0 & 0xff));
        o.put(13, BitsPrc.nat32toNat8(x15 >>  8 & 0xff));
        o.put(14, BitsPrc.nat32toNat8(x15 >> 16 & 0xff));
        o.put(15, BitsPrc.nat32toNat8(x15 >> 24 & 0xff));

        o.put(16, BitsPrc.nat32toNat8(x6 >>  0 & 0xff));
        o.put(17, BitsPrc.nat32toNat8(x6 >>  8 & 0xff));
        o.put(18, BitsPrc.nat32toNat8(x6 >> 16 & 0xff));
        o.put(19, BitsPrc.nat32toNat8(x6 >> 24 & 0xff));

        o.put(20, BitsPrc.nat32toNat8(x7 >>  0 & 0xff));
        o.put(21, BitsPrc.nat32toNat8(x7 >>  8 & 0xff));
        o.put(22, BitsPrc.nat32toNat8(x7 >> 16 & 0xff));
        o.put(23, BitsPrc.nat32toNat8(x7 >> 24 & 0xff));

        o.put(24, BitsPrc.nat32toNat8(x8 >>  0 & 0xff));
        o.put(25, BitsPrc.nat32toNat8(x8 >>  8 & 0xff));
        o.put(26, BitsPrc.nat32toNat8(x8 >> 16 & 0xff));
        o.put(27, BitsPrc.nat32toNat8(x8 >> 24 & 0xff));

        o.put(28, BitsPrc.nat32toNat8(x9 >>  0 & 0xff));
        o.put(29, BitsPrc.nat32toNat8(x9 >>  8 & 0xff));
        o.put(30, BitsPrc.nat32toNat8(x9 >> 16 & 0xff));
        o.put(31, BitsPrc.nat32toNat8(x9 >> 24 & 0xff));
    };

    func crypto_core_salsa20(out : Buffer.Buffer<Nat8>, inp : [Nat8], k : [Nat8], c : [Nat8]) {
        core_salsa20(out, inp, k, c);
    };

    func crypto_core_hsalsa20(out : Buffer.Buffer<Nat8>, inp : [Nat8],k  : [Nat8], c  : [Nat8]) {
        core_hsalsa20(out, inp, k, c);
    };

    var sigma : [Nat8] = [101, 120, 112, 97, 110, 100, 32, 51, 50, 45, 98, 121, 116, 101, 32, 107];

    func crypto_stream_salsa20_xor(c : Buffer.Buffer<Nat8>, cposInput : Nat, m : [Nat8], mposInput : Nat, b : Nat, n : [Nat8], k : [Nat8]) : Nat {
        var z : Buffer.Buffer<Nat8> = Buffer.fromArray(Array.tabulate<Nat8>(16, func (i) {
                                                                if (i < 8) {
                                                                    n[i];
                                                                } else {
                                                                    0;
                                                                };
                                                            }));
        var x : Buffer.Buffer<Nat8> = Buffer.fromArray(Array.tabulate<Nat8>(64, func (i) {0}));
        var u : Nat32 = 0;
        var i = 0;
        var bIndex = b;
        var cpos = cposInput;
        var mpos = mposInput;
        while (bIndex >= 64) {
            crypto_core_salsa20(x, Buffer.toArray(z), k, sigma);
            i := 0;
            while (i < 64) {
                c.put(cpos + i, m[mpos+i] ^ x.get(i));
                i += 1;
            };
            u := 1;
            i := 8;
            while (i < 16) {
                u := u + BitsPrc.nat8toNat32(z.get(i) & 0xff) | 0;
                z.put(i, BitsPrc.nat32toNat8(u & 0xff));
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
                c.put(cpos + i, m[mpos+i] ^ x.get(i));
                i += 1;
            };
        };
        return 0;
    };

    func crypto_stream_salsa20(c : Buffer.Buffer<Nat8>, cpos : Nat, b : Nat, n : [Nat8], k : [Nat8]) : Nat8 {
        var z : Buffer.Buffer<Nat8> = Buffer.fromArray(Array.tabulate<Nat8>(16, func (i) {
                                                                                            if (i < 8) {
                                                                                                n[i];
                                                                                            } else {
                                                                                                0;
                                                                                            };
                                                                                        }));
        var x : Buffer.Buffer<Nat8> = Buffer.fromArray(Array.tabulate<Nat8>(64, func (i) {0}));
        var u : Nat32 = 0;
        var i = 0;
        var bIndex = b;
        var cposIndex = cpos;
        while (bIndex >= 64) {
            crypto_core_salsa20(x, Buffer.toArray(z), k, sigma);
            i := 0;
            while (i < 64) {
                c.put(cposIndex + i, x.get(i));
                i += 1;
            };
            u := 1;
            i := 8;
            while (i < 16) {
                u := u + BitsPrc.nat8toNat32(z.get(i) & 0xff) | 0;
                z.put(i, BitsPrc.nat32toNat8(u & 0xff));
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
                c.put(cposIndex + i, x.get(i));
                i += 1;
            };
        };
        return 0;
    };

    func crypto_stream(c : Buffer.Buffer<Nat8>,cpos : Nat, d : Nat,n : [Nat8],k : [Nat8]) : Nat8 {
        var s = Buffer.fromArray<Nat8>(Array.tabulate<Nat8>(32, func (i) {0}));
        crypto_core_hsalsa20(s, n, k, sigma);
        var sn = Array.tabulate<Nat8>(8, func (i) {n[i + 16]});
        return crypto_stream_salsa20(c, cpos, d, sn, Buffer.toArray(s));
    };
    
    func crypto_stream_xor(c : Buffer.Buffer<Nat8>, cpos : Nat, m : [Nat8], mpos : Nat, d : Nat, n : [Nat8], k : [Nat8]) : Nat {
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
        let r = Array.tabulateVar<Nat16>(10, func i = 0);
        let h = Array.tabulateVar<Nat16>(10, func i = 0);
        let pad = Array.tabulateVar<Nat16>(8, func i = 0);
        var leftover = 0;
        var fin = 0;

        var t0 : Nat16 = BitsPrc.nat8toNat16(key[ 0] & 0xff) | (BitsPrc.nat8toNat16(key[ 1] & 0xff) << 8); 
        r[0] := t0 & 0x1fff;
        var t1 : Nat16 = BitsPrc.nat8toNat16(key[ 2] & 0xff) | (BitsPrc.nat8toNat16(key[ 3] & 0xff) << 8); 
        r[1] := ((t0 >> 13) | (t1 <<  3)) & 0x1fff;
        var t2 : Nat16 = BitsPrc.nat8toNat16(key[ 4] & 0xff) | (BitsPrc.nat8toNat16(key[ 5] & 0xff) << 8);
        r[2] := ((t1 >> 10) | (t2 <<  6)) & 0x1f03;
        var t3 : Nat16 = BitsPrc.nat8toNat16(key[ 6] & 0xff) | (BitsPrc.nat8toNat16(key[ 7] & 0xff) << 8);
        r[3] := ((t2 >>  7) | (t3 <<  9)) & 0x1fff;
        var t4 : Nat16 = BitsPrc.nat8toNat16(key[ 8] & 0xff) | (BitsPrc.nat8toNat16(key[ 9] & 0xff) << 8);
        r[4] := ((t3 >>  4) | (t4 << 12)) & 0x00ff;
        r[5] := ((t4 >>  1)) & 0x1ffe;
        var t5 : Nat16 = BitsPrc.nat8toNat16(key[10] & 0xff) | (BitsPrc.nat8toNat16(key[11] & 0xff) << 8);
        r[6] := ((t4 >> 14) | (t5 << 2)) & 0x1fff;
        var t6 : Nat16 = BitsPrc.nat8toNat16(key[12] & 0xff) | (BitsPrc.nat8toNat16(key[13] & 0xff) << 8);
        r[7] := ((t5 >> 11) | (t6 <<  5)) & 0x1f81;
        var t7 : Nat16 = BitsPrc.nat8toNat16(key[14] & 0xff) | (BitsPrc.nat8toNat16(key[15] & 0xff) << 8);
        r[8] := ((t6 >>  8) | (t7 <<  8)) & 0x1fff;
        r[9] := ((t7 >>  5)) & 0x007f;

        pad[0] := BitsPrc.nat8toNat16(key[16] & 0xff) | (BitsPrc.nat8toNat16(key[17] & 0xff) << 8);
        pad[1] := BitsPrc.nat8toNat16(key[18] & 0xff) | (BitsPrc.nat8toNat16(key[19] & 0xff) << 8);
        pad[2] := BitsPrc.nat8toNat16(key[20] & 0xff) | (BitsPrc.nat8toNat16(key[21] & 0xff) << 8);
        pad[3] := BitsPrc.nat8toNat16(key[22] & 0xff) | (BitsPrc.nat8toNat16(key[23] & 0xff) << 8);
        pad[4] := BitsPrc.nat8toNat16(key[24] & 0xff) | (BitsPrc.nat8toNat16(key[25] & 0xff) << 8);
        pad[5] := BitsPrc.nat8toNat16(key[26] & 0xff) | (BitsPrc.nat8toNat16(key[27] & 0xff) << 8);
        pad[6] := BitsPrc.nat8toNat16(key[28] & 0xff) | (BitsPrc.nat8toNat16(key[29] & 0xff) << 8);
        pad[7] := BitsPrc.nat8toNat16(key[30] & 0xff) | (BitsPrc.nat8toNat16(key[31] & 0xff) << 8);

        private func blocks(m : [Nat8], mposInput : Nat, bytesInput : Nat) {
            var hibit : Nat16 = switch(fin) {
                case 0 {
                    (1 << 11);
                };
                case _ {
                    0;
                };
            };
            var mpos = mposInput;
            var bytes = bytesInput;

            var t0 : Nat16 = 0;
            var t1 : Nat16 = 0;
            var t2 : Nat16 = 0;
            var t3 : Nat16 = 0;
            var t4 : Nat16 = 0;
            var t5 : Nat16 = 0;
            var t6 : Nat16 = 0;
            var t7 : Nat16 = 0;
            var c : Nat16 = 0;

            var d0 : Nat16 = 0;
            var d1 : Nat16 = 0;
            var d2 : Nat16 = 0;
            var d3 : Nat16 = 0;
            var d4 : Nat16 = 0;
            var d5 : Nat16 = 0;
            var d6 : Nat16 = 0;
            var d7 : Nat16 = 0;
            var d8 : Nat16 = 0;
            var d9 : Nat16 = 0;

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
                t0 :=  BitsPrc.nat8toNat16(m[mpos+ 0] & 0xff) | (BitsPrc.nat8toNat16(m[mpos+ 1] & 0xff) << 8); 
                h0 += t0 & 0x1fff;
                t1 := BitsPrc.nat8toNat16(m[mpos+ 2] & 0xff) | (BitsPrc.nat8toNat16(m[mpos+ 3] & 0xff) << 8); 
                h1 += ((t0 >> 13) | (t1 <<  3)) & 0x1fff;
                t2 := BitsPrc.nat8toNat16(m[mpos+ 4] & 0xff) | (BitsPrc.nat8toNat16(m[mpos+ 5] & 0xff) << 8); 
                h2 += ((t1 >> 10) | (t2 <<  6)) & 0x1fff;
                t3 := BitsPrc.nat8toNat16(m[mpos+ 6] & 0xff) | (BitsPrc.nat8toNat16(m[mpos+ 7] & 0xff) << 8); 
                h3 += ((t2 >>  7) | (t3 <<  9)) & 0x1fff;
                t4 := BitsPrc.nat8toNat16(m[mpos+ 8] & 0xff) | (BitsPrc.nat8toNat16(m[mpos+ 9] & 0xff) << 8); 
                h4 += ((t3 >>  4) | (t4 << 12)) & 0x1fff;
                h5 += ((t4 >> 1)) & 0x1fff;
                t5 := BitsPrc.nat8toNat16(m[mpos+10] & 0xff) | (BitsPrc.nat8toNat16(m[mpos+11] & 0xff) << 8); 
                h6 += ((t4 >> 14) | (t5 <<  2)) & 0x1fff;
                t6 := BitsPrc.nat8toNat16(m[mpos+12] & 0xff) | (BitsPrc.nat8toNat16(m[mpos+13] & 0xff) << 8); 
                h7 += ((t5 >> 11) | (t6 <<  5)) & 0x1fff;
                t7 := BitsPrc.nat8toNat16(m[mpos+14] & 0xff) | (BitsPrc.nat8toNat16(m[mpos+15] & 0xff) << 8); 
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
            h[0] := h0;
            h[1] := h1;
            h[2] := h2;
            h[3] := h3;
            h[4] := h4;
            h[5] := h5;
            h[6] := h6;
            h[7] := h7;
            h[8] := h8;
            h[9] := h9;
        };

        public func finish(mac : Buffer.Buffer<Nat8>, macpos : Nat) {
            var g = Array.tabulateVar<Nat16>(10, func i = 0);
            var c : Nat16 = 0;
            // var mask : Int16 = 0;
            var mask : Nat16 = 0; // warning : mask may be Int16
            var f : Nat16 = 0;
            var i = 0;
            switch (leftover) {
                case 0 {

                };
                case _ {
                    i := leftover;
                    i += 1;
                    buffer[i] := 1;
                    while(i < 16) {
                        buffer[i] := 0;
                        i += 1;  
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

            // g[9] -= (1 << 13); // warning : agrithmetic overflow in motoko but javascript is ok
            g[9] := switch (g[9] & 0xe000) { // mask with 0xe000 because if (1110000000000000 & g[9]) != 0 => g[9] >= 0x1fff = g[9] >= (1 << 13) 
                case 0 { 0 };
                case _ {  g[9] - (1 << 13); };
            };

            mask := (c ^ 1) - 1;
            i := 0;
            while (i < 10) {
                g[i] &= mask;
                i += 1;
            };
            // mask = ~mask;
            mask := Nat16.bitnot(mask); // warning : take care in case mask is Int16? signed integer -> need more test case to confirm this
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

            mac.put(macpos+ 0, BitsPrc.nat16toNat8((h[0] >> 0) & 0xff));
            mac.put(macpos+ 1, BitsPrc.nat16toNat8((h[0] >> 8) & 0xff));
            mac.put(macpos+ 2, BitsPrc.nat16toNat8((h[1] >> 0) & 0xff));
            mac.put(macpos+ 3, BitsPrc.nat16toNat8((h[1] >> 8) & 0xff));
            mac.put(macpos+ 4, BitsPrc.nat16toNat8((h[2] >> 0) & 0xff));
            mac.put(macpos+ 5, BitsPrc.nat16toNat8((h[2] >> 8) & 0xff));
            mac.put(macpos+ 6, BitsPrc.nat16toNat8((h[3] >> 0) & 0xff));
            mac.put(macpos+ 7, BitsPrc.nat16toNat8((h[3] >> 8) & 0xff));
            mac.put(macpos+ 8, BitsPrc.nat16toNat8((h[4] >> 0) & 0xff));
            mac.put(macpos+ 9, BitsPrc.nat16toNat8((h[4] >> 8) & 0xff));
            mac.put(macpos+10, BitsPrc.nat16toNat8((h[5] >> 0) & 0xff));
            mac.put(macpos+11, BitsPrc.nat16toNat8((h[5] >> 8) & 0xff));
            mac.put(macpos+12, BitsPrc.nat16toNat8((h[6] >> 0) & 0xff));
            mac.put(macpos+13, BitsPrc.nat16toNat8((h[6] >> 8) & 0xff));
            mac.put(macpos+14, BitsPrc.nat16toNat8((h[7] >> 0) & 0xff));
            mac.put(macpos+15, BitsPrc.nat16toNat8((h[7] >> 8) & 0xff));
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
                        leftover += bytes;
                        i += 1;
                    };
                };
            };
        };

        // end class Poly1305
    };


    func crypto_onetimeauth(out : Buffer.Buffer<Nat8>, outpos : Nat, m : [Nat8], mpos : Nat, n : Nat, k : [Nat8]) : Int {
        let s = Poly1305(k);
        s.update(m, mpos, n);
        s.finish(out, outpos);
        return 0;
    };

    func crypto_onetimeauth_verify(h : [Nat8], hpos : Nat, m : [Nat8], mpos : Nat, n : Nat, k : [Nat8]) : Int {
        let x = Buffer.fromArray<Nat8>(Array.tabulate<Nat8>(16, func i = 0));
        ignore crypto_onetimeauth(x, 0, m, mpos, n, k);
        let rs = crypto_verify_16(h,hpos, Buffer.toArray(x), 0);
        return Nat8.toNat(rs);
    };

    func crypto_secretbox(c : Buffer.Buffer<Nat8>, m : [Nat8], d : Nat, n : [Nat8], k : [Nat8]) : Int {
        if (d < 32) return -1;
        ignore crypto_stream_xor(c, 0, m, 0, d, n, k);
        ignore crypto_onetimeauth(c, 16, Buffer.toArray(c), 32, d - 32, Buffer.toArray(c));
        for (i in Iter.range(0, c.size() - 1)) { c.put(i, 0) };
        return 0;
    };

    func crypto_secretbox_open(m : Buffer.Buffer<Nat8>, c : [Nat8], d : Nat, n : [Nat8], k : [Nat8]) : Int {
        var x = Buffer.fromArray<Nat8>(Array.tabulate<Nat8>(32, func i = 0));
        if (d < 32) return -1;
        ignore crypto_stream(x, 0, 32, n, k);
        if (crypto_onetimeauth_verify(c, 16, c, 32,d - 32, Buffer.toArray(x)) != 0) return -1;
        ignore crypto_stream_xor(m, 0, c, 0, d, n, k);
        for (i in Iter.range(0, 31)) m.put(i, 0);
        return 0;
    };
    
    func set25519(r : Buffer.Buffer<Int64>, a : [Int64]) {
        for (i in Iter.range(0, 15)) r.put(i, a[i] | 0);
    };

    // warning : this mod function need test
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

    func pack25519(o : Buffer.Buffer<Nat8>, n : [Int64]) {
        var b : Int64 = 0;
        var m = gf(null);
        var t = gf(null);
        for (i in Iter.range(0, 15)) t.put(i, n[i]);
        car25519(t);
        car25519(t);
        car25519(t);
        for (j in Iter.range(0, 1)) {
            m.put(0, t.get(0) - 0xffed);
            for (i in Iter.range(0, 14)) {
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
            o.put(2*i+1, BitsPrc.int64toNat8(t.get(i) >> 8));
        };
    };

    func neq25519(a : [Int64], b : [Int64]) : Nat8 {
        let c = Buffer.fromArray<Nat8>(Array.tabulate<Nat8>(32, func i = 0));
        var d = Buffer.fromArray<Nat8>(Array.tabulate<Nat8>(32, func i = 0));
        pack25519(c, a);
        pack25519(d, b);
        return crypto_verify_32(Buffer.toArray(c), 0, Buffer.toArray(d), 0);
    };

    func par25519(a : [Int64]) : Nat8 {
        var d = Buffer.fromArray<Nat8>(Array.tabulate<Nat8>(32, func i = 0));
        pack25519(d, a);
        return d.get(0) & 1;
    };

    func unpack25519(o : Buffer.Buffer<Int64>, n : [Nat8]) {
        for (i in Iter.range(0, 15)) o.put(i, BitsPrc.nat8toInt64(n[2*i]) + (BitsPrc.nat8toInt64(n[2*i+1]) << 8));
        o.put(15, o.get(15) & 0x7fff);
    };

    func A(o : Buffer.Buffer<Int64>, a : [Int64], b : [Int64]) {
        for (i in Iter.range(0, 15)) o.put(i, a[i] + b[i]);
    };

    func Z(o : Buffer.Buffer<Int64>, a : [Int64], b : [Int64]) {
        for (i in Iter.range(0, 15)) o.put(i, a[i] - b[i]);
    };

    func M(o : Buffer.Buffer<Int64>, a : [Int64], b : [Int64]) {
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

        var b0 = b[0];
        var b1 = b[1];
        var b2 = b[2];
        var b3 = b[3];
        var b4 = b[4];
        var b5 = b[5];
        var b6 = b[6];
        var b7 = b[7];
        var b8 = b[8];
        var b9 = b[9];
        var b10 = b[10];
        var b11 = b[11];
        var b12 = b[12];
        var b13 = b[13];
        var b14 = b[14];
        var b15 = b[15];

        var v : Int64 = a[0];
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
        v := a[1];
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
        v := a[2];
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
        v := a[3];
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
        v := a[4];
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
        v := a[5];
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
        v := a[6];
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
        v := a[7];
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
        v := a[8];
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
        v := a[9];
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
        v := a[10];
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
        v := a[11];
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
        v := a[12];
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
        v := a[13];
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
        v := a[14];
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
        v := a[15];
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

    func S(o : Buffer.Buffer<Int64>, a : [Int64]) {
        M(o, a, a);
    };

    func inv25519(o : Buffer.Buffer<Int64>, i : [Int64]) {
        var c = gf(null);
        for (a in Iter.range(0, 15)) c.put(a, i[a]);
        for (a in Iter.revRange(253, 0)) {
            S(c, Buffer.toArray(c));
            if(a != 2 and a != 4) M(c, Buffer.toArray(c), i);
        };
        for (a in Iter.range(0, 15)) o.put(a, c.get(a));
    };

    func pow2523(o : Buffer.Buffer<Int64>, i : [Int64]) {
        var c = gf(null);
        for (a in Iter.range(0, 15)) c.put(a, i[a]);
        for (a in Iter.revRange(250, 0)) {
            S(c, Buffer.toArray(c));
            if(a != 1) M(c, Buffer.toArray(c), i);
        };
        for (a in Iter.range(0, 15)) o.put(a, c.get(a));
    };

    func crypto_scalarmult(q : Buffer.Buffer<Nat8>, n : [Nat8], p : [Nat8]) : Int {
        let z = Array.tabulateVar<Nat8>(32, func i = 0);
        let x = Buffer.fromArray<Int64>(Array.tabulate<Int64>(80, func i = 0));
        let a = gf(null);
        let b = gf(null);
        let c = gf(null);
        let d = gf(null);
        let e = gf(null);
        let f = gf(null);
        for (i in Iter.range(0, 30)) z[i] := n[i];
        z[31] := (n[31]&127)|64;
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
            A(e, Buffer.toArray(a), Buffer.toArray(c));
            Z(a, Buffer.toArray(a), Buffer.toArray(c));
            A(c, Buffer.toArray(b), Buffer.toArray(d));
            Z(b, Buffer.toArray(b), Buffer.toArray(d));
            S(d, Buffer.toArray(e));
            S(f, Buffer.toArray(a));
            M(a, Buffer.toArray(c), Buffer.toArray(a));
            M(c, Buffer.toArray(b), Buffer.toArray(e));
            A(e, Buffer.toArray(a), Buffer.toArray(c));
            Z(a, Buffer.toArray(a), Buffer.toArray(c));
            S(b, Buffer.toArray(a));
            Z(c, Buffer.toArray(d), Buffer.toArray(f));
            M(a, Buffer.toArray(c),_121665);
            A(a, Buffer.toArray(a), Buffer.toArray(d));
            M(c, Buffer.toArray(c), Buffer.toArray(a));
            M(a, Buffer.toArray(d), Buffer.toArray(f));
            M(d, Buffer.toArray(b), Buffer.toArray(x));
            S(b, Buffer.toArray(e));
            sel25519(a,b,r);
            sel25519(c,d,r);
        };
        for (i in Iter.range(0, 15)) {
            x.put(i+16, a.get(i));
            x.put(i+32, c.get(i));
            x.put(i+48, b.get(i));
            x.put(i+64, d.get(i));
        };
        var x32 = Buffer.subBuffer<Int64>(x, 32, x.size() - 32);
        var x16 = Buffer.subBuffer<Int64>(x, 16, x.size() - 16);
        inv25519(x32, Buffer.toArray(x32));
        M(x16, Buffer.toArray(x16), Buffer.toArray(x32));
        pack25519(q, Buffer.toArray(x16));
        return 0;
    };

    func crypto_scalarmult_base(q : Buffer.Buffer<Nat8>, n : [Nat8]) : Int {
        return crypto_scalarmult(q, n, _9);
    };

    func randomBytes(byteNum : Nat) : [Nat8] {
        switch (randomBytesFuncShared) {
            case (?f) {
                f(byteNum);
            };
            case null {
                // process local
                [0, 0, 0, 0, 0];
            };
        };
    };

    func crypto_box_keypair(y : Buffer.Buffer<Nat8>, x : Buffer.Buffer<Nat8>) : Int {
        // let z = randombytes(32); // warning
        return crypto_scalarmult_base(y, Buffer.toArray(x));
    };

    func crypto_box_beforenm(k : Buffer.Buffer<Nat8>, y : [Nat8], x : [Nat8]) {
        var s = Buffer.fromArray<Nat8>(Array.tabulate<Nat8>(32, func i = 0));
        ignore crypto_scalarmult(s, x, y);
        return crypto_core_hsalsa20(k, _0, Buffer.toArray(s), sigma);
    };

    let crypto_box_afternm = crypto_secretbox;
    let crypto_box_open_afternm = crypto_secretbox_open;

    func crypto_box(c : Buffer.Buffer<Nat8>, m : [Nat8], d : Nat, n : [Nat8], y : [Nat8], x : [Nat8]) : Int {
        var k = Buffer.fromArray<Nat8>(Array.tabulate<Nat8>(32, func i = 0));
        crypto_box_beforenm(k, y, x);
        return crypto_box_afternm(c, m, d, n, Buffer.toArray(k));
    };

    func crypto_box_open(m : Buffer.Buffer<Nat8>, c : [Nat8], d : Nat, n : [Nat8], y : [Nat8], x : [Nat8]) : Int {
        var k = Buffer.fromArray<Nat8>(Array.tabulate<Nat8>(32, func i = 0));
        crypto_box_beforenm(k, y, x);
        return crypto_box_open_afternm(m, c, d, n, Buffer.toArray(k));
    };

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

    func crypto_hash(out : Buffer.Buffer<Nat8>, m : [Nat8], nInput : Nat) : Int {
        var x = Buffer.Buffer<Nat8>(256);
        
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
        ts64(x, n-8,  (Int32.fromNat32(Nat32.fromNat(b)) / 0x20000000) | 0, Int32.fromNat32(Nat32.fromNat(b) << 3)); // warning : test b value
        ignore crypto_hashblocks_hl(hh, hl, Buffer.toArray(x), n);

        for (i in Iter.range(0, 7)) {ts64(out, 8 * i, BitsPrc.int64toInt32(hh.get(i)), BitsPrc.int64toInt32(hl.get(i)))};

        return 0;
    };

    // warning : test
    func add(p : [Buffer.Buffer<Int64>], q : [Buffer.Buffer<Int64>]) {
        let a = gf(null); 
        let b = gf(null);
        let c = gf(null);
        let d = gf(null);
        let e = gf(null);
        let f = gf(null);
        let g = gf(null);
        let h = gf(null);
        let t = gf(null);

        Z(a, Buffer.toArray(p[1]), Buffer.toArray(p[0]));
        Z(t, Buffer.toArray(q[1]), Buffer.toArray(q[0]));
        M(a, Buffer.toArray(a), Buffer.toArray(t));
        A(b, Buffer.toArray(p[0]), Buffer.toArray(p[1]));
        A(t, Buffer.toArray(q[0]), Buffer.toArray(q[1]));
        M(b, Buffer.toArray(b), Buffer.toArray(t));
        M(c, Buffer.toArray(p[3]), Buffer.toArray(q[3]));
        M(c, Buffer.toArray(c), D2);
        M(d, Buffer.toArray(p[2]), Buffer.toArray(q[2]));
        A(d, Buffer.toArray(d), Buffer.toArray(d));
        Z(e, Buffer.toArray(b), Buffer.toArray(a));
        Z(f, Buffer.toArray(d), Buffer.toArray(c));
        A(g, Buffer.toArray(d), Buffer.toArray(c));
        A(h, Buffer.toArray(b), Buffer.toArray(a));

        M(p[0], Buffer.toArray(e), Buffer.toArray(f));
        M(p[1], Buffer.toArray(h), Buffer.toArray(g));
        M(p[2], Buffer.toArray(g), Buffer.toArray(f));
        M(p[3], Buffer.toArray(e), Buffer.toArray(h));
    };

    func cswap(p : [Buffer.Buffer<Int64>], q : [Buffer.Buffer<Int64>], b : Int64) {
        for (i in Iter.range(0, 3)) {
            sel25519(p[i], q[i], b);
        };
    };

    // warning : test
    func pack(r : Buffer.Buffer<Nat8>, p : [Buffer.Buffer<Int64>]) {
        var tx = gf(null);
        let ty = gf(null);
        let zi = gf(null);
        inv25519(zi, Buffer.toArray(p[2]));
        M(tx, Buffer.toArray(p[0]), Buffer.toArray(zi));
        M(ty, Buffer.toArray(p[1]), Buffer.toArray(zi));
        pack25519(r, Buffer.toArray(ty));
        r.put(31, r.get(31) ^ par25519(Buffer.toArray(tx)) << 7);
    };

    func scalarmult(p : [Buffer.Buffer<Int64>], q : [Buffer.Buffer<Int64>], s : [Nat8]) {
        set25519(p[0], gf0);
        set25519(p[1], gf1);
        set25519(p[2], gf1);
        set25519(p[3], gf0);
        for (i in Iter.revRange(255, 0)) {
            let b = (BitsPrc.nat8toInt64(s[Nat8.toNat((Nat8.fromNat(Int.abs(i))/8) | 0)]) >> (Int64.fromInt(i) & 7)) & 1;
            cswap(p, q, b);
            add(q, p);
            add(p, p);
            cswap(p, q, b);
        };
    };

    func scalarbase(p : [Buffer.Buffer<Int64>], s : [Nat8]) {
        var q = [gf(null), gf(null), gf(null), gf(null)];
        set25519(q[0], X);
        set25519(q[1], Y);
        set25519(q[2], gf1);
        M(q[3], X, Y);
        scalarmult(p, q, s);
    };

    func crypto_sign_keypair(pk : Buffer.Buffer<Nat8>, sk : Buffer.Buffer<Nat8>, seeded : Bool) : Int {
        var d = Buffer.fromArray<Nat8>(Array.tabulate<Nat8>(64, func i = 0));
        var p = [gf(null), gf(null), gf(null), gf(null)];

        // if (seeded == false) randombytes(sk, 32); // warning
        ignore crypto_hash(d, Buffer.toArray(sk), 32);
        d.put(0, d.get(0) & 248);
        d.put(31, d.get(31) & 127);
        d.put(31, d.get(31) | 64);

        scalarbase(p, Buffer.toArray(d));
        pack(pk, p);

        for (i in Iter.range(0, 31)) sk.put(i+32, pk.get(i));
        return 0;
    };

    let L : [Int64] = [0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10];
    // end module Nacl
};
