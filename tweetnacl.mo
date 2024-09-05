/****************************************************************************
* Copyright         : 2024 nirvana369
* File Name         : tweetnacl.mo
* Description       : This library is porting version of library tweetnacl.
*                    
* Revision History  :
* Date				Author    		Comments
* ---------------------------------------------------------------------------
* 08/31/2024		nirvana369 		Created.
* 09/02/2024		nirvana369 		Added core function.
*
*****************************************************************************/

import Float "mo:base/Float";
import Buffer "mo:base/Buffer";
import Array "mo:base/Array";
import Nat32 "mo:base/Nat32";
import Nat16 "mo:base/Nat16";
import Nat8 "mo:base/Nat8";

class TweetNaCl() {

    private func gf(init : ?[Float]) : Buffer.Buffer<Float> {
        let r = Buffer.Buffer<Float>(16);
        switch (init) {
            case (?arr) {
                for (i in arr.vals()) {
                    r.add(i);       
                };
            };
            case null {};
        };
        return r;
    };

    var randomBytes : ?(()->()) = null;

    public let setRandomBytesFunc = func (f : () -> ()) {
        randomBytes := ?f;
    };

    let _0 : [Nat8] = Array.tabulate<Nat8>(16, func (i) : Nat8 {0});
    let _9 : [Nat8] = Array.tabulate<Nat8>(32, func (i) : Nat8 {if (i == 0) { 9 } else 0});

    var gf0 = gf(null);
    var gf1 = gf(?[1]);
    var _121665 = gf(?[0xdb41, 1]);
    var D = gf(?[0x78a3, 0x1359, 0x4dca, 0x75eb, 0xd8ab, 0x4141, 0x0a4d, 0x0070, 0xe898, 0x7779, 0x4079, 0x8cc7, 0xfe73, 0x2b6f, 0x6cee, 0x5203]);
    var D2 = gf(?[0xf159, 0x26b2, 0x9b94, 0xebd6, 0xb156, 0x8283, 0x149a, 0x00e0, 0xd130, 0xeef3, 0x80f2, 0x198e, 0xfce7, 0x56df, 0xd9dc, 0x2406]);
    var X = gf(?[0xd51a, 0x8f25, 0x2d60, 0xc956, 0xa7b2, 0x9525, 0xc760, 0x692c, 0xdc5c, 0xfdd6, 0xe231, 0xc0a4, 0x53fe, 0xcd6e, 0x36d3, 0x2169]);
    var Y = gf(?[0x6658, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666]);
    var I = gf(?[0xa0b0, 0x4a0e, 0x1b27, 0xc4ee, 0xe478, 0xad2f, 0x1806, 0x2f43, 0xd7a7, 0x3dfb, 0x0099, 0x2b4d, 0xdf0b, 0x4fc1, 0x2480, 0x2b83]);

    module BitOrder {
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
    };

    func ts64(x : [var Nat8], i : Nat, h : Nat32, l : Nat32) {
        x[i]   := BitOrder.nat32toNat8((h >> 24) & 0xff);
        x[i+1] := BitOrder.nat32toNat8((h >> 16) & 0xff);
        x[i+2] := BitOrder.nat32toNat8((h >>  8) & 0xff);
        x[i+3] := BitOrder.nat32toNat8(h & 0xff);
        x[i+4] := BitOrder.nat32toNat8((l >> 24)  & 0xff);
        x[i+5] := BitOrder.nat32toNat8((l >> 16)  & 0xff);
        x[i+6] := BitOrder.nat32toNat8((l >>  8)  & 0xff);
        x[i+7] := BitOrder.nat32toNat8(l & 0xff);
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

    func core_salsa20(o : [var Nat8], p : [Nat8], k : [Nat8], c : [Nat8]) {
        var j0  = BitOrder.nat8toNat32(c[ 0] & 0xff) | (BitOrder.nat8toNat32(c[ 1] & 0xff)<<8) | (BitOrder.nat8toNat32(c[ 2] & 0xff)<<16) | (BitOrder.nat8toNat32(c[ 3] & 0xff)<<24);
        var j1  = BitOrder.nat8toNat32(k[ 0] & 0xff) | (BitOrder.nat8toNat32(k[ 1] & 0xff)<<8) | (BitOrder.nat8toNat32(k[ 2] & 0xff)<<16) | (BitOrder.nat8toNat32(k[ 3] & 0xff)<<24);
        var j2  = BitOrder.nat8toNat32(k[ 4] & 0xff) | (BitOrder.nat8toNat32(k[ 5] & 0xff)<<8) | (BitOrder.nat8toNat32(k[ 6] & 0xff)<<16) | (BitOrder.nat8toNat32(k[ 7] & 0xff)<<24);
        var j3  = BitOrder.nat8toNat32(k[ 8] & 0xff) | (BitOrder.nat8toNat32(k[ 9] & 0xff)<<8) | (BitOrder.nat8toNat32(k[10] & 0xff)<<16) | (BitOrder.nat8toNat32(k[11] & 0xff)<<24);
        var j4  = BitOrder.nat8toNat32(k[12] & 0xff) | (BitOrder.nat8toNat32(k[13] & 0xff)<<8) | (BitOrder.nat8toNat32(k[14] & 0xff)<<16) | (BitOrder.nat8toNat32(k[15] & 0xff)<<24);
        var j5  = BitOrder.nat8toNat32(c[ 4] & 0xff) | (BitOrder.nat8toNat32(c[ 5] & 0xff)<<8) | (BitOrder.nat8toNat32(c[ 6] & 0xff)<<16) | (BitOrder.nat8toNat32(c[ 7] & 0xff)<<24);
        var j6  = BitOrder.nat8toNat32(p[ 0] & 0xff) | (BitOrder.nat8toNat32(p[ 1] & 0xff)<<8) | (BitOrder.nat8toNat32(p[ 2] & 0xff)<<16) | (BitOrder.nat8toNat32(p[ 3] & 0xff)<<24);
        var j7  = BitOrder.nat8toNat32(p[ 4] & 0xff) | (BitOrder.nat8toNat32(p[ 5] & 0xff)<<8) | (BitOrder.nat8toNat32(p[ 6] & 0xff)<<16) | (BitOrder.nat8toNat32(p[ 7] & 0xff)<<24);
        var j8  = BitOrder.nat8toNat32(p[ 8] & 0xff) | (BitOrder.nat8toNat32(p[ 9] & 0xff)<<8) | (BitOrder.nat8toNat32(p[10] & 0xff)<<16) | (BitOrder.nat8toNat32(p[11] & 0xff)<<24);
        var j9  = BitOrder.nat8toNat32(p[12] & 0xff) | (BitOrder.nat8toNat32(p[13] & 0xff)<<8) | (BitOrder.nat8toNat32(p[14] & 0xff)<<16) | (BitOrder.nat8toNat32(p[15] & 0xff)<<24);
        var j10 = BitOrder.nat8toNat32(c[ 8] & 0xff) | (BitOrder.nat8toNat32(c[ 9] & 0xff)<<8) | (BitOrder.nat8toNat32(c[10] & 0xff)<<16) | (BitOrder.nat8toNat32(c[11] & 0xff)<<24);
        var j11 = BitOrder.nat8toNat32(k[16] & 0xff) | (BitOrder.nat8toNat32(k[17] & 0xff)<<8) | (BitOrder.nat8toNat32(k[18] & 0xff)<<16) | (BitOrder.nat8toNat32(k[19] & 0xff)<<24);
        var j12 = BitOrder.nat8toNat32(k[20] & 0xff) | (BitOrder.nat8toNat32(k[21] & 0xff)<<8) | (BitOrder.nat8toNat32(k[22] & 0xff)<<16) | (BitOrder.nat8toNat32(k[23] & 0xff)<<24);
        var j13 = BitOrder.nat8toNat32(k[24] & 0xff) | (BitOrder.nat8toNat32(k[25] & 0xff)<<8) | (BitOrder.nat8toNat32(k[26] & 0xff)<<16) | (BitOrder.nat8toNat32(k[27] & 0xff)<<24);
        var j14 = BitOrder.nat8toNat32(k[28] & 0xff) | (BitOrder.nat8toNat32(k[29] & 0xff)<<8) | (BitOrder.nat8toNat32(k[30] & 0xff)<<16) | (BitOrder.nat8toNat32(k[31] & 0xff)<<24);
        var j15 = BitOrder.nat8toNat32(c[12] & 0xff) | (BitOrder.nat8toNat32(c[13] & 0xff)<<8) | (BitOrder.nat8toNat32(c[14] & 0xff)<<16) | (BitOrder.nat8toNat32(c[15] & 0xff)<<24);

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

        o[ 0] := BitOrder.nat32toNat8(x0 >>  0 & 0xff);
        o[ 1] := BitOrder.nat32toNat8(x0 >>  8 & 0xff);
        o[ 2] := BitOrder.nat32toNat8(x0 >> 16 & 0xff);
        o[ 3] := BitOrder.nat32toNat8(x0 >> 24 & 0xff);

        o[ 4] := BitOrder.nat32toNat8(x1 >>  0 & 0xff);
        o[ 5] := BitOrder.nat32toNat8(x1 >>  8 & 0xff);
        o[ 6] := BitOrder.nat32toNat8(x1 >> 16 & 0xff);
        o[ 7] := BitOrder.nat32toNat8(x1 >> 24 & 0xff);

        o[ 8] := BitOrder.nat32toNat8(x2 >>  0 & 0xff);
        o[ 9] := BitOrder.nat32toNat8(x2 >>  8 & 0xff);
        o[10] := BitOrder.nat32toNat8(x2 >> 16 & 0xff);
        o[11] := BitOrder.nat32toNat8(x2 >> 24 & 0xff);

        o[12] := BitOrder.nat32toNat8(x3 >>  0 & 0xff);
        o[13] := BitOrder.nat32toNat8(x3 >>  8 & 0xff);
        o[14] := BitOrder.nat32toNat8(x3 >> 16 & 0xff);
        o[15] := BitOrder.nat32toNat8(x3 >> 24 & 0xff);

        o[16] := BitOrder.nat32toNat8(x4 >>  0 & 0xff);
        o[17] := BitOrder.nat32toNat8(x4 >>  8 & 0xff);
        o[18] := BitOrder.nat32toNat8(x4 >> 16 & 0xff);
        o[19] := BitOrder.nat32toNat8(x4 >> 24 & 0xff);

        o[20] := BitOrder.nat32toNat8(x5 >>  0 & 0xff);
        o[21] := BitOrder.nat32toNat8(x5 >>  8 & 0xff);
        o[22] := BitOrder.nat32toNat8(x5 >> 16 & 0xff);
        o[23] := BitOrder.nat32toNat8(x5 >> 24 & 0xff);

        o[24] := BitOrder.nat32toNat8(x6 >>  0 & 0xff);
        o[25] := BitOrder.nat32toNat8(x6 >>  8 & 0xff);
        o[26] := BitOrder.nat32toNat8(x6 >> 16 & 0xff);
        o[27] := BitOrder.nat32toNat8(x6 >> 24 & 0xff);

        o[28] := BitOrder.nat32toNat8(x7 >>  0 & 0xff);
        o[29] := BitOrder.nat32toNat8(x7 >>  8 & 0xff);
        o[30] := BitOrder.nat32toNat8(x7 >> 16 & 0xff);
        o[31] := BitOrder.nat32toNat8(x7 >> 24 & 0xff);

        o[32] := BitOrder.nat32toNat8(x8 >>  0 & 0xff);
        o[33] := BitOrder.nat32toNat8(x8 >>  8 & 0xff);
        o[34] := BitOrder.nat32toNat8(x8 >> 16 & 0xff);
        o[35] := BitOrder.nat32toNat8(x8 >> 24 & 0xff);

        o[36] := BitOrder.nat32toNat8(x9 >>  0 & 0xff);
        o[37] := BitOrder.nat32toNat8(x9 >>  8 & 0xff);
        o[38] := BitOrder.nat32toNat8(x9 >> 16 & 0xff);
        o[39] := BitOrder.nat32toNat8(x9 >> 24 & 0xff);

        o[40] := BitOrder.nat32toNat8(x10 >>  0 & 0xff);
        o[41] := BitOrder.nat32toNat8(x10 >>  8 & 0xff);
        o[42] := BitOrder.nat32toNat8(x10 >> 16 & 0xff);
        o[43] := BitOrder.nat32toNat8(x10 >> 24 & 0xff);

        o[44] := BitOrder.nat32toNat8(x11 >>  0 & 0xff);
        o[45] := BitOrder.nat32toNat8(x11 >>  8 & 0xff);
        o[46] := BitOrder.nat32toNat8(x11 >> 16 & 0xff);
        o[47] := BitOrder.nat32toNat8(x11 >> 24 & 0xff);

        o[48] := BitOrder.nat32toNat8(x12 >>  0 & 0xff);
        o[49] := BitOrder.nat32toNat8(x12 >>  8 & 0xff);
        o[50] := BitOrder.nat32toNat8(x12 >> 16 & 0xff);
        o[51] := BitOrder.nat32toNat8(x12 >> 24 & 0xff);

        o[52] := BitOrder.nat32toNat8(x13 >>  0 & 0xff);
        o[53] := BitOrder.nat32toNat8(x13 >>  8 & 0xff);
        o[54] := BitOrder.nat32toNat8(x13 >> 16 & 0xff);
        o[55] := BitOrder.nat32toNat8(x13 >> 24 & 0xff);

        o[56] := BitOrder.nat32toNat8(x14 >>  0 & 0xff);
        o[57] := BitOrder.nat32toNat8(x14 >>  8 & 0xff);
        o[58] := BitOrder.nat32toNat8(x14 >> 16 & 0xff);
        o[59] := BitOrder.nat32toNat8(x14 >> 24 & 0xff);

        o[60] := BitOrder.nat32toNat8(x15 >>  0 & 0xff);
        o[61] := BitOrder.nat32toNat8(x15 >>  8 & 0xff);
        o[62] := BitOrder.nat32toNat8(x15 >> 16 & 0xff);
        o[63] := BitOrder.nat32toNat8(x15 >> 24 & 0xff);
    };

    func core_hsalsa20(o : [var Nat8], p : [Nat8], k : [Nat8], c : [Nat8]) {
        var j0  = BitOrder.nat8toNat32(c[ 0] & 0xff) | (BitOrder.nat8toNat32(c[ 1] & 0xff)<<8) | (BitOrder.nat8toNat32(c[ 2] & 0xff)<<16) | (BitOrder.nat8toNat32(c[ 3] & 0xff)<<24);
        var j1  = BitOrder.nat8toNat32(k[ 0] & 0xff) | (BitOrder.nat8toNat32(k[ 1] & 0xff)<<8) | (BitOrder.nat8toNat32(k[ 2] & 0xff)<<16) | (BitOrder.nat8toNat32(k[ 3] & 0xff)<<24);
        var j2  = BitOrder.nat8toNat32(k[ 4] & 0xff) | (BitOrder.nat8toNat32(k[ 5] & 0xff)<<8) | (BitOrder.nat8toNat32(k[ 6] & 0xff)<<16) | (BitOrder.nat8toNat32(k[ 7] & 0xff)<<24);
        var j3  = BitOrder.nat8toNat32(k[ 8] & 0xff) | (BitOrder.nat8toNat32(k[ 9] & 0xff)<<8) | (BitOrder.nat8toNat32(k[10] & 0xff)<<16) | (BitOrder.nat8toNat32(k[11] & 0xff)<<24);
        var j4  = BitOrder.nat8toNat32(k[12] & 0xff) | (BitOrder.nat8toNat32(k[13] & 0xff)<<8) | (BitOrder.nat8toNat32(k[14] & 0xff)<<16) | (BitOrder.nat8toNat32(k[15] & 0xff)<<24);
        var j5  = BitOrder.nat8toNat32(c[ 4] & 0xff) | (BitOrder.nat8toNat32(c[ 5] & 0xff)<<8) | (BitOrder.nat8toNat32(c[ 6] & 0xff)<<16) | (BitOrder.nat8toNat32(c[ 7] & 0xff)<<24);
        var j6  = BitOrder.nat8toNat32(p[ 0] & 0xff) | (BitOrder.nat8toNat32(p[ 1] & 0xff)<<8) | (BitOrder.nat8toNat32(p[ 2] & 0xff)<<16) | (BitOrder.nat8toNat32(p[ 3] & 0xff)<<24);
        var j7  = BitOrder.nat8toNat32(p[ 4] & 0xff) | (BitOrder.nat8toNat32(p[ 5] & 0xff)<<8) | (BitOrder.nat8toNat32(p[ 6] & 0xff)<<16) | (BitOrder.nat8toNat32(p[ 7] & 0xff)<<24);
        var j8  = BitOrder.nat8toNat32(p[ 8] & 0xff) | (BitOrder.nat8toNat32(p[ 9] & 0xff)<<8) | (BitOrder.nat8toNat32(p[10] & 0xff)<<16) | (BitOrder.nat8toNat32(p[11] & 0xff)<<24);
        var j9  = BitOrder.nat8toNat32(p[12] & 0xff) | (BitOrder.nat8toNat32(p[13] & 0xff)<<8) | (BitOrder.nat8toNat32(p[14] & 0xff)<<16) | (BitOrder.nat8toNat32(p[15] & 0xff)<<24);
        var j10 = BitOrder.nat8toNat32(c[ 8] & 0xff) | (BitOrder.nat8toNat32(c[ 9] & 0xff)<<8) | (BitOrder.nat8toNat32(c[10] & 0xff)<<16) | (BitOrder.nat8toNat32(c[11] & 0xff)<<24);
        var j11 = BitOrder.nat8toNat32(k[16] & 0xff) | (BitOrder.nat8toNat32(k[17] & 0xff)<<8) | (BitOrder.nat8toNat32(k[18] & 0xff)<<16) | (BitOrder.nat8toNat32(k[19] & 0xff)<<24);
        var j12 = BitOrder.nat8toNat32(k[20] & 0xff) | (BitOrder.nat8toNat32(k[21] & 0xff)<<8) | (BitOrder.nat8toNat32(k[22] & 0xff)<<16) | (BitOrder.nat8toNat32(k[23] & 0xff)<<24);
        var j13 = BitOrder.nat8toNat32(k[24] & 0xff) | (BitOrder.nat8toNat32(k[25] & 0xff)<<8) | (BitOrder.nat8toNat32(k[26] & 0xff)<<16) | (BitOrder.nat8toNat32(k[27] & 0xff)<<24);
        var j14 = BitOrder.nat8toNat32(k[28] & 0xff) | (BitOrder.nat8toNat32(k[29] & 0xff)<<8) | (BitOrder.nat8toNat32(k[30] & 0xff)<<16) | (BitOrder.nat8toNat32(k[31] & 0xff)<<24);
        var j15 = BitOrder.nat8toNat32(c[12] & 0xff) | (BitOrder.nat8toNat32(c[13] & 0xff)<<8) | (BitOrder.nat8toNat32(c[14] & 0xff)<<16) | (BitOrder.nat8toNat32(c[15] & 0xff)<<24);

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

        o[ 0] := BitOrder.nat32toNat8(x0 >>  0 & 0xff);
        o[ 1] := BitOrder.nat32toNat8(x0 >>  8 & 0xff);
        o[ 2] := BitOrder.nat32toNat8(x0 >> 16 & 0xff);
        o[ 3] := BitOrder.nat32toNat8(x0 >> 24 & 0xff);

        o[ 4] := BitOrder.nat32toNat8(x5 >>  0 & 0xff);
        o[ 5] := BitOrder.nat32toNat8(x5 >>  8 & 0xff);
        o[ 6] := BitOrder.nat32toNat8(x5 >> 16 & 0xff);
        o[ 7] := BitOrder.nat32toNat8(x5 >> 24 & 0xff);

        o[ 8] := BitOrder.nat32toNat8(x10 >>  0 & 0xff);
        o[ 9] := BitOrder.nat32toNat8(x10 >>  8 & 0xff);
        o[10] := BitOrder.nat32toNat8(x10 >> 16 & 0xff);
        o[11] := BitOrder.nat32toNat8(x10 >> 24 & 0xff);

        o[12] := BitOrder.nat32toNat8(x15 >>  0 & 0xff);
        o[13] := BitOrder.nat32toNat8(x15 >>  8 & 0xff);
        o[14] := BitOrder.nat32toNat8(x15 >> 16 & 0xff);
        o[15] := BitOrder.nat32toNat8(x15 >> 24 & 0xff);

        o[16] := BitOrder.nat32toNat8(x6 >>  0 & 0xff);
        o[17] := BitOrder.nat32toNat8(x6 >>  8 & 0xff);
        o[18] := BitOrder.nat32toNat8(x6 >> 16 & 0xff);
        o[19] := BitOrder.nat32toNat8(x6 >> 24 & 0xff);

        o[20] := BitOrder.nat32toNat8(x7 >>  0 & 0xff);
        o[21] := BitOrder.nat32toNat8(x7 >>  8 & 0xff);
        o[22] := BitOrder.nat32toNat8(x7 >> 16 & 0xff);
        o[23] := BitOrder.nat32toNat8(x7 >> 24 & 0xff);

        o[24] := BitOrder.nat32toNat8(x8 >>  0 & 0xff);
        o[25] := BitOrder.nat32toNat8(x8 >>  8 & 0xff);
        o[26] := BitOrder.nat32toNat8(x8 >> 16 & 0xff);
        o[27] := BitOrder.nat32toNat8(x8 >> 24 & 0xff);

        o[28] := BitOrder.nat32toNat8(x9 >>  0 & 0xff);
        o[29] := BitOrder.nat32toNat8(x9 >>  8 & 0xff);
        o[30] := BitOrder.nat32toNat8(x9 >> 16 & 0xff);
        o[31] := BitOrder.nat32toNat8(x9 >> 24 & 0xff);
    };

    func crypto_core_salsa20(out : [var Nat8], inp : [Nat8], k : [Nat8], c : [Nat8]) {
        core_salsa20(out, inp, k, c);
    };

    func crypto_core_hsalsa20(out : [var Nat8], inp : [Nat8],k  : [Nat8], c  : [Nat8]) {
        core_hsalsa20(out, inp, k, c);
    };

    var sigma : [Nat8] = [101, 120, 112, 97, 110, 100, 32, 51, 50, 45, 98, 121, 116, 101, 32, 107];

    func crypto_stream_salsa20_xor(c : [var Nat8], cpos : Nat, m : [Nat8], mpos : Nat, b : Nat, n : [Nat8], k : [Nat8]) : Nat8 {
        var z : [var Nat8] = Array.tabulateVar<Nat8>(16, func (i) {0});
        var x : [var Nat8] = Array.tabulateVar<Nat8>(64, func (i) {
                                                                    if (i < 8) {
                                                                        n[i];
                                                                    } else {
                                                                        0;
                                                                    };
                                                                });
        var u : Nat32 = 0;
        var i = 0;
        var bIndex = b;
        var cposIndex = cpos;
        var mposIndex = mpos;
        while (bIndex >= 64) {
            crypto_core_salsa20(x, Array.freeze(z), k, sigma);
            i := 0;
            while (i < 64) {
                c[cposIndex+i] := m[mposIndex+i] ^ x[i];
                i += 1;
            };
            u := 1;
            i := 8;
            while (i < 16) {
                u := u + BitOrder.nat8toNat32(z[i] & 0xff) | 0;
                z[i] := BitOrder.nat32toNat8(u & 0xff);
                u >>= 8;
                i += 1;
            };
            bIndex -= 64;
            cposIndex += 64;
            mposIndex += 64;
        };
        if (bIndex > 0) {
            crypto_core_salsa20(x, Array.freeze(z), k, sigma);
            i := 0;
            while (i < bIndex) {
                c[cposIndex+i] := m[mposIndex+i] ^ x[i];
                i += 1;
            };
        };
        return 0;
    };

    func crypto_stream_salsa20(c : [var Nat8], cpos : Nat, b : Nat, n : [Nat8], k : [Nat8]) : Nat8 {
        var z : [var Nat8] = Array.tabulateVar<Nat8>(16, func (i) {0});
        var x : [var Nat8] = Array.tabulateVar<Nat8>(64, func (i) {
                                                                    if (i < 8) {
                                                                        n[i];
                                                                    } else {
                                                                        0;
                                                                    };
                                                                });
        var u : Nat32 = 0;
        var i = 0;
        var bIndex = b;
        var cposIndex = cpos;
        while (bIndex >= 64) {
            crypto_core_salsa20(x, Array.freeze(z), k, sigma);
            i := 0;
            while (i < 64) {
                c[cposIndex+i] := x[i];
                i += 1;
            };
            u := 1;
            i := 8;
            while (i < 16) {
                u := u + BitOrder.nat8toNat32(z[i] & 0xff) | 0;
                z[i] := BitOrder.nat32toNat8(u & 0xff);
                u >>= 8;
                i += 1;
            };
            bIndex -= 64;
            cposIndex += 64;
        };
        if (bIndex > 0) {
            crypto_core_salsa20(x, Array.freeze(z), k, sigma);
            i := 0;
            while (i < bIndex) {
                c[cposIndex + i] := x[i];
                i += 1;
            };
        };
        return 0;
    };

    func crypto_stream(c : [var Nat8],cpos : Nat, d : Nat,n : [Nat8],k : [Nat8]) : Nat8 {
        var s = Array.tabulateVar<Nat8>(32, func (i) {0});
        crypto_core_hsalsa20(s, n, k, sigma);
        var sn = Array.tabulate<Nat8>(8, func (i) {n[i + 16]});
        return crypto_stream_salsa20(c, cpos, d, sn, Array.freeze(s));
    };
    
    func crypto_stream_xor(c : [var Nat8], cpos : Nat, m : [Nat8], mpos : Nat,d : Nat,n : [Nat8],k : [Nat8]) : Nat8 {
        var s = Array.tabulateVar<Nat8>(32, func (i) {0});
        crypto_core_hsalsa20(s, n, k, sigma);
        var sn = Array.tabulate<Nat8>(8, func (i) {n[i + 16]});
        return crypto_stream_salsa20_xor(c, cpos, m, mpos, d, sn, Array.freeze(s));
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

        var t0 : Nat16 = BitOrder.nat8toNat16(key[ 0] & 0xff) | (BitOrder.nat8toNat16(key[ 1] & 0xff) << 8); 
        r[0] := t0 & 0x1fff;
        var t1 : Nat16 = BitOrder.nat8toNat16(key[ 2] & 0xff) | (BitOrder.nat8toNat16(key[ 3] & 0xff) << 8); 
        r[1] := ((t0 >> 13) | (t1 <<  3)) & 0x1fff;
        var t2 : Nat16 = BitOrder.nat8toNat16(key[ 4] & 0xff) | (BitOrder.nat8toNat16(key[ 5] & 0xff) << 8);
        r[2] := ((t1 >> 10) | (t2 <<  6)) & 0x1f03;
        var t3 : Nat16 = BitOrder.nat8toNat16(key[ 6] & 0xff) | (BitOrder.nat8toNat16(key[ 7] & 0xff) << 8);
        r[3] := ((t2 >>  7) | (t3 <<  9)) & 0x1fff;
        var t4 : Nat16 = BitOrder.nat8toNat16(key[ 8] & 0xff) | (BitOrder.nat8toNat16(key[ 9] & 0xff) << 8);
        r[4] := ((t3 >>  4) | (t4 << 12)) & 0x00ff;
        r[5] := ((t4 >>  1)) & 0x1ffe;
        var t5 : Nat16 = BitOrder.nat8toNat16(key[10] & 0xff) | (BitOrder.nat8toNat16(key[11] & 0xff) << 8);
        r[6] := ((t4 >> 14) | (t5 << 2)) & 0x1fff;
        var t6 : Nat16 = BitOrder.nat8toNat16(key[12] & 0xff) | (BitOrder.nat8toNat16(key[13] & 0xff) << 8);
        r[7] := ((t5 >> 11) | (t6 <<  5)) & 0x1f81;
        var t7 : Nat16 = BitOrder.nat8toNat16(key[14] & 0xff) | (BitOrder.nat8toNat16(key[15] & 0xff) << 8);
        r[8] := ((t6 >>  8) | (t7 <<  8)) & 0x1fff;
        r[9] := ((t7 >>  5)) & 0x007f;

        pad[0] := BitOrder.nat8toNat16(key[16] & 0xff) | (BitOrder.nat8toNat16(key[17] & 0xff) << 8);
        pad[1] := BitOrder.nat8toNat16(key[18] & 0xff) | (BitOrder.nat8toNat16(key[19] & 0xff) << 8);
        pad[2] := BitOrder.nat8toNat16(key[20] & 0xff) | (BitOrder.nat8toNat16(key[21] & 0xff) << 8);
        pad[3] := BitOrder.nat8toNat16(key[22] & 0xff) | (BitOrder.nat8toNat16(key[23] & 0xff) << 8);
        pad[4] := BitOrder.nat8toNat16(key[24] & 0xff) | (BitOrder.nat8toNat16(key[25] & 0xff) << 8);
        pad[5] := BitOrder.nat8toNat16(key[26] & 0xff) | (BitOrder.nat8toNat16(key[27] & 0xff) << 8);
        pad[6] := BitOrder.nat8toNat16(key[28] & 0xff) | (BitOrder.nat8toNat16(key[29] & 0xff) << 8);
        pad[7] := BitOrder.nat8toNat16(key[30] & 0xff) | (BitOrder.nat8toNat16(key[31] & 0xff) << 8);

        private func blocks(m : [var Nat8], mposInput : Nat, bytesInput : Nat) {
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
                t0 :=  BitOrder.nat8toNat16(m[mpos+ 0] & 0xff) | (BitOrder.nat8toNat16(m[mpos+ 1] & 0xff) << 8); 
                h0 += t0 & 0x1fff;
                t1 := BitOrder.nat8toNat16(m[mpos+ 2] & 0xff) | (BitOrder.nat8toNat16(m[mpos+ 3] & 0xff) << 8); 
                h1 += ((t0 >> 13) | (t1 <<  3)) & 0x1fff;
                t2 := BitOrder.nat8toNat16(m[mpos+ 4] & 0xff) | (BitOrder.nat8toNat16(m[mpos+ 5] & 0xff) << 8); 
                h2 += ((t1 >> 10) | (t2 <<  6)) & 0x1fff;
                t3 := BitOrder.nat8toNat16(m[mpos+ 6] & 0xff) | (BitOrder.nat8toNat16(m[mpos+ 7] & 0xff) << 8); 
                h3 += ((t2 >>  7) | (t3 <<  9)) & 0x1fff;
                t4 := BitOrder.nat8toNat16(m[mpos+ 8] & 0xff) | (BitOrder.nat8toNat16(m[mpos+ 9] & 0xff) << 8); 
                h4 += ((t3 >>  4) | (t4 << 12)) & 0x1fff;
                h5 += ((t4 >> 1)) & 0x1fff;
                t5 := BitOrder.nat8toNat16(m[mpos+10] & 0xff) | (BitOrder.nat8toNat16(m[mpos+11] & 0xff) << 8); 
                h6 += ((t4 >> 14) | (t5 <<  2)) & 0x1fff;
                t6 := BitOrder.nat8toNat16(m[mpos+12] & 0xff) | (BitOrder.nat8toNat16(m[mpos+13] & 0xff) << 8); 
                h7 += ((t5 >> 11) | (t6 <<  5)) & 0x1fff;
                t7 := BitOrder.nat8toNat16(m[mpos+14] & 0xff) | (BitOrder.nat8toNat16(m[mpos+15] & 0xff) << 8); 
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

        public func finish(mac : [var Nat8], macpos : Nat) {
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
                    blocks(buffer, 0, 16);
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

            // mask := ~mask;
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

            mac[macpos+ 0] := BitOrder.nat16toNat8((h[0] >> 0) & 0xff);
            mac[macpos+ 1] := BitOrder.nat16toNat8((h[0] >> 8) & 0xff);
            mac[macpos+ 2] := BitOrder.nat16toNat8((h[1] >> 0) & 0xff);
            mac[macpos+ 3] := BitOrder.nat16toNat8((h[1] >> 8) & 0xff);
            mac[macpos+ 4] := BitOrder.nat16toNat8((h[2] >> 0) & 0xff);
            mac[macpos+ 5] := BitOrder.nat16toNat8((h[2] >> 8) & 0xff);
            mac[macpos+ 6] := BitOrder.nat16toNat8((h[3] >> 0) & 0xff);
            mac[macpos+ 7] := BitOrder.nat16toNat8((h[3] >> 8) & 0xff);
            mac[macpos+ 8] := BitOrder.nat16toNat8((h[4] >> 0) & 0xff);
            mac[macpos+ 9] := BitOrder.nat16toNat8((h[4] >> 8) & 0xff);
            mac[macpos+10] := BitOrder.nat16toNat8((h[5] >> 0) & 0xff);
            mac[macpos+11] := BitOrder.nat16toNat8((h[5] >> 8) & 0xff);
            mac[macpos+12] := BitOrder.nat16toNat8((h[6] >> 0) & 0xff);
            mac[macpos+13] := BitOrder.nat16toNat8((h[6] >> 8) & 0xff);
            mac[macpos+14] := BitOrder.nat16toNat8((h[7] >> 0) & 0xff);
            mac[macpos+15] := BitOrder.nat16toNat8((h[7] >> 8) & 0xff);
        };

        public func update(m : [var Nat8], mposInput : Nat, bytesInput : Nat) {
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
                    blocks(buffer, 0, 16);
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

    // end module Nacl
};
