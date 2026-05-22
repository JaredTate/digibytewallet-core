//
//  BRBech32.h
//  breadwallet-core
//
//  Created by Aaron Voisine on 1/20/18.
//  Copyright (c) 2018 breadwallet LLC
//
//  Permission is hereby granted, free of charge, to any person obtaining a copy
//  of this software and associated documentation files (the "Software"), to deal
//  in the Software without restriction, including without limitation the rights
//  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//  copies of the Software, and to permit persons to whom the Software is
//  furnished to do so, subject to the following conditions:
//
//  The above copyright notice and this permission notice shall be included in
//  all copies or substantial portions of the Software.
//
//  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
//  THE SOFTWARE.

#ifndef BRBech32_h
#define BRBech32_h

#include <stddef.h>
#include <inttypes.h>

#ifdef __cplusplus
extern "C" {
#endif

// bech32 address format: https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki
// bech32m address format: https://github.com/bitcoin/bips/blob/master/bip-0350.mediawiki

typedef enum {
    BRBech32EncodingNone = 0,
    BRBech32EncodingBech32 = 1,
    BRBech32EncodingBech32m = 2
} BRBech32Encoding;

// returns the number of bytes written to data42 (maximum of 42)
size_t BRBech32Decode(char *hrp84, uint8_t *data42, const char *addr);

// returns the number of bytes written to data42 and writes the checksum encoding used by addr
size_t BRBech32DecodeEx(char *hrp84, uint8_t *data42, const char *addr, BRBech32Encoding *encoding);

// data must contain a valid BIP141 witness program
// returns the number of bytes written to addr91 (maximum of 91)
size_t BRBech32Encode(char *addr91, const char *hrp, const uint8_t data[]);

// data must contain a valid BIP141 witness program
// returns the number of bytes written to addr91 using the requested checksum encoding
size_t BRBech32EncodeEx(char *addr91, const char *hrp, const uint8_t data[], BRBech32Encoding encoding);

#ifdef __cplusplus
}
#endif

#endif // BRBech32_h
