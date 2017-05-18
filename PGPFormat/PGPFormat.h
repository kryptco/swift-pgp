//
//  PGPFormat.h
//  PGPFormat
//
//  Created by Alex Grinman on 5/15/17.
//  Copyright © 2017 KryptCo, Inc. All rights reserved.
//

#import <UIKit/UIKit.h>

//! Project version number for PGPFormat.
FOUNDATION_EXPORT double PGPFormatVersionNumber;

//! Project version string for PGPFormat.
FOUNDATION_EXPORT const unsigned char PGPFormatVersionString[];

// In this header, you should import all the public headers of your framework using statements like #import <PGPFormat/PublicHeader.h>



// CRC-24 Checksum
// https://tools.ietf.org/html/rfc4880
// section 6.1
#define CRC24_INIT 0xB704CEL
#define CRC24_POLY 0x1864CFBL

typedef long crc24;
crc24 crc_octets(unsigned char *octets, size_t len)
{
    crc24 crc = CRC24_INIT;
    int i;
    while (len--) {
        crc ^= (*octets++) << 16;
        for (i = 0; i < 8; i++) {
            crc <<= 1;
            if (crc & 0x1000000)
                crc ^= CRC24_POLY;
        }
    }
    return crc & 0xFFFFFFL;
}
