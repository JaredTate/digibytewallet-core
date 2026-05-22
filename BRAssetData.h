//
//  BRAssetData.h
//  DigiByte
//
//  Created by Yoshi Jaeger on 05.10.19.
//  Copyright © 2019 DigiByte Foundation NZ Limited. All rights reserved.
//

#ifndef BRAssetData_h
#define BRAssetData_h

#include <stdint.h>

typedef enum {
    DA_UNDEFINED,
    DA_ISSUANCE,
    DA_TRANSFER,
    DA_BURN
} BRAssetOperation;

typedef struct {
    uint16_t info_hash[20];
    uint16_t metadata[32];
    
    uint8_t version;
    uint8_t has_metadata;
    uint8_t has_infohash;
    BRAssetOperation type;
    uint8_t locked;
} BRAssetData;

#endif /* BRAssetData_h */
