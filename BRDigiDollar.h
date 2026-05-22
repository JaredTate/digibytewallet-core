//
//  BRDigiDollar.h
//  DigiByte
//
//  Protocol helpers for DigiDollar transaction metadata.
//

#ifndef BRDigiDollar_h
#define BRDigiDollar_h

#include "BRTransaction.h"
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define BR_DIGIDOLLAR_VERSION_MARKER      0x0770u
#define BR_DIGIDOLLAR_VERSION_BASE        0x0D1D0770u
#define BR_DIGIDOLLAR_VERSION_MASK        0x0000ffffu
#define BR_DIGIDOLLAR_TYPE_MASK           0xff000000u
#define BR_DIGIDOLLAR_FLAGS_MASK          0x00ff0000u
#define BR_DIGIDOLLAR_MAX_AMOUNT_COUNT    16
#define BR_DIGIDOLLAR_MIN_MINT_AMOUNT     10000ULL
#define BR_DIGIDOLLAR_MAX_MINT_AMOUNT     10000000ULL
#define BR_DIGIDOLLAR_MIN_OUTPUT_AMOUNT   100ULL
#define BR_DIGIDOLLAR_MAX_AMOUNT          (21000000000ULL * 100ULL)
#define BR_DIGIDOLLAR_XONLY_KEY_LENGTH    32

typedef enum {
    BRDigiDollarTxNone = 0,
    BRDigiDollarTxMint = 1,
    BRDigiDollarTxTransfer = 2,
    BRDigiDollarTxRedeem = 3
} BRDigiDollarTxType;

typedef enum {
    BRDigiDollarMainNet = 0,
    BRDigiDollarTestNet = 1,
    BRDigiDollarRegTest = 2
} BRDigiDollarNetwork;

typedef struct {
    BRDigiDollarTxType type;
    uint64_t amounts[BR_DIGIDOLLAR_MAX_AMOUNT_COUNT];
    size_t amountCount;
    uint64_t lockHeight;
    uint32_t lockTier;
    uint8_t ownerXOnlyPubKey[BR_DIGIDOLLAR_XONLY_KEY_LENGTH];
    int hasOwnerXOnlyPubKey;
} BRDigiDollarOpReturn;

uint32_t BRDigiDollarMakeVersion(BRDigiDollarTxType type, uint8_t flags);
BRDigiDollarTxType BRDigiDollarTypeForVersion(uint32_t version);
uint8_t BRDigiDollarFlagsForVersion(uint32_t version);
BRDigiDollarTxType BRDigiDollarTypeForTx(const BRTransaction *tx);

size_t BRDigiDollarAddressEncode(char *addr, size_t addrLen, BRDigiDollarNetwork network,
                                 const uint8_t outputKey[BR_DIGIDOLLAR_XONLY_KEY_LENGTH]);
int BRDigiDollarAddressDecode(uint8_t outputKey[BR_DIGIDOLLAR_XONLY_KEY_LENGTH],
                              BRDigiDollarNetwork *network, const char *addr);
int BRDigiDollarAddressIsValid(const char *addr);
int BRDigiDollarAddressIsValidForNetwork(const char *addr, BRDigiDollarNetwork network);

size_t BRDigiDollarP2TRScriptPubKey(uint8_t *script, size_t scriptLen,
                                    const uint8_t outputKey[BR_DIGIDOLLAR_XONLY_KEY_LENGTH]);
int BRDigiDollarOutputIsP2TR(const BRTxOutput *output);

size_t BRDigiDollarBuildMintOpReturn(uint8_t *script, size_t scriptLen, uint64_t amount,
                                     uint64_t lockHeight, uint32_t lockTier,
                                     const uint8_t ownerXOnlyPubKey[BR_DIGIDOLLAR_XONLY_KEY_LENGTH]);
size_t BRDigiDollarBuildTransferOpReturn(uint8_t *script, size_t scriptLen,
                                         const uint64_t amounts[], size_t amountCount);
size_t BRDigiDollarBuildRedeemOpReturn(uint8_t *script, size_t scriptLen, uint64_t ddChange);

int BRDigiDollarParseOpReturn(BRDigiDollarOpReturn *metadata, const uint8_t *script, size_t scriptLen);
int BRDigiDollarTxFindOpReturn(const BRTransaction *tx, BRDigiDollarOpReturn *metadata, size_t *outputIndex);

size_t BRDigiDollarLockTierCount(void);
uint64_t BRDigiDollarLockTierBlocks(size_t tier);
int BRDigiDollarLockTierForBlocks(uint64_t blocks);
uint32_t BRDigiDollarCollateralRatioForLockTier(size_t tier);

#ifdef __cplusplus
}
#endif

#endif /* BRDigiDollar_h */
