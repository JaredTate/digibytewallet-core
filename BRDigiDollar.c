//
//  BRDigiDollar.c
//  DigiByte
//
//  Protocol helpers for DigiDollar transaction metadata.
//

#include "BRDigiDollar.h"
#include "BRAddress.h"
#include "BRBase58.h"
#include "BRCrypto.h"
#include "BRInt.h"
#include "secp256k1/include/secp256k1.h"
#include "secp256k1/include/secp256k1_extrakeys.h"
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

static const uint8_t BRDigiDollarMainNetPrefix[2] = { 0x52, 0x85 };
static const uint8_t BRDigiDollarTestNetPrefix[2] = { 0xb1, 0x29 };
static const uint8_t BRDigiDollarRegTestPrefix[2] = { 0xa3, 0xa4 };

static const uint8_t BRDigiDollarCollateralNUMS[BR_DIGIDOLLAR_XONLY_KEY_LENGTH] = {
    0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54,
    0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9, 0x7a, 0x5e,
    0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5,
    0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80, 0x3a, 0xc0
};

static secp256k1_context *BRDigiDollarSecpCtx = NULL;
static pthread_once_t BRDigiDollarSecpCtxOnce = PTHREAD_ONCE_INIT;

static void _BRDigiDollarSecpCtxInit(void)
{
    BRDigiDollarSecpCtx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
}

static const uint64_t BRDigiDollarLockTiers[] = {
    240ULL,
    30ULL * 24ULL * 60ULL * 4ULL,
    90ULL * 24ULL * 60ULL * 4ULL,
    180ULL * 24ULL * 60ULL * 4ULL,
    365ULL * 24ULL * 60ULL * 4ULL,
    2ULL * 365ULL * 24ULL * 60ULL * 4ULL,
    3ULL * 365ULL * 24ULL * 60ULL * 4ULL,
    5ULL * 365ULL * 24ULL * 60ULL * 4ULL,
    7ULL * 365ULL * 24ULL * 60ULL * 4ULL,
    10ULL * 365ULL * 24ULL * 60ULL * 4ULL
};

static const uint32_t BRDigiDollarCollateralRatios[] = {
    1000, 500, 400, 350, 300, 275, 250, 225, 212, 200
};

static const uint8_t *_BRDigiDollarPrefixForNetwork(BRDigiDollarNetwork network)
{
    switch (network) {
        case BRDigiDollarMainNet: return BRDigiDollarMainNetPrefix;
        case BRDigiDollarTestNet: return BRDigiDollarTestNetPrefix;
        case BRDigiDollarRegTest: return BRDigiDollarRegTestPrefix;
    }

    return NULL;
}

static int _BRDigiDollarNetworkForPrefix(const uint8_t prefix[2], BRDigiDollarNetwork *network)
{
    if (memcmp(prefix, BRDigiDollarMainNetPrefix, 2) == 0) {
        if (network) *network = BRDigiDollarMainNet;
        return 1;
    }
    if (memcmp(prefix, BRDigiDollarTestNetPrefix, 2) == 0) {
        if (network) *network = BRDigiDollarTestNet;
        return 1;
    }
    if (memcmp(prefix, BRDigiDollarRegTestPrefix, 2) == 0) {
        if (network) *network = BRDigiDollarRegTest;
        return 1;
    }

    return 0;
}

static int _BRDigiDollarStringHasWhitespace(const char *str)
{
    if (!str) return 1;

    for (const unsigned char *p = (const unsigned char *)str; *p; p++) {
        if (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r' || *p == '\f' || *p == '\v') return 1;
    }

    return 0;
}

uint32_t BRDigiDollarMakeVersion(BRDigiDollarTxType type, uint8_t flags)
{
    if (type <= BRDigiDollarTxNone || type > BRDigiDollarTxRedeem) return 0;

    return ((uint32_t)type << 24) | ((uint32_t)flags << 16) |
           (BR_DIGIDOLLAR_VERSION_BASE & BR_DIGIDOLLAR_VERSION_MASK);
}

BRDigiDollarTxType BRDigiDollarTypeForVersion(uint32_t version)
{
    if ((version & BR_DIGIDOLLAR_VERSION_MASK) != BR_DIGIDOLLAR_VERSION_MARKER) return BRDigiDollarTxNone;

    uint8_t type = (uint8_t)((version & BR_DIGIDOLLAR_TYPE_MASK) >> 24);
    if (type <= BRDigiDollarTxNone || type > BRDigiDollarTxRedeem) return BRDigiDollarTxNone;

    return (BRDigiDollarTxType)type;
}

uint8_t BRDigiDollarFlagsForVersion(uint32_t version)
{
    if (BRDigiDollarTypeForVersion(version) == BRDigiDollarTxNone) return 0;
    return (uint8_t)((version & BR_DIGIDOLLAR_FLAGS_MASK) >> 16);
}

BRDigiDollarTxType BRDigiDollarTypeForTx(const BRTransaction *tx)
{
    return (tx) ? BRDigiDollarTypeForVersion(tx->version) : BRDigiDollarTxNone;
}

size_t BRDigiDollarAddressEncode(char *addr, size_t addrLen, BRDigiDollarNetwork network,
                                 const uint8_t outputKey[BR_DIGIDOLLAR_XONLY_KEY_LENGTH])
{
    uint8_t payload[2 + BR_DIGIDOLLAR_XONLY_KEY_LENGTH];
    const uint8_t *prefix = _BRDigiDollarPrefixForNetwork(network);

    if (!prefix || !outputKey) return 0;

    memcpy(payload, prefix, 2);
    memcpy(&payload[2], outputKey, BR_DIGIDOLLAR_XONLY_KEY_LENGTH);

    return BRBase58CheckEncode(addr, addrLen, payload, sizeof(payload));
}

int BRDigiDollarAddressDecode(uint8_t outputKey[BR_DIGIDOLLAR_XONLY_KEY_LENGTH],
                              BRDigiDollarNetwork *network, const char *addr)
{
    uint8_t payload[2 + BR_DIGIDOLLAR_XONLY_KEY_LENGTH];
    BRDigiDollarNetwork decodedNetwork;

    if (_BRDigiDollarStringHasWhitespace(addr)) return 0;
    if (BRBase58CheckDecode(payload, sizeof(payload), addr) != sizeof(payload)) return 0;
    if (!_BRDigiDollarNetworkForPrefix(payload, &decodedNetwork)) return 0;

    if (outputKey) memcpy(outputKey, &payload[2], BR_DIGIDOLLAR_XONLY_KEY_LENGTH);
    if (network) *network = decodedNetwork;

    return 1;
}

int BRDigiDollarAddressIsValid(const char *addr)
{
    return BRDigiDollarAddressDecode(NULL, NULL, addr);
}

int BRDigiDollarAddressIsValidForNetwork(const char *addr, BRDigiDollarNetwork network)
{
    BRDigiDollarNetwork decodedNetwork;

    return BRDigiDollarAddressDecode(NULL, &decodedNetwork, addr) && decodedNetwork == network;
}

size_t BRDigiDollarP2TRScriptPubKey(uint8_t *script, size_t scriptLen,
                                    const uint8_t outputKey[BR_DIGIDOLLAR_XONLY_KEY_LENGTH])
{
    if (!outputKey) return 0;

    if (script && scriptLen >= 34) {
        script[0] = OP_1;
        script[1] = BR_DIGIDOLLAR_XONLY_KEY_LENGTH;
        memcpy(&script[2], outputKey, BR_DIGIDOLLAR_XONLY_KEY_LENGTH);
    }

    return (!script || scriptLen >= 34) ? 34 : 0;
}

int BRDigiDollarOutputIsP2TR(const BRTxOutput *output)
{
    return output && output->script && output->scriptLen == 34 &&
           output->script[0] == OP_1 && output->script[1] == BR_DIGIDOLLAR_XONLY_KEY_LENGTH;
}

static size_t _BRDigiDollarScriptPush(uint8_t *script, size_t scriptLen, size_t off,
                                      const uint8_t *data, size_t dataLen)
{
    size_t pushLen = BRScriptPushData((script && off <= scriptLen) ? &script[off] : NULL,
                                      (off <= scriptLen) ? scriptLen - off : 0,
                                      data, dataLen);

    return (pushLen > 0) ? off + pushLen : 0;
}

static size_t _BRDigiDollarScriptPushNum(uint8_t *script, size_t scriptLen, size_t off, uint64_t n)
{
    uint8_t buf[9];
    size_t len = 0;

    if (n == 0) {
        if (script && off < scriptLen) script[off] = OP_0;
        return (!script || off < scriptLen) ? off + 1 : 0;
    }
    if (n <= 16) {
        if (script && off < scriptLen) script[off] = (uint8_t)(OP_1 + n - 1);
        return (!script || off < scriptLen) ? off + 1 : 0;
    }

    while (n > 0 && len < sizeof(buf)) {
        buf[len++] = (uint8_t)(n & 0xff);
        n >>= 8;
    }

    if (len == 0 || n != 0) return 0;
    if (buf[len - 1] & 0x80) {
        if (len >= sizeof(buf)) return 0;
        buf[len++] = 0;
    }

    return _BRDigiDollarScriptPush(script, scriptLen, off, buf, len);
}

static int _BRDigiDollarScriptNumIsMinimal(const uint8_t *data, size_t dataLen)
{
    if (dataLen == 0) return 1;
    if ((data[dataLen - 1] & 0x7f) != 0) return 1;
    if (dataLen <= 1) return 0;
    return (data[dataLen - 2] & 0x80) != 0;
}

static int _BRDigiDollarScriptNumDecode(uint64_t *n, const uint8_t *elem, size_t maxLen)
{
    size_t dataLen = 0;
    const uint8_t *data;
    uint64_t value = 0;

    if (!n || !elem) return 0;

    if (*elem == OP_0) {
        *n = 0;
        return 1;
    }
    if (*elem >= OP_1 && *elem <= OP_16) {
        *n = (uint64_t)(*elem - OP_1 + 1);
        return 1;
    }

    data = BRScriptData(elem, &dataLen);
    if (!data || dataLen == 0 || dataLen > maxLen || !_BRDigiDollarScriptNumIsMinimal(data, dataLen)) return 0;
    if (data[dataLen - 1] & 0x80) return 0;

    for (size_t i = 0; i < dataLen; i++) {
        value |= ((uint64_t)data[i] << (8 * i));
    }

    *n = value;
    return 1;
}

static int _BRDigiDollarAmountIsValid(uint64_t amount)
{
    return amount > 0 && amount <= BR_DIGIDOLLAR_MAX_AMOUNT;
}

static int _BRDigiDollarTaggedSHA256(uint8_t out32[BR_DIGIDOLLAR_XONLY_KEY_LENGTH], const char *tag,
                                     const uint8_t *data, size_t dataLen)
{
    uint8_t tagHash[32], *buf;
    size_t tagLen, bufLen;

    if (!out32 || !tag || (!data && dataLen > 0)) return 0;

    tagLen = strlen(tag);
    bufLen = sizeof(tagHash)*2 + dataLen;
    buf = malloc(bufLen);
    if (!buf) return 0;

    BRSHA256(tagHash, tag, tagLen);
    memcpy(buf, tagHash, sizeof(tagHash));
    memcpy(&buf[sizeof(tagHash)], tagHash, sizeof(tagHash));
    if (dataLen > 0) memcpy(&buf[sizeof(tagHash)*2], data, dataLen);
    BRSHA256(out32, buf, bufLen);

    mem_clean(tagHash, sizeof(tagHash));
    mem_clean(buf, bufLen);
    free(buf);
    return 1;
}

static int _BRDigiDollarTaprootOutputKey(uint8_t outputKey[BR_DIGIDOLLAR_XONLY_KEY_LENGTH], int *parity,
                                         const uint8_t internalKey[BR_DIGIDOLLAR_XONLY_KEY_LENGTH],
                                         const uint8_t merkleRoot[BR_DIGIDOLLAR_XONLY_KEY_LENGTH])
{
    uint8_t tweakData[64], tweak[32];
    secp256k1_xonly_pubkey internalXOnly, outputXOnly;
    secp256k1_pubkey outputPubKey;
    int outputParity = 0;

    if (!outputKey || !internalKey || !merkleRoot) return 0;
    pthread_once(&BRDigiDollarSecpCtxOnce, _BRDigiDollarSecpCtxInit);

    memcpy(tweakData, internalKey, BR_DIGIDOLLAR_XONLY_KEY_LENGTH);
    memcpy(&tweakData[BR_DIGIDOLLAR_XONLY_KEY_LENGTH], merkleRoot, BR_DIGIDOLLAR_XONLY_KEY_LENGTH);

    if (!BRDigiDollarSecpCtx ||
        !secp256k1_xonly_pubkey_parse(BRDigiDollarSecpCtx, &internalXOnly, internalKey) ||
        !_BRDigiDollarTaggedSHA256(tweak, "TapTweak", tweakData, sizeof(tweakData)) ||
        !secp256k1_xonly_pubkey_tweak_add(BRDigiDollarSecpCtx, &outputPubKey, &internalXOnly, tweak) ||
        !secp256k1_xonly_pubkey_from_pubkey(BRDigiDollarSecpCtx, &outputXOnly, &outputParity, &outputPubKey) ||
        !secp256k1_xonly_pubkey_serialize(BRDigiDollarSecpCtx, outputKey, &outputXOnly)) {
        mem_clean(tweakData, sizeof(tweakData));
        mem_clean(tweak, sizeof(tweak));
        return 0;
    }

    if (parity) *parity = outputParity;
    mem_clean(tweakData, sizeof(tweakData));
    mem_clean(tweak, sizeof(tweak));
    return 1;
}

static int _BRDigiDollarTapLeafHash(uint8_t hash[BR_DIGIDOLLAR_XONLY_KEY_LENGTH], const uint8_t *script,
                                    size_t scriptLen)
{
    uint8_t *data;
    size_t viLen, dataLen, off = 0;
    int r = 0;

    if (!hash || !script || scriptLen == 0) return 0;

    viLen = BRVarIntSize(scriptLen);
    dataLen = 1 + viLen + scriptLen;
    data = malloc(dataLen);
    if (!data) return 0;

    data[off++] = BR_DIGIDOLLAR_TAPROOT_LEAF_VERSION;
    off += BRVarIntSet(&data[off], dataLen - off, scriptLen);
    memcpy(&data[off], script, scriptLen);
    off += scriptLen;

    r = (off == dataLen && _BRDigiDollarTaggedSHA256(hash, "TapLeaf", data, dataLen));
    mem_clean(data, dataLen);
    free(data);
    return r;
}

static int _BRDigiDollarTapBranchHash(uint8_t hash[BR_DIGIDOLLAR_XONLY_KEY_LENGTH],
                                      const uint8_t a[BR_DIGIDOLLAR_XONLY_KEY_LENGTH],
                                      const uint8_t b[BR_DIGIDOLLAR_XONLY_KEY_LENGTH])
{
    uint8_t data[BR_DIGIDOLLAR_XONLY_KEY_LENGTH*2];

    if (!hash || !a || !b) return 0;
    if (memcmp(a, b, BR_DIGIDOLLAR_XONLY_KEY_LENGTH) < 0) {
        memcpy(data, a, BR_DIGIDOLLAR_XONLY_KEY_LENGTH);
        memcpy(&data[BR_DIGIDOLLAR_XONLY_KEY_LENGTH], b, BR_DIGIDOLLAR_XONLY_KEY_LENGTH);
    } else {
        memcpy(data, b, BR_DIGIDOLLAR_XONLY_KEY_LENGTH);
        memcpy(&data[BR_DIGIDOLLAR_XONLY_KEY_LENGTH], a, BR_DIGIDOLLAR_XONLY_KEY_LENGTH);
    }

    return _BRDigiDollarTaggedSHA256(hash, "TapBranch", data, sizeof(data));
}

size_t BRDigiDollarCollateralNUMSKey(uint8_t out32[BR_DIGIDOLLAR_XONLY_KEY_LENGTH])
{
    if (!out32) return sizeof(BRDigiDollarCollateralNUMS);
    memcpy(out32, BRDigiDollarCollateralNUMS, sizeof(BRDigiDollarCollateralNUMS));
    return sizeof(BRDigiDollarCollateralNUMS);
}

size_t BRDigiDollarBuildNormalRedemptionScript(uint8_t *script, size_t scriptLen, uint64_t amountCents,
                                               uint64_t lockHeight,
                                               const uint8_t ownerXOnlyPubKey[BR_DIGIDOLLAR_XONLY_KEY_LENGTH])
{
    size_t off = 0;

    if (!_BRDigiDollarAmountIsValid(amountCents) || lockHeight == 0 || !ownerXOnlyPubKey) return 0;

    off = _BRDigiDollarScriptPushNum(script, scriptLen, off, lockHeight);
    if (off == 0) return 0;
    if (script && off < scriptLen) script[off] = OP_CHECKLOCKTIMEVERIFY;
    off = (!script || off < scriptLen) ? off + 1 : 0;
    if (off == 0) return 0;
    if (script && off < scriptLen) script[off] = OP_DROP;
    off = (!script || off < scriptLen) ? off + 1 : 0;
    if (off == 0) return 0;
    if (script && off < scriptLen) script[off] = OP_DIGIDOLLAR;
    off = (!script || off < scriptLen) ? off + 1 : 0;
    if (off == 0) return 0;
    off = _BRDigiDollarScriptPushNum(script, scriptLen, off, amountCents);
    if (off == 0) return 0;
    if (script && off < scriptLen) script[off] = OP_DDVERIFY;
    off = (!script || off < scriptLen) ? off + 1 : 0;
    if (off == 0) return 0;
    off = _BRDigiDollarScriptPush(script, scriptLen, off, ownerXOnlyPubKey, BR_DIGIDOLLAR_XONLY_KEY_LENGTH);
    if (off == 0) return 0;
    if (script && off < scriptLen) script[off] = OP_CHECKSIG;
    off = (!script || off < scriptLen) ? off + 1 : 0;

    return off;
}

size_t BRDigiDollarBuildERRRedemptionScript(uint8_t *script, size_t scriptLen, uint64_t amountCents,
                                            uint64_t lockHeight,
                                            const uint8_t ownerXOnlyPubKey[BR_DIGIDOLLAR_XONLY_KEY_LENGTH])
{
    size_t off = 0;

    if (!_BRDigiDollarAmountIsValid(amountCents) || lockHeight == 0 || !ownerXOnlyPubKey) return 0;

    off = _BRDigiDollarScriptPushNum(script, scriptLen, off, lockHeight);
    if (off == 0) return 0;
    if (script && off < scriptLen) script[off] = OP_CHECKLOCKTIMEVERIFY;
    off = (!script || off < scriptLen) ? off + 1 : 0;
    if (off == 0) return 0;
    if (script && off < scriptLen) script[off] = OP_DROP;
    off = (!script || off < scriptLen) ? off + 1 : 0;
    if (off == 0) return 0;
    off = _BRDigiDollarScriptPushNum(script, scriptLen, off, 100);
    if (off == 0) return 0;
    if (script && off < scriptLen) script[off] = OP_CHECKCOLLATERAL;
    off = (!script || off < scriptLen) ? off + 1 : 0;
    if (off == 0) return 0;
    if (script && off < scriptLen) script[off] = OP_NOT;
    off = (!script || off < scriptLen) ? off + 1 : 0;
    if (off == 0) return 0;
    if (script && off < scriptLen) script[off] = OP_VERIFY;
    off = (!script || off < scriptLen) ? off + 1 : 0;
    if (off == 0) return 0;
    if (script && off < scriptLen) script[off] = OP_DIGIDOLLAR;
    off = (!script || off < scriptLen) ? off + 1 : 0;
    if (off == 0) return 0;
    off = _BRDigiDollarScriptPushNum(script, scriptLen, off, amountCents);
    if (off == 0) return 0;
    if (script && off < scriptLen) script[off] = OP_DDVERIFY;
    off = (!script || off < scriptLen) ? off + 1 : 0;
    if (off == 0) return 0;
    off = _BRDigiDollarScriptPush(script, scriptLen, off, ownerXOnlyPubKey, BR_DIGIDOLLAR_XONLY_KEY_LENGTH);
    if (off == 0) return 0;
    if (script && off < scriptLen) script[off] = OP_CHECKSIG;
    off = (!script || off < scriptLen) ? off + 1 : 0;

    return off;
}

static int _BRDigiDollarCollateralHashes(uint8_t normalHash[BR_DIGIDOLLAR_XONLY_KEY_LENGTH],
                                         uint8_t errHash[BR_DIGIDOLLAR_XONLY_KEY_LENGTH],
                                         uint8_t merkleRoot[BR_DIGIDOLLAR_XONLY_KEY_LENGTH],
                                         uint64_t amountCents, uint64_t lockHeight,
                                         const uint8_t ownerXOnlyPubKey[BR_DIGIDOLLAR_XONLY_KEY_LENGTH])
{
    uint8_t normalScript[96], errScript[128];
    size_t normalLen, errLen;

    normalLen = BRDigiDollarBuildNormalRedemptionScript(normalScript, sizeof(normalScript), amountCents,
                                                        lockHeight, ownerXOnlyPubKey);
    errLen = BRDigiDollarBuildERRRedemptionScript(errScript, sizeof(errScript), amountCents,
                                                  lockHeight, ownerXOnlyPubKey);
    if (normalLen == 0 || errLen == 0 ||
        !_BRDigiDollarTapLeafHash(normalHash, normalScript, normalLen) ||
        !_BRDigiDollarTapLeafHash(errHash, errScript, errLen) ||
        !_BRDigiDollarTapBranchHash(merkleRoot, normalHash, errHash)) {
        mem_clean(normalScript, sizeof(normalScript));
        mem_clean(errScript, sizeof(errScript));
        return 0;
    }

    mem_clean(normalScript, sizeof(normalScript));
    mem_clean(errScript, sizeof(errScript));
    return 1;
}

int BRDigiDollarCollateralLeafHash(uint8_t leafHash32[BR_DIGIDOLLAR_XONLY_KEY_LENGTH],
                                   BRDigiDollarRedeemPath path, uint64_t amountCents, uint64_t lockHeight,
                                   const uint8_t ownerXOnlyPubKey[BR_DIGIDOLLAR_XONLY_KEY_LENGTH])
{
    uint8_t script[128];
    size_t scriptLen;

    if (!leafHash32) return 0;
    if (path == BRDigiDollarRedeemNormal) {
        scriptLen = BRDigiDollarBuildNormalRedemptionScript(script, sizeof(script), amountCents,
                                                            lockHeight, ownerXOnlyPubKey);
    } else if (path == BRDigiDollarRedeemERR) {
        scriptLen = BRDigiDollarBuildERRRedemptionScript(script, sizeof(script), amountCents,
                                                         lockHeight, ownerXOnlyPubKey);
    } else {
        return 0;
    }

    if (scriptLen == 0) return 0;
    int r = _BRDigiDollarTapLeafHash(leafHash32, script, scriptLen);
    mem_clean(script, sizeof(script));
    return r;
}

size_t BRDigiDollarCollateralControlBlock(uint8_t *control, size_t controlLen, BRDigiDollarRedeemPath path,
                                          uint64_t amountCents, uint64_t lockHeight,
                                          const uint8_t ownerXOnlyPubKey[BR_DIGIDOLLAR_XONLY_KEY_LENGTH])
{
    uint8_t normalHash[32], errHash[32], merkleRoot[32], outputKey[32];
    int parity = 0;

    if (path != BRDigiDollarRedeemNormal && path != BRDigiDollarRedeemERR) return 0;
    if (!_BRDigiDollarCollateralHashes(normalHash, errHash, merkleRoot, amountCents, lockHeight,
                                       ownerXOnlyPubKey) ||
        !_BRDigiDollarTaprootOutputKey(outputKey, &parity, BRDigiDollarCollateralNUMS, merkleRoot)) {
        return 0;
    }

    if (control && controlLen >= 65) {
        control[0] = BR_DIGIDOLLAR_TAPROOT_LEAF_VERSION | (uint8_t)parity;
        memcpy(&control[1], BRDigiDollarCollateralNUMS, BR_DIGIDOLLAR_XONLY_KEY_LENGTH);
        memcpy(&control[33], (path == BRDigiDollarRedeemNormal) ? errHash : normalHash,
               BR_DIGIDOLLAR_XONLY_KEY_LENGTH);
    }

    return (!control || controlLen >= 65) ? 65 : 0;
}

size_t BRDigiDollarCollateralScriptPubKey(uint8_t *script, size_t scriptLen, uint64_t amountCents,
                                          uint64_t lockHeight,
                                          const uint8_t ownerXOnlyPubKey[BR_DIGIDOLLAR_XONLY_KEY_LENGTH],
                                          uint8_t outputKey32[BR_DIGIDOLLAR_XONLY_KEY_LENGTH])
{
    uint8_t normalHash[32], errHash[32], merkleRoot[32], outputKey[32];

    if (!_BRDigiDollarCollateralHashes(normalHash, errHash, merkleRoot, amountCents, lockHeight,
                                       ownerXOnlyPubKey) ||
        !_BRDigiDollarTaprootOutputKey(outputKey, NULL, BRDigiDollarCollateralNUMS, merkleRoot)) {
        return 0;
    }

    if (outputKey32) memcpy(outputKey32, outputKey, BR_DIGIDOLLAR_XONLY_KEY_LENGTH);
    return BRDigiDollarP2TRScriptPubKey(script, scriptLen, outputKey);
}

size_t BRDigiDollarBuildMintOpReturn(uint8_t *script, size_t scriptLen, uint64_t amount,
                                     uint64_t lockHeight, uint32_t lockTier,
                                     const uint8_t ownerXOnlyPubKey[BR_DIGIDOLLAR_XONLY_KEY_LENGTH])
{
    static const uint8_t tag[2] = { 'D', 'D' };
    size_t off = 0;

    if (amount < BR_DIGIDOLLAR_MIN_MINT_AMOUNT || amount > BR_DIGIDOLLAR_MAX_MINT_AMOUNT) return 0;
    if (lockHeight == 0 || lockTier >= BRDigiDollarLockTierCount() || !ownerXOnlyPubKey) return 0;

    if (script && off < scriptLen) script[off] = OP_RETURN;
    off = (!script || off < scriptLen) ? off + 1 : 0;
    if (off == 0) return 0;

    off = _BRDigiDollarScriptPush(script, scriptLen, off, tag, sizeof(tag));
    if (off == 0) return 0;
    off = _BRDigiDollarScriptPushNum(script, scriptLen, off, BRDigiDollarTxMint);
    if (off == 0) return 0;
    off = _BRDigiDollarScriptPushNum(script, scriptLen, off, amount);
    if (off == 0) return 0;
    off = _BRDigiDollarScriptPushNum(script, scriptLen, off, lockHeight);
    if (off == 0) return 0;
    off = _BRDigiDollarScriptPushNum(script, scriptLen, off, lockTier);
    if (off == 0) return 0;
    off = _BRDigiDollarScriptPush(script, scriptLen, off, ownerXOnlyPubKey, BR_DIGIDOLLAR_XONLY_KEY_LENGTH);

    return off;
}

size_t BRDigiDollarBuildTransferOpReturn(uint8_t *script, size_t scriptLen,
                                         const uint64_t amounts[], size_t amountCount)
{
    static const uint8_t tag[2] = { 'D', 'D' };
    size_t off = 0;

    if (!amounts || amountCount == 0 || amountCount > BR_DIGIDOLLAR_MAX_AMOUNT_COUNT) return 0;
    for (size_t i = 0; i < amountCount; i++) {
        if (amounts[i] < BR_DIGIDOLLAR_MIN_OUTPUT_AMOUNT || amounts[i] > BR_DIGIDOLLAR_MAX_AMOUNT) return 0;
    }

    if (script && off < scriptLen) script[off] = OP_RETURN;
    off = (!script || off < scriptLen) ? off + 1 : 0;
    if (off == 0) return 0;

    off = _BRDigiDollarScriptPush(script, scriptLen, off, tag, sizeof(tag));
    if (off == 0) return 0;
    off = _BRDigiDollarScriptPushNum(script, scriptLen, off, BRDigiDollarTxTransfer);
    if (off == 0) return 0;

    for (size_t i = 0; i < amountCount; i++) {
        off = _BRDigiDollarScriptPushNum(script, scriptLen, off, amounts[i]);
        if (off == 0) return 0;
    }

    return off;
}

size_t BRDigiDollarBuildRedeemOpReturn(uint8_t *script, size_t scriptLen, uint64_t ddChange)
{
    static const uint8_t tag[2] = { 'D', 'D' };
    size_t off = 0;

    if (!_BRDigiDollarAmountIsValid(ddChange)) return 0;

    if (script && off < scriptLen) script[off] = OP_RETURN;
    off = (!script || off < scriptLen) ? off + 1 : 0;
    if (off == 0) return 0;

    off = _BRDigiDollarScriptPush(script, scriptLen, off, tag, sizeof(tag));
    if (off == 0) return 0;
    off = _BRDigiDollarScriptPushNum(script, scriptLen, off, BRDigiDollarTxRedeem);
    if (off == 0) return 0;
    off = _BRDigiDollarScriptPushNum(script, scriptLen, off, ddChange);

    return off;
}

int BRDigiDollarParseOpReturn(BRDigiDollarOpReturn *metadata, const uint8_t *script, size_t scriptLen)
{
    const uint8_t *elems[BR_DIGIDOLLAR_MAX_AMOUNT_COUNT + 8];
    size_t elemsCount, dataLen = 0, expectedCount;
    const uint8_t *data;
    uint64_t n;

    if (!metadata || !script || scriptLen == 0) return 0;
    memset(metadata, 0, sizeof(*metadata));

    elemsCount = BRScriptElements(elems, sizeof(elems)/sizeof(*elems), script, scriptLen);
    if (elemsCount < 4 || elemsCount > sizeof(elems)/sizeof(*elems)) return 0;
    if (*elems[0] != OP_RETURN) return 0;

    data = BRScriptData(elems[1], &dataLen);
    if (!data || dataLen != 2 || data[0] != 'D' || data[1] != 'D') return 0;

    if (!_BRDigiDollarScriptNumDecode(&n, elems[2], 8)) return 0;
    metadata->type = (BRDigiDollarTxType)n;
    if (metadata->type <= BRDigiDollarTxNone || metadata->type > BRDigiDollarTxRedeem) return 0;

    switch (metadata->type) {
        case BRDigiDollarTxMint:
            expectedCount = 7;
            if (elemsCount != expectedCount) return 0;
            if (!_BRDigiDollarScriptNumDecode(&metadata->amounts[0], elems[3], 8) ||
                metadata->amounts[0] < BR_DIGIDOLLAR_MIN_MINT_AMOUNT ||
                metadata->amounts[0] > BR_DIGIDOLLAR_MAX_MINT_AMOUNT) return 0;
            metadata->amountCount = 1;
            if (!_BRDigiDollarScriptNumDecode(&metadata->lockHeight, elems[4], 8) || metadata->lockHeight == 0) return 0;
            if (!_BRDigiDollarScriptNumDecode(&n, elems[5], 8) || n >= BRDigiDollarLockTierCount()) return 0;
            metadata->lockTier = (uint32_t)n;
            data = BRScriptData(elems[6], &dataLen);
            if (!data || dataLen != BR_DIGIDOLLAR_XONLY_KEY_LENGTH) return 0;
            memcpy(metadata->ownerXOnlyPubKey, data, BR_DIGIDOLLAR_XONLY_KEY_LENGTH);
            metadata->hasOwnerXOnlyPubKey = 1;
            return 1;

        case BRDigiDollarTxTransfer:
            if (elemsCount < 4 || elemsCount > BR_DIGIDOLLAR_MAX_AMOUNT_COUNT + 3) return 0;
            metadata->amountCount = elemsCount - 3;
            for (size_t i = 0; i < metadata->amountCount; i++) {
                if (!_BRDigiDollarScriptNumDecode(&metadata->amounts[i], elems[i + 3], 8) ||
                    metadata->amounts[i] < BR_DIGIDOLLAR_MIN_OUTPUT_AMOUNT ||
                    metadata->amounts[i] > BR_DIGIDOLLAR_MAX_AMOUNT) return 0;
            }
            return 1;

        case BRDigiDollarTxRedeem:
            expectedCount = 4;
            if (elemsCount != expectedCount) return 0;
            if (!_BRDigiDollarScriptNumDecode(&metadata->amounts[0], elems[3], 8) ||
                !_BRDigiDollarAmountIsValid(metadata->amounts[0])) return 0;
            metadata->amountCount = 1;
            return 1;

        case BRDigiDollarTxNone:
            return 0;
    }

    return 0;
}

int BRDigiDollarTxFindOpReturn(const BRTransaction *tx, BRDigiDollarOpReturn *metadata, size_t *outputIndex)
{
    BRDigiDollarOpReturn parsed, result;
    size_t resultIndex = 0;
    int found = 0;

    if (!tx) return 0;

    for (size_t i = 0; i < tx->outCount; i++) {
        const BRTxOutput *output = &tx->outputs[i];

        if (!output->script || output->scriptLen == 0 || output->script[0] != OP_RETURN) continue;
        if (!BRDigiDollarParseOpReturn(&parsed, output->script, output->scriptLen)) continue;

        if (found) return 0;
        result = parsed;
        resultIndex = i;
        found = 1;
    }

    if (!found) return 0;
    if (metadata) *metadata = result;
    if (outputIndex) *outputIndex = resultIndex;

    return 1;
}

int BRDigiDollarTxOutputAmount(uint64_t *amountCents, const BRTransaction *tx, size_t outputIndex)
{
    BRDigiDollarOpReturn metadata;
    BRDigiDollarTxType type;
    size_t tokenIndex = 0;
    size_t tokenCount = 0;

    if (amountCents) *amountCents = 0;
    if (!tx || outputIndex >= tx->outCount) return 0;
    if (!BRDigiDollarOutputIsP2TR(&tx->outputs[outputIndex]) || tx->outputs[outputIndex].amount != 0) return 0;

    type = BRDigiDollarTypeForTx(tx);
    if (type == BRDigiDollarTxNone) return 0;
    if (!BRDigiDollarTxFindOpReturn(tx, &metadata, NULL) || metadata.type != type) return 0;

    for (size_t i = 0; i < tx->outCount; i++) {
        if (!BRDigiDollarOutputIsP2TR(&tx->outputs[i]) || tx->outputs[i].amount != 0) continue;
        if (i == outputIndex) tokenIndex = tokenCount;
        tokenCount++;
    }

    switch (type) {
        case BRDigiDollarTxMint:
            if (metadata.amountCount != 1 || tokenCount != 1 || outputIndex != 1) return 0;
            if (amountCents) *amountCents = metadata.amounts[0];
            return 1;

        case BRDigiDollarTxTransfer:
            if (metadata.amountCount != tokenCount || tokenIndex >= metadata.amountCount) return 0;
            if (amountCents) *amountCents = metadata.amounts[tokenIndex];
            return 1;

        case BRDigiDollarTxRedeem:
            if (metadata.amountCount != 1 || tokenCount != 1 || tokenIndex != 0) return 0;
            if (amountCents) *amountCents = metadata.amounts[0];
            return 1;

        case BRDigiDollarTxNone:
            return 0;
    }

    return 0;
}

size_t BRDigiDollarLockTierCount(void)
{
    return sizeof(BRDigiDollarLockTiers)/sizeof(*BRDigiDollarLockTiers);
}

uint64_t BRDigiDollarLockTierBlocks(size_t tier)
{
    return (tier < BRDigiDollarLockTierCount()) ? BRDigiDollarLockTiers[tier] : 0;
}

int BRDigiDollarLockTierForBlocks(uint64_t blocks)
{
    for (size_t i = 0; i < BRDigiDollarLockTierCount(); i++) {
        if (BRDigiDollarLockTiers[i] == blocks) return (int)i;
    }

    return -1;
}

uint32_t BRDigiDollarCollateralRatioForLockTier(size_t tier)
{
    return (tier < BRDigiDollarLockTierCount()) ? BRDigiDollarCollateralRatios[tier] : 0;
}

uint32_t BRDigiDollarDCAMultiplierBps(int32_t systemHealth)
{
    if (systemHealth < 0) systemHealth = 0;
    if (systemHealth > 30000) systemHealth = 30000;

    if (systemHealth >= 150) return 10000;
    if (systemHealth >= 120) return 12500;
    if (systemHealth >= 110) return 15000;
    return 20000;
}

uint32_t BRDigiDollarEffectiveCollateralRatio(uint32_t baseRatio, int32_t systemHealth)
{
    uint32_t multiplier = BRDigiDollarDCAMultiplierBps(systemHealth);
    uint64_t adjusted;

    if (baseRatio == 0) return 0;
    adjusted = (uint64_t)baseRatio * multiplier;
    adjusted = (adjusted + 9999) / 10000;

    return (adjusted <= UINT32_MAX) ? (uint32_t)adjusted : 0;
}

uint64_t BRDigiDollarRequiredCollateral(uint64_t amountCents, uint32_t lockTier,
                                        uint64_t oraclePriceMicroUSD, int32_t systemHealth)
{
    uint32_t baseRatio = BRDigiDollarCollateralRatioForLockTier(lockTier);
    uint32_t effectiveRatio = BRDigiDollarEffectiveCollateralRatio(baseRatio, systemHealth);
    __int128 numerator, denominator, result;

    if (amountCents < BR_DIGIDOLLAR_MIN_MINT_AMOUNT || amountCents > BR_DIGIDOLLAR_MAX_MINT_AMOUNT ||
        baseRatio == 0 || effectiveRatio == 0 || oraclePriceMicroUSD == 0) {
        return 0;
    }

    numerator = (__int128)amountCents * SATOSHIS * effectiveRatio * 100;
    denominator = (__int128)oraclePriceMicroUSD;
    result = (numerator + denominator - 1) / denominator;
    if (result <= 0 || result > MAX_MONEY) return 0;

    return (uint64_t)result;
}

uint64_t BRDigiDollarRequiredCollateralWithSafetyMargin(uint64_t amountCents, uint32_t lockTier,
                                                        uint64_t oraclePriceMicroUSD, int32_t systemHealth)
{
    uint64_t required = BRDigiDollarRequiredCollateral(amountCents, lockTier, oraclePriceMicroUSD, systemHealth);
    __int128 padded;

    if (required == 0) return 0;
    padded = ((__int128)required * 101) / 100;
    if (padded <= 0 || padded > MAX_MONEY) return 0;

    return (uint64_t)padded;
}

uint64_t BRDigiDollarMintLockHeight(uint32_t currentBlockHeight, uint32_t lockTier)
{
    uint64_t lockBlocks = BRDigiDollarLockTierBlocks(lockTier);

    if (lockBlocks == 0) return 0;
    return (uint64_t)currentBlockHeight + lockBlocks + BR_DIGIDOLLAR_MINT_LOCK_CONFIRMATION_BUFFER_BLOCKS;
}

uint32_t BRDigiDollarERRRatioBps(int32_t systemHealth)
{
    if (systemHealth >= 100) return 10000;
    if (systemHealth >= 95) return 9500;
    if (systemHealth >= 90) return 9000;
    if (systemHealth >= 85) return 8500;
    return 8000;
}

uint64_t BRDigiDollarERRRequiredBurn(uint64_t originalAmountCents, int32_t systemHealth)
{
    uint32_t ratio = BRDigiDollarERRRatioBps(systemHealth);
    __int128 required;

    if (!_BRDigiDollarAmountIsValid(originalAmountCents) || ratio == 0) return 0;
    required = ((__int128)originalAmountCents * 10000 + ratio - 1) / ratio;
    if (required <= 0 || required > BR_DIGIDOLLAR_MAX_AMOUNT) return 0;

    return (uint64_t)required;
}
