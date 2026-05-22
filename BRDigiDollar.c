//
//  BRDigiDollar.c
//  DigiByte
//
//  Protocol helpers for DigiDollar transaction metadata.
//

#include "BRDigiDollar.h"
#include "BRAddress.h"
#include "BRBase58.h"
#include "BRInt.h"
#include <string.h>

static const uint8_t BRDigiDollarMainNetPrefix[2] = { 0x52, 0x85 };
static const uint8_t BRDigiDollarTestNetPrefix[2] = { 0xb1, 0x29 };
static const uint8_t BRDigiDollarRegTestPrefix[2] = { 0xa3, 0xa4 };

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
