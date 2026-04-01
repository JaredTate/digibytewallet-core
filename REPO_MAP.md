# DigiByte Wallet Core — Repo Map

> Every source file in the repository with its public API documented.
> Excludes `.git/` internals. secp256k1 submodule summarized by directory.

---

## Root — Core Library

### BRInt.h
- **Header-only** — large integer types and utilities
- `typedef union UInt128` — 128-bit integer (u8/u16/u32/u64 views)
- `typedef union UInt160` — 160-bit integer (u8/u16/u32 views)
- `typedef union UInt256` — 256-bit integer (u8/u16/u32/u64 views)
- `typedef union UInt512` — 512-bit integer (u8/u16/u32/u64 views)
- `UINT128_ZERO`, `UINT160_ZERO`, `UINT256_ZERO`, `UINT512_ZERO` — zero constants
- `UInt256IsZero()`, `UInt256Eq()`, `UInt256Reverse()` — inline comparison/manipulation
- `u256_hex_encode(u)`, `u256_hex_decode(s)` — hex encoding macros
- Endian conversion: `UInt16GetBE/LE`, `UInt32GetBE/LE`, `UInt64GetBE/LE`, `UInt128Get/Set`, `UInt256Get/Set`

### BRArray.h
- **Header-only** — macro-based growable arrays with type checking
- `array_new(array, capacity)` — allocate with initial capacity
- `array_capacity(array)`, `array_count(array)` — size queries
- `array_add(array, item)`, `array_add_array(array, other, count)` — append
- `array_insert(array, index, item)`, `array_insert_array(...)` — insert
- `array_rm(array, index)`, `array_rm_last(array)`, `array_rm_range(...)` — remove
- `array_set_count(array, count)`, `array_set_capacity(array, capacity)` — resize
- `array_clear(array)`, `array_free(array)` — cleanup

### BRCrypto.h / BRCrypto.c
- `void BRSHA1(void *md20, const void *data, size_t len)`
- `void BRSHA224(void *md28, const void *data, size_t len)`
- `void BRSHA256(void *md32, const void *data, size_t len)`
- `void BRSHA256_2(void *md32, const void *data, size_t len)` — double SHA-256
- `void BRSHA384(void *md48, const void *data, size_t len)`
- `void BRSHA512(void *md64, const void *data, size_t len)`
- `void BRRMD160(void *md20, const void *data, size_t len)` — RIPEMD-160
- `void BRHash160(void *md20, const void *data, size_t len)` — RIPEMD160(SHA256(x))
- `void BRMD5(void *md16, const void *data, size_t len)` — non-cryptographic
- `uint32_t BRMurmur3_32(const void *data, size_t len, uint32_t seed)` — MurmurHash3
- `void BRHMAC(void *mac, hash_fn, hashLen, key, keyLen, data, dataLen)` — HMAC
- `void BRHMACDRBG(...)` — HMAC-DRBG deterministic random
- `void BRPoly1305(void *mac16, const void *key32, data, len)` — Poly1305 MAC
- `void BRChacha20(...)` — ChaCha20 stream cipher
- `size_t BRChacha20Poly1305AEADEncrypt(...)` / `...Decrypt(...)` — AEAD
- `void BRPBKDF2(...)` — PBKDF2 key derivation
- `void BRScrypt(...)` — scrypt key derivation
- `var_clean(...)` — macro to zero-wipe variables

### BRBase58.h / BRBase58.c
- `size_t BRBase58Encode(char *str, size_t strLen, const uint8_t *data, size_t dataLen)`
- `size_t BRBase58Decode(uint8_t *data, size_t dataLen, const char *str)`
- `size_t BRBase58CheckEncode(char *str, size_t strLen, const uint8_t *data, size_t dataLen)`
- `size_t BRBase58CheckDecode(uint8_t *data, size_t dataLen, const char *str)`

### BRKey.h / BRKey.c
- `typedef struct BRECPoint` — compressed EC point (33 bytes)
- `typedef struct BRKey` — private key (secret UInt256, pubKey[65], compressed flag)
- `int BRSecp256k1ModAdd(UInt256 *a, const UInt256 *b)` — modular addition
- `int BRSecp256k1ModMul(UInt256 *a, const UInt256 *b)` — modular multiplication
- `int BRSecp256k1PointGen(BRECPoint *p, const UInt256 *i)` — generator multiply
- `int BRSecp256k1PointAdd(BRECPoint *p, const UInt256 *i)` — point addition
- `int BRSecp256k1PointMul(BRECPoint *p, const UInt256 *i)` — point multiplication
- `int BRPrivKeyIsValid(const char *privKey)` — WIF validation
- `int BRKeySetSecret(BRKey *key, const UInt256 *secret, int compressed)`
- `int BRKeySetPrivKey(BRKey *key, const char *privKey)` — from WIF
- `int BRKeySetPubKey(BRKey *key, const uint8_t *pubKey, size_t pkLen)`
- `size_t BRKeyPrivKey(const BRKey *key, char *privKey, size_t pkLen)` — to WIF
- `size_t BRKeyPubKey(BRKey *key, void *pubKey, size_t pkLen)`
- `size_t BRKeyAddress(BRKey *key, char *addr, size_t addrLen)` — DigiByte address
- `size_t BRKeySign(const BRKey *key, void *sig, size_t sigLen, UInt256 md)` — ECDSA sign
- `int BRKeyVerify(BRKey *key, UInt256 md, const void *sig, size_t sigLen)` — ECDSA verify
- `void BRKeyClean(BRKey *key)` — zero-wipe key material
- `size_t BRKeyCompactSign(const BRKey *key, void *compactSig, size_t sigLen, UInt256 md)`
- `int BRKeyRecoverPubKey(BRKey *key, UInt256 md, const void *compactSig, size_t sigLen)`
- Constants: `BITCOIN_PRIVKEY=128`, `BITCOIN_PRIVKEY_TEST=239`

### BRBIP32Sequence.h / BRBIP32Sequence.c
- `typedef struct BRMasterPubKey` — fingerPrint, chainCode (UInt256), pubKey[33]
- `BR_MASTER_PUBKEY_NONE` — empty master pubkey constant
- `BRMasterPubKey BRBIP32MasterPubKey(const void *seed, size_t seedLen)` — derive from seed
- `size_t BRBIP32PubKey(uint8_t *pubKey, size_t pkLen, BRMasterPubKey mpk, uint32_t chain, uint32_t index)`
- `void BRBIP32PrivKey(BRKey *key, const void *seed, size_t seedLen, uint32_t chain, uint32_t index)`
- `void BRBIP32PrivKeyList(BRKey keys[], size_t count, const void *seed, size_t seedLen, uint32_t chain, const uint32_t indexes[])`
- `void BRBIP32PrivKeyPath(BRKey *key, const void *seed, size_t seedLen, int depth, ...)`
- `void BRBIP32vPrivKeyPath(BRKey *key, const void *seed, size_t seedLen, int depth, va_list vlist)`
- `size_t BRBIP32SerializeMasterPrivKey(char *str, size_t strLen, const void *seed, size_t seedLen)`
- `size_t BRBIP32ParseMasterPrivKey(void *seed, size_t seedLen, const char *str)`
- `size_t BRBIP32SerializeMasterPubKey(char *str, size_t strLen, BRMasterPubKey mpk)`
- `BRMasterPubKey BRBIP32ParseMasterPubKey(const char *str)`
- `void BRBIP32APIAuthKey(BRKey *key, const void *seed, size_t seedLen)` — API auth key derivation
- `void BRBIP32BitIDKey(BRKey *key, const void *seed, size_t seedLen, uint32_t index, const char *uri)` — BitID
- Constants: `BIP32_HARD=0x80000000`, `BIP32_SEED_KEY="DigiByte seed"`, `SEQUENCE_GAP_LIMIT_EXTERNAL=10`, `SEQUENCE_GAP_LIMIT_INTERNAL=5`

### BRBIP38Key.h / BRBIP38Key.c
- `int BRBIP38KeyIsValid(const char *bip38Key)`
- `int BRKeySetBIP38Key(BRKey *key, const char *bip38Key, const char *passphrase)`
- `size_t BRKeyBIP38ItermediateCode(char *code, size_t codeLen, uint64_t salt, const char *passphrase)`
- `size_t BRKeyBIP38ItermediateCodeLS(char *code, size_t codeLen, uint32_t lot, uint16_t sequence, uint32_t salt, const char *passphrase)`
- `void BRKeySetBIP38ItermediateCode(BRKey *key, const char *code, const uint8_t *seedb, int compressed)`
- `size_t BRKeyBIP38Key(BRKey *key, char *bip38Key, size_t bip38KeyLen, const char *passphrase)`
- Internal: `_BRAES256ECBEncrypt()`, `_BRAES256ECBDecrypt()`, `_BRBIP38DerivePassfactor()`, `_BRBIP38DeriveKey()`

### BRBIP39Mnemonic.h / BRBIP39Mnemonic.c
- `size_t BRBIP39Encode(char *phrase, size_t phraseLen, const char *wordList[], const uint8_t *data, size_t dataLen)`
- `size_t BRBIP39Decode(uint8_t *data, size_t dataLen, const char *wordList[], const char *phrase)`
- `int BRBIP39PhraseIsValid(const char *wordList[], const char *phrase)`
- `void BRBIP39DeriveKey(void *key64, const char *phrase, const char *passphrase)` — PBKDF2 seed derivation
- Constants: `BIP39_CREATION_TIME=1388534400`, `BIP39_WORDLIST_COUNT=2048`

### BRBIP39WordsEn.h
- `static const char *BRBIP39WordsEn[2048]` — English BIP39 word list

### BRAddress.h / BRAddress.c
- `typedef struct BRAddress` — 36-char address string
- `BR_ADDRESS_NONE` — empty address constant
- `uint64_t BRVarInt(const uint8_t *buf, size_t bufLen, size_t *intLen)` — read varint
- `size_t BRVarIntSet(uint8_t *buf, size_t bufLen, uint64_t i)` — write varint
- `size_t BRVarIntSize(uint64_t i)` — varint byte length
- `size_t BRScriptElements(const uint8_t *elems[], size_t elemsCount, const uint8_t *script, size_t scriptLen)`
- `const uint8_t *BRScriptData(const uint8_t *elem, size_t *dataLen)`
- `size_t BRScriptPushData(uint8_t *script, size_t scriptLen, const uint8_t *data, size_t dataLen)`
- `size_t BRAddressFromScriptPubKey(char *addr, size_t addrLen, const uint8_t *script, size_t scriptLen)`
- `size_t BRAddressFromScriptSig(char *addr, size_t addrLen, const uint8_t *script, size_t scriptLen)`
- `size_t BRAddressScriptPubKey(uint8_t *script, size_t scriptLen, const char *addr)`
- `int BRAddressIsValid(const char *addr)`
- `int BRAddressHash160(void *md20, const char *addr)`
- Constants: `BITCOIN_PUBKEY_ADDRESS=30`, `BITCOIN_SCRIPT_ADDRESS=5`, opcodes (OP_0 through OP_CHECKSIG)

### BRTransaction.h / BRTransaction.c
- `typedef struct BRTxInput` — txHash, index, address[36], script, signature
- `typedef struct BRTxOutput` — address[36], amount (uint64_t), script
- `typedef struct BRTransaction` — txHash, version, inputs, outputs, lockTime, blockHeight, timestamp
- `uint32_t BRRand(uint32_t upperBound)` — non-cryptographic random
- `void BRTxInputSetAddress(BRTxInput *input, const char *address)`
- `void BRTxInputSetScript(BRTxInput *input, const uint8_t *script, size_t scriptLen)`
- `void BRTxInputSetSignature(BRTxInput *input, const uint8_t *signature, size_t sigLen)`
- `void BRTxOutputSetAddress(BRTxOutput *output, const char *address)`
- `void BRTxOutputSetScript(BRTxOutput *output, const uint8_t *script, size_t scriptLen)`
- `BRTransaction *BRTransactionNew(void)` — allocate new tx
- `BRTransaction *BRTransactionParse(const uint8_t *buf, size_t bufLen)` — deserialize
- `size_t BRTransactionSerialize(const BRTransaction *tx, uint8_t *buf, size_t bufLen)` — serialize
- `void BRTransactionAddInput(BRTransaction *tx, UInt256 txHash, uint32_t index, uint64_t amount, const uint8_t *script, size_t scriptLen, const uint8_t *signature, size_t sigLen, uint32_t sequence)`
- `void BRTransactionAddOutput(BRTransaction *tx, uint64_t amount, const uint8_t *script, size_t scriptLen)`
- `void BRTransactionShuffleOutputs(BRTransaction *tx)` — randomize output order
- `size_t BRTransactionSize(const BRTransaction *tx)` — estimated byte size
- `uint64_t BRTransactionStandardFee(const BRTransaction *tx)` — fee calculation
- `int BRTransactionIsSigned(const BRTransaction *tx)`
- `int BRTransactionSign(BRTransaction *tx, int forkId, BRKey keys[], size_t keysCount)`
- `int BRTransactionIsStandard(const BRTransaction *tx)`
- `void BRTransactionFree(BRTransaction *tx)`
- Constants: `TX_FEE_PER_KB=5000`, `TX_MIN_OUTPUT_AMOUNT=100000001`, `TX_MAX_SIZE=100000`, `SATOSHIS=100000000`, `MAX_MONEY=21000000*SATOSHIS`

### BRBloomFilter.h / BRBloomFilter.c
- `typedef struct BRBloomFilter` — filter bytes, hashFuncs, elemCount, tweak, flags
- `BR_BLOOM_FILTER_FULL` — matches-everything filter constant
- `BRBloomFilter *BRBloomFilterNew(double falsePositiveRate, size_t elemCount, uint32_t tweak, uint8_t flags)`
- `BRBloomFilter *BRBloomFilterParse(const uint8_t *buf, size_t bufLen)`
- `size_t BRBloomFilterSerialize(const BRBloomFilter *filter, uint8_t *buf, size_t bufLen)`
- `int BRBloomFilterContainsData(const BRBloomFilter *filter, const uint8_t *data, size_t dataLen)`
- `void BRBloomFilterInsertData(BRBloomFilter *filter, const uint8_t *data, size_t dataLen)`
- `void BRBloomFilterFree(BRBloomFilter *filter)`
- Constants: `BLOOM_DEFAULT_FALSEPOSITIVE_RATE=0.0005`, `BLOOM_MAX_FILTER_LENGTH=36000`

### BRMerkleBlock.h / BRMerkleBlock.c
- `typedef struct BRMerkleBlock` — blockHash, powHash, version, prevBlock, merkleRoot, timestamp, target, nonce, totalTx, hashes, flags, height
- `BR_MERKLE_BLOCK_NONE` — empty block constant
- `BRMerkleBlock *BRMerkleBlockNew(void)`
- `BRMerkleBlock *BRMerkleBlockParse(const uint8_t *buf, size_t bufLen)`
- `size_t BRMerkleBlockSerialize(const BRMerkleBlock *block, uint8_t *buf, size_t bufLen)`
- `size_t BRMerkleBlockTxHashes(const BRMerkleBlock *block, UInt256 *txHashes, size_t hashesCount)`
- `void BRMerkleBlockSetTxHashes(BRMerkleBlock *block, const UInt256 hashes[], size_t hashesCount, const uint8_t *flags, size_t flagsLen)`
- `int BRMerkleBlockIsValid(const BRMerkleBlock *block, uint32_t currentTime)`
- `int BRMerkleBlockContainsTxHash(const BRMerkleBlock *block, UInt256 txHash)`
- `int BRMerkleBlockVerifyDifficulty(const BRMerkleBlock *block, const BRMerkleBlock *previous, uint32_t transitionTime)`
- `void BRMerkleBlockFree(BRMerkleBlock *block)`
- Constants: `MAX_PROOF_OF_WORK=0x1e0fffff`, `TARGET_TIMESPAN=0.10*24*60*60`, `BLOCK_DIFFICULTY_INTERVAL=144`
- Cross-platform logging: `digi_log(...)` → NSLog / __android_log_print / printf

### BRPeer.h / BRPeer.c
- `typedef struct BRPeer` — address (UInt128), port, services, timestamp, flags
- `BRPeer *BRPeerNew(void)` — allocate peer
- `void BRPeerSetCallbacks(BRPeer *peer, void *info, ...)` — set event callbacks
- `void BRPeerSetEarliestKeyTime(BRPeer *peer, uint32_t earliestKeyTime)`
- `void BRPeerSetCurrentBlockHeight(BRPeer *peer, uint32_t currentBlockHeight)`
- `void BRPeerConnect(BRPeer *peer)` — start TCP connection
- `void BRPeerDisconnect(BRPeer *peer)`
- `void BRPeerSendMessage(BRPeer *peer, const uint8_t *msg, size_t msgLen, const char *type)`
- `void BRPeerSendFilterload(BRPeer *peer, const uint8_t *filter, size_t filterLen)`
- `void BRPeerSendMempool(BRPeer *peer, ...)`
- `void BRPeerSendGetheaders(BRPeer *peer, const UInt256 locators[], size_t count, UInt256 hashStop)`
- `void BRPeerSendGetblocks(BRPeer *peer, const UInt256 locators[], size_t count, UInt256 hashStop)`
- `void BRPeerSendInv(BRPeer *peer, const UInt256 txHashes[], size_t txCount)`
- `void BRPeerSendGetdata(BRPeer *peer, ...)`
- `void BRPeerSendPing(BRPeer *peer, void *info, void (*pongCallback)(void *info, int success))`
- `void BRPeerSendVersionMessage(BRPeer *peer)` / `...VerackMessage` / `...Addr`
- `const char *BRPeerHost(BRPeer *peer)` — IP string
- `void BRPeerFree(BRPeer *peer)`
- Message protocol: `_BRPeerAcceptVersionMessage`, `...VerackMessage`, `...AddrMessage`, `...InvMessage`, `...TxMessage`, `...HeadersMessage`, `...GetaddrMessage`, `...GetdataMessage`, `...NotfoundMessage`, `...PingMessage`, `...PongMessage`, `...MerkleblockMessage`, `...RejectMessage`, `...FeeFilterMessage`
- Constants: `MAGIC_NUMBER=0xdab6c3fa`, `STANDARD_PORT=12024`, `PROTOCOL_VERSION=70015`, `USER_AGENT="/digiwallet:1.0.0/"`

### BRPeerManager.h / BRPeerManager.c
- `typedef struct BRPeerManagerStruct BRPeerManager` — opaque
- `BRPeerManager *BRPeerManagerNew(BRWallet *wallet, uint32_t earliestKeyTime, BRMerkleBlock *blocks[], size_t blocksCount, const BRPeer peers[], size_t peersCount)`
- `void BRPeerManagerSetCallbacks(BRPeerManager *manager, void *info, syncStarted, syncStopped, txStatusUpdate, saveBlocks, savePeers, networkIsReachable, threadCleanup)`
- `void BRPeerManagerSetFixedPeer(BRPeerManager *manager, UInt128 address, uint16_t port)`
- `int BRPeerManagerIsConnected(BRPeerManager *manager)`
- `void BRPeerManagerConnect(BRPeerManager *manager)`
- `void BRPeerManagerDisconnect(BRPeerManager *manager)`
- `void BRPeerManagerRescan(BRPeerManager *manager)`
- `uint32_t BRPeerManagerEstimatedBlockHeight(BRPeerManager *manager)`
- `uint32_t BRPeerManagerLastBlockHeight(BRPeerManager *manager)`
- `uint32_t BRPeerManagerLastBlockTimestamp(BRPeerManager *manager)`
- `double BRPeerManagerSyncProgress(BRPeerManager *manager, uint32_t startHeight)`
- `size_t BRPeerManagerPeerCount(BRPeerManager *manager)`
- `const char *BRPeerManagerDownloadPeerName(BRPeerManager *manager)`
- `void BRPeerManagerPublishTx(BRPeerManager *manager, BRTransaction *tx, void *info, void (*callback)(void *, int))`
- `size_t BRPeerManagerRelayCount(BRPeerManager *manager, UInt256 txHash)`
- `void BRPeerManagerFree(BRPeerManager *manager)`
- DNS seeds: `seed.digibyte.io`, `seed2.digibyte.io`, `seed3.digibyte.io`, `digiexplorer.info`
- Checkpoint array with heights, hashes, timestamps, targets
- Internal: `_BRPeerManagerFindPeers`, `_BRPeerManagerLoadBloomFilter`, `_BRPeerManagerUpdateFilter`, `_BRPeerManagerSyncStopped`, `_BRPeerManagerLoadMempools`, `_addressLookup`

### BRWallet.h / BRWallet.c
- `typedef struct BRUTXO` — hash (UInt256), n (uint32_t)
- `BRUTXOHash()`, `BRUTXOEq()` — inline hash/equality for UTXO set
- `typedef struct BRWalletStruct BRWallet` — opaque
- `BRWallet *BRWalletNew(BRTransaction *transactions[], size_t txCount, BRMasterPubKey mpk)`
- `void BRWalletSetCallbacks(BRWallet *wallet, void *info, balanceChanged, txAdded, txUpdated, txDeleted)`
- `size_t BRWalletUnusedAddrs(BRWallet *wallet, BRAddress addrs[], uint32_t gapLimit, int internal)`
- `BRAddress BRWalletReceiveAddress(BRWallet *wallet)`
- `size_t BRWalletAllAddrs(BRWallet *wallet, BRAddress addrs[], size_t addrsCount)`
- `int BRWalletContainsAddress(BRWallet *wallet, const char *addr)`
- `int BRWalletAddressIsUsed(BRWallet *wallet, const char *addr)`
- `uint64_t BRWalletBalance(BRWallet *wallet)`
- `uint64_t BRWalletTotalSent(BRWallet *wallet)` / `...TotalReceived`
- `size_t BRWalletUTXOs(BRWallet *wallet, BRUTXO utxos[], size_t utxosCount)`
- `uint64_t BRWalletFeePerKb(BRWallet *wallet)` / `void BRWalletSetFeePerKb(...)`
- `BRTransaction *BRWalletCreateTransaction(BRWallet *wallet, uint64_t amount, const char *addr)`
- `BRTransaction *BRWalletCreateTxForOutputs(BRWallet *wallet, const BRTxOutput outputs[], size_t outCount)`
- `int BRWalletSignTransaction(BRWallet *wallet, BRTransaction *tx, int forkId, const void *seed, size_t seedLen)`
- `int BRWalletContainsTransaction(BRWallet *wallet, const BRTransaction *tx)`
- `int BRWalletRegisterTransaction(BRWallet *wallet, BRTransaction *tx)`
- `void BRWalletRemoveTransaction(BRWallet *wallet, UInt256 txHash)`
- `BRTransaction *BRWalletTransactionForHash(BRWallet *wallet, UInt256 txHash)`
- `int BRWalletTransactionIsValid(...)` / `...IsPending(...)` / `...IsVerified(...)`
- `void BRWalletUpdateTransactions(BRWallet *wallet, const UInt256 txHashes[], size_t txCount, uint32_t blockHeight, uint32_t timestamp)`
- `void BRWalletSetTxUnconfirmedAfter(BRWallet *wallet, uint32_t blockHeight)`
- `uint64_t BRWalletAmountReceivedFromTx(...)` / `...AmountSentByTx(...)` / `...FeeForTx(...)`
- `uint64_t BRWalletBalanceAfterTx(...)` / `...FeeForTxSize(...)` / `...FeeForTxAmount(...)`
- `uint64_t BRWalletMinOutputAmount(...)` / `...MaxOutputAmount(...)`
- `void BRWalletFree(BRWallet *wallet)`
- `int64_t BRLocalAmount(int64_t amount, double price)` — fiat conversion
- `int64_t BRBitcoinAmount(int64_t localAmount, double price)` — reverse conversion
- Constants: `DEFAULT_FEE_PER_KB=10000000`, `MIN_FEE_PER_KB=10000000`, `MAX_FEE_PER_KB=100000000`

### BRPaymentProtocol.h / BRPaymentProtocol.c
- `typedef struct BRPaymentProtocolDetails` — network, outputs, time, expires, memo, paymentURL, merchantData
- `typedef struct BRPaymentProtocolRequest` — version, pkiType, pkiData, details, signature
- `typedef struct BRPaymentProtocolPayment` — merchantData, transactions, refundTo, memo
- `typedef struct BRPaymentProtocolACK` — payment, memo
- `typedef struct BRPaymentProtocolInvoiceRequest` — senderPubKey, amount, pkiType, pkiData, memo, notifyUrl, signature
- `typedef enum BRPaymentProtocolMessageType` — InvoiceRequest, PaymentRequest, Payment, PaymentACK
- `typedef struct BRPaymentProtocolMessage` — msgType, message, statusCode, statusMsg, identifier
- `typedef struct BRPaymentProtocolEncryptedMessage` — msgType, encrypted msg, receiverPubKey, senderPubKey, nonce, signature, identifier, statusCode, statusMsg
- Each type has `New()`, `Parse()`, `Serialize()`, `Free()` functions
- Additional: `BRPaymentProtocolRequestCert()`, `BRPaymentProtocolRequestDigest()`, `BRPaymentProtocolInvoiceRequestCert()`, `BRPaymentProtocolInvoiceRequestDigest()`
- Internal protobuf parser: `_ProtoBufVarInt`, `_ProtoBufLenDelim`, `_ProtoBufField`, etc.

### BRSet.h / BRSet.c
- `typedef struct BRSetStruct BRSet` — opaque hash set
- `BRSet *BRSetNew(hash_fn, eq_fn, capacity)`
- `void *BRSetAdd(BRSet *set, void *item)` — add/replace, returns replaced item
- `void *BRSetRemove(BRSet *set, const void *item)` — returns removed item
- `void BRSetClear(BRSet *set)`
- `size_t BRSetCount(const BRSet *set)`
- `int BRSetContains(const BRSet *set, const void *item)`
- `int BRSetIntersects(const BRSet *set, const BRSet *otherSet)`
- `void *BRSetGet(const BRSet *set, const void *item)` — lookup
- `void *BRSetIterate(const BRSet *set, const void *previous)` — iterate
- `size_t BRSetAll(const BRSet *set, void *allItems[], size_t count)` — dump all
- `void BRSetApply(const BRSet *set, void *info, void (*apply)(void *, void *))` — for-each
- `void BRSetUnion(BRSet *set, const BRSet *otherSet)`
- `void BRSetMinus(BRSet *set, const BRSet *otherSet)`
- `void BRSetIntersect(BRSet *set, const BRSet *otherSet)`
- `void BRSetFree(BRSet *set)`

### test.c
- Comprehensive test suite covering all modules
- Tests: SHA1, SHA256, SHA512, RIPEMD160, MD5, Base58, BIP39, BIP32, BIP38, ECDSA sign/verify, bloom filters, merkle blocks, transactions, wallet, payment protocol, peer manager
- Includes SPV sync integration test
- `#define SKIP_BIP38 1` — BIP38 tests slow (scrypt)

### module.modulemap
- Defines `BRCore` module for Swift/Clang import
- Includes all BR*.h headers and secp256k1 textual headers
- `export *` — re-exports everything

---

## secp256k1/ — Bundled libsecp256k1

Git submodule providing elliptic curve cryptography for secp256k1.

### secp256k1/include/secp256k1.h
- Main public API: context create/destroy, EC pubkey parse/serialize, ECDSA sign/verify, secret key verify/negate
- `secp256k1_context_create()`, `secp256k1_ecdsa_sign()`, `secp256k1_ecdsa_verify()`, `secp256k1_ec_pubkey_create()`

### secp256k1/include/secp256k1_recovery.h
- ECDSA recovery: `secp256k1_ecdsa_sign_recoverable()`, `secp256k1_ecdsa_recover()`

### secp256k1/include/secp256k1_ecdh.h
- ECDH: `secp256k1_ecdh()` — compute shared secret

### secp256k1/src/secp256k1.c
- Main implementation file (includes all *_impl.h files)

### secp256k1/src/ (implementation headers)
- `field.h` / `field_impl.h` — finite field arithmetic (10x26 and 5x52 representations)
- `group.h` / `group_impl.h` — EC group operations (point add, double, etc.)
- `scalar.h` / `scalar_impl.h` — scalar arithmetic (4x64 and 8x32 representations)
- `ecmult.h` / `ecmult_impl.h` — EC multiplication (multi-exp, wNAF)
- `ecmult_gen.h` / `ecmult_gen_impl.h` — EC generator multiplication (blinded)
- `ecmult_const.h` / `ecmult_const_impl.h` — constant-time EC multiplication
- `ecdsa.h` / `ecdsa_impl.h` — ECDSA sign/verify implementation
- `eckey.h` / `eckey_impl.h` — EC key operations
- `hash.h` / `hash_impl.h` — SHA-256 for internal use
- `num.h` / `num_impl.h` / `num_gmp.h` / `num_gmp_impl.h` — bignum (GMP backend)
- `util.h` — utility macros
- `testrand.h` / `testrand_impl.h` — test random generator
- `basic-config.h` — minimal compile config (no GMP, no ASM)

### secp256k1/src/modules/
- `recovery/main_impl.h` — recoverable signature implementation
- `ecdh/main_impl.h` — ECDH implementation

### secp256k1/src/asm/
- `field_10x26_arm.s` — ARM assembly for field arithmetic

### secp256k1/src/java/
- JNI bindings: `org_bitcoin_NativeSecp256k1.{c,h}`, `org_bitcoin_Secp256k1Context.{c,h}`
- Java classes: `NativeSecp256k1.java`, `NativeSecp256k1Test.java`, `NativeSecp256k1Util.java`, `Secp256k1Context.java`

### secp256k1/src/tests.c / tests_exhaustive.c / bench_*.c
- Test suite and benchmarks (sign, verify, recover, ECDH, internal ops)

### secp256k1/contrib/
- `lax_der_parsing.{c,h}` — relaxed DER signature parsing
- `lax_der_privatekey_parsing.{c,h}` — relaxed private key parsing

### secp256k1/sage/
- `secp256k1.sage`, `group_prover.sage`, `weierstrass_prover.sage` — Sage math proofs

### secp256k1/ (build files)
- `configure.ac`, `Makefile.am`, `autogen.sh`, `libsecp256k1.pc.in`
- `build-aux/m4/` — autoconf macros (bitcoin_secp.m4, ax_jni_include_dir.m4, ax_prog_cc_for_build.m4)

---

## Metadata Files

### .gitignore
- Build artifacts exclusion

### .gitmodules
- secp256k1 submodule reference

### LICENSE
- MIT License (breadwallet LLC)

### README.md
- Brief description: "SPV bitcoin C library"
