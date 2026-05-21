# DigiByte Wallet Core Repo Map

Last refreshed: 2026-05-21
Compatibility target: DigiByte Core `v8.26.2`

## Core Utility Files

- `BRInt.h` - UInt128/160/256/512 unions, endian helpers, hex conversion, fixed integer utilities.
- `BRArray.h` - Header-only dynamic array macros used throughout the library.
- `BRSet.h`, `BRSet.c` - Generic hash set used for peers, blocks, UTXOs, transactions, and checkpoints.

## Crypto And Encoding

- `BRCrypto.h`, `BRCrypto.c` - SHA family, RIPEMD160, HASH160, HMAC, HMAC-DRBG, PBKDF2, scrypt, ChaCha20, Poly1305, Murmur3.
- `BRBase58.h`, `BRBase58.c` - Base58 and Base58Check encode/decode.
- `BRKey.h`, `BRKey.c` - secp256k1 key handling, WIF import/export, ECDSA signing/verification, compact signatures, ECDH.
- `secp256k1/` - Bundled secp256k1 implementation and headers included by `BRKey.c`.

## Wallet Derivation

- `BRBIP39Mnemonic.h`, `BRBIP39Mnemonic.c` - BIP39 phrase encode/decode/validate and seed derivation.
- `BRBIP39WordsEn.h` - English BIP39 word list.
- `BRBIP32Sequence.h`, `BRBIP32Sequence.c` - DigiByte mobile HD path `m/0H/chain/index`, external/internal chain derivation, API auth and BitID keys.
- `BRBIP38Key.h`, `BRBIP38Key.c` - BIP38 encrypted key import/export and intermediate-code flows.

## Address And Script Handling

- `BRAddress.h`, `BRAddress.c` - Base58Check address validation, hash160 extraction, scriptPubKey/scriptSig address extraction, varint helpers, script push helpers.
- v8.26.2 constants audited here: mainnet P2PKH `30`, legacy P2SH-old `5`, testnet P2PKH `126`, testnet P2SH `140`.
- This standalone core does not implement Bech32/SegWit/Taproot address creation.

## Transactions And Wallet State

- `BRTransaction.h`, `BRTransaction.c` - Legacy transaction parse/serialize, txid calculation, input/output mutation, output shuffling, standard fee helper, ECDSA signing.
- `BRWallet.h`, `BRWallet.c` - Wallet ownership, address discovery, UTXO selection, balance/accounting, transaction creation/signing, callback registration, fee bounds.
- Important constants: `MAX_MONEY = 21,000,000,000 * SATOSHIS`, `TX_FEE_PER_KB = 5000`, `TX_MIN_OUTPUT_AMOUNT = 100000001`, wallet fee bounds `10,000,000` to `100,000,000` sat/kB.

## SPV Blocks And Filters

- `BRBloomFilter.h`, `BRBloomFilter.c` - BIP37 filter creation, serialization, insertion, matching, and cleanup.
- `BRMerkleBlock.h`, `BRMerkleBlock.c` - Merkleblock parse/serialize, tx hash extraction, merkle proof validation, timestamp/target checks, block hash tracking.

## P2P Networking

- `BRPeer.h`, `BRPeer.c` - Single peer socket lifecycle, message serialization, `version/verack`, `addr`, `inv`, `getdata`, `getheaders`, `getblocks`, `headers`, `merkleblock`, `tx`, `mempool`, `filterload`, `filteradd`, `filterclear`, `ping/pong`, `reject`, `feefilter`.
- Current constants after this audit: mainnet magic `0xdab6c3fa`, testnet magic `0xddbdc8fd`, mainnet port `12024`, testnet port `12026`, protocol `70019`, minimum peer protocol `70017`, user agent `/digiwallet:1.0.0/`.
- `BRPeerManager.h`, `BRPeerManager.c` - Peer discovery, fixed-peer support, checkpoint/block/orphan sets, bloom filter loading, sync state, peer callbacks, transaction publish callbacks.

## Payment Protocol

- `BRPaymentProtocol.h`, `BRPaymentProtocol.c` - BIP70/BIP75-era payment request/details/payment/ack/invoice structures, protobuf-style serialization, certificate digest helpers, encrypted payment message helpers.

## Integration Files

- `module.modulemap` - Clang module definition for Swift import as `BRCore`.
- `test.c` - Legacy standalone test harness; useful for compile smoke tests, but fixtures need refresh before treating it as a correctness gate.
- `README.md`, `LICENSE` - Project metadata.

## v8.26.2 Compatibility Findings

- Basic legacy mainnet SPV parameters now align with DigiByte Core `v8.26.2`.
- Testnet magic, port, address prefixes, and WIF were stale and have been corrected.
- Protocol `70019` matters because `v8.26.2` disconnects peers below `70017`.
- DigiByte max supply sanity checks were stale at Bitcoin's 21M value and have been corrected to 21B DGB.
- Remaining gaps are architectural rather than one-line constants: no SegWit/Taproot/Schnorr wallet support, incomplete multi-algo PoW verification, stale seed/checkpoint strategy, and BIP37 reliance.
