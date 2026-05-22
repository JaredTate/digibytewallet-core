# DigiByte Wallet Core Repo Map

Last refreshed: 2026-05-22
Compatibility target: DigiByte Core `v8.26.2` for public DigiByte SPV behavior, plus RC41/testnet25 DigiDollar bring-up

## Core Utility Files

- `BRInt.h` - UInt128/160/256/512 unions, endian helpers, hex conversion, fixed integer utilities.
- `BRArray.h` - Header-only dynamic array macros used throughout the library.
- `BRSet.h`, `BRSet.c` - Generic hash set used for peers, blocks, UTXOs, transactions, and checkpoints.

## Crypto And Encoding

- `BRCrypto.h`, `BRCrypto.c` - SHA family, RIPEMD160, HASH160, HMAC, HMAC-DRBG, PBKDF2, scrypt, ChaCha20, Poly1305, Murmur3, DigiByte multi-algo helpers.
- `crypto/`, `crypto/sha3/` - Groestl, Skein, Qubit, Odocrypt, and SHA3-family implementations used by DigiByte header validation.
- `BRBase58.h`, `BRBase58.c` - Base58 and Base58Check encode/decode.
- `BRKey.h`, `BRKey.c` - secp256k1 key handling, WIF import/export, ECDSA signing/verification, compact signatures, ECDH, BIP340 Schnorr, x-only keys, and Taproot output keys.
- `secp256k1/` - Bundled secp256k1 implementation and headers included by `BRKey.c`.

## Wallet Derivation

- `BRBIP39Mnemonic.h`, `BRBIP39Mnemonic.c` - BIP39 phrase encode/decode/validate and seed derivation.
- `BRBIP39WordsEn.h` - English BIP39 word list.
- `BRBIP32Sequence.h`, `BRBIP32Sequence.c` - DigiByte mobile HD path `m/0H/chain/index`, external/internal chain derivation, API auth and BitID keys.
- `BRBIP38Key.h`, `BRBIP38Key.c` - BIP38 encrypted key import/export and intermediate-code flows.

## Address And Script Handling

- `BRAddress.h`, `BRAddress.c` - Base58Check and Bech32 address validation, hash160 extraction, witness/Taproot script handling, scriptPubKey/scriptSig address extraction, varint helpers, script push helpers.
- v8.26.2 constants audited here: mainnet P2PKH `30`, legacy P2SH-old `5`, testnet P2PKH `126`, testnet P2SH `140`.
- Taproot output-key support is present for DigiDollar token outputs and collateral spends.

## Transactions And Wallet State

- `BRTransaction.h`, `BRTransaction.c` - Transaction parse/serialize, txid/wtxid calculation, witness data, input/output mutation, output shuffling, standard fee helper, ECDSA signing, Taproot key-path sighash, and Taproot script-path sighash.
- `BRWallet.h`, `BRWallet.c` - Wallet ownership, address discovery, UTXO selection, DGB and DigiDollar balance/accounting, transaction creation/signing, callback registration, fee bounds.
- Important constants: `MAX_MONEY = 21,000,000,000 * SATOSHIS`, `TX_FEE_PER_KB = 5000`, `TX_MIN_OUTPUT_AMOUNT = 100000001`, wallet fee bounds `10,000,000` to `100,000,000` sat/kB.

## DigiAsset And DigiDollar

- `BRAssetData.h`, `BRAssetData.c` - DigiAsset metadata structures used by inherited mobile asset paths.
- `BRDigiAsset.h`, `BRDigiAsset.c` - DigiAsset helper parsing and wallet integration support.
- `BRDigiDollar.h`, `BRDigiDollar.c` - DigiDollar TD/DD address encoding, transaction version markers, mint/transfer/redeem OP_RETURN builders/parsers, lock-tier policy, DCA/ERR math, P2TR token scripts, collateral Taproot trees, leaf hashes, and control blocks.
- `BRWalletCreateDigiDollarTransfer()` - Builds a DD transfer with wallet-owned DD token inputs, DD change, OP_RETURN metadata, and DGB fee inputs.
- `BRWalletCreateDigiDollarMint()` - Builds a mint transaction with collateral P2TR output, DD token output, mint OP_RETURN, and DGB fee/change outputs.
- `BRWalletCreateDigiDollarRedeem()` - Builds a full-position vault redeem transaction with collateral input first, DD burn inputs, collateral return, optional DD change, and DGB fee/change outputs.

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
- `test.c` - Standalone C harness covering key, DigiDollar protocol, wallet accounting, mint/transfer/redeem builders, and transaction signing vectors.
- `README.md`, `LICENSE` - Project metadata.

## v8.26.2 Compatibility Findings

- Basic legacy mainnet SPV parameters now align with DigiByte Core `v8.26.2`.
- Testnet magic, port, address prefixes, and WIF were stale and have been corrected.
- Protocol `70019` matters because `v8.26.2` disconnects peers below `70017`.
- DigiByte max supply sanity checks were stale at Bitcoin's 21M value and have been corrected to 21B DGB.
- Remaining gaps are architectural rather than one-line constants: mobile does not run a DigiDollar oracle, live RC41 mint/redeem needs funded test wallets, seed/checkpoint strategy still needs refresh, and BIP37 reliance remains a peer-availability risk.
