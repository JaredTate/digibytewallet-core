# DigiByte Wallet Core — Architecture

## Executive Summary

**digibytewallet-core** is a pure C library implementing SPV (Simplified Payment Verification) functionality for the DigiByte blockchain. Forked from [breadwallet-core](https://github.com/breadwallet/breadwallet-core), it provides all cryptographic primitives, transaction handling, peer-to-peer networking, and wallet management needed by the DigiByte mobile wallets (iOS and Android).

The library is designed to be embedded directly into platform-specific apps via Swift module maps (iOS) or JNI bridges (Android), with zero external dependencies beyond the bundled `secp256k1` elliptic curve library.

## System Overview

```
┌─────────────────────────────────────────────────────┐
│              Mobile App (iOS / Android)              │
│         Swift/ObjC bridge  or  JNI bridge           │
└──────────────────────┬──────────────────────────────┘
                       │ C API
┌──────────────────────▼──────────────────────────────┐
│                  digibytewallet-core                 │
│                                                     │
│  ┌─────────────┐  ┌──────────────┐  ┌────────────┐ │
│  │  BRWallet    │  │ BRPeerManager│  │ BRPayment  │ │
│  │  (UTXO mgmt, │  │ (SPV sync,   │  │ Protocol   │ │
│  │   balances,  │  │  block relay, │  │ (BIP70/75) │ │
│  │   tx create) │  │  peer disco.) │  │            │ │
│  └──────┬───────┘  └──────┬───────┘  └────────────┘ │
│         │                 │                          │
│  ┌──────▼─────────────────▼───────────────────────┐ │
│  │          Core Primitives                        │ │
│  │  BRTransaction  BRMerkleBlock  BRBloomFilter    │ │
│  │  BRAddress      BRKey          BRCrypto         │ │
│  │  BRBase58       BRBIP32Seq     BRBIP39Mnemonic  │ │
│  │  BRBIP38Key     BRInt          BRSet  BRArray   │ │
│  └──────────────────────┬─────────────────────────┘ │
│                         │                            │
│  ┌──────────────────────▼─────────────────────────┐ │
│  │              secp256k1 (libsecp256k1)           │ │
│  │    Elliptic curve operations, ECDSA signing     │ │
│  └────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────┘
              │
              ▼ TCP/IP
    DigiByte P2P Network (port 12024)
```

## Directory Structure

```
digibytewallet-core/
├── BR*.h / BR*.c          # Core library (16 modules, 32 files)
├── BRInt.h                # Large integer types (UInt128/160/256/512)
├── BRArray.h              # Growable array macros (header-only)
├── BRSet.{h,c}            # Hash set data structure
├── BRCrypto.{h,c}         # SHA1/256/384/512, RIPEMD160, HMAC, PBKDF2, etc.
├── BRBase58.{h,c}         # Base58 / Base58Check encoding
├── BRKey.{h,c}            # EC key operations (secp256k1 wrapper)
├── BRBIP32Sequence.{h,c}  # HD key derivation (BIP32)
├── BRBIP38Key.{h,c}       # Encrypted private keys (BIP38)
├── BRBIP39Mnemonic.{h,c}  # Mnemonic seed phrases (BIP39)
├── BRBIP39WordsEn.h       # English BIP39 word list (2048 words)
├── BRAddress.{h,c}        # Address encoding/decoding, script parsing
├── BRTransaction.{h,c}    # Transaction creation, serialization, signing
├── BRBloomFilter.{h,c}    # Bloom filters (BIP37)
├── BRMerkleBlock.{h,c}    # Block headers + merkle proof validation
├── BRPeer.{h,c}           # P2P peer connection and message handling
├── BRPeerManager.{h,c}    # SPV sync, peer discovery, block chain mgmt
├── BRWallet.{h,c}         # Wallet: UTXO set, balance, tx creation
├── BRPaymentProtocol.{h,c}# BIP70/BIP75 payment protocol
├── module.modulemap        # Swift/Clang module definition (BRCore)
├── test.c                  # Comprehensive test suite
├── secp256k1/              # Bundled libsecp256k1 (git submodule)
│   ├── src/                # EC math, ECDSA, field arithmetic
│   ├── include/            # Public API headers
│   ├── contrib/            # Lax DER parsing helpers
│   └── src/modules/        # ECDH and recovery modules
├── LICENSE                 # MIT License
└── README.md               # Brief description
```

## Key Components

### Cryptographic Primitives (`BRCrypto`)
Hash functions (SHA-1/224/256/384/512, RIPEMD-160, MD5), HMAC-SHA256/512, PBKDF2, DRBGs, and AES-ECB. All implemented in pure C with no external dependencies.

### Key Management (`BRKey`, `BRBIP32Sequence`, `BRBIP38Key`, `BRBIP39Mnemonic`)
- **BRKey**: Wraps secp256k1 for EC key pairs — sign, verify, ECDH, compact signatures, WIF import/export
- **BRBIP32Sequence**: HD wallet key derivation from master seed. Default path `m/0H/chain/index`
- **BRBIP38Key**: Passphrase-encrypted private keys with EC multiply mode support
- **BRBIP39Mnemonic**: Mnemonic phrase encode/decode/verify with PBKDF2-based seed derivation

### Address & Encoding (`BRAddress`, `BRBase58`)
- DigiByte pubkey address prefix: **30** (vs Bitcoin's 0), script prefix: **5**
- Varint encoding, script parsing (P2PKH, P2SH), output script generation
- Base58 and Base58Check encode/decode

### Transaction Handling (`BRTransaction`)
- UTXO-based inputs/outputs with full serialization/deserialization
- Transaction signing with SIGHASH_ALL
- Fee estimation: `TX_FEE_PER_KB = 5000`, min output `100000001` satoshis
- Max tx size 100KB, lock time support

### Wallet (`BRWallet`)
- UTXO management with efficient hash-based lookups
- Balance calculation, fee-per-KB configuration (default 10000000)
- Address generation with gap limit (external: 10, internal: 5)
- Callback-based notifications for balance changes, tx updates

### SPV Networking (`BRPeer`, `BRPeerManager`)
- **BRPeer**: TCP socket connection to DigiByte nodes (port 12024), full message protocol (version, verack, inv, tx, headers, getblocks, getdata, merkleblock, ping/pong, etc.)
- **BRPeerManager**: Manages up to 3 simultaneous peer connections, handles blockchain sync, block validation, bloom filter management, transaction broadcast and relay

### Block Validation (`BRMerkleBlock`, `BRBloomFilter`)
- Merkle block parsing with proof-of-inclusion verification
- Separate `blockHash` and `powHash` fields (DigiByte multi-algo support)
- Bloom filters (BIP37) for SPV transaction filtering

### Payment Protocol (`BRPaymentProtocol`)
- BIP70 payment requests and payment/payment-ack messages
- BIP75 encrypted payment protocol with x509 certificate validation

### Data Structures (`BRSet`, `BRArray`, `BRInt`)
- **BRSet**: Generic hash set with function-pointer-based hash/equality
- **BRArray**: Macro-based growable arrays with type checking
- **BRInt**: Union types for UInt128, UInt160, UInt256, UInt512 with endian conversion helpers

## Data Flow

```
Mnemonic Phrase
    │ BRBIP39DeriveKey()
    ▼
512-bit Seed
    │ BRBIP32MasterPubKey()
    ▼
Master Public Key ──► BRWallet (address generation, UTXO tracking)
                          │
                          │ BRPeerManager (SPV sync)
                          ▼
              DigiByte P2P Network
              ├── getblocks / getheaders
              ├── merkleblock (filtered blocks)
              ├── tx (broadcast / receive)
              └── bloom filter updates
```

## Configuration

### Network Parameters (compile-time)
| Parameter | Mainnet | Testnet |
|-----------|---------|---------|
| Pubkey prefix | 30 | 111 |
| Script prefix | 5 | 196 |
| Standard port | 12024 | 12024 |
| Magic bytes | Set in BRPeer.c | — |

### Build Integration
- **iOS**: Import via `module.modulemap` as `BRCore` Swift module. Include `secp256k1/src/basic-config.h` and `secp256k1/src/secp256k1.c` as textual headers.
- **Android**: Compile as native library via NDK, bridge through JNI.
- **Standalone test**: Compile `test.c` with all `.c` files and link.

## Key Technical Decisions

1. **Pure C with no dependencies** — Maximum portability across iOS, Android, and embedded targets
2. **Header-only data structures** — `BRArray` and `BRInt` are entirely in headers for zero-cost abstraction
3. **Callback-based architecture** — Wallet, PeerManager, and Peer all use function-pointer callbacks, allowing platform-specific integration without modifying core code
4. **Separate powHash field** — DigiByte's multi-algorithm PoW requires distinct block hash and proof-of-work hash (unlike Bitcoin's single hash)
5. **Bundled secp256k1** — Included as git submodule to avoid external dependency management
6. **Thread-safety via platform callbacks** — `threadCleanup` callback lets platforms handle thread lifecycle
7. **Cross-platform logging** — Compile-time macros route `digi_log()` to NSLog (iOS), Android log, or printf
