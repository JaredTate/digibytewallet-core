# DigiByte Wallet Core Architecture

Last refreshed: 2026-05-21
Compatibility target: DigiByte Core `v8.26.2`

## Executive Summary

`digibytewallet-core` is a compact C SPV wallet library derived from breadwallet-core. It is embedded by the mobile wallets through Swift/Clang modules on iOS and JNI/CMake on Android. It is not a DigiByte Core full node: it has no UTXO set, RPC server, mempool, compact block filter index, descriptor wallet, Taproot wallet, or DigiDollar logic.

The library preserves the original mobile SPV model: BIP39 mnemonic seed, breadwallet-style BIP32 derivation, legacy address/transaction creation, BIP37 bloom filters, merkleblock verification, and direct DigiByte P2P peer connections.

## System Boundaries

```
host mobile app
  |
  | C API + callbacks
  v
BRWallet <-> BRPeerManager <-> BRPeer <-> DigiByte P2P network
  |              |
  |              +-- DNS/fixed peer discovery, headers, merkleblock, tx relay
  |
  +-- BRTransaction, BRAddress, BRKey, BRBIP32Sequence, BRBIP39Mnemonic
```

The host application owns secure storage, SQLite persistence, UI, app lifecycle, reachability checks, fee/rate APIs, and platform logging. The C core owns deterministic keys, address/script handling, transaction serialization/signing, peer protocol messages, BIP37 filters, checkpoint storage, and wallet accounting.

## Directory Structure

```
digibytewallet-core/
├── BRAddress.*           # Base58 address/script handling
├── BRArray.h             # Header-only growable array macros
├── BRBase58.*            # Base58/Base58Check
├── BRBIP32Sequence.*     # HD derivation, m/0H/chain/index
├── BRBIP38Key.*          # Encrypted private keys
├── BRBIP39Mnemonic.*     # Mnemonic validation and seed derivation
├── BRBIP39WordsEn.h      # English BIP39 word list
├── BRBloomFilter.*       # BIP37 bloom filters
├── BRCrypto.*            # Hashes, HMAC, PBKDF2, scrypt, ChaCha/Poly1305
├── BRInt.h               # UInt128/160/256/512 and endian helpers
├── BRKey.*               # secp256k1 key, WIF, ECDSA, compact signatures
├── BRMerkleBlock.*       # Block header and merkle proof handling
├── BRPaymentProtocol.*   # BIP70/BIP75-era payment protocol
├── BRPeer.*              # One P2P connection
├── BRPeerManager.*       # SPV sync, peers, checkpoints, bloom filters
├── BRSet.*               # Generic hash set
├── BRTransaction.*       # Legacy tx parse/serialize/sign
├── BRWallet.*            # UTXO accounting and tx creation
├── module.modulemap      # Clang/Swift module definition
├── test.c                # Standalone C test harness
└── secp256k1/            # Bundled secp256k1 source
```

## Key Components

### Wallet

`BRWallet` tracks wallet transactions, UTXOs, balances, internal/external address indexes, fees, and callbacks. It derives keys from the seed only when signing and zeroes temporary key arrays after use.

### Keys And Mnemonics

`BRBIP39Mnemonic` implements standard BIP39 phrase checks and PBKDF2-HMAC-SHA512 seed derivation. `BRBIP32Sequence` uses the legacy DigiByte mobile path `m/0H/chain/index` with seed key string `"DigiByte seed"`. This is intentionally not BIP44 `m/44'/20'/...`; changing it would break existing wallet recovery.

### Transactions

`BRTransaction` supports legacy non-witness transaction serialization and ECDSA `SIGHASH_ALL` signing. It does not create SegWit witnesses, Taproot key/script spends, Schnorr signatures, PSBTs, descriptors, or DigiDollar transactions.

### SPV Networking

`BRPeer` speaks the DigiByte P2P protocol over TCP. `BRPeerManager` discovers peers, filters for full nodes with bloom support, loads BIP37 filters, syncs headers/merkleblocks, publishes transactions, and persists peers/blocks through host callbacks.

### Merkle Blocks And PoW

`BRMerkleBlock` parses headers and merkleblock payloads, validates merkle roots, timestamp drift, compact target range, and `powHash <= target`. The historical implementation is not a complete modern DigiByte multi-algo verifier; mobile SPV security depends on checkpoints, peer diversity, and merkle inclusion rather than full validation.

## DigiByte Core v8.26.2 Compatibility

| Surface | v8.26.2 value | wallet-core status |
| --- | --- | --- |
| Mainnet message start | `fa c3 b6 da` | Matches |
| Testnet message start | `fd c8 bd dd` | Corrected |
| Mainnet P2P port | `12024` | Matches |
| Testnet P2P port | `12026` | Corrected |
| Protocol version | `70019` | Corrected |
| Minimum peer protocol | `70017` | Corrected |
| Mainnet P2PKH | `30` | Matches |
| Mainnet legacy P2SH-old | `5` | Matches |
| Testnet P2PKH/P2SH | `126` / `140` | Corrected |
| Mainnet/testnet WIF | `128` / `254` | Corrected for testnet |
| DigiByte max money | `21,000,000,000 DGB` | Corrected |
| DNS seeds | Core has several maintained seeds | This standalone repo has weak/old seed coverage |
| Bech32/SegWit/Taproot | `dgb`, `dgbt`, Taproot active | Not implemented in this standalone core |
| BIP37 | Supported only by peers advertising bloom | Core uses BIP37 and filters for bloom peers |

The current public stable compatibility target is `v8.26.2`. Newer `v9.26.0-rc*` releases are DigiDollar testnet/release-candidate work and are intentionally not used as this wallet's protocol baseline.

## Data Flow

1. The host app obtains or creates a BIP39 phrase and stores it securely.
2. `BRBIP39DeriveKey()` derives the seed.
3. `BRBIP32MasterPubKey()` derives the master public key for watch-only address generation.
4. `BRWallet` derives external/internal addresses and tracks known transactions.
5. The host app rehydrates transactions, peers, and merkle blocks from SQLite.
6. `BRPeerManager` selects a checkpoint/start block, discovers peers, and opens P2P connections.
7. Bloom filters are loaded; matching `merkleblock` and `tx` messages update wallet state.
8. Outgoing transactions are signed by `BRWalletSignTransaction()` and published through connected peers.

## Build Notes

The standalone repository can be compiled as plain C, but the legacy `test.c` harness still contains stale breadwallet/DigiByte fixtures and is not a reliable release gate without fixture cleanup. The iOS and Android repos embed their own detached copies of this core; those embedded copies must be audited separately before mobile release.

## Design Patterns

- Flat C API with opaque structs for wallet and peer-manager ownership.
- Callback-driven persistence and UI notifications.
- Header-only generic containers for portability.
- Compile-time network selection through `BITCOIN_TESTNET`.
- No background threads are hidden from the host; cleanup callbacks are provided for platform runtimes.

## Known Risks

- The standalone core lacks current Bech32/SegWit/Taproot wallet support.
- Multi-algo PoW and DigiByte difficulty validation are incomplete for a modern adversarial SPV threat model.
- BIP37 peer availability is limited because many modern nodes disable bloom filters by default.
- DNS seeds and checkpoints are much weaker than DigiByte Core `v8.26.2`.
- The standalone repo is not automatically the exact core compiled by iOS/Android; mobile embedded copies must stay synchronized deliberately.
