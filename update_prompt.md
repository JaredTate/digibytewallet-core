# DigiByte Mobile Wallet Resurrection Prompt

## Purpose

The DigiByte mobile wallet stack has been dormant for years and needs to be brought back to life without losing the original SPV wallet model. The goal is to document the three codebases clearly, then get the iOS and Android wallets building, launching, and connecting to the public DigiByte network again.

This work must align the mobile wallets with the latest stable public DigiByte Core `v8.26.x` release line on GitHub, not the experimental DigiDollar/RC branch. Before changing wallet code, verify the exact current stable `v8.26.x` tag from `https://github.com/DigiByte-Core/digibyte` and use that release line as the protocol compatibility target.

The end state is a maintainable resurrection path: updated architecture docs, accurate repo maps, a working iOS wallet on this computer, a working Android wallet on this computer, and a clear record of every build/runtime blocker fixed along the way. Keep the work pragmatic: prove the apps compile and run first, then fix network compatibility, dependency rot, and platform toolchain breakage.

## Local Repositories

Use these exact local paths:

- Core wallet library: `/home/jared/Code/digibytewallet-core`
- iOS wallet: `/home/jared/Code/digibytewallet-ios`
- Android wallet: `/home/jared/Code/digibytewallet-android`
- DigiByte Core reference repo: `/home/jared/Code/digibyte`

Current wallet remotes:

- `digibytewallet-core`
  - `origin`: `https://github.com/JaredTate/digibytewallet-core.git`
  - `upstream`: `https://github.com/DigiByte-Core/digibytewallet-core.git`
  - usual local branch: `dev`
- `digibytewallet-ios`
  - `origin`: `https://github.com/JaredTate/digibytewallet-ios.git`
  - `upstream`: `https://github.com/DigiByte-Core/digibytewallet-ios.git`
  - usual local branch: `develop`
- `digibytewallet-android`
  - `origin`: `https://github.com/JaredTate/digibytewallet-android.git`
  - `upstream`: `https://github.com/DigiByte-Core/digibytewallet-android.git`
  - usual local branch: `master`

Do not push to GitHub. Commit locally only when a coherent step is complete.

## Source Material To Read First

Use the main DigiByte Core repo documentation style as the model. These files are mandatory references, not optional background. Read them first and explicitly use them to shape the wallet docs:

1. `/home/jared/Code/digibyte/ARCHITECTURE.md`
2. `/home/jared/Code/digibyte/REPO_MAP.md`
3. `/home/jared/Code/digibyte/DIGIDOLLAR_ARCHITECTURE.md`
4. `/home/jared/Code/digibyte/REPO_MAP_DIGIDOLLAR.md`

For the mobile-wallet documentation pass, mirror the useful structure from `/home/jared/Code/digibyte/ARCHITECTURE.md` and `/home/jared/Code/digibyte/REPO_MAP.md`: executive summary, system boundaries, directory structure, key components, data flow, configuration/build notes, design patterns, and a practical file/module map. Do not copy DigiByte Core content blindly; adapt the structure to each wallet repo's actual code.

Then audit the existing wallet docs, refreshing or replacing them if stale:

1. `/home/jared/Code/digibytewallet-core/ARCHITECTURE.md`
2. `/home/jared/Code/digibytewallet-core/REPO_MAP.md`
3. `/home/jared/Code/digibytewallet-ios/ARCHITECTURE.md`
4. `/home/jared/Code/digibytewallet-ios/REPO_MAP.md`
5. `/home/jared/Code/digibytewallet-android/ARCHITECTURE.md`
6. `/home/jared/Code/digibytewallet-android/REPO_MAP.md`

## Agent Team Operating Model

Use up to five sub-agents. Keep each sub-agent scoped to a repo or responsibility and require concrete file-path outputs.

- Agent 1, core/library: audit `digibytewallet-core`, refresh `ARCHITECTURE.md` and `REPO_MAP.md`, verify DigiByte Core `v8.26.x` protocol constants relevant to SPV wallets.
- Agent 2, iOS documentation/build: audit `digibytewallet-ios`, refresh docs, identify Xcode/Carthage/Swift dependency rot, and get the iOS project compiling.
- Agent 3, iOS runtime/network: launch the iOS wallet on this computer or simulator, verify wallet creation/recovery flows, SPV peer connection, sync behavior, and logs.
- Agent 4, Android documentation/build: audit `digibytewallet-android`, refresh docs, identify Gradle/Android SDK/NDK/CMake/JNI dependency rot, and get the Android project compiling.
- Agent 5, Android runtime/network: launch the Android wallet on this computer or emulator, verify wallet creation/recovery flows, SPV peer connection, sync behavior, and logs.

The lead agent owns coordination, conflict resolution, final integration, commits, and the final report. Sub-agents must not overwrite unrelated work or revert user changes.

## Prompt 1: Base Documentation And iOS Wallet Bring-Up

You are an agent team resurrecting the DigiByte mobile wallet stack. Your first job is to create or refresh `ARCHITECTURE.md` and `REPO_MAP.md` in all three wallet repos: `/home/jared/Code/digibytewallet-core`, `/home/jared/Code/digibytewallet-ios`, and `/home/jared/Code/digibytewallet-android`. Before writing those wallet docs, read `/home/jared/Code/digibyte/ARCHITECTURE.md` and `/home/jared/Code/digibyte/REPO_MAP.md` in the DigiByte root directory and use them as the reference format for depth, naming, and organization. Also read `/home/jared/Code/digibyte/DIGIDOLLAR_ARCHITECTURE.md` and `/home/jared/Code/digibyte/REPO_MAP_DIGIDOLLAR.md` for examples of subsystem-level documentation, then adapt the approach to the mobile wallet code instead of copying unrelated Core details.

After the documentation pass, focus on the iOS wallet. Get `/home/jared/Code/digibytewallet-ios` building and running on this computer using its local core module and current Apple tooling. Audit the Xcode project, Swift version issues, Carthage or dependency breakage, signing requirements, embedded `Modules/digibytewallet-core`, network constants, checkpoints, seed/peer discovery, and any code needed for compatibility with the latest stable public DigiByte Core `v8.26.x` release line.

Validation must include more than a compile. Launch the iOS wallet in a simulator or available local target, create or restore a wallet as needed, verify the app reaches the main wallet screen, verify it attempts DigiByte SPV peer connectivity, and inspect logs for crashes, peer protocol failures, database/keychain errors, broken API calls, or address/network mismatches. Record every command used, every blocker found, every file changed, and the exact remaining risk.

Deliverables for Prompt 1:

- Refreshed `ARCHITECTURE.md` and `REPO_MAP.md` in `digibytewallet-core`.
- Refreshed `ARCHITECTURE.md` and `REPO_MAP.md` in `digibytewallet-ios`.
- Refreshed `ARCHITECTURE.md` and `REPO_MAP.md` in `digibytewallet-android`.
- iOS wallet builds locally.
- iOS wallet launches locally.
- iOS wallet performs or attempts DigiByte SPV connection against the public `v8.26.x` network.
- A short final report with build commands, runtime validation, known blockers, and local commit hashes.

## Prompt 2: Android Wallet Bring-Up

You are an agent team resurrecting `/home/jared/Code/digibytewallet-android` after years of bit rot. Start by reading the DigiByte root documentation references in `/home/jared/Code/digibyte/ARCHITECTURE.md` and `/home/jared/Code/digibyte/REPO_MAP.md`, then read the refreshed docs from Prompt 1 in all three wallet repos. After that, audit the Android build from the root Gradle project down through `app/build.gradle`, `app/CMakeLists.txt`, `app/src/main/jni/transition`, and `app/src/main/jni/digibytewallet-core`.

Get the Android wallet compiling with the local Android SDK/NDK/toolchain available on this computer. Fix Gradle wrapper issues, Android plugin incompatibilities, SDK/NDK/CMake problems, Java/Kotlin compatibility, JNI bridge compile failures, native core integration problems, packaging/resource breakage, and emulator launch blockers. Keep fixes narrow and preserve the wallet's existing architecture unless a dependency is dead and must be replaced.

Then launch the app on a local emulator or available Android target. Verify wallet creation or restore, the main wallet screen, native library load, JNI calls into `digibytewallet-core`, SQLite persistence, network permissions, SPV peer manager startup, DigiByte mainnet peer connection attempts, and compatibility with the latest stable public DigiByte Core `v8.26.x` release line. Inspect Android logs for crashes, native faults, peer protocol disconnects, address/network mismatches, API failures, and background sync errors.

Deliverables for Prompt 2:

- Android wallet builds locally.
- Android wallet launches locally.
- Native `core-lib` loads successfully.
- Wallet creation or restore reaches usable UI.
- SPV peer manager starts and attempts DigiByte network connectivity.
- Compatibility checks against DigiByte Core stable `v8.26.x` are documented.
- A short final report with build commands, runtime validation, known blockers, and local commit hashes.

## Technical Compatibility Checklist

Check these against DigiByte Core stable `v8.26.x` before declaring success:

- Mainnet and testnet network magic bytes.
- Mainnet and testnet default ports.
- DNS seeds and fixed seed strategy.
- Address prefixes and supported address formats.
- Checkpoints and header sync assumptions.
- Block header validation and DigiByte multi-algo PoW handling.
- Transaction serialization/signing assumptions.
- Fee/min-output policies used by the mobile wallets.
- BIP32/BIP39 derivation path compatibility between iOS and Android.
- SPV/BIP37 behavior against modern DigiByte nodes.
- API endpoints used for fiat rates, metadata, broadcast helpers, or support services.

## Ground Rules

- Do not push to GitHub.
- Do not silently delete or rewrite user work.
- Prefer small local commits with plain-English messages.
- Keep consensus/protocol assumptions tied to DigiByte Core stable `v8.26.x`, not the DigiDollar RC branch.
- If a dependency must be upgraded, explain why and document the before/after version.
- If a platform requirement cannot be satisfied on this computer, document the exact missing tool, version, command, and error.
- Full validation means build plus launch plus logs; a green compile alone is not done.
