Renaissance Contract now orbits Soroban — Stellar's smart-contract platform. This repository contains Soroban-compatible Rust contracts compiled to WebAssembly (WASM), inspired by navigation, discovery, and resilient on-chain systems.

"From stardust to ledgers — we script the cosmos in Rust and Wasm."

Languages: Rust / Soroban (WASM)

✨ Why Soroban?
Soroban brings secure, predictable, and familiar Rust-based smart contracts to the Stellar network. It pairs well with WASM tooling and delivers deterministic execution, fast finality, and Stellar-native assets and accounts.

🚀 Features
Soroban-first contract(s) written in Rust using the soroban-sdk.
Clean, modular architecture for contract logic, registries, and controllers.
Local dev & test flows using the soroban-cli and Stellar testnet.
Designed for auditability: small, well-documented units of logic.
📁 Repository layout
contracts/ — Rust/Soroban contract crates (WASM targets)
tests/ — unit & integration tests (Rust + soroban test harness)
scripts/ — deploy and helper scripts (soroban-cli wrappers)
docs/ — design notes, upgrade considerations, and diagrams
Adjust paths above to actual repo structure if different.

🔧 Requirements
Rust (stable) and cargo
WASM target: wasm32-unknown-unknown
soroban-cli (Soroban command-line tooling)
Optional: wasm-opt (binaryen) for optimizing WASM artifacts
Node.js / npm (only if frontend/tools depend on it)
Recommended installs:

Rust: https://rustup.rs
Add WASM target: rustup target add wasm32-unknown-unknown
soroban-cli: follow Soroban docs (or: cargo install --locked soroban-cli) — check official repo for latest installation instructions
wasm-opt (optional): binaryen package or brew/choco install
🛠 Quickstart (basic workflow)
Clone repo: git clone https://github.com/The-DevSolution/Renaissance-contract.git cd Renaissance-contract

Build contract to WASM: cd contracts/your_contract_crate rustup run stable cargo build --target wasm32-unknown-unknown --release

WASM output: target/wasm32-unknown-unknown/release/your_contract_crate.wasm
(Optional) Optimize WASM: wasm-opt -Oz target/wasm32-unknown-unknown/release/your_contract_crate.wasm -o build/your_contract.wasm

Deploy with soroban-cli (example — replace placeholders): soroban contract deploy --wasm build/your_contract.wasm --network testnet --secret-file ./keys/your_account_secret

Invoke an entrypoint: soroban contract invoke --id <CONTRACT_ID> --fn <FUNCTION_NAME> --network testnet --args <ARGS...> --secret-file ./keys/your_account_secret

Notes:

Replace function names, arguments, and network with your values.
Consult official Soroban docs for the exact soroban-cli flags and auth methods.
🧪 Testing
Unit tests: cargo test (runs Rust unit tests)
Integration: use soroban-cli or a local Soroban sandbox to deploy and run end-to-end scenarios.
CI: run rustfmt, clippy, cargo test, and wasm build steps in CI pipeline.
Example CI steps:

rustup and add wasm target
cargo fmt -- --check
cargo clippy -- -D warnings
cargo test
cargo build --target wasm32-unknown-unknown --release
🛰️ Deployment & Networks
Typical flow:

Build WASM artifact
Optionally optimize
Deploy to Stellar testnet using soroban-cli
Run post-deploy initialization transactions
Common targets:

Local sandbox (for development)
Stellar testnet (for public testing)
Stellar mainnet (production — require audits and secure key management)
🛡 Security & Auditing
Keep contracts small and deterministic.
Add comprehensive unit & integration tests.
Avoid on-chain secrets; use Stellar accounts and signers securely.
Consider formal audits before mainnet deployment.
✍️ Contributing
Fork and open a PR
Add tests for new behaviors
Follow Rust formatting and linting (rustfmt + clippy)
Include clear PR descriptions, testing notes, and upgrade instructions
📜 License
Specify the project license (e.g., MIT or Apache-2.0) and ensure LICENSE file is present.

📬 Maintainers
@Divineifed1 
