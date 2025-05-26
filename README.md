# Renaissance Smart Contracts - Decentralized Football Betting

The smart contract suite for Renaissance, implementing decentralized betting, premium content access, and fan engagement features on the Starknet blockchain using Cairo.

## 🏗️ Architecture Overview

Renaissance is built as a **microservices architecture** with three main repositories:

- **Frontend**: Next.js 14 with TypeScript - User interface and Web3 interactions
- **Backend**: NestJS with TypeScript - API services and business logic
- **Smart Contracts** (This repo): Cairo on Starknet - Decentralized betting and content access

## 🚀 Smart Contract Features

### Core Contracts
- 🎯 **Betting Contract** - Decentralized sports betting with transparent odds
- 🎫 **Content Access Contract** - NFT-based premium content gating
- 🏆 **Tournament Contract** - Tournament management and prize distribution
- 💰 **Token Contract** - ERC-20 utility token for platform economy
- 🎮 **Governance Contract** - Community governance and voting

### Advanced Features
- 🔐 **Zero-Knowledge Proofs** - Privacy-preserving bet verification
- ⚡ **Optimized Gas Usage** - Efficient Cairo implementations
- 🔄 **Upgradeability** - Proxy pattern for contract upgrades
- 🛡️ **Security Audited** - Multiple security audit layers
- 📊 **Oracle Integration** - Real-world sports data integration

## 🛠️ Tech Stack

### Blockchain & Language
- **Starknet** - Ethereum Layer 2 scaling solution
- **Cairo** - Smart contract programming language
- **Starknet.js** - JavaScript SDK for interaction

### Development Tools
- **Scarb** - Cairo package manager and build tool
- **Starknet Foundry** - Testing and deployment framework
- **Protostar** - Development environment
- **Cairo-lang** - Cairo compiler and utilities

### Testing & Security
- **Starknet Test Runner** - Contract testing framework
- **Property-based Testing** - Formal verification tools
- **Security Scanners** - Automated vulnerability detection
- **Gas Optimization** - Performance analysis tools

## 🏁 Getting Started

### Prerequisites
- Cairo 2.0+ installed
- Scarb package manager
- Starknet CLI tools
- Node.js 18+ (for scripts)

### Installation

1. **Clone the contracts repository:**
```bash
git clone https://github.com/renaissance-org/renaissance-contracts.git
cd renaissance-contracts
```

2. **Install Cairo and Scarb:**
```bash
# Install Cairo
curl -L https://github.com/starkware-libs/cairo/releases/latest/download/install.sh | bash

# Install Scarb
curl --proto '=https' --tlsv1.2 -sSf https://docs.swmansion.com/scarb/install.sh | sh
```

3. **Install dependencies:**
```bash
scarb build
```

4. **Set up environment variables:**
```bash
cp .env.example .env
```

Configure your environment:
```env
# Network Configuration
STARKNET_NETWORK=goerli-alpha
STARKNET_RPC_URL=https://starknet-goerli.g.alchemy.com/v2/your-api-key

# Account Configuration
DEPLOYER_ACCOUNT_ADDRESS=0x...
DEPLOYER_PRIVATE_KEY=0x...
DEPLOYER_PUBLIC_KEY=0x...

# Contract Addresses (after deployment)
BETTING_CONTRACT_ADDRESS=0x...
CONTENT_CONTRACT_ADDRESS=0x...
TOKEN_CONTRACT_ADDRESS=0x...
TOURNAMENT_CONTRACT_ADDRESS=0x...
GOVERNANCE_CONTRACT_ADDRESS=0x...

# Oracle Configuration
ORACLE_ADDRESS=0x...
ORACLE_ADMIN_KEY=0x...

# Security
MULTI_SIG_THRESHOLD=2
ADMIN_ADDRESSES=0x...,0x...,0x...
```

5. **Compile contracts:**
```bash
scarb build
```

6. **Run tests:**
```bash
scarb test
```

## 📁 Project Structure

```


## 🎯 Core Contracts Overview

### 1. Betting Contract (`src/betting/betting_core.cairo`)

**Main Functions:**
```cairo
// Place a bet on a match
fn place_bet(
    match_id: u256,
    bet_type: BetType,
    amount: u256,
    odds: u256
) -> bool

// Resolve match and distribute payouts
fn resolve_match(
    match_id: u256,
    result: MatchResult
) -> bool

// Claim winnings
fn claim_winnings(bet_id: u256) -> bool

// Get current odds
fn get_odds(match_id: u256, bet_type: BetType) -> u256
```

**Key Features:**
- Multiple bet types (winner, over/under, handicap)
- Dynamic odds calculation
- Automated payout distribution
- Bet history tracking

### 2. Content Access Contract (`src/content/content_access.cairo`)

**Main Functions:**
```cairo
// Purchase content access NFT
fn purchase_access(
    content_id: u256,
    access_type: AccessType
) -> u256

// Verify content access
fn verify_access(
    user: ContractAddress,
    content_id: u256
) -> bool

// Create new content (admin only)
fn create_content(
    metadata_uri: felt252,
    price: u256,
    access_duration: u64
) -> u256
```

**Key Features:**
- NFT-based access control
- Time-limited access
- Tiered content pricing
- Creator royalties

### 3. Renaissance Token Contract (`src/token/renaissance_token.cairo`)

**Main Functions:**
```cairo
// Standard ERC-20 functions
fn transfer(to: ContractAddress, amount: u256) -> bool
fn approve(spender: ContractAddress, amount: u256) -> bool

// Staking rewards
fn stake(amount: u256) -> bool
fn unstake(amount: u256) -> bool
fn claim_rewards() -> u256

// Governance utilities
fn delegate(delegatee: ContractAddress) -> bool
fn get_voting_power(account: ContractAddress) -> u256
```

### 4. Tournament Contract (`src/tournament/tournament.cairo`)

**Main Functions:**
```cairo
// Create tournament
fn create_tournament(
    name: felt252,
    entry_fee: u256,
    prize_pool: u256,
    start_time: u64
) -> u256

// Enter tournament
fn enter_tournament(tournament_id: u256) -> bool

// Update tournament results
fn update_results(
    tournament_id: u256,
    results: Array<MatchResult>
) -> bool
```

## 🔧 Available Scripts

```bash
# Development
scarb build              # Compile all contracts
scarb test              # Run all tests
scarb clean             # Clean build artifacts

# Testing
scarb test betting      # Test specific contract
scarb test --coverage   # Run tests with coverage
protostar test          # Alternative test runner

# Deployment
./scripts/deploy/deploy_all.sh      # Deploy all contracts
./scripts/deploy/deploy_betting.sh  # Deploy betting contract
./scripts/verify/verify_all.sh      # Verify contracts

# Interaction
./scripts/interact/place_bet.sh     # Place a test bet
./scripts/interact/create_content.sh # Create test content
./scripts/interact/check_balance.sh  # Check token balance

# Development Tools
./scripts/generate_abi.sh           # Generate contract ABIs
./scripts/calculate_gas.sh          # Estimate gas costs
./scripts/security_check.sh         # Run security analysis
```

## 🧪 Testing Framework

### Unit Tests
```cairo
// Example test structure
#[cfg(test)]
mod betting_tests {
    use super::*;
    
    #[test]
    fn test_place_bet_success() {
        // Test placing a valid bet
        let (betting_contract, _) = setup_betting_contract();
        let result = betting_contract.place_bet(1, BetType::Winner, 100, 200);
        assert(result == true, 'Bet placement failed');
    }
    
    #[test]
    fn test_invalid_bet_amount() {
        // Test invalid bet amount
        let (betting_contract, _) = setup_betting_contract();
        let result = betting_contract.place_bet(1, BetType::Winner, 0, 200);
        assert(result == false, 'Should reject zero amount');
    }
}
```

### Integration Tests
```cairo
// Cross-contract interaction tests
#[test]
fn test_bet_with_token_integration() {
    let (betting_contract, token_contract) = setup_integrated_contracts();
    
    // Approve tokens for betting
    token_contract.approve(betting_contract.contract_address, 1000);
    
    // Place bet using tokens
    let result = betting_contract.place_bet(1, BetType::Winner, 100, 200);
    assert(result == true, 'Integrated bet failed');
}
```

## 🔐 Security Considerations

### Access Control
```cairo
// Role-based access control
#[generate_trait]
impl AccessControl of IAccessControl {
    fn only_admin(self: @ContractState) {
        let caller = get_caller_address();
        assert(self.admins.read(caller), 'Unauthorized: Admin only');
    }
    
    fn only_oracle(self: @ContractState) {
        let caller = get_caller_address();
        assert(caller == self.oracle_address.read(), 'Unauthorized: Oracle only');
    }
}
```

### Reentrancy Protection
```cairo
// Reentrancy guard implementation
#[storage]
struct Storage {
    reentrancy_guard: bool,
}

fn nonreentrant_start(ref self: ContractState) {
    assert(!self.reentrancy_guard.read(), 'Reentrant call');
    self.reentrancy_guard.write(true);
}

fn nonreentrant_end(ref self: ContractState) {
    self.reentrancy_guard.write(false);
}
```

### Input Validation
```cairo
// Comprehensive input validation
fn validate_bet_params(
    match_id: u256,
    amount: u256,
    odds: u256
) -> bool {
    // Check match exists and is active
    assert(match_id > 0, 'Invalid match ID');
    
    // Check minimum bet amount
    assert(amount >= MIN_BET_AMOUNT, 'Bet amount too low');
    
    // Check odds are reasonable
    assert(odds >= MIN_ODDS && odds <= MAX_ODDS, 'Invalid odds');
    
    true
}
```

## 🚀 Deployment Guide

### Testnet Deployment
```bash
# 1. Deploy token contract first
./scripts/deploy/deploy_token.sh goerli-alpha

# 2. Deploy betting contract
./scripts/deploy/deploy_betting.sh goerli-alpha

# 3. Deploy content access contract
./scripts/deploy/deploy_content.sh goerli-alpha

# 4. Initialize contracts
./scripts/deploy/initialize_contracts.sh goerli-alpha
```

### Mainnet Deployment
```bash
# Use multi-sig deployment for mainnet
./scripts/deploy/deploy_multisig.sh mainnet-alpha

# Perform security checks
./scripts/verify/security_audit.sh

# Verify contract source code
./scripts/verify/verify_source.sh mainnet-alpha
```

## 📊 Gas Optimization

### Efficient Data Structures
```cairo
// Use packed structs for gas efficiency
#[derive(Drop, Serde, starknet::Store)]
struct PackedBet {
    match_id: u32,        // Reduced from u256
    amount: u128,         // Sufficient for bet amounts
    odds: u32,            // Packed odds representation
    timestamp: u64,       // Unix timestamp
}
```

### Batch Operations
```cairo
// Batch multiple operations for gas savings
fn batch_resolve_matches(
    match_ids: Array<u256>,
    results: Array<MatchResult>
) {
    let mut i = 0;
    loop {
        if i >= match_ids.len() {
            break;
        }
        resolve_match_internal(*match_ids.at(i), *results.at(i));
        i += 1;
    }
}
```

## 🤝 Contributing

### Development Workflow
1. Fork the repository
2. Create feature branch: `git checkout -b feature/new-betting-type`
3. Write Cairo code following style guidelines
4. Add comprehensive tests
5. Run security checks and gas optimization
6. Submit pull request with detailed description

### Code Standards
- Follow Cairo naming conventions
- Write comprehensive tests for all functions
- Include inline documentation
- Optimize for gas efficiency
- Implement proper error handling

### Security Checklist
- [ ] Input validation on all external functions
- [ ] Reentrancy protection where needed
- [ ] Access control properly implemented
- [ ] Integer overflow/underflow checks
- [ ] Event emission for important state changes

## 📚 Related Repositories

- **Frontend**: [renaissance-frontend](https://github.com/renaissance-org/renaissance-frontend) - Next.js application
- **Backend**: [renaissance-backend](https://github.com/renaissance-org/renaissance-backend) - NestJS API server

## 📄 License

This project is open source and available under the [MIT License](LICENSE).

## 🌟 Community

- 🔍 **Security Audits**: Regular third-party security reviews
- 🐛 **Bug Bounty**: Rewards for finding vulnerabilities
- 📖 **Documentation**: Comprehensive guides and examples
- 💬 **Developer Support**: Active community support

---

Built with 🔐 for the decentralized future. Powered by Cairo and Starknet.
