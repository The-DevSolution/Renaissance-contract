use starknet::ContractAddress;
use core::array::Array;

/// User profile data structure
#[derive(Drop, Serde, starknet::Store)]
pub struct UserProfile {
    pub user_address: ContractAddress,
    pub username: felt252,
    pub email_hash: felt252, // Hashed email for privacy
    pub registration_timestamp: u64,
    pub is_active: bool,
    pub reputation_score: u32,
    pub total_bets: u32,
    pub successful_bets: u32,
    pub profile_metadata_uri: felt252 // IPFS hash for additional profile data
}

/// User registration parameters
#[derive(Drop, Serde)]
pub struct RegistrationParams {
    pub username: felt252,
    pub email_hash: felt252,
    pub profile_metadata_uri: felt252,
    pub referrer: ContractAddress // Optional referrer for referral system
}

/// User role enumeration
#[allow(starknet::store_no_default_variant)]
#[derive(Drop, Serde, starknet::Store)]
pub enum UserRole {
    Banned,
    Regular,
    Premium,
    VIP,
    Moderator,
    Admin,
    Oracle,
}

/// Authentication challenge structure
#[derive(Drop, Serde, starknet::Store)]
pub struct AuthChallenge {
    pub challenge_hash: felt252,
    pub expiry_timestamp: u64,
    pub is_used: bool,
}

#[starknet::interface]
pub trait IUserManager<TState> {
    // ============ User Registration & Management ============

    /// Register a new user with profile information
    /// @param user_address: The user's wallet address
    /// @param params: Registration parameters including username, email hash, etc.
    /// @return success: Boolean indicating successful registration
    fn register_user(
        ref self: TState, user_address: ContractAddress, params: RegistrationParams,
    ) -> bool;

    /// Update user profile information (can only be called by user or admin)
    /// @param user_address: The user's wallet address
    /// @param username: New username (optional)
    /// @param email_hash: New email hash (optional)
    /// @param profile_metadata_uri: New profile metadata URI (optional)
    /// @return success: Boolean indicating successful update
    fn update_user_profile(
        ref self: TState,
        user_address: ContractAddress,
        username: felt252,
        email_hash: felt252,
        profile_metadata_uri: felt252,
    ) -> bool;

    /// Deactivate/ban a user (admin only)
    /// @param user_address: The user's wallet address
    /// @param reason: Reason for deactivation
    /// @return success: Boolean indicating successful deactivation
    fn deactivate_user(ref self: TState, user_address: ContractAddress, reason: felt252) -> bool;

    /// Reactivate a deactivated user (admin only)
    /// @param user_address: The user's wallet address
    /// @return success: Boolean indicating successful reactivation
    fn reactivate_user(ref self: TState, user_address: ContractAddress) -> bool;

    // ============ User Query Functions ============

    /// Check if a user is registered
    /// @param user_address: The user's wallet address
    /// @return is_registered: Boolean indicating if user is registered
    fn is_user_registered(self: @TState, user_address: ContractAddress) -> bool;

    /// Check if a user is active (registered and not banned)
    /// @param user_address: The user's wallet address
    /// @return is_active: Boolean indicating if user is active
    fn is_user_active(self: @TState, user_address: ContractAddress) -> bool;

    /// Get user profile information
    /// @param user_address: The user's wallet address
    /// @return profile: User profile data
    fn get_user_profile(self: @TState, user_address: ContractAddress) -> UserProfile;

    /// Check if username is available
    /// @param username: The username to check
    /// @return is_available: Boolean indicating if username is available
    fn is_username_available(self: @TState, username: felt252) -> bool;

    /// Get user address by username
    /// @param username: The username to lookup
    /// @return user_address: The associated user address
    fn get_user_by_username(self: @TState, username: felt252) -> ContractAddress;

    /// Get total number of registered users
    /// @return count: Total user count
    fn get_total_users(self: @TState) -> u32;

    /// Get paginated list of users
    /// @param offset: Starting index
    /// @param limit: Maximum number of users to return
    /// @return users: Array of user addresses
    fn get_users_paginated(self: @TState, offset: u32, limit: u32) -> Array<ContractAddress>;

    // ============ Role Management ============

    /// Assign a role to a user (admin only)
    /// @param user_address: The user's wallet address
    /// @param role: The role to assign
    /// @return success: Boolean indicating successful role assignment
    fn assign_user_role(ref self: TState, user_address: ContractAddress, role: UserRole) -> bool;

    /// Remove a role from a user (admin only)
    /// @param user_address: The user's wallet address
    /// @param role: The role to remove
    /// @return success: Boolean indicating successful role removal
    fn remove_user_role(ref self: TState, user_address: ContractAddress, role: UserRole) -> bool;

    /// Check if user has a specific role
    /// @param user_address: The user's wallet address
    /// @param role: The role to check
    /// @return has_role: Boolean indicating if user has the role
    fn user_has_role(self: @TState, user_address: ContractAddress, role: UserRole) -> bool;

    /// Get all roles for a user
    /// @param user_address: The user's wallet address
    /// @return roles: Array of user roles
    fn get_user_roles(self: @TState, user_address: ContractAddress) -> Array<UserRole>;

    /// Get users with a specific role
    /// @param role: The role to search for
    /// @return users: Array of user addresses with the role
    fn get_users_with_role(self: @TState, role: UserRole) -> Array<ContractAddress>;

    // ============ Reputation & Statistics ============

    /// Update user reputation score (called by other contracts)
    /// @param user_address: The user's wallet address
    /// @param score_change: Positive or negative score change
    /// @return new_score: Updated reputation score
    fn update_reputation(ref self: TState, user_address: ContractAddress, score_change: i32) -> u32;

    /// Record a bet result for user statistics
    /// @param user_address: The user's wallet address
    /// @param was_successful: Whether the bet was successful
    /// @return success: Boolean indicating successful recording
    fn record_bet_result(
        ref self: TState, user_address: ContractAddress, was_successful: bool,
    ) -> bool;

    /// Get user statistics
    /// @param user_address: The user's wallet address
    /// @return total_bets: Total number of bets
    /// @return successful_bets: Number of successful bets
    /// @return reputation_score: Current reputation score
    fn get_user_stats(self: @TState, user_address: ContractAddress) -> (u32, u32, u32);

    // ============ Authentication & Security ============

    /// Generate authentication challenge for user
    /// @param user_address: The user's wallet address
    /// @return challenge_hash: Generated challenge hash
    fn generate_auth_challenge(ref self: TState, user_address: ContractAddress) -> felt252;

    /// Verify authentication challenge response
    /// @param user_address: The user's wallet address
    /// @param challenge_hash: The challenge hash
    /// @param signature: User's signature of the challenge
    /// @return is_valid: Boolean indicating if authentication is valid
    fn verify_auth_challenge(
        ref self: TState,
        user_address: ContractAddress,
        challenge_hash: felt252,
        signature: Array<felt252>,
    ) -> bool;

    /// Check if user can perform an action (combines registration, active status, and role checks)
    /// @param user_address: The user's wallet address
    /// @param required_role: Minimum role required for the action
    /// @return can_perform: Boolean indicating if user can perform the action
    fn can_user_perform_action(
        self: @TState, user_address: ContractAddress, required_role: UserRole,
    ) -> bool;

    // ============ Referral System ============

    /// Get user's referrer
    /// @param user_address: The user's wallet address
    /// @return referrer: Address of the user who referred this user
    fn get_user_referrer(self: @TState, user_address: ContractAddress) -> ContractAddress;

    /// Get users referred by a specific user
    /// @param referrer_address: The referrer's wallet address
    /// @return referrals: Array of referred user addresses
    fn get_user_referrals(
        self: @TState, referrer_address: ContractAddress,
    ) -> Array<ContractAddress>;

    /// Get referral count for a user
    /// @param referrer_address: The referrer's wallet address
    /// @return count: Number of users referred
    fn get_referral_count(self: @TState, referrer_address: ContractAddress) -> u32;

    // ============ Admin Functions ============

    /// Set minimum reputation score required for certain actions
    /// @param min_score: Minimum reputation score
    /// @return success: Boolean indicating successful update
    fn set_min_reputation_score(ref self: TState, min_score: u32) -> bool;

    /// Emergency pause user registrations (admin only)
    /// @param paused: Whether to pause registrations
    /// @return success: Boolean indicating successful update
    fn set_registration_paused(ref self: TState, paused: bool) -> bool;

    /// Check if registrations are currently paused
    /// @return is_paused: Boolean indicating if registrations are paused
    fn is_registration_paused(self: @TState) -> bool;

    /// Get contract configuration
    /// @return min_reputation: Minimum reputation score required
    /// @return is_paused: Whether registrations are paused
    /// @return total_users: Total number of registered users
    fn get_contract_config(self: @TState) -> (u32, bool, u32);
}
