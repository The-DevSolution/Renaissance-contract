#[starknet::component]
pub mod UserManagerComponent {
    use core::hash::HashStateTrait;
    use core::{array::Array, poseidon::PoseidonTrait};
    use starknet::{
        ContractAddress, get_caller_address, get_block_timestamp, get_tx_info,
        storage::{
            StorageMapReadAccess, StorageMapWriteAccess, StoragePointerReadAccess,
            StoragePointerWriteAccess, Map,
        },
    };
    use renaissance::{
        interfaces::{
            IUserManager::{UserProfile, RegistrationParams, UserRole, AuthChallenge},
            IAccessControl::IAccessControl,
        },
        components::accessControl::{AccessControlComponent},
    };
    use starknet::secp256_trait::{
        Secp256PointTrait, Signature, is_valid_signature, recover_public_key,
    };

    /// Storage for the UserManager component
    #[storage]
    struct Storage {
        /// Maps user address -> UserProfile
        user_profiles: Map<ContractAddress, UserProfile>,
        /// Maps username -> user address
        username_to_address: Map<felt252, ContractAddress>,
        /// Maps user address -> role
        user_roles: Map<(ContractAddress, u8), bool>,
        /// Maps user address -> referrer address
        user_referrer: Map<ContractAddress, ContractAddress>,
        /// Maps referrer -> count of referrals
        referral_count: Map<ContractAddress, u32>,
        /// Maps user address -> auth challenge
        auth_challenges: Map<ContractAddress, AuthChallenge>,
        /// Total number of registered users
        total_users: u32,
        /// Minimum reputation score required for actions
        min_reputation_score: u32,
        /// Whether registrations are paused
        registration_paused: bool,
        /// Array of all registered user addresses (for pagination)
        user_addresses: Map<u32, ContractAddress>,
        /// Maps referrer -> array index for referrals
        referrer_referrals: Map<(ContractAddress, u32), ContractAddress>,
        /// Maps referrer -> referral array length
        referrer_referral_length: Map<ContractAddress, u32>,
        /// Maps role -> array of users with that role
        role_users: Map<(u8, u32), ContractAddress>,
        /// Maps role -> count of users with that role
        role_user_count: Map<u8, u32>,
        /// Maps user address -> nonce for challenge generation
        user_nonces: Map<ContractAddress, u64>,
        /// Maps user address -> last challenge timestamp (for rate limiting)
        last_challenge_timestamp: Map<ContractAddress, u64>,
        /// Maps user address -> failed verification attempts
        failed_auth_attempts: Map<ContractAddress, u32>,
        /// Challenge rate limit (seconds between challenges)
        challenge_rate_limit: u64,
        /// Max failed attempts before temporary lockout
        max_failed_attempts: u32,
        /// Lockout duration in seconds
        lockout_duration: u64,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        UserRegistered: UserRegistered,
        UserProfileUpdated: UserProfileUpdated,
        UserDeactivated: UserDeactivated,
        UserReactivated: UserReactivated,
        UserRoleAssigned: UserRoleAssigned,
        UserRoleRemoved: UserRoleRemoved,
        ReputationUpdated: ReputationUpdated,
        BetResultRecorded: BetResultRecorded,
        AuthChallengeGenerated: AuthChallengeGenerated,
        AuthChallengeVerified: AuthChallengeVerified,
        AuthChallengeExpired: AuthChallengeExpired,
        AuthAttemptFailed: AuthAttemptFailed,
        UserLockedOut: UserLockedOut,
        RegistrationPauseChanged: RegistrationPauseChanged,
        MinReputationChanged: MinReputationChanged,
    }

    #[derive(Drop, starknet::Event)]
    struct UserRegistered {
        user_address: ContractAddress,
        username: felt252,
        referrer: ContractAddress,
        timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct UserProfileUpdated {
        user_address: ContractAddress,
        username: felt252,
        timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct UserDeactivated {
        user_address: ContractAddress,
        reason: felt252,
        timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct UserReactivated {
        user_address: ContractAddress,
        timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct UserRoleAssigned {
        user_address: ContractAddress,
        role: u8,
        assigned_by: ContractAddress,
    }

    #[derive(Drop, starknet::Event)]
    struct UserRoleRemoved {
        user_address: ContractAddress,
        role: u8,
        removed_by: ContractAddress,
    }

    #[derive(Drop, starknet::Event)]
    struct ReputationUpdated {
        user_address: ContractAddress,
        old_score: u32,
        new_score: u32,
    }

    #[derive(Drop, starknet::Event)]
    struct BetResultRecorded {
        user_address: ContractAddress,
        was_successful: bool,
        total_bets: u32,
        successful_bets: u32,
    }

    #[derive(Drop, starknet::Event)]
    struct AuthChallengeGenerated {
        user_address: ContractAddress,
        challenge_hash: felt252,
        expiry: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct AuthChallengeVerified {
        user_address: ContractAddress,
        challenge_hash: felt252,
        success: bool,
    }

    #[derive(Drop, starknet::Event)]
    struct RegistrationPauseChanged {
        paused: bool,
        changed_by: ContractAddress,
    }

    #[derive(Drop, starknet::Event)]
    struct MinReputationChanged {
        old_score: u32,
        new_score: u32,
        changed_by: ContractAddress,
    }

    #[derive(Drop, starknet::Event)]
    struct AuthChallengeExpired {
        user_address: ContractAddress,
        challenge_hash: felt252,
        timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct AuthAttemptFailed {
        user_address: ContractAddress,
        challenge_hash: felt252,
        reason: felt252,
        timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct UserLockedOut {
        user_address: ContractAddress,
        failed_attempts: u32,
        lockout_until: u64,
    }

    #[embeddable_as(UserManagerImpl)]
    impl UserManager<
        TContractState,
        +HasComponent<TContractState>,
        +Drop<TContractState>,
        impl AccessControl: AccessControlComponent::HasComponent<TContractState>,
    > of renaissance::interfaces::IUserManager::IUserManager<ComponentState<TContractState>> {
        // ============ User Registration & Management ============

        fn register_user(
            ref self: ComponentState<TContractState>,
            user_address: ContractAddress,
            params: RegistrationParams,
        ) -> bool {
            // Check if registrations are paused
            assert(!self.registration_paused.read(), 'Registration is paused');

            // Check if user is already registered
            assert(!self._is_user_registered(user_address), 'User already registered');

            // Check if username is available
            assert(self._is_username_available(params.username), 'Username not available');

            let timestamp = get_block_timestamp();

            // Create user profile
            let profile = UserProfile {
                user_address,
                username: params.username,
                email_hash: params.email_hash,
                registration_timestamp: timestamp,
                is_active: true,
                reputation_score: 100, // Default starting reputation
                total_bets: 0,
                successful_bets: 0,
                profile_metadata_uri: params.profile_metadata_uri,
            };

            // Store profile
            self.user_profiles.write(user_address, profile);

            // Map username to address
            self.username_to_address.write(params.username, user_address);

            // Handle referrer if provided
            let zero_address: ContractAddress = 0.try_into().unwrap();
            if params.referrer != zero_address {
                self.user_referrer.write(user_address, params.referrer);
                let current_count = self.referral_count.read(params.referrer);
                self.referral_count.write(params.referrer, current_count + 1);

                // Add to referrer's referral array
                let referral_length = self.referrer_referral_length.read(params.referrer);
                self.referrer_referrals.write((params.referrer, referral_length), user_address);
                self.referrer_referral_length.write(params.referrer, referral_length + 1);
            }

            // Assign default role (Regular)
            self.user_roles.write((user_address, UserRole::Regular), true);

            // Add to role users array
            let role_count = self.role_user_count.read(UserRole::Regular);
            self.role_users.write((UserRole::Regular, role_count), user_address);
            self.role_user_count.write(UserRole::Regular, role_count + 1);

            // Increment total users and add to user addresses array
            let total = self.total_users.read();
            self.user_addresses.write(total, user_address);
            self.total_users.write(total + 1);

            // Emit event
            self
                .emit(
                    Event::UserRegistered(
                        UserRegistered {
                            user_address,
                            username: params.username,
                            referrer: params.referrer,
                            timestamp,
                        },
                    ),
                );

            true
        }

        fn update_user_profile(
            ref self: ComponentState<TContractState>,
            user_address: ContractAddress,
            username: felt252,
            email_hash: felt252,
            profile_metadata_uri: felt252,
        ) -> bool {
            let caller = get_caller_address();

            // Check if caller is the user or admin
            assert(caller == user_address || self._has_admin_access_role(), 'Unauthorized');

            // Check if user is registered
            assert(self._is_user_registered(user_address), 'User not registered');

            let mut profile = self.user_profiles.read(user_address);

            // Update username if provided and available
            if username != 0 {
                // Check if username is available (unless it's the same username)
                if username != profile.username {
                    assert(self._is_username_available(username), 'Username not available');
                    // Remove old username mapping
                    self.username_to_address.write(profile.username, 0.try_into().unwrap());
                    // Add new username mapping
                    self.username_to_address.write(username, user_address);
                    profile.username = username;
                }
            }

            // Update other fields if provided
            if email_hash != 0 {
                profile.email_hash = email_hash;
            }
            if profile_metadata_uri != 0 {
                profile.profile_metadata_uri = profile_metadata_uri;
            }

            // Save updated profile
            self.user_profiles.write(user_address, profile.clone());

            // Emit event
            self
                .emit(
                    Event::UserProfileUpdated(
                        UserProfileUpdated {
                            user_address,
                            username: profile.username,
                            timestamp: get_block_timestamp(),
                        },
                    ),
                );

            true
        }

        fn deactivate_user(
            ref self: ComponentState<TContractState>,
            user_address: ContractAddress,
            reason: felt252,
        ) -> bool {
            // Only admin can deactivate users
            assert(self._has_admin_access_role(), 'Unauthorized');

            // Check if user is registered
            assert(self._is_user_registered(user_address), 'User not registered');

            let mut profile = self.user_profiles.read(user_address);
            profile.is_active = false;
            self.user_profiles.write(user_address, profile);

            // Assign banned role
            self.user_roles.write((user_address, UserRole::Banned), true);

            // Emit event
            self
                .emit(
                    Event::UserDeactivated(
                        UserDeactivated { user_address, reason, timestamp: get_block_timestamp() },
                    ),
                );

            true
        }

        fn reactivate_user(
            ref self: ComponentState<TContractState>, user_address: ContractAddress,
        ) -> bool {
            // Only admin can reactivate users
            assert(self._has_admin_access_role(), 'Unauthorized');

            // Check if user is registered
            assert(self._is_user_registered(user_address), 'User not registered');

            let mut profile = self.user_profiles.read(user_address);
            profile.is_active = true;
            self.user_profiles.write(user_address, profile);

            // Remove banned role
            self.user_roles.write((user_address, UserRole::Banned), false);

            // Emit event
            self
                .emit(
                    Event::UserReactivated(
                        UserReactivated { user_address, timestamp: get_block_timestamp() },
                    ),
                );

            true
        }

        // ============ User Query Functions ============

        fn is_user_registered(
            self: @ComponentState<TContractState>, user_address: ContractAddress,
        ) -> bool {
            self._is_user_registered(user_address)
        }

        fn is_user_active(
            self: @ComponentState<TContractState>, user_address: ContractAddress,
        ) -> bool {
            if !self._is_user_registered(user_address) {
                return false;
            }
            let profile = self.user_profiles.read(user_address);
            profile.is_active && !self.user_roles.read((user_address, UserRole::Banned))
        }

        fn get_user_profile(
            self: @ComponentState<TContractState>, user_address: ContractAddress,
        ) -> UserProfile {
            assert(self._is_user_registered(user_address), 'User not registered');
            self.user_profiles.read(user_address)
        }

        fn is_username_available(self: @ComponentState<TContractState>, username: felt252) -> bool {
            self._is_username_available(username)
        }

        fn get_user_by_username(
            self: @ComponentState<TContractState>, username: felt252,
        ) -> ContractAddress {
            self.username_to_address.read(username)
        }

        fn get_total_users(self: @ComponentState<TContractState>) -> u32 {
            self.total_users.read()
        }

        fn get_users_paginated(
            self: @ComponentState<TContractState>, offset: u32, limit: u32,
        ) -> Array<ContractAddress> {
            let mut users = ArrayTrait::new();
            let total_users = self.total_users.read();

            // Bounds checking
            if offset >= total_users {
                return users;
            }

            let end_index = if offset + limit > total_users {
                total_users
            } else {
                offset + limit
            };

            // Collect users within the specified range
            let mut i = offset;
            while i < end_index {
                let user_address = self.user_addresses.read(i);
                users.append(user_address);
                i += 1;
            };

            users
        }

        // ============ Role Management ============

        fn assign_user_role(
            ref self: ComponentState<TContractState>, user_address: ContractAddress, role: u8,
        ) -> bool {
            // Only admin can assign roles
            assert(self._has_admin_access_role(), 'Unauthorized');

            // Check if user is registered
            assert(self._is_user_registered(user_address), 'User not registered');

            // Assign role
            self.user_roles.write((user_address, role), true);

            // Add to role users array
            let role_count = self.role_user_count.read(role);
            self.role_users.write((role, role_count), user_address);
            self.role_user_count.write(role, role_count + 1);

            // Emit event
            self
                .emit(
                    Event::UserRoleAssigned(
                        UserRoleAssigned { user_address, role, assigned_by: get_caller_address() },
                    ),
                );

            true
        }

        fn remove_user_role(
            ref self: ComponentState<TContractState>, user_address: ContractAddress, role: u8,
        ) -> bool {
            // Only admin can remove roles
            assert(self._has_admin_access_role(), 'Unauthorized');

            // Check if user is registered
            assert(self._is_user_registered(user_address), 'User not registered');

            // Remove role
            self.user_roles.write((user_address, role), false);

            // Emit event
            self
                .emit(
                    Event::UserRoleRemoved(
                        UserRoleRemoved { user_address, role, removed_by: get_caller_address() },
                    ),
                );

            true
        }

        fn user_has_role(
            self: @ComponentState<TContractState>, user_address: ContractAddress, role: u8,
        ) -> bool {
            self.user_roles.read((user_address, role))
        }

        fn get_user_roles(
            self: @ComponentState<TContractState>, user_address: ContractAddress,
        ) -> Array<u8> {
            let mut roles = ArrayTrait::new();

            // Check each possible role
            if self.user_roles.read((user_address, UserRole::Banned)) {
                roles.append(UserRole::Banned);
            }
            if self.user_roles.read((user_address, UserRole::Regular)) {
                roles.append(UserRole::Regular);
            }
            if self.user_roles.read((user_address, UserRole::Premium)) {
                roles.append(UserRole::Premium);
            }
            if self.user_roles.read((user_address, UserRole::VIP)) {
                roles.append(UserRole::VIP);
            }
            if self.user_roles.read((user_address, UserRole::Moderator)) {
                roles.append(UserRole::Moderator);
            }
            if self.user_roles.read((user_address, UserRole::Admin)) {
                roles.append(UserRole::Admin);
            }
            if self.user_roles.read((user_address, UserRole::Oracle)) {
                roles.append(UserRole::Oracle);
            }

            roles
        }

        fn get_users_with_role(
            self: @ComponentState<TContractState>, role: u8,
        ) -> Array<ContractAddress> {
            let mut users = ArrayTrait::new();
            let role_count = self.role_user_count.read(role);

            // Collect all users with the specified role
            let mut i = 0;
            while i < role_count {
                let user_address = self.role_users.read((role, i));
                // Verify the user still has this role (in case of removals)
                if self.user_roles.read((user_address, role)) {
                    users.append(user_address);
                }
                i += 1;
            };

            users
        }

        // ============ Reputation & Statistics ============

        fn update_reputation(
            ref self: ComponentState<TContractState>,
            user_address: ContractAddress,
            score_change: i32,
        ) -> u32 {
            // Check if user is registered
            assert(self._is_user_registered(user_address), 'User not registered');

            let mut profile = self.user_profiles.read(user_address);
            let old_score = profile.reputation_score;

            // Apply score change with bounds checking
            if score_change >= 0 {
                profile.reputation_score += score_change.try_into().unwrap();
            } else {
                let decrease: u32 = (-score_change).try_into().unwrap();
                if profile.reputation_score > decrease {
                    profile.reputation_score -= decrease;
                } else {
                    profile.reputation_score = 0;
                }
            }

            // Cap at maximum value
            if profile.reputation_score > 10000 {
                profile.reputation_score = 10000;
            }

            // Save updated profile
            self.user_profiles.write(user_address, profile.clone());

            // Emit event
            self
                .emit(
                    Event::ReputationUpdated(
                        ReputationUpdated {
                            user_address, old_score, new_score: profile.reputation_score,
                        },
                    ),
                );

            profile.reputation_score
        }

        fn record_bet_result(
            ref self: ComponentState<TContractState>,
            user_address: ContractAddress,
            was_successful: bool,
        ) -> bool {
            // Check if user is registered
            assert(self._is_user_registered(user_address), 'User not registered');

            let mut profile = self.user_profiles.read(user_address);
            profile.total_bets += 1;

            if was_successful {
                profile.successful_bets += 1;
            }

            // Save updated profile
            self.user_profiles.write(user_address, profile.clone());

            // Emit event
            self
                .emit(
                    Event::BetResultRecorded(
                        BetResultRecorded {
                            user_address,
                            was_successful,
                            total_bets: profile.total_bets,
                            successful_bets: profile.successful_bets,
                        },
                    ),
                );

            true
        }

        fn get_user_stats(
            self: @ComponentState<TContractState>, user_address: ContractAddress,
        ) -> (u32, u32, u32) {
            assert(self._is_user_registered(user_address), 'User not registered');
            let profile = self.user_profiles.read(user_address);
            (profile.total_bets, profile.successful_bets, profile.reputation_score)
        }

        // ============ Authentication & Security ============

        fn generate_auth_challenge(
            ref self: ComponentState<TContractState>, user_address: ContractAddress,
        ) -> felt252 {
            // Check if user is registered and active
            assert(self.is_user_active(user_address), 'User not active');

            let current_timestamp = get_block_timestamp();

            // Check if user is currently locked out
            let failed_attempts = self.failed_auth_attempts.read(user_address);
            let max_attempts = self.max_failed_attempts.read();
            if failed_attempts >= max_attempts {
                let last_failed_time = self.last_challenge_timestamp.read(user_address);
                let lockout_duration = self.lockout_duration.read();
                assert(current_timestamp > last_failed_time + lockout_duration, 'User locked out');
                // Reset failed attempts after lockout period
                self.failed_auth_attempts.write(user_address, 0);
            }

            // Rate limiting: Check if enough time has passed since last challenge
            let last_challenge_time = self.last_challenge_timestamp.read(user_address);
            let rate_limit = self.challenge_rate_limit.read();
            assert(current_timestamp >= last_challenge_time + rate_limit, 'Rate limit exceeded');

            // Clean up expired challenge if exists
            self._cleanup_expired_challenge(user_address);

            // Increment user nonce for uniqueness
            let current_nonce = self.user_nonces.read(user_address);
            self.user_nonces.write(user_address, current_nonce + 1);

            let tx_info = get_tx_info().unbox();

            // Use Poseidon hash for better security and include more entropy
            let challenge_hash = PoseidonTrait::new()
                .update(user_address.into())
                .update(current_timestamp.into())
                .update(tx_info.nonce)
                .update((current_nonce + 1).into())
                .update(tx_info.transaction_hash)
                .finalize();

            let expiry = current_timestamp + 900; // 15 minutes

            // Store challenge
            let challenge = AuthChallenge {
                challenge_hash, expiry_timestamp: expiry, is_used: false,
            };
            self.auth_challenges.write(user_address, challenge);

            // Update last challenge timestamp
            self.last_challenge_timestamp.write(user_address, current_timestamp);

            // Emit event
            self
                .emit(
                    Event::AuthChallengeGenerated(
                        AuthChallengeGenerated { user_address, challenge_hash, expiry },
                    ),
                );

            challenge_hash
        }

        fn verify_auth_challenge(
            ref self: ComponentState<TContractState>,
            user_address: ContractAddress,
            challenge_hash: felt252,
            signature: Signature,
        ) -> bool {
            let caller_address = get_caller_address();
            assert(caller_address == user_address, 'Invalid user address');

            // Check if user is registered and active
            assert(self.is_user_active(user_address), 'User not active');

            let current_timestamp = get_block_timestamp();

            // Get stored challenge
            let mut challenge = self.auth_challenges.read(user_address);

            // Check if challenge exists
            if challenge.challenge_hash == 0 {
                self._record_failed_attempt(user_address, challenge_hash, 'No challenge found');
                return false;
            }

            // Verify challenge matches
            if challenge.challenge_hash != challenge_hash {
                self._record_failed_attempt(user_address, challenge_hash, 'Invalid challenge hash');
                return false;
            }

            // Check if challenge has expired
            if current_timestamp > challenge.expiry_timestamp {
                // Clean up expired challenge
                self._cleanup_expired_challenge(user_address);
                self._record_failed_attempt(user_address, challenge_hash, 'Challenge expired');
                return false;
            }

            // Verify challenge hasn't been used
            if challenge.is_used {
                self._record_failed_attempt(user_address, challenge_hash, 'Challenge already used');
                return false;
            }

            // Mark challenge as used
            challenge.is_used = true;
            self.auth_challenges.write(user_address, challenge);

            // let public_key =
            //     match recover_public_key(challenge_hash.try_into().unwrap(), signature) {
            //     Result::Ok(public_key) => public_key,
            //     Result::Err(_) => {
            //         self._record_failed_attempt(user_address, challenge_hash, 'Invalid
            //         signature');
            //         panic!('Invalid signature');
            //     },
            // };

            // // Enhanced signature validation
            // let is_valid = is_valid_signature(
            //     challenge_hash.try_into().unwrap(), signature.r, signature.s, public_key,
            // );

            // if is_valid {
            //     // Reset failed attempts on successful authentication
            //     self.failed_auth_attempts.write(user_address, 0);

            //     // Emit success event
            //     self
            //         .emit(
            //             Event::AuthChallengeVerified(
            //                 AuthChallengeVerified { user_address, challenge_hash, success: true
            //                 },
            //             ),
            //         );
            // } else {
            //     self._record_failed_attempt(user_address, challenge_hash, 'Invalid signature');
            // }

            self.failed_auth_attempts.write(user_address, 0);
            self
                .emit(
                    Event::AuthChallengeVerified(
                        AuthChallengeVerified { user_address, challenge_hash, success: true },
                    ),
                );
            true
        }

        fn can_user_perform_action(
            self: @ComponentState<TContractState>, user_address: ContractAddress, required_role: u8,
        ) -> bool {
            // Check if user is active
            if !self.is_user_active(user_address) {
                return false;
            }

            // Check if user has required role
            if !self.user_has_role(user_address, required_role) {
                return false;
            }

            // Check reputation requirements
            let profile = self.user_profiles.read(user_address);
            if profile.reputation_score < self.min_reputation_score.read() {
                return false;
            }

            true
        }

        // ============ Referral System ============

        fn get_user_referrer(
            self: @ComponentState<TContractState>, user_address: ContractAddress,
        ) -> ContractAddress {
            self.user_referrer.read(user_address)
        }

        fn get_user_referrals(
            self: @ComponentState<TContractState>, referrer_address: ContractAddress,
        ) -> Array<ContractAddress> {
            let mut referrals = ArrayTrait::new();
            let referral_length = self.referrer_referral_length.read(referrer_address);

            // Collect all referrals for the specified referrer
            let mut i = 0;
            while i < referral_length {
                let referral_address = self.referrer_referrals.read((referrer_address, i));
                referrals.append(referral_address);
                i += 1;
            };

            referrals
        }

        fn get_referral_count(
            self: @ComponentState<TContractState>, referrer_address: ContractAddress,
        ) -> u32 {
            self.referral_count.read(referrer_address)
        }

        // ============ Admin Functions ============

        fn set_min_reputation_score(
            ref self: ComponentState<TContractState>, min_score: u32,
        ) -> bool {
            // Only admin can set minimum reputation score
            assert(self._has_admin_access_role(), 'Unauthorized');

            let old_score = self.min_reputation_score.read();
            self.min_reputation_score.write(min_score);

            // Emit event
            self
                .emit(
                    Event::MinReputationChanged(
                        MinReputationChanged {
                            old_score, new_score: min_score, changed_by: get_caller_address(),
                        },
                    ),
                );

            true
        }

        fn set_registration_paused(ref self: ComponentState<TContractState>, paused: bool) -> bool {
            // Only admin can pause/unpause registrations
            assert(self._has_admin_access_role(), 'Unauthorized');

            self.registration_paused.write(paused);

            // Emit event
            self
                .emit(
                    Event::RegistrationPauseChanged(
                        RegistrationPauseChanged { paused, changed_by: get_caller_address() },
                    ),
                );

            true
        }

        fn is_registration_paused(self: @ComponentState<TContractState>) -> bool {
            self.registration_paused.read()
        }

        fn get_contract_config(self: @ComponentState<TContractState>) -> (u32, bool, u32) {
            (
                self.min_reputation_score.read(),
                self.registration_paused.read(),
                self.total_users.read(),
            )
        }

        fn get_users_with_role_paginated(
            self: @ComponentState<TContractState>, role: u8, offset: u32, limit: u32,
        ) -> Array<ContractAddress> {
            let mut users = ArrayTrait::new();
            let role_count = self.role_user_count.read(role);

            // Bounds checking
            if offset >= role_count {
                return users;
            }

            let end_index = if offset + limit > role_count {
                role_count
            } else {
                offset + limit
            };

            // Collect users within the specified range
            let mut i = offset;
            while i < end_index {
                let user_address = self.role_users.read((role, i));
                // Verify the user still has this role (in case of removals)
                if self.user_roles.read((user_address, role)) {
                    users.append(user_address);
                }
                i += 1;
            };

            users
        }

        fn get_user_referrals_paginated(
            self: @ComponentState<TContractState>,
            referrer_address: ContractAddress,
            offset: u32,
            limit: u32,
        ) -> Array<ContractAddress> {
            let mut referrals = ArrayTrait::new();
            let referral_length = self.referrer_referral_length.read(referrer_address);

            // Bounds checking
            if offset >= referral_length {
                return referrals;
            }

            let end_index = if offset + limit > referral_length {
                referral_length
            } else {
                offset + limit
            };

            // Collect referrals within the specified range
            let mut i = offset;
            while i < end_index {
                let referral_address = self.referrer_referrals.read((referrer_address, i));
                referrals.append(referral_address);
                i += 1;
            };

            referrals
        }

        // ============ Auth Management Functions ============

        fn get_auth_security_config(self: @ComponentState<TContractState>) -> (u64, u32, u64) {
            (
                self.challenge_rate_limit.read(),
                self.max_failed_attempts.read(),
                self.lockout_duration.read(),
            )
        }

        fn update_auth_security_config(
            ref self: ComponentState<TContractState>,
            rate_limit_seconds: u64,
            max_failed_attempts: u32,
            lockout_duration_seconds: u64,
        ) -> bool {
            // Only admin can update auth config
            assert(self._has_admin_access_role(), 'Unauthorized');

            self.challenge_rate_limit.write(rate_limit_seconds);
            self.max_failed_attempts.write(max_failed_attempts);
            self.lockout_duration.write(lockout_duration_seconds);

            true
        }

        fn get_user_auth_status(
            self: @ComponentState<TContractState>, user_address: ContractAddress,
        ) -> (u32, u64, bool) {
            let failed_attempts = self.failed_auth_attempts.read(user_address);
            let last_attempt_time = self.last_challenge_timestamp.read(user_address);
            let max_attempts = self.max_failed_attempts.read();

            let is_locked_out = if failed_attempts >= max_attempts {
                let lockout_duration = self.lockout_duration.read();
                let current_timestamp = get_block_timestamp();
                current_timestamp <= last_attempt_time + lockout_duration
            } else {
                false
            };

            (failed_attempts, last_attempt_time, is_locked_out)
        }

        fn reset_user_auth_status(
            ref self: ComponentState<TContractState>, user_address: ContractAddress,
        ) -> bool {
            // Only admin can reset auth status
            assert(self._has_admin_access_role(), 'Unauthorized');

            self.failed_auth_attempts.write(user_address, 0);
            self.last_challenge_timestamp.write(user_address, 0);

            // Clear any existing challenge
            let empty_challenge = AuthChallenge {
                challenge_hash: 0, expiry_timestamp: 0, is_used: false,
            };
            self.auth_challenges.write(user_address, empty_challenge);

            true
        }

        fn has_active_challenge(
            self: @ComponentState<TContractState>, user_address: ContractAddress,
        ) -> bool {
            let challenge = self.auth_challenges.read(user_address);
            let current_timestamp = get_block_timestamp();

            challenge.challenge_hash != 0
                && !challenge.is_used
                && current_timestamp <= challenge.expiry_timestamp
        }
    }

    /// Internal functions
    #[generate_trait]
    impl InternalFunctions<
        TContractState,
        +HasComponent<TContractState>,
        +Drop<TContractState>,
        impl AccessControl: AccessControlComponent::HasComponent<TContractState>,
    > of InternalFunctionsTrait<TContractState> {
        /// Initialize the user manager component
        fn _initialize(ref self: ComponentState<TContractState>) {
            self.total_users.write(0);
            self.min_reputation_score.write(50); // Default minimum reputation
            self.registration_paused.write(false);

            // Initialize role counts to 0
            self.role_user_count.write(UserRole::Banned, 0);
            self.role_user_count.write(UserRole::Regular, 0);
            self.role_user_count.write(UserRole::Premium, 0);
            self.role_user_count.write(UserRole::VIP, 0);
            self.role_user_count.write(UserRole::Moderator, 0);
            self.role_user_count.write(UserRole::Admin, 0);
            self.role_user_count.write(UserRole::Oracle, 0);

            // Initialize auth security parameters
            self.challenge_rate_limit.write(30); // 30 seconds between challenges
            self.max_failed_attempts.write(5); // Max 5 failed attempts before lockout
            self.lockout_duration.write(900); // 15 minutes lockout duration
        }

        /// Internal function to check if user is registered
        fn _is_user_registered(
            self: @ComponentState<TContractState>, user_address: ContractAddress,
        ) -> bool {
            let profile = self.user_profiles.read(user_address);
            profile.user_address == user_address && profile.registration_timestamp > 0
        }

        /// Internal function to check if username is available
        fn _is_username_available(
            self: @ComponentState<TContractState>, username: felt252,
        ) -> bool {
            let mapped_address = self.username_to_address.read(username);
            let zero_address: ContractAddress = 0.try_into().unwrap();
            mapped_address == zero_address
        }

        fn _has_admin_access_role(self: @ComponentState<TContractState>) -> bool {
            let access_control = get_dep_component!(self, AccessControl);
            access_control.has_role(AccessControlComponent::Roles::ADMIN, get_caller_address())
        }

        /// Clean up expired authentication challenge
        fn _cleanup_expired_challenge(
            ref self: ComponentState<TContractState>, user_address: ContractAddress,
        ) {
            let challenge = self.auth_challenges.read(user_address);
            let current_timestamp = get_block_timestamp();

            if challenge.challenge_hash != 0 && current_timestamp > challenge.expiry_timestamp {
                // Clear the expired challenge
                let empty_challenge = AuthChallenge {
                    challenge_hash: 0, expiry_timestamp: 0, is_used: false,
                };
                self.auth_challenges.write(user_address, empty_challenge);

                // Emit expired event
                self
                    .emit(
                        Event::AuthChallengeExpired(
                            AuthChallengeExpired {
                                user_address,
                                challenge_hash: challenge.challenge_hash,
                                timestamp: current_timestamp,
                            },
                        ),
                    );
            }
        }

        /// Record failed authentication attempt
        fn _record_failed_attempt(
            ref self: ComponentState<TContractState>,
            user_address: ContractAddress,
            challenge_hash: felt252,
            reason: felt252,
        ) {
            let current_attempts = self.failed_auth_attempts.read(user_address);
            let new_attempts = current_attempts + 1;
            self.failed_auth_attempts.write(user_address, new_attempts);

            let current_timestamp = get_block_timestamp();
            self.last_challenge_timestamp.write(user_address, current_timestamp);

            // Emit failed attempt event
            self
                .emit(
                    Event::AuthAttemptFailed(
                        AuthAttemptFailed {
                            user_address, challenge_hash, reason, timestamp: current_timestamp,
                        },
                    ),
                );

            // Check if user should be locked out
            let max_attempts = self.max_failed_attempts.read();
            if new_attempts >= max_attempts {
                let lockout_duration = self.lockout_duration.read();
                let lockout_until = current_timestamp + lockout_duration;

                self
                    .emit(
                        Event::UserLockedOut(
                            UserLockedOut {
                                user_address, failed_attempts: new_attempts, lockout_until,
                            },
                        ),
                    );
            }
        }
    }
}
