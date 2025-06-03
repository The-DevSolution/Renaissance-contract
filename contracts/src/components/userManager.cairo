#[starknet::component]
pub mod UserManagerComponent {
    use core::hash::HashStateTrait;
    use core::{array::Array, pedersen::PedersenTrait};
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
            }

            // Assign default role (Regular)
            self.user_roles.write((user_address, UserRole::Regular), true);

            // Increment total users
            let total = self.total_users.read();
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
            //TODO: Implement this
            // This is a simplified implementation - in practice you'd want a more efficient
            // approach
            let mut users = ArrayTrait::new();
            // Note: This would require iterating through stored users, which is not efficient
            // In production, you'd maintain a separate array of user addresses
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
            //TODO: Implement this
            // This is a simplified implementation - in practice you'd maintain reverse mappings
            let mut users = ArrayTrait::new();
            // Note: This would require iterating through all users, which is not efficient
            // In production, you'd maintain separate arrays for each role
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
            let tx_info = get_tx_info().unbox();

            let challenge_hash = PedersenTrait::new(0)
                .update(user_address.into())
                .update(get_block_timestamp().into())
                .update(tx_info.nonce)
                .update(3)
                .finalize();

            let expiry = get_block_timestamp() + 900; // 15 minutes

            // Store challenge
            let challenge = AuthChallenge {
                challenge_hash, expiry_timestamp: expiry, is_used: false,
            };
            self.auth_challenges.write(user_address, challenge);

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
            signature: Array<felt252>,
        ) -> bool {
            // Check if user is registered and active
            assert(self.is_user_active(user_address), 'User not active');

            // Get stored challenge
            let mut challenge = self.auth_challenges.read(user_address);

            // Verify challenge hasn't been used and hasn't expired
            assert(!challenge.is_used, 'Challenge already used');
            assert(challenge.challenge_hash == challenge_hash, 'Invalid challenge');
            assert(get_block_timestamp() <= challenge.expiry_timestamp, 'Challenge expired');

            // Mark challenge as used
            challenge.is_used = true;
            self.auth_challenges.write(user_address, challenge);
            //TODO: Verify signature here
            // In a real implementation, you would verify the signature here
            // For now, we'll just check that a signature was provided
            let is_valid = signature.len() > 0;

            // Emit event
            self
                .emit(
                    Event::AuthChallengeVerified(
                        AuthChallengeVerified { user_address, challenge_hash, success: is_valid },
                    ),
                );

            is_valid
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
            // This is a simplified implementation - in practice you'd maintain a list of referrals
            let mut referrals = ArrayTrait::new();
            //TODO: Implement this
            // Note: This would require iterating through all users, which is not efficient
            // In production, you'd maintain a separate array of referrals per user
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
    }
}
