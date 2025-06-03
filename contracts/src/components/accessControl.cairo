#[starknet::component]
pub mod AccessControlComponent {
    use starknet::{ContractAddress, get_caller_address};
    use starknet::storage::{
        StorageMapReadAccess, StorageMapWriteAccess, StoragePointerReadAccess,
        StoragePointerWriteAccess, Map,
    };

    /// Role constants
    pub mod Roles {
        pub const ADMIN: u8 = 0;
        pub const DEFAULT_ADMIN: u8 = 0;
    }

    /// Storage for the AccessControl component
    #[storage]
    struct Storage {
        /// Maps role -> account -> has_role
        role_members: Map<(u8, ContractAddress), bool>,
        /// Maps role -> exists
        roles: Map<u8, bool>,
        /// Admin address
        admin: ContractAddress,
        /// Maps role -> admin_role (role that can manage this role)
        role_admin: Map<u8, u8>,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        RoleAdded: RoleAdded,
        RoleRemoved: RoleRemoved,
        RoleGranted: RoleGranted,
        RoleRevoked: RoleRevoked,
        RoleRenounced: RoleRenounced,
        AdminChanged: AdminChanged,
    }

    #[derive(Drop, starknet::Event)]
    struct RoleAdded {
        role: u8,
    }

    #[derive(Drop, starknet::Event)]
    struct RoleRemoved {
        role: u8,
    }

    #[derive(Drop, starknet::Event)]
    struct RoleGranted {
        role: u8,
        account: ContractAddress,
        sender: ContractAddress,
    }

    #[derive(Drop, starknet::Event)]
    struct RoleRevoked {
        role: u8,
        account: ContractAddress,
        sender: ContractAddress,
    }

    #[derive(Drop, starknet::Event)]
    struct RoleRenounced {
        role: u8,
        account: ContractAddress,
    }

    #[derive(Drop, starknet::Event)]
    struct AdminChanged {
        previous_admin: ContractAddress,
        new_admin: ContractAddress,
    }

    #[embeddable_as(AccessControlImpl)]
    impl AccessControl<
        TContractState, +HasComponent<TContractState>,
    > of renaissance::interfaces::IAccessControl::IAccessControl<ComponentState<TContractState>> {
        /// Add a new role (admin only)
        fn add_role(ref self: ComponentState<TContractState>, role: u8) {
            self._only_admin();

            // Check if role already exists
            assert(!self.roles.read(role), 'Role already exists');

            // Add the role
            self.roles.write(role, true);

            // Set admin role as the default admin for this role
            self.role_admin.write(role, Roles::ADMIN);

            // Emit event
            self.emit(Event::RoleAdded(RoleAdded { role }));
        }

        /// Remove a role (admin only)
        fn remove_role(ref self: ComponentState<TContractState>, role: u8) {
            self._only_admin();

            // Cannot remove admin role
            assert(role != Roles::ADMIN, 'Cannot remove admin role');

            // Check if role exists
            assert(self.roles.read(role), 'Role does not exist');

            // Remove the role
            self.roles.write(role, false);

            // Emit event
            self.emit(Event::RoleRemoved(RoleRemoved { role }));
        }

        /// Check if account has role
        fn has_role(
            self: @ComponentState<TContractState>, role: u8, account: ContractAddress,
        ) -> bool {
            self.role_members.read((role, account))
        }

        /// Grant role to account (admin only)
        fn grant_role(
            ref self: ComponentState<TContractState>, role: u8, account: ContractAddress,
        ) {
            let caller = get_caller_address();

            // Check if caller has permission to grant this role
            self._check_role_admin(role);

            // Check if role exists (except for admin role which always exists)
            if role != Roles::ADMIN {
                assert(self.roles.read(role), 'Role does not exist');
            }

            // Grant the role
            self.role_members.write((role, account), true);

            // Emit event
            self.emit(Event::RoleGranted(RoleGranted { role, account, sender: caller }));
        }

        /// Revoke role from account (admin only)
        fn revoke_role(
            ref self: ComponentState<TContractState>, role: u8, account: ContractAddress,
        ) {
            let caller = get_caller_address();

            // Check if caller has permission to revoke this role
            self._check_role_admin(role);

            // Revoke the role
            self.role_members.write((role, account), false);

            // Emit event
            self.emit(Event::RoleRevoked(RoleRevoked { role, account, sender: caller }));
        }

        /// Renounce role (can only be called by the account holder)
        fn renounce_role(ref self: ComponentState<TContractState>, role: u8) {
            let caller = get_caller_address();

            // Check if caller has the role
            assert(self.role_members.read((role, caller)), 'Account does not have role');

            // Cannot renounce admin role if you are the only admin
            if role == Roles::ADMIN {
                // This is a simplified check - in production you might want to count all admins
                let zero_address: ContractAddress = 0.try_into().unwrap();
                assert(
                    self.admin.read() != caller || self.admin.read() == zero_address,
                    'Cannot renounce last admin',
                );
            }

            // Renounce the role
            self.role_members.write((role, caller), false);

            // Emit event
            self.emit(Event::RoleRenounced(RoleRenounced { role, account: caller }));
        }

        /// Get the current admin
        fn get_admin(self: @ComponentState<TContractState>) -> ContractAddress {
            self.admin.read()
        }
    }

    /// Internal functions
    #[generate_trait]
    impl InternalFunctions<
        TContractState, +HasComponent<TContractState>,
    > of InternalFunctionsTrait<TContractState> {
        /// Initialize the access control component
        fn _initialize(ref self: ComponentState<TContractState>, admin: ContractAddress) {
            // Set the admin
            self.admin.write(admin);

            // Grant admin role to the admin
            self.role_members.write((Roles::ADMIN, admin), true);

            // Admin role exists by default
            self.roles.write(Roles::ADMIN, true);
        }

        /// Change admin (current admin only)
        fn _change_admin(ref self: ComponentState<TContractState>, new_admin: ContractAddress) {
            self._only_admin();

            let previous_admin = self.admin.read();

            // Revoke admin role from previous admin
            self.role_members.write((Roles::ADMIN, previous_admin), false);

            // Grant admin role to new admin
            self.role_members.write((Roles::ADMIN, new_admin), true);

            // Update admin address
            self.admin.write(new_admin);

            // Emit event
            self.emit(Event::AdminChanged(AdminChanged { previous_admin, new_admin }));
        }

        /// Check if caller is admin
        fn _only_admin(self: @ComponentState<TContractState>) {
            let caller = get_caller_address();
            assert(self.role_members.read((Roles::ADMIN, caller)), 'Caller is not admin');
        }

        /// Check if caller can manage the specified role
        fn _check_role_admin(self: @ComponentState<TContractState>, role: u8) {
            let caller = get_caller_address();
            let admin_role = self.role_admin.read(role);
            assert(self.role_members.read((admin_role, caller)), 'Insufficient permissions');
        }

        /// Check if caller has specific role
        fn _check_role(self: @ComponentState<TContractState>, role: u8) {
            let caller = get_caller_address();
            assert(self.role_members.read((role, caller)), 'Missing required role');
        }

        /// Get role admin
        fn _get_role_admin(self: @ComponentState<TContractState>, role: u8) -> u8 {
            self.role_admin.read(role)
        }

        /// Set role admin (admin only)
        fn _set_role_admin(ref self: ComponentState<TContractState>, role: u8, admin_role: u8) {
            self._only_admin();
            self.role_admin.write(role, admin_role);
        }
    }
}
