use starknet::ContractAddress;

#[starknet::interface]
pub trait IAccessControl<TState> {
    fn add_role(ref self: TState, role: u8);
    fn remove_role(ref self: TState, role: u8);
    fn has_role(self: @TState, role: u8, account: ContractAddress) -> bool;
    fn grant_role(ref self: TState, role: u8, account: ContractAddress);
    fn revoke_role(ref self: TState, role: u8, account: ContractAddress);
    fn renounce_role(ref self: TState, role: u8);
    fn get_admin(self: @TState) -> ContractAddress;
}
