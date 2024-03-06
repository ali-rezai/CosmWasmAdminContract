use cosmwasm_schema::cw_serde;
use cosmwasm_std::Addr;
use cw_storage_plus::{Item, Map};

#[cw_serde]
pub struct VotingData {
    pub threshold: u128,
    pub voted_for: u128,
    pub voted_against: u128,
}

pub const ADMIN_CONTRACT: Item<Addr> = Item::new("admin_contract");
pub const PROPOSED_ADMIN: Item<Addr> = Item::new("proposed_admin");
pub const CREATED_AT: Item<u64> = Item::new("created_at");
pub const VOTING: Item<VotingData> = Item::new("voting");
pub const VOTED: Map<&Addr, bool> = Map::new("voted");
pub const DECISION: Item<Option<bool>> = Item::new("decision");
