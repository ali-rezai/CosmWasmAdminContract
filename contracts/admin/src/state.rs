use cosmwasm_std::Addr;
use cw_storage_plus::{Item, Map};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct AdminData {
    pub joined_block: u64,
    pub withdrawn: u128,
}

pub const ADMINS: Map<&Addr, AdminData> = Map::new("admins");
pub const ADMIN_COUNT: Item<u128> = Item::new("admin_count");
pub const DONATION_DENOM: Item<String> = Item::new("donation_denom");
pub const DONATED: Item<u128> = Item::new("donated");
pub const VOTING_CONTRACT: Item<u64> = Item::new("voting_contract");
pub const VOTING_TRACKER: Map<&Addr, Addr> = Map::new("voting_tracker");
