use cosmwasm_schema::{cw_serde, QueryResponses};
use cosmwasm_std::CosmosMsg;

#[cw_serde]
pub struct InstantiateMsg {
    pub admins: Vec<String>,
    pub donation_denom: String,
    pub voting_contract_code_id: u64,
}

#[cw_serde]
pub enum ExecuteMsg {
    Leave {},
    Donate {},
    Withdraw {},
    AddAdmin { admin: String },
    Execute { msg: CosmosMsg },
}

#[cw_serde]
pub struct AdminInfoResponse {
    pub joined_block: u64,
}

#[cw_serde]
pub struct AdminWithdrawableResponse {
    pub amount: u128,
}

#[cw_serde]
pub struct AdminCountResponse {
    pub count: u128,
}

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {
    #[returns(AdminInfoResponse)]
    AdminInfo { admin: String },
    #[returns(AdminWithdrawableResponse)]
    AdminWithdrawable { admin: String },
    #[returns(AdminCountResponse)]
    AdminCount {},
}

pub const VOTING_CONTRACT_INSTANTIATION_REPLY_ID: u64 = 1;
pub const EXECUTE_COSMOS_MSG_ID: u64 = 2;
