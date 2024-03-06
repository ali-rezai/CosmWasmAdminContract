use crate::state::VotingData;
use cosmwasm_schema::{cw_serde, QueryResponses};

#[cw_serde]
pub struct InstantiateMsg {
    pub proposed_admin: String,
    pub threshold: u128,
}

#[cw_serde]
pub struct InstantiateResponse {
    pub proposed_admin: String,
}

#[cw_serde]
pub enum ExecuteMsg {
    SubmitVote { value: bool },
}

pub type VotingInfoResponse = VotingData;

#[cw_serde]
pub struct HasVotedResponse {
    pub vote: Option<bool>,
}

#[cw_serde]
pub struct DecisionResponse {
    pub decision: Option<bool>,
}

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {
    #[returns(VotingInfoResponse)]
    VotingInfo {},
    #[returns(HasVotedResponse)]
    HasVoted { admin: String },
    #[returns(DecisionResponse)]
    Decision {},
}
