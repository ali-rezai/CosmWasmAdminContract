pub mod voting_interface {
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
    pub struct DecisionResponse {
        pub decision: Option<bool>,
    }

    #[cw_serde]
    #[derive(QueryResponses)]
    pub enum QueryMsg {
        #[returns(DecisionResponse)]
        Decision {},
    }
}
