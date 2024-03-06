pub mod admin_interface {
    use cosmwasm_schema::{cw_serde, QueryResponses};

    #[cw_serde]
    pub struct AdminInfoResponse {
        pub joined_block: u64,
    }

    #[cw_serde]
    pub enum ExecuteMsg {
        AddAdmin { admin: String },
    }

    #[cw_serde]
    #[derive(QueryResponses)]
    pub enum QueryMsg {
        #[returns(AdminInfoResponse)]
        AdminInfo { admin: String },
    }
}
