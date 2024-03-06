use cosmwasm_std::StdError;
use cw_utils::{ParseReplyError, PaymentError};
use thiserror::Error;

#[derive(Error, Debug, PartialEq)]
pub enum ContractError {
    #[error("{0}")]
    StdError(#[from] StdError),
    #[error("Payment error: {0}")]
    PaymentError(#[from] PaymentError),
    #[error("No donations left to withdraw")]
    NoDonations(),
    #[error("Integer overflow")]
    Overflow(),
    #[error("Admin not found")]
    AdminNotFound(),
    #[error("Admin already exists")]
    AdminAlreadyExists(),
    #[error("Proposed admin is already being voted on")]
    AlreadyBeingVotedOn(),
    #[error("The contract needs at least 1 admin")]
    LastAdmin(),
    #[error("{0}")]
    ParseReplyError(#[from] ParseReplyError),
    #[error("Not allowed to spend donations")]
    NotAllowedToSpend(),
}
