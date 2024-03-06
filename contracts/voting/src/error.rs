use cosmwasm_std::StdError;
use thiserror::Error;

#[derive(Error, Debug, PartialEq)]
pub enum ContractError {
    #[error("{0}")]
    StdError(#[from] StdError),
    #[error("Decision has already been made")]
    DecisionAlreadyMade(),
    #[error("The user is an admin but joined after the voting began")]
    AdminNotAllowedToVote(),
    #[error("Couldn't get admin data")]
    AdminDataError(),
    #[error("You have already voted {0}")]
    AlreadyVoted(bool),
}
