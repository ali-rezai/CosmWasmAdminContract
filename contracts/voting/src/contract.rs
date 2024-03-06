use crate::{error::*, interface::*, msg::*, state::*};
use cosmwasm_std::{
    to_json_binary, wasm_execute, Binary, CosmosMsg, Deps, DepsMut, Env, Event, MessageInfo,
    Response, StdError, StdResult,
};

pub fn instantiate(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: InstantiateMsg,
) -> StdResult<Response> {
    let proposed_admin = deps.api.addr_validate(&msg.proposed_admin)?;
    ADMIN_CONTRACT.save(deps.storage, &info.sender)?;
    PROPOSED_ADMIN.save(deps.storage, &proposed_admin)?;
    CREATED_AT.save(deps.storage, &env.block.height)?;
    VOTING.save(
        deps.storage,
        &VotingData {
            threshold: msg.threshold,
            voted_for: 0,
            voted_against: 0,
        },
    )?;
    DECISION.save(deps.storage, &None)?;
    Ok(
        Response::new().set_data(to_json_binary(&InstantiateResponse {
            proposed_admin: msg.proposed_admin,
        })?),
    )
}

pub fn execute(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, ContractError> {
    use ExecuteMsg::*;
    match msg {
        SubmitVote { value } => submit_vote(deps, info, value),
    }
}

fn submit_vote(deps: DepsMut, info: MessageInfo, value: bool) -> Result<Response, ContractError> {
    let decision = DECISION.load(deps.storage)?;
    if let Some(_) = decision {
        return Err(ContractError::DecisionAlreadyMade());
    }

    match deps
        .querier
        .query_wasm_smart::<admin_interface::AdminInfoResponse>(
            ADMIN_CONTRACT.load(deps.storage)?,
            &admin_interface::QueryMsg::AdminInfo {
                admin: info.sender.to_string(),
            },
        ) {
        Ok(admin_info) => {
            if admin_info.joined_block >= CREATED_AT.load(deps.storage)? {
                return Err(ContractError::AdminNotAllowedToVote());
            }
        }
        Err(_) => return Err(ContractError::AdminDataError()),
    };

    let mut current_votes = VOTING.load(deps.storage)?;
    let last_vote = VOTED.load(deps.storage, &info.sender);
    match last_vote {
        Ok(vote) => {
            if vote == value {
                return Err(ContractError::AlreadyVoted(value));
            } else {
                if value {
                    current_votes.voted_for += 1;
                    current_votes.voted_against -= 1;
                } else {
                    current_votes.voted_for -= 1;
                    current_votes.voted_against += 1;
                }
            }
        }
        Err(err) => match err {
            StdError::NotFound { kind: _ } => {
                if value {
                    current_votes.voted_for += 1;
                } else {
                    current_votes.voted_against += 1;
                }
            }
            _ => return Err(ContractError::from(err)),
        },
    }
    VOTED.save(deps.storage, &info.sender, &value)?;
    VOTING.save(deps.storage, &current_votes)?;

    let resp = Response::new().add_event(
        Event::new("voted")
            .add_attribute("admin", info.sender)
            .add_attribute("value", value.to_string()),
    );

    let resp = if current_votes.threshold <= current_votes.voted_against {
        DECISION.save(deps.storage, &Some(false))?;
        resp.add_event(Event::new("voting-finished").add_attribute("outcome", false.to_string()))
    } else if current_votes.threshold <= current_votes.voted_for {
        DECISION.save(deps.storage, &Some(true))?;
        let msg = CosmosMsg::Wasm(wasm_execute(
            ADMIN_CONTRACT.load(deps.storage)?,
            &admin_interface::ExecuteMsg::AddAdmin {
                admin: PROPOSED_ADMIN.load(deps.storage)?.to_string(),
            },
            vec![],
        )?);
        resp.add_message(msg)
            .add_event(Event::new("voting-finished").add_attribute("outcome", true.to_string()))
    } else {
        resp
    };

    Ok(resp)
}

pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    use QueryMsg::*;
    match msg {
        VotingInfo {} => {
            let voting_data = VOTING.load(deps.storage)? as VotingInfoResponse;
            to_json_binary(&voting_data)
        }
        HasVoted { admin } => {
            let admin_addr = deps.api.addr_validate(&admin)?;
            let voted = VOTED.load(deps.storage, &admin_addr);
            let mut voting_data = HasVotedResponse { vote: None };
            match voted {
                Ok(value) => {
                    voting_data.vote = Some(value);
                }
                Err(err) => match err {
                    StdError::NotFound { kind: _ } => {}
                    _ => return Err(err),
                },
            }
            to_json_binary(&voting_data)
        }
        Decision {} => to_json_binary(&DecisionResponse {
            decision: DECISION.load(deps.storage)?,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use admin;
    use cosmwasm_std::Addr;
    use cw_multi_test::{App, AppResponse, ContractWrapper, Executor};

    fn instantiate_admin_contract(app: &mut App, msg: admin::msg::InstantiateMsg) -> Addr {
        use admin::contract::*;
        let code = ContractWrapper::new(execute, instantiate, query);
        let code = code.with_reply(reply);
        let code_id = app.store_code(Box::new(code));
        app.instantiate_contract(
            code_id,
            Addr::unchecked("owner"),
            &msg,
            &[],
            "Contract",
            None,
        )
        .unwrap()
    }

    fn voting_contract_code_id(app: &mut App) -> u64 {
        let code = ContractWrapper::new(execute, instantiate, query);
        app.store_code(Box::new(code))
    }

    fn voting_info(app: &App, addr: &Addr) -> StdResult<VotingInfoResponse> {
        app.wrap().query_wasm_smart(addr, &QueryMsg::VotingInfo {})
    }
    fn has_voted(app: &App, addr: &Addr, admin: &str) -> StdResult<HasVotedResponse> {
        app.wrap().query_wasm_smart(
            addr,
            &QueryMsg::HasVoted {
                admin: admin.to_string(),
            },
        )
    }
    fn decision(app: &App, addr: &Addr) -> StdResult<DecisionResponse> {
        app.wrap().query_wasm_smart(addr, &QueryMsg::Decision {})
    }

    fn vote(
        app: &mut App,
        addr: &Addr,
        admin: impl Into<String>,
        value: bool,
    ) -> Result<AppResponse, ContractError> {
        match app.execute_contract(
            Addr::unchecked(admin),
            addr.clone(),
            &ExecuteMsg::SubmitVote { value: value },
            &[],
        ) {
            Ok(resp) => Ok(resp),
            Err(err) => Err(err.downcast().unwrap()),
        }
    }

    fn add_admin(
        app: &mut App,
        addr: &Addr,
        admin: impl Into<String>,
        proposed_admin: &str,
    ) -> Result<(AppResponse, Addr), admin::error::ContractError> {
        match app.execute_contract(
            Addr::unchecked(admin),
            addr.clone(),
            &admin::msg::ExecuteMsg::AddAdmin {
                admin: proposed_admin.to_string(),
            },
            &[],
        ) {
            Ok(resp) => {
                let voting_addr = Addr::unchecked(
                    resp.events
                        .iter()
                        .find(|e| e.ty == "wasm-voting-contract-instantiated")
                        .unwrap()
                        .attributes
                        .iter()
                        .find(|attr| attr.key == "address")
                        .unwrap()
                        .value
                        .to_string(),
                );
                Ok((resp, voting_addr))
            }
            Err(err) => Err(err.downcast().unwrap()),
        }
    }

    fn increment_block(app: &mut App) {
        app.update_block(|block| {
            block.height += 1;
        });
    }

    #[test]
    fn test_get_voting_info() {
        let mut app = App::default();
        let voting_contract_code_id = voting_contract_code_id(&mut app);
        let admin_addr = instantiate_admin_contract(
            &mut app,
            admin::msg::InstantiateMsg {
                admins: vec!["admin1".to_owned(), "admin2".to_owned()],
                donation_denom: "eth".to_owned(),
                voting_contract_code_id: voting_contract_code_id,
            },
        );
        increment_block(&mut app);
        let (_, addr) = add_admin(&mut app, &admin_addr, "admin1", "admin3").unwrap();
        vote(&mut app, &addr, "admin1", true).unwrap();
        vote(&mut app, &addr, "admin2", false).unwrap();
        let resp = voting_info(&app, &addr).unwrap();
        assert_eq!(
            resp,
            VotingData {
                threshold: 2,
                voted_against: 1,
                voted_for: 1
            }
        )
    }
    #[test]
    fn test_get_has_voted() {
        let mut app = App::default();
        let voting_contract_code_id = voting_contract_code_id(&mut app);
        let admin_addr = instantiate_admin_contract(
            &mut app,
            admin::msg::InstantiateMsg {
                admins: vec!["admin1".to_owned(), "admin2".to_owned()],
                donation_denom: "eth".to_owned(),
                voting_contract_code_id: voting_contract_code_id,
            },
        );
        increment_block(&mut app);
        let (_, addr) = add_admin(&mut app, &admin_addr, "admin1", "admin3").unwrap();

        let resp = has_voted(&app, &addr, "admin1").unwrap();
        assert_eq!(resp.vote, None);
        vote(&mut app, &addr, "admin1", true).unwrap();
        let resp = has_voted(&app, &addr, "admin1").unwrap();
        assert_eq!(resp.vote.unwrap(), true);

        let resp = has_voted(&app, &addr, "admin2").unwrap();
        assert_eq!(resp.vote, None);
        vote(&mut app, &addr, "admin2", false).unwrap();
        let resp = has_voted(&app, &addr, "admin2").unwrap();
        assert_eq!(resp.vote.unwrap(), false);
    }
    #[test]
    fn test_get_decision() {
        let mut app = App::default();
        let voting_contract_code_id = voting_contract_code_id(&mut app);
        let admin_addr = instantiate_admin_contract(
            &mut app,
            admin::msg::InstantiateMsg {
                admins: vec!["admin1".to_owned(), "admin2".to_owned()],
                donation_denom: "eth".to_owned(),
                voting_contract_code_id: voting_contract_code_id,
            },
        );
        increment_block(&mut app);

        let (_, addr) = add_admin(&mut app, &admin_addr, "admin1", "admin3").unwrap();
        let resp = decision(&app, &addr).unwrap();
        assert_eq!(resp.decision, None);
        vote(&mut app, &addr, "admin1", true).unwrap();
        let resp = decision(&app, &addr).unwrap();
        assert_eq!(resp.decision, None);
        vote(&mut app, &addr, "admin2", true).unwrap();
        let resp = decision(&app, &addr).unwrap();
        assert_eq!(resp.decision.unwrap(), true);

        let (_, addr) = add_admin(&mut app, &admin_addr, "admin2", "admin4").unwrap();
        let resp = decision(&app, &addr).unwrap();
        assert_eq!(resp.decision, None);
        vote(&mut app, &addr, "admin1", false).unwrap();
        let resp = decision(&app, &addr).unwrap();
        assert_eq!(resp.decision, None);
        vote(&mut app, &addr, "admin2", false).unwrap();
        let resp = decision(&app, &addr).unwrap();
        assert_eq!(resp.decision.unwrap(), false);
    }
    #[test]
    fn test_submit_vote() {
        let mut app = App::default();
        let voting_contract_code_id = voting_contract_code_id(&mut app);
        let admin_addr = instantiate_admin_contract(
            &mut app,
            admin::msg::InstantiateMsg {
                admins: vec!["admin1".to_owned(), "admin2".to_owned()],
                donation_denom: "eth".to_owned(),
                voting_contract_code_id: voting_contract_code_id,
            },
        );
        increment_block(&mut app);
        let (_, addr) = add_admin(&mut app, &admin_addr, "admin1", "admin3").unwrap();

        let err = vote(&mut app, &addr, "admin3", true).unwrap_err();
        assert_eq!(ContractError::AdminDataError(), err);

        let resp = vote(&mut app, &addr, "admin1", false).unwrap();
        resp.assert_event(
            &Event::new("wasm-voted")
                .add_attribute("admin", "admin1")
                .add_attribute("value", false.to_string()),
        );
        let err = vote(&mut app, &addr, "admin1", false).unwrap_err();
        assert_eq!(ContractError::AlreadyVoted(false), err);
        let resp = voting_info(&app, &addr).unwrap();
        assert_eq!(
            resp,
            VotingData {
                threshold: 2,
                voted_against: 1,
                voted_for: 0
            }
        );

        let resp = vote(&mut app, &addr, "admin1", true).unwrap();
        resp.assert_event(
            &Event::new("wasm-voted")
                .add_attribute("admin", "admin1")
                .add_attribute("value", true.to_string()),
        );
        let err = vote(&mut app, &addr, "admin1", true).unwrap_err();
        assert_eq!(ContractError::AlreadyVoted(true), err);
        let resp = voting_info(&app, &addr).unwrap();
        assert_eq!(
            resp,
            VotingData {
                threshold: 2,
                voted_against: 0,
                voted_for: 1
            }
        );

        let resp = vote(&mut app, &addr, "admin2", true).unwrap();
        resp.assert_event(
            &Event::new("wasm-voted")
                .add_attribute("admin", "admin2")
                .add_attribute("value", true.to_string()),
        );
        resp.assert_event(
            &Event::new("wasm-voting-finished").add_attribute("outcome", true.to_string()),
        );
        let resp = decision(&app, &addr).unwrap();
        assert_eq!(resp.decision.unwrap(), true);
        let err = vote(&mut app, &addr, "admin1", true).unwrap_err();
        assert_eq!(ContractError::DecisionAlreadyMade(), err);

        let err = add_admin(&mut app, &admin_addr, "admin1", "admin3").unwrap_err();
        assert_eq!(admin::error::ContractError::AdminAlreadyExists(), err);
        let (_, addr) = add_admin(&mut app, &admin_addr, "admin1", "admin4").unwrap();

        let err = vote(&mut app, &addr, "admin3", true).unwrap_err();
        assert_eq!(ContractError::AdminNotAllowedToVote(), err);

        let resp = vote(&mut app, &addr, "admin1", false).unwrap();
        resp.assert_event(
            &Event::new("wasm-voted")
                .add_attribute("admin", "admin1")
                .add_attribute("value", false.to_string()),
        );
        let resp = voting_info(&app, &addr).unwrap();
        assert_eq!(
            resp,
            VotingData {
                threshold: 2,
                voted_against: 1,
                voted_for: 0
            }
        );
        let resp = vote(&mut app, &addr, "admin2", false).unwrap();
        resp.assert_event(
            &Event::new("wasm-voted")
                .add_attribute("admin", "admin2")
                .add_attribute("value", false.to_string()),
        );
        resp.assert_event(
            &Event::new("wasm-voting-finished").add_attribute("outcome", false.to_string()),
        );
        let resp = voting_info(&app, &addr).unwrap();
        assert_eq!(
            resp,
            VotingData {
                threshold: 2,
                voted_against: 2,
                voted_for: 0
            }
        );

        let (_, _) = add_admin(&mut app, &admin_addr, "admin1", "admin4").unwrap();
    }
}
