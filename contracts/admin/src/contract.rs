use crate::{error::ContractError, interface::*, msg::*, state::*};
use cosmwasm_std::{
    coins, to_json_binary, wasm_instantiate, BankMsg, Binary, Deps, DepsMut, Env, Event,
    MessageInfo, Reply, Response, StdError, StdResult, SubMsgResult,
};

pub fn instantiate(
    deps: DepsMut,
    env: Env,
    _info: MessageInfo,
    msg: InstantiateMsg,
) -> StdResult<Response> {
    let admins: StdResult<Vec<_>> = msg
        .admins
        .iter()
        .map(|addr| deps.api.addr_validate(&addr))
        .collect();
    if let Err(x) = admins {
        return Err(x);
    }
    let admins = admins.unwrap();

    for admin in admins.iter() {
        ADMINS.save(
            deps.storage,
            admin,
            &AdminData {
                joined_block: env.block.height,
                withdrawn: 0,
            },
        )?;
    }
    ADMIN_COUNT.save(deps.storage, &(admins.len() as u128))?;
    DONATION_DENOM.save(deps.storage, &msg.donation_denom)?;
    DONATED.save(deps.storage, &0)?;
    VOTING_CONTRACT.save(deps.storage, &msg.voting_contract_code_id)?;
    Ok(Response::new())
}

pub fn execute(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, ContractError> {
    use ExecuteMsg::*;
    match msg {
        Leave {} => execute::leave(deps, info),
        Donate {} => execute::donate(deps, info),
        Withdraw {} => execute::withdraw(deps, info),
        AddAdmin { admin } => execute::add_admin(deps, env, info, admin),
        Execute { msg } => execute::execute_msg(deps, info, msg),
    }
}

mod execute {
    use super::*;
    use cosmwasm_std::{CosmosMsg, SubMsg};

    fn handle_admin_not_found<T>(res: StdResult<T>) -> Result<T, ContractError> {
        match res {
            Ok(resp) => Ok(resp),
            Err(err) => match err {
                StdError::NotFound { kind: _ } => Err(ContractError::AdminNotFound()),
                _ => Err(ContractError::from(err)),
            },
        }
    }

    fn withdraw_helper(
        deps: &mut DepsMut,
        info: &MessageInfo,
    ) -> Result<(BankMsg, Event), ContractError> {
        let admin = info.sender.to_string();
        let withdrawable =
            handle_admin_not_found(query::get_admin_withdrawable(deps.as_ref(), &admin))?.amount;
        if withdrawable == 0 {
            return Err(ContractError::NoDonations());
        }
        ADMINS.update(
            deps.storage,
            &info.sender,
            |admin_data| -> Result<AdminData, ContractError> {
                if let Some(mut data) = admin_data {
                    return match data.withdrawn.checked_add(withdrawable) {
                        Some(x) => {
                            data.withdrawn = x;
                            Ok(data)
                        }
                        None => Err(ContractError::Overflow()),
                    };
                }
                Err(ContractError::from(StdError::generic_err(
                    "Couldn't load admin data to update",
                )))
            },
        )?;

        PRE_EXEC_BALANCE.update(deps.storage, |pre_balance| -> Result<u128, ContractError> {
            Ok(pre_balance - withdrawable)
        })?;

        let denom = DONATION_DENOM.load(deps.storage)?;
        let event = Event::new("withdraw")
            .add_attribute("admin", &admin)
            .add_attribute("amount", withdrawable.to_string());
        let message = BankMsg::Send {
            to_address: admin,
            amount: coins(withdrawable, &denom),
        };
        Ok((message, event))
    }

    pub fn donation_storage_update(
        deps: DepsMut,
        distributed: u128,
        admin_count: u128,
        loaded_pre_balance: Option<u128>,
    ) -> Result<(), ContractError> {
        if distributed > 0 {
            DONATED.update(deps.storage, |donated| -> Result<u128, ContractError> {
                match donated.checked_add(distributed) {
                    Some(x) => Ok(x),
                    None => Err(ContractError::Overflow()),
                }
            })?;

            let pre_balance = match loaded_pre_balance {
                Some(x) => Some(x),
                None => PRE_EXEC_BALANCE.may_load(deps.storage)?,
            };

            let new_balance = match pre_balance {
                Some(x) => x + distributed * admin_count,
                None => distributed * admin_count,
            };
            PRE_EXEC_BALANCE.save(deps.storage, &new_balance)?;
        }
        Ok(())
    }

    pub fn add_admin(
        deps: DepsMut,
        env: Env,
        info: MessageInfo,
        admin: String,
    ) -> Result<Response, ContractError> {
        let mut is_voting_contract = true;
        let admin_addr = deps.api.addr_validate(&admin)?;

        match VOTING_TRACKER.load(deps.storage, &admin_addr) {
            Ok(instantiated_voting_contract) => {
                if info.sender != instantiated_voting_contract {
                    is_voting_contract = false;
                }
            }
            Err(err) => match err {
                StdError::NotFound { kind: _ } => {
                    is_voting_contract = false;
                }
                _ => return Err(ContractError::from(err)),
            },
        }

        if !is_voting_contract && !ADMINS.has(deps.storage, &info.sender) {
            return Err(ContractError::AdminNotFound());
        }

        if ADMINS.has(deps.storage, &admin_addr) {
            return Err(ContractError::AdminAlreadyExists());
        }

        if is_voting_contract {
            let donated = DONATED.load(deps.storage)?;
            ADMINS.save(
                deps.storage,
                &admin_addr,
                &AdminData {
                    joined_block: env.block.height,
                    // Acting as if he has withdrawn all donations so far so he doesn't get access to the donations made before he joined
                    withdrawn: donated,
                },
            )?;
            ADMIN_COUNT.update(deps.storage, |count| -> Result<u128, ContractError> {
                Ok(count + 1)
            })?;
            let resp =
                Response::new().add_event(Event::new("admin-added").add_attribute("admin", admin));
            return Ok(resp);
        }

        match VOTING_TRACKER.load(deps.storage, &admin_addr) {
            Ok(addr) => {
                let decision = deps
                    .querier
                    .query_wasm_smart::<voting_interface::DecisionResponse>(
                        addr,
                        &voting_interface::QueryMsg::Decision {},
                    )
                    .unwrap();
                if None == decision.decision {
                    return Err(ContractError::AlreadyBeingVotedOn());
                }
            }
            Err(err) => match err {
                StdError::NotFound { kind: _ } => {}
                _ => return Err(ContractError::from(err)),
            },
        }
        let voting_contract = VOTING_CONTRACT.load(deps.storage)?;

        let msg = SubMsg::reply_always(
            CosmosMsg::Wasm(wasm_instantiate(
                voting_contract,
                &voting_interface::InstantiateMsg {
                    proposed_admin: admin.clone(),
                    threshold: ADMIN_COUNT.load(deps.storage)? / 2 + 1,
                },
                vec![],
                "voting_contract".to_owned(),
            )?),
            VOTING_CONTRACT_INSTANTIATION_REPLY_ID,
        );

        let resp = Response::new().add_submessage(msg).add_event(
            Event::new("voting-initiated")
                .add_attribute("by", info.sender)
                .add_attribute("admin", admin),
        );

        Ok(resp)
    }
    pub fn leave(mut deps: DepsMut, info: MessageInfo) -> Result<Response, ContractError> {
        if !ADMINS.has(deps.storage, &info.sender) {
            return Err(ContractError::AdminNotFound());
        }

        let resp =
            Response::new().add_event(Event::new("leave").add_attribute("admin", &info.sender));
        let withdrawal = withdraw_helper(&mut deps, &info);

        let resp = match withdrawal {
            Ok((message, event)) => resp.add_message(message).add_event(event),
            Err(err) => match err {
                ContractError::NoDonations() => resp,
                _ => return Err(err),
            },
        };

        ADMINS.remove(deps.storage, &info.sender);
        ADMIN_COUNT.update(deps.storage, |count| -> Result<u128, ContractError> {
            let new_count = count - 1;
            if new_count == 0 {
                return Err(ContractError::LastAdmin());
            }
            Ok(new_count)
        })?;

        Ok(resp)
    }
    pub fn donate(deps: DepsMut, info: MessageInfo) -> Result<Response, ContractError> {
        let denom = DONATION_DENOM.load(deps.storage)?;
        let donation = cw_utils::must_pay(&info, &denom)?.u128();
        let admin_count = ADMIN_COUNT.load(deps.storage)?;
        let distributed = donation / admin_count;

        donation_storage_update(deps, distributed, admin_count, None)?;

        let resp = Response::new().add_event(
            Event::new("donate")
                .add_attribute("sender", info.sender)
                .add_attribute("amount", donation.to_string()),
        );
        Ok(resp)
    }
    pub fn withdraw(mut deps: DepsMut, info: MessageInfo) -> Result<Response, ContractError> {
        let (message, event) = withdraw_helper(&mut deps, &info)?;
        let resp = Response::new().add_message(message).add_event(event);
        Ok(resp)
    }
    pub fn execute_msg(
        deps: DepsMut,
        info: MessageInfo,
        msg: CosmosMsg,
    ) -> Result<Response, ContractError> {
        if !ADMINS.has(deps.storage, &info.sender) {
            return Err(ContractError::AdminNotFound());
        }
        let sub = SubMsg::reply_always(msg, EXECUTE_COSMOS_MSG_ID);
        let resp = Response::new().add_submessage(sub);
        Ok(resp)
    }
}

pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    use QueryMsg::*;
    match msg {
        AdminInfo { admin } => to_json_binary(&query::get_admin_info(deps, &admin)?),
        AdminWithdrawable { admin } => {
            to_json_binary(&query::get_admin_withdrawable(deps, &admin)?)
        }
        AdminCount {} => to_json_binary(&query::get_admin_count(deps)?),
    }
}

mod query {
    use super::*;

    pub fn get_admin_info(deps: Deps, admin: &str) -> StdResult<AdminInfoResponse> {
        let admin_addr = deps.api.addr_validate(admin)?;
        let admin_data = ADMINS.load(deps.storage, &admin_addr)?;
        Ok(AdminInfoResponse {
            joined_block: admin_data.joined_block,
        })
    }

    pub fn get_admin_withdrawable(deps: Deps, admin: &str) -> StdResult<AdminWithdrawableResponse> {
        let admin_addr = deps.api.addr_validate(admin)?;
        let admin_data = ADMINS.load(deps.storage, &admin_addr)?;
        let donated = DONATED.load(deps.storage)?;
        Ok(AdminWithdrawableResponse {
            amount: donated - admin_data.withdrawn,
        })
    }

    pub fn get_admin_count(deps: Deps) -> StdResult<AdminCountResponse> {
        Ok(AdminCountResponse {
            count: ADMIN_COUNT.load(deps.storage)?,
        })
    }
}

pub fn reply(deps: DepsMut, env: Env, msg: Reply) -> Result<Response, ContractError> {
    match msg.id {
        VOTING_CONTRACT_INSTANTIATION_REPLY_ID => reply::voting_instantiation(deps, msg),
        EXECUTE_COSMOS_MSG_ID => reply::check_balance(deps, env, msg),
        id => Err(ContractError::from(StdError::generic_err(format!(
            "Unknown reply id: {}",
            id
        )))),
    }
}

mod reply {
    use super::*;
    use cosmwasm_std::from_json;
    use cw_utils::parse_reply_instantiate_data;
    pub fn voting_instantiation(deps: DepsMut, msg: Reply) -> Result<Response, ContractError> {
        match parse_reply_instantiate_data(msg) {
            Ok(parsed) => {
                let data: voting_interface::InstantiateResponse =
                    from_json(parsed.data.unwrap()).unwrap();
                let proposed_admin = deps.api.addr_validate(&data.proposed_admin)?;
                let contract_address = deps.api.addr_validate(&parsed.contract_address)?;
                VOTING_TRACKER.save(deps.storage, &proposed_admin, &contract_address)?;
                let resp = Response::new().add_event(
                    Event::new("voting-contract-instantiated")
                        .add_attribute("address", contract_address)
                        .add_attribute("proposed_admin", proposed_admin),
                );
                Ok(resp)
            }
            Err(err) => Err(ContractError::from(err)),
        }
    }
    pub fn check_balance(deps: DepsMut, env: Env, msg: Reply) -> Result<Response, ContractError> {
        let result = msg.result;
        match result {
            SubMsgResult::Ok(_) => {
                let denom = DONATION_DENOM.load(deps.storage)?;
                let pre_balance = match PRE_EXEC_BALANCE.may_load(deps.storage) {
                    Ok(balance) => match balance {
                        Some(x) => x,
                        None => 0,
                    },
                    Err(err) => return Err(ContractError::from(err)),
                };
                let curr_balance = deps
                    .querier
                    .query_balance(env.contract.address, denom)?
                    .amount
                    .u128();
                if curr_balance < pre_balance {
                    Err(ContractError::NotAllowedToSpend())
                } else if curr_balance > pre_balance {
                    let amount = curr_balance - pre_balance;
                    let admin_count = ADMIN_COUNT.load(deps.storage)?;
                    let distributed = amount / admin_count;
                    execute::donation_storage_update(
                        deps,
                        distributed,
                        admin_count,
                        Some(pre_balance),
                    )?;
                    if distributed > 0 {
                        Ok(Response::new().add_event(
                            Event::new("distributed")
                                .add_attribute("amount", (distributed * admin_count).to_string()),
                        ))
                    } else {
                        Ok(Response::new())
                    }
                } else {
                    Ok(Response::new())
                }
            }
            SubMsgResult::Err(err) => Err(ContractError::from(StdError::generic_err(err))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cosmwasm_std::{coin, wasm_execute, Addr, CosmosMsg};
    use cw_multi_test::{App, AppResponse, ContractWrapper, Executor};
    use voting;

    fn instantiate_admin_contract(app: &mut App, msg: InstantiateMsg) -> Addr {
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
        use voting::contract::*;
        let code = ContractWrapper::new(execute, instantiate, query);
        app.store_code(Box::new(code))
    }

    fn get_admin_info(app: &App, addr: &Addr, admin: &str) -> StdResult<AdminInfoResponse> {
        app.wrap().query_wasm_smart(
            addr,
            &QueryMsg::AdminInfo {
                admin: admin.to_string(),
            },
        )
    }

    fn admin_count(app: &App, addr: &Addr) -> u128 {
        let resp: AdminCountResponse = app
            .wrap()
            .query_wasm_smart(addr, &QueryMsg::AdminCount {})
            .unwrap();
        resp.count
    }

    fn leave(
        app: &mut App,
        addr: &Addr,
        admin: impl Into<String>,
    ) -> Result<AppResponse, ContractError> {
        match app.execute_contract(
            Addr::unchecked(admin),
            addr.clone(),
            &ExecuteMsg::Leave {},
            &[],
        ) {
            Ok(resp) => Ok(resp),
            Err(err) => Err(err.downcast().unwrap()),
        }
    }

    fn get_balance(app: &App, addr: impl Into<String>, denom: impl Into<String>) -> u128 {
        app.wrap().query_balance(addr, denom).unwrap().amount.u128()
    }

    fn donate(
        app: &mut App,
        addr: &Addr,
        user: impl Into<String>,
        amount: u128,
        denom: impl Into<String>,
    ) -> Result<AppResponse, ContractError> {
        match app.execute_contract(
            Addr::unchecked(user),
            addr.clone(),
            &ExecuteMsg::Donate {},
            &coins(amount, denom),
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
    ) -> Result<(AppResponse, Addr), ContractError> {
        match app.execute_contract(
            Addr::unchecked(admin),
            addr.clone(),
            &ExecuteMsg::AddAdmin {
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

    fn withdraw(
        app: &mut App,
        addr: &Addr,
        admin: impl Into<String>,
    ) -> Result<AppResponse, ContractError> {
        match app.execute_contract(
            Addr::unchecked(admin),
            addr.clone(),
            &ExecuteMsg::Withdraw {},
            &[],
        ) {
            Ok(resp) => Ok(resp),
            Err(err) => Err(err.downcast().unwrap()),
        }
    }

    fn withdrawable(app: &App, addr: &Addr, admin: &str) -> StdResult<AdminWithdrawableResponse> {
        app.wrap().query_wasm_smart(
            addr,
            &QueryMsg::AdminWithdrawable {
                admin: admin.to_string(),
            },
        )
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
            &voting::msg::ExecuteMsg::SubmitVote { value: value },
            &[],
        ) {
            Ok(resp) => Ok(resp),
            Err(err) => Err(err.downcast().unwrap()),
        }
    }

    fn increment_block(app: &mut App) {
        app.update_block(|block| {
            block.height += 1;
        });
    }

    #[test]
    fn test_get_admin_info() {
        let mut app = App::default();
        let voting_contract_code_id = voting_contract_code_id(&mut app);
        let addr = instantiate_admin_contract(
            &mut app,
            InstantiateMsg {
                admins: vec!["admin1".to_owned(), "admin2".to_owned()],
                donation_denom: "eth".to_owned(),
                voting_contract_code_id: voting_contract_code_id,
            },
        );

        let resp = get_admin_info(&app, &addr, "admin1").unwrap();
        assert_eq!(resp.joined_block, app.block_info().height);

        let resp = get_admin_info(&app, &addr, "admin2").unwrap();
        assert_eq!(resp.joined_block, app.block_info().height);

        let err = get_admin_info(&app, &addr, "owner").unwrap_err();
        assert!(err.to_string().contains("not found"));
    }

    #[test]
    fn test_get_admin_count() {
        let mut app = App::default();
        let voting_contract_code_id = voting_contract_code_id(&mut app);
        let addr = instantiate_admin_contract(
            &mut app,
            InstantiateMsg {
                admins: vec!["admin1".to_owned(), "admin2".to_owned()],
                donation_denom: "eth".to_owned(),
                voting_contract_code_id: voting_contract_code_id,
            },
        );
        assert_eq!(admin_count(&app, &addr), 2);
    }

    #[test]
    fn test_get_admin_withdrawable() {
        let initial_balance = 1000;
        let denom = "eth";
        let mut app = App::new(|router, _, storage| {
            router
                .bank
                .init_balance(
                    storage,
                    &Addr::unchecked("user1"),
                    coins(initial_balance, denom),
                )
                .unwrap();
        });
        let voting_contract_code_id = voting_contract_code_id(&mut app);
        let addr = instantiate_admin_contract(
            &mut app,
            InstantiateMsg {
                admins: vec!["admin1".to_owned(), "admin2".to_owned()],
                donation_denom: "eth".to_owned(),
                voting_contract_code_id: voting_contract_code_id,
            },
        );

        let resp = withdrawable(&app, &addr, "admin1").unwrap();
        assert_eq!(resp.amount, 0);

        donate(&mut app, &addr, "user1", initial_balance / 2, denom).unwrap();
        let resp = withdrawable(&app, &addr, "admin1").unwrap();
        assert_eq!(resp.amount, initial_balance / 4);
        let resp = withdrawable(&app, &addr, "admin2").unwrap();
        assert_eq!(resp.amount, initial_balance / 4);

        withdraw(&mut app, &addr, "admin1").unwrap();
        let resp = withdrawable(&app, &addr, "admin1").unwrap();
        assert_eq!(resp.amount, 0);
        let resp = withdrawable(&app, &addr, "admin2").unwrap();
        assert_eq!(resp.amount, initial_balance / 4);

        donate(&mut app, &addr, "user1", initial_balance / 2, denom).unwrap();
        let resp = withdrawable(&app, &addr, "admin1").unwrap();
        assert_eq!(resp.amount, initial_balance / 4);
        let resp = withdrawable(&app, &addr, "admin2").unwrap();
        assert_eq!(resp.amount, initial_balance / 2);
    }

    #[test]
    fn test_add_admin() {
        let initial_balance = 1000;
        let denom = "eth";
        let mut app = App::new(|router, _, storage| {
            router
                .bank
                .init_balance(
                    storage,
                    &Addr::unchecked("user1"),
                    coins(initial_balance, denom),
                )
                .unwrap();
        });
        let voting_contract_code_id = voting_contract_code_id(&mut app);
        let addr = instantiate_admin_contract(
            &mut app,
            InstantiateMsg {
                admins: vec!["admin1".to_owned(), "admin2".to_owned()],
                donation_denom: "eth".to_owned(),
                voting_contract_code_id: voting_contract_code_id,
            },
        );
        donate(&mut app, &addr, "user1", initial_balance / 2, denom).unwrap();
        increment_block(&mut app);

        let err = add_admin(&mut app, &addr, "admin3", "admin3").unwrap_err();
        assert_eq!(ContractError::AdminNotFound(), err);

        let err = add_admin(&mut app, &addr, "admin1", "admin2").unwrap_err();
        assert_eq!(ContractError::AdminAlreadyExists(), err);

        let (resp, voting_addr) = add_admin(&mut app, &addr, "admin1", "admin3").unwrap();
        resp.assert_event(
            &Event::new("wasm-voting-initiated")
                .add_attribute("by", "admin1")
                .add_attribute("admin", "admin3"),
        );
        resp.assert_event(
            &Event::new("wasm-voting-contract-instantiated")
                .add_attribute("address", &voting_addr)
                .add_attribute("proposed_admin", "admin3"),
        );

        let err = add_admin(&mut app, &addr, "admin1", "admin3").unwrap_err();
        assert_eq!(ContractError::AlreadyBeingVotedOn(), err);

        vote(&mut app, &voting_addr, "admin1", false).unwrap();
        vote(&mut app, &voting_addr, "admin2", false).unwrap();
        let (resp, voting_addr) = add_admin(&mut app, &addr, "admin2", "admin3").unwrap();
        resp.assert_event(
            &Event::new("wasm-voting-initiated")
                .add_attribute("by", "admin2")
                .add_attribute("admin", "admin3"),
        );
        resp.assert_event(
            &Event::new("wasm-voting-contract-instantiated")
                .add_attribute("address", &voting_addr)
                .add_attribute("proposed_admin", "admin3"),
        );

        vote(&mut app, &voting_addr, "admin1", true).unwrap();
        let resp = vote(&mut app, &voting_addr, "admin2", true).unwrap();
        resp.assert_event(&Event::new("wasm-admin-added").add_attribute("admin", "admin3"));
        assert_eq!(admin_count(&app, &addr), 3);

        let resp = withdrawable(&app, &addr, "admin1").unwrap();
        assert_eq!(resp.amount, initial_balance / 4);
        let resp = withdrawable(&app, &addr, "admin3").unwrap();
        assert_eq!(resp.amount, 0);

        donate(&mut app, &addr, "user1", initial_balance / 2, denom).unwrap();
        let resp = withdrawable(&app, &addr, "admin1").unwrap();
        assert_eq!(resp.amount, initial_balance / 4 + initial_balance / 6);
        let resp = withdrawable(&app, &addr, "admin3").unwrap();
        assert_eq!(resp.amount, initial_balance / 6);

        let resp = get_admin_info(&app, &addr, "admin3").unwrap();
        assert_eq!(resp.joined_block, app.block_info().height);
    }

    #[test]
    fn test_leave() {
        let initial_balance = 1000;
        let denom = "eth";
        let mut app = App::new(|router, _, storage| {
            router
                .bank
                .init_balance(
                    storage,
                    &Addr::unchecked("user1"),
                    coins(initial_balance, denom),
                )
                .unwrap();
        });
        let voting_contract_code_id = voting_contract_code_id(&mut app);
        let addr = instantiate_admin_contract(
            &mut app,
            InstantiateMsg {
                admins: vec!["admin1".to_owned(), "admin2".to_owned()],
                donation_denom: "eth".to_owned(),
                voting_contract_code_id: voting_contract_code_id,
            },
        );

        let err = leave(&mut app, &addr, "admin3").unwrap_err();
        assert_eq!(ContractError::AdminNotFound(), err);

        let resp = get_admin_info(&app, &addr, "admin1").unwrap();
        assert_eq!(resp.joined_block, app.block_info().height);
        let resp = leave(&mut app, &addr, "admin1").unwrap();
        resp.assert_event(&Event::new("wasm-leave").add_attribute("admin", "admin1"));
        let err = get_admin_info(&app, &addr, "admin1").unwrap_err();
        assert!(err.to_string().contains("not found"));
        assert_eq!(admin_count(&app, &addr), 1);

        donate(&mut app, &addr, "user1", initial_balance / 4, denom).unwrap();

        increment_block(&mut app);

        let (_, voting_addr) = add_admin(&mut app, &addr, "admin2", "admin3").unwrap();
        let err = leave(&mut app, &addr, "admin2").unwrap_err();
        assert_eq!(ContractError::LastAdmin(), err);
        vote(&mut app, &voting_addr, "admin2", true).unwrap();

        let resp = leave(&mut app, &addr, "admin2").unwrap();
        resp.assert_event(&Event::new("wasm-leave").add_attribute("admin", "admin2"));
        resp.assert_event(
            &Event::new("wasm-withdraw")
                .add_attribute("admin", "admin2")
                .add_attribute("amount", (initial_balance / 4).to_string()),
        );
        let err = get_admin_info(&app, &addr, "admin2").unwrap_err();
        assert!(err.to_string().contains("not found"));
        assert_eq!(admin_count(&app, &addr), 1);
    }

    #[test]
    fn test_donate() {
        let initial_balance = 1000;
        let denom = "eth";
        let denom2 = "hte";
        let mut app = App::new(|router, _, storage| {
            router
                .bank
                .init_balance(
                    storage,
                    &Addr::unchecked("user1"),
                    vec![coin(initial_balance, denom), coin(initial_balance, denom2)],
                )
                .unwrap();
            router
                .bank
                .init_balance(storage, &Addr::unchecked("user2"), coins(u128::MAX, denom))
                .unwrap();
        });
        let voting_contract_code_id = voting_contract_code_id(&mut app);
        let addr = instantiate_admin_contract(
            &mut app,
            InstantiateMsg {
                admins: vec!["admin1".to_owned(), "admin2".to_owned()],
                donation_denom: denom.to_string(),
                voting_contract_code_id: voting_contract_code_id,
            },
        );

        let donation1 = 463;
        let err = donate(&mut app, &addr, "user1", donation1, denom2).unwrap_err();
        assert_eq!(
            ContractError::PaymentError(cw_utils::PaymentError::MissingDenom("eth".to_owned())),
            err
        );

        let resp = donate(&mut app, &addr, "user1", donation1, denom).unwrap();
        resp.assert_event(
            &Event::new("wasm-donate")
                .add_attribute("sender", "user1")
                .add_attribute("amount", donation1.to_string()),
        );
        assert_eq!(get_balance(&app, &addr, denom), donation1);
        assert_eq!(
            get_balance(&app, "user1", denom),
            initial_balance - donation1
        );
        assert_eq!(get_balance(&app, "admin1", denom), 0);

        withdraw(&mut app, &addr, "admin1").unwrap();
        withdraw(&mut app, &addr, "admin2").unwrap();

        increment_block(&mut app);
        let (_, voting_addr) = add_admin(&mut app, &addr, "admin1", "admin3").unwrap();
        vote(&mut app, &voting_addr, "admin1", true).unwrap();
        vote(&mut app, &voting_addr, "admin2", true).unwrap();

        let donation2 = 3;
        let resp = donate(&mut app, &addr, "user2", donation2, denom).unwrap();
        resp.assert_event(
            &Event::new("wasm-donate")
                .add_attribute("sender", "user2")
                .add_attribute("amount", donation2.to_string()),
        );

        let contract_balance = get_balance(&app, &addr, denom);
        assert_eq!(
            contract_balance,
            donation2 + donation1 - (donation1 / 2) * 2
        );

        leave(&mut app, &addr, "admin1").unwrap();
        leave(&mut app, &addr, "admin2").unwrap();
        let err = donate(
            &mut app,
            &addr,
            "user2",
            u128::MAX - contract_balance,
            denom,
        )
        .unwrap_err();
        assert_eq!(ContractError::Overflow(), err);
    }

    #[test]
    fn test_withdraw() {
        let initial_balance = 1000;
        let denom = "eth";
        let mut app = App::new(|router, _, storage| {
            router
                .bank
                .init_balance(
                    storage,
                    &Addr::unchecked("user1"),
                    coins(initial_balance, denom),
                )
                .unwrap();
        });
        let voting_contract_code_id = voting_contract_code_id(&mut app);
        let addr = instantiate_admin_contract(
            &mut app,
            InstantiateMsg {
                admins: vec!["admin1".to_owned(), "admin2".to_owned()],
                donation_denom: denom.to_string(),
                voting_contract_code_id: voting_contract_code_id,
            },
        );

        let err = withdraw(&mut app, &addr, "admin3").unwrap_err();
        assert_eq!(ContractError::AdminNotFound(), err);

        let err = withdraw(&mut app, &addr, "admin1").unwrap_err();
        assert_eq!(ContractError::NoDonations(), err);

        let donation1 = 463;
        donate(&mut app, &addr, "user1", donation1, denom).unwrap();

        assert_eq!(get_balance(&app, "admin1", denom), 0);
        let resp = withdraw(&mut app, &addr, "admin1").unwrap();
        resp.assert_event(
            &Event::new("wasm-withdraw")
                .add_attribute("admin", "admin1")
                .add_attribute("amount", (donation1 / 2).to_string()),
        );

        assert_eq!(get_balance(&app, "admin1", "eth"), donation1 / 2);
        assert_eq!(get_balance(&app, "admin2", "eth"), 0);
        assert_eq!(get_balance(&app, "admin3", "eth"), 0);

        let err = withdraw(&mut app, &addr, "admin3").unwrap_err();
        assert_eq!(ContractError::AdminNotFound(), err);

        increment_block(&mut app);
        let (_, voting_addr) = add_admin(&mut app, &addr, "admin1", "admin3").unwrap();
        vote(&mut app, &voting_addr, "admin1", true).unwrap();
        vote(&mut app, &voting_addr, "admin2", true).unwrap();

        let donation2 = 3;
        donate(&mut app, &addr, "user1", donation2, denom).unwrap();

        let resp = withdraw(&mut app, &addr, "admin1").unwrap();
        resp.assert_event(
            &Event::new("wasm-withdraw")
                .add_attribute("admin", "admin1")
                .add_attribute("amount", (donation2 / 3).to_string()),
        );
        let resp = withdraw(&mut app, &addr, "admin3").unwrap();
        resp.assert_event(
            &Event::new("wasm-withdraw")
                .add_attribute("admin", "admin3")
                .add_attribute("amount", (donation2 / 3).to_string()),
        );

        assert_eq!(
            get_balance(&app, "admin1", "eth"),
            donation1 / 2 + donation2 / 3
        );
        assert_eq!(get_balance(&app, "admin2", "eth"), 0);
        assert_eq!(get_balance(&app, "admin3", "eth"), donation2 / 3);
    }

    #[test]
    fn test_execute_msg() {
        let initial_balance = 1000;
        let denom = "eth";
        let mut app = App::new(|router, _, storage| {
            router
                .bank
                .init_balance(
                    storage,
                    &Addr::unchecked("user1"),
                    coins(initial_balance, denom),
                )
                .unwrap();
        });
        let voting_contract_code_id = voting_contract_code_id(&mut app);

        let user_contract = instantiate_admin_contract(
            &mut app,
            InstantiateMsg {
                admins: vec!["admin1".to_owned(), "admin2".to_owned()],
                donation_denom: denom.to_string(),
                voting_contract_code_id: voting_contract_code_id,
            },
        );

        let addr = instantiate_admin_contract(
            &mut app,
            InstantiateMsg {
                admins: vec![user_contract.to_string(), "admin3".to_owned()],
                donation_denom: denom.to_string(),
                voting_contract_code_id: voting_contract_code_id,
            },
        );

        increment_block(&mut app);

        let err = add_admin(&mut app, &addr, "admin1", "admin5").unwrap_err();
        assert_eq!(ContractError::AdminNotFound(), err);

        let msg = CosmosMsg::Wasm(
            wasm_execute(
                &addr,
                &ExecuteMsg::AddAdmin {
                    admin: "admin1".to_owned(),
                },
                vec![],
            )
            .unwrap(),
        );
        let resp = app
            .execute_contract(
                Addr::unchecked("admin1"),
                user_contract.clone(),
                &ExecuteMsg::Execute { msg: msg },
                &[],
            )
            .unwrap();
        resp.assert_event(
            &Event::new("wasm-voting-initiated")
                .add_attribute("by", user_contract.to_string())
                .add_attribute("admin", "admin1"),
        );
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

        let msg = CosmosMsg::Wasm(
            wasm_execute(
                &voting_addr,
                &voting::msg::ExecuteMsg::SubmitVote { value: true },
                vec![],
            )
            .unwrap(),
        );
        app.execute_contract(
            Addr::unchecked("admin1"),
            user_contract.clone(),
            &ExecuteMsg::Execute { msg: msg },
            &[],
        )
        .unwrap();
        let resp = vote(&mut app, &voting_addr, "admin3", true).unwrap();
        resp.assert_event(&Event::new("wasm-admin-added").add_attribute("admin", "admin1"));

        let donation = 3;
        donate(&mut app, &user_contract, "user1", donation, denom).unwrap();
        let msg = CosmosMsg::Bank(BankMsg::Send {
            to_address: "admin1".to_owned(),
            amount: coins(donation, denom),
        });
        let err = app
            .execute_contract(
                Addr::unchecked("admin1"),
                user_contract.clone(),
                &ExecuteMsg::Execute { msg: msg },
                &[],
            )
            .unwrap_err()
            .downcast()
            .unwrap();
        assert_eq!(ContractError::NotAllowedToSpend(), err);

        let msg = CosmosMsg::Bank(BankMsg::Send {
            to_address: "admin1".to_owned(),
            amount: coins(donation - (donation / 2) * 2, denom),
        });
        app.execute_contract(
            Addr::unchecked("admin1"),
            user_contract.clone(),
            &ExecuteMsg::Execute { msg: msg },
            &[],
        )
        .unwrap();
        assert_eq!(get_balance(&app, &user_contract, denom), 2);
        assert_eq!(get_balance(&app, "admin1", denom), 1);

        donate(&mut app, &user_contract, "user1", donation, denom).unwrap();
        donate(&mut app, &user_contract, "user1", donation, denom).unwrap();
        donate(&mut app, &user_contract, "user1", donation, denom).unwrap();
        let msg = CosmosMsg::Bank(BankMsg::Send {
            to_address: "admin1".to_owned(),
            amount: coins(donation - (donation / 2) * 2, denom),
        });
        let resp = app
            .execute_contract(
                Addr::unchecked("admin1"),
                user_contract.clone(),
                &ExecuteMsg::Execute { msg: msg },
                &[],
            )
            .unwrap();
        resp.assert_event(&Event::new("wasm-distributed").add_attribute("amount", "2"));
        assert_eq!(get_balance(&app, &user_contract, denom), 10);
        assert_eq!(get_balance(&app, "admin1", denom), 2);
        withdraw(&mut app, &user_contract, "admin1").unwrap();
        withdraw(&mut app, &user_contract, "admin2").unwrap();
        assert_eq!(get_balance(&app, &user_contract, denom), 0);
        assert_eq!(get_balance(&app, "admin1", denom), 7);
        assert_eq!(get_balance(&app, "admin2", denom), 5);
    }
}
