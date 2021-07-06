// Copyright 2018-2021 Cargill Incorporated
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::fmt;

use crate::network::auth::ManagedAuthorizationState;

use super::{
    AuthorizationActionError, AuthorizationLocalAction, AuthorizationLocalState,
    AuthorizationRemoteAction, AuthorizationRemoteState, Identity,
};

#[derive(PartialEq, Debug, Clone)]
pub(crate) enum ChallengeAuthorizationLocalState {
    ChallengeConnecting,
    WaitingForAuthChallengeNonceResponse,
    ReceivedAuthChallengeNonceResponse,
    WaitingForAuthChallengeSubmitResponse,
}

impl fmt::Display for ChallengeAuthorizationLocalState {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(match self {
            ChallengeAuthorizationLocalState::ChallengeConnecting => "ChallengeConnecting",
            ChallengeAuthorizationLocalState::WaitingForAuthChallengeNonceResponse => {
                "WaitingForAuthChallengeNonceResponse"
            }
            ChallengeAuthorizationLocalState::ReceivedAuthChallengeNonceResponse => {
                "ReceivedAuthChallengeNonceResponse"
            }
            ChallengeAuthorizationLocalState::WaitingForAuthChallengeSubmitResponse => {
                "WaitingForAuthChallengeSubmitResponse"
            }
        })
    }
}

/// The state transitions that can be applied on a connection during authorization.
#[derive(PartialEq, Debug)]
pub(crate) enum ChallengeAuthorizationLocalAction {
    SendAuthChallengeNonceRequest,
    ReceiveAuthChallengeNonceResponse,
    SendAuthChallengeSubmitRequest,
    ReceiveAuthChallengeSubmitResponse,
}

impl fmt::Display for ChallengeAuthorizationLocalAction {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ChallengeAuthorizationLocalAction::SendAuthChallengeNonceRequest => {
                f.write_str("SendAuthChallengeNonceRequest")
            }
            ChallengeAuthorizationLocalAction::ReceiveAuthChallengeNonceResponse => {
                f.write_str("ReceiveAuthChallengeNonceResponse")
            }
            ChallengeAuthorizationLocalAction::SendAuthChallengeSubmitRequest => {
                f.write_str("SendAuthChallengeSubmitRequest")
            }
            ChallengeAuthorizationLocalAction::ReceiveAuthChallengeSubmitResponse => {
                f.write_str("ReceiveAuthChallengeSubmitResponse")
            }
        }
    }
}

#[derive(PartialEq, Debug, Clone)]
pub(crate) enum ChallengeAuthorizationRemoteState {
    ChallengeConnecting,
    ReceivedAuthChallengeNonce,
    WaitingForAuthChallengeSubmitRequest,
    ReceivedAuthChallengeSubmitRequest(Identity),
}

impl fmt::Display for ChallengeAuthorizationRemoteState {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(match self {
            ChallengeAuthorizationRemoteState::ChallengeConnecting => "ChallengeConnecting",
            ChallengeAuthorizationRemoteState::ReceivedAuthChallengeNonce => {
                "ReceivedAuthChallengeNonce"
            }
            ChallengeAuthorizationRemoteState::WaitingForAuthChallengeSubmitRequest => {
                "WaitingForAuthChallengeSubmitRequest"
            }
            ChallengeAuthorizationRemoteState::ReceivedAuthChallengeSubmitRequest(_) => {
                "ReceivedAuthChallengeSubmitRequest"
            }
        })
    }
}

/// The state transitions that can be applied on a connection during authorization.
#[derive(PartialEq, Debug)]
pub(crate) enum ChallengeAuthorizationRemoteAction {
    ReceiveAuthChallengeNonceRequest,
    SendAuthChallengeNonceResponse,
    ReceiveAuthChallengeSubmitRequest(Identity),
    SendAuthChallengeSubmitResponse,
}

impl fmt::Display for ChallengeAuthorizationRemoteAction {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ChallengeAuthorizationRemoteAction::ReceiveAuthChallengeNonceRequest => {
                f.write_str("ReceiveAuthChallengeNonceRequest")
            }
            ChallengeAuthorizationRemoteAction::SendAuthChallengeNonceResponse => {
                f.write_str("SendAuthChallengeNonceResponse")
            }
            ChallengeAuthorizationRemoteAction::ReceiveAuthChallengeSubmitRequest(_) => {
                f.write_str("ReceiveAuthChallengeSubmitRequest")
            }
            ChallengeAuthorizationRemoteAction::SendAuthChallengeSubmitResponse => {
                f.write_str("SendAuthChallengeSubmitResponse")
            }
        }
    }
}

impl ChallengeAuthorizationLocalState {
    /// Transitions from one authorization state to another
    ///
    /// Errors
    ///
    /// The errors are error messages that should be returned on the appropriate message
    pub(crate) fn next_local_state(
        &self,
        action: ChallengeAuthorizationLocalAction,
        cur_state: &mut ManagedAuthorizationState,
    ) -> Result<AuthorizationLocalState, AuthorizationActionError> {
        match &self {
            ChallengeAuthorizationLocalState::ChallengeConnecting => match action {
                ChallengeAuthorizationLocalAction::SendAuthChallengeNonceRequest => {
                    let new_state = AuthorizationLocalState::Challenge(
                        ChallengeAuthorizationLocalState::WaitingForAuthChallengeNonceResponse,
                    );
                    cur_state.local_state = new_state.clone();
                    Ok(new_state)
                }
                _ => Err(AuthorizationActionError::InvalidLocalMessageOrder(
                    AuthorizationLocalState::Challenge(self.clone()),
                    AuthorizationLocalAction::Challenge(action),
                )),
            },
            ChallengeAuthorizationLocalState::WaitingForAuthChallengeNonceResponse => {
                match action {
                    ChallengeAuthorizationLocalAction::ReceiveAuthChallengeNonceResponse => {
                        let new_state = AuthorizationLocalState::Challenge(
                            ChallengeAuthorizationLocalState::ReceivedAuthChallengeNonceResponse,
                        );
                        cur_state.local_state = new_state.clone();
                        Ok(new_state)
                    }
                    _ => Err(AuthorizationActionError::InvalidLocalMessageOrder(
                        AuthorizationLocalState::Challenge(self.clone()),
                        AuthorizationLocalAction::Challenge(action),
                    )),
                }
            }
            ChallengeAuthorizationLocalState::ReceivedAuthChallengeNonceResponse => match action {
                ChallengeAuthorizationLocalAction::SendAuthChallengeSubmitRequest => {
                    let new_state = AuthorizationLocalState::Challenge(
                        ChallengeAuthorizationLocalState::WaitingForAuthChallengeSubmitResponse,
                    );
                    cur_state.local_state = new_state.clone();
                    Ok(new_state)
                }
                _ => Err(AuthorizationActionError::InvalidLocalMessageOrder(
                    AuthorizationLocalState::Challenge(self.clone()),
                    AuthorizationLocalAction::Challenge(action),
                )),
            },
            ChallengeAuthorizationLocalState::WaitingForAuthChallengeSubmitResponse => match action
            {
                ChallengeAuthorizationLocalAction::ReceiveAuthChallengeSubmitResponse => {
                    let new_state = AuthorizationLocalState::Authorized;
                    cur_state.local_state = new_state.clone();
                    Ok(new_state)
                }
                _ => Err(AuthorizationActionError::InvalidLocalMessageOrder(
                    AuthorizationLocalState::Challenge(self.clone()),
                    AuthorizationLocalAction::Challenge(action),
                )),
            },
        }
    }
}

impl ChallengeAuthorizationRemoteState {
    /// Transitions from one authorization state to another
    ///
    /// Errors
    ///
    /// The errors are error messages that should be returned on the appropriate message
    pub(crate) fn next_remote_state(
        &self,
        action: ChallengeAuthorizationRemoteAction,
        cur_state: &mut ManagedAuthorizationState,
    ) -> Result<AuthorizationRemoteState, AuthorizationActionError> {
        match &self {
            ChallengeAuthorizationRemoteState::ChallengeConnecting => match action {
                ChallengeAuthorizationRemoteAction::ReceiveAuthChallengeNonceRequest => {
                    let new_state = AuthorizationRemoteState::Challenge(
                        ChallengeAuthorizationRemoteState::ReceivedAuthChallengeNonce,
                    );
                    cur_state.remote_state = new_state.clone();
                    Ok(new_state)
                }
                _ => Err(AuthorizationActionError::InvalidRemoteMessageOrder(
                    AuthorizationRemoteState::Challenge(self.clone()),
                    AuthorizationRemoteAction::Challenge(action),
                )),
            },
            ChallengeAuthorizationRemoteState::ReceivedAuthChallengeNonce => match action {
                ChallengeAuthorizationRemoteAction::SendAuthChallengeNonceResponse => {
                    let new_state = AuthorizationRemoteState::Challenge(
                        ChallengeAuthorizationRemoteState::WaitingForAuthChallengeSubmitRequest,
                    );
                    cur_state.remote_state = new_state.clone();
                    Ok(new_state)
                }
                _ => Err(AuthorizationActionError::InvalidRemoteMessageOrder(
                    AuthorizationRemoteState::Challenge(self.clone()),
                    AuthorizationRemoteAction::Challenge(action),
                )),
            },
            ChallengeAuthorizationRemoteState::WaitingForAuthChallengeSubmitRequest => match action
            {
                ChallengeAuthorizationRemoteAction::ReceiveAuthChallengeSubmitRequest(identity) => {
                    let new_state = AuthorizationRemoteState::Challenge(
                        ChallengeAuthorizationRemoteState::ReceivedAuthChallengeSubmitRequest(
                            identity,
                        ),
                    );
                    cur_state.remote_state = new_state.clone();
                    Ok(new_state)
                }
                _ => Err(AuthorizationActionError::InvalidRemoteMessageOrder(
                    AuthorizationRemoteState::Challenge(self.clone()),
                    AuthorizationRemoteAction::Challenge(action),
                )),
            },
            ChallengeAuthorizationRemoteState::ReceivedAuthChallengeSubmitRequest(identity) => {
                match action {
                    ChallengeAuthorizationRemoteAction::SendAuthChallengeSubmitResponse => {
                        let new_state = AuthorizationRemoteState::Done(identity.clone());
                        cur_state.remote_state = new_state.clone();
                        Ok(new_state)
                    }
                    _ => Err(AuthorizationActionError::InvalidRemoteMessageOrder(
                        AuthorizationRemoteState::Challenge(self.clone()),
                        AuthorizationRemoteAction::Challenge(action),
                    )),
                }
            }
        }
    }
}
