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

use super::{AuthorizationAction, AuthorizationActionError, AuthorizationState, Identity};

#[derive(PartialEq, Debug, Clone)]
pub(crate) enum ChallengeAuthorizationState {
    ChallengeConnecting,
    NonceSent { nonce: Vec<u8> },
    Identified { public_key: Vec<u8> },
    Authorized { public_key: Vec<u8> },
}

impl fmt::Display for ChallengeAuthorizationState {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(match self {
            ChallengeAuthorizationState::ChallengeConnecting => "ChallengeConnecting",
            ChallengeAuthorizationState::NonceSent { .. } => "NonceSent",
            ChallengeAuthorizationState::Identified { .. } => "Identified",
            ChallengeAuthorizationState::Authorized { .. } => "Authorized",
        })
    }
}

/// The state transitions that can be applied on a connection during authorization.
#[derive(PartialEq, Debug)]
pub(crate) enum ChallengeAuthorizationAction {
    AddingNonce { nonce: Vec<u8> },
    Submitting { public_key: Vec<u8> },
    Authorizing,
}

impl fmt::Display for ChallengeAuthorizationAction {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ChallengeAuthorizationAction::AddingNonce { .. } => f.write_str("AddingNonce"),
            ChallengeAuthorizationAction::Submitting { .. } => f.write_str("Submitting"),
            ChallengeAuthorizationAction::Authorizing { .. } => f.write_str("Authorizing"),
        }
    }
}

impl ChallengeAuthorizationState {
    /// Transitions from one authorization state to another
    ///
    /// Errors
    ///
    /// The errors are error messages that should be returned on the appropriate message
    pub(crate) fn next_state(
        &self,
        action: ChallengeAuthorizationAction,
        cur_state: &mut ManagedAuthorizationState,
    ) -> Result<AuthorizationState, AuthorizationActionError> {
        match &self {
            ChallengeAuthorizationState::ChallengeConnecting => match action {
                ChallengeAuthorizationAction::AddingNonce { nonce } => {
                    let new_state =
                        AuthorizationState::Challenge(ChallengeAuthorizationState::NonceSent {
                            nonce,
                        });
                    cur_state.local_state = new_state.clone();
                    Ok(new_state)
                }
                _ => Err(AuthorizationActionError::InvalidMessageOrder(
                    AuthorizationState::Challenge(self.clone()),
                    AuthorizationAction::Challenge(action),
                )),
            },
            ChallengeAuthorizationState::NonceSent { .. } => match action {
                ChallengeAuthorizationAction::Submitting { public_key } => {
                    let new_state =
                        AuthorizationState::Challenge(ChallengeAuthorizationState::Identified {
                            public_key,
                        });
                    cur_state.local_state = new_state.clone();
                    Ok(new_state)
                }
                _ => Err(AuthorizationActionError::InvalidMessageOrder(
                    AuthorizationState::Challenge(self.clone()),
                    AuthorizationAction::Challenge(action),
                )),
            },
            ChallengeAuthorizationState::Identified { public_key } => match action {
                ChallengeAuthorizationAction::Authorizing => {
                    let new_state = {
                        match &cur_state.remote_state {
                            AuthorizationState::Challenge(
                                ChallengeAuthorizationState::Authorized {
                                    public_key: local_public_key,
                                },
                            ) => {
                                cur_state.remote_state =
                                    AuthorizationState::AuthComplete(Some(Identity::Challenge {
                                        public_key: local_public_key.clone(),
                                    }));

                                AuthorizationState::AuthComplete(Some(Identity::Challenge {
                                    public_key: public_key.to_vec(),
                                }))
                            }
                            _ => AuthorizationState::Challenge(
                                ChallengeAuthorizationState::Authorized {
                                    public_key: public_key.to_vec(),
                                },
                            ),
                        }
                    };

                    cur_state.local_state = new_state.clone();
                    Ok(new_state)
                }
                _ => Err(AuthorizationActionError::InvalidMessageOrder(
                    AuthorizationState::Challenge(self.clone()),
                    AuthorizationAction::Challenge(action),
                )),
            },
            _ => Err(AuthorizationActionError::InvalidMessageOrder(
                AuthorizationState::Challenge(self.clone()),
                AuthorizationAction::Challenge(action),
            )),
        }
    }

    /// Transitions from one authorization state to another
    ///
    /// Errors
    ///
    /// The errors are error messages that should be returned on the appropriate message
    pub(crate) fn next_remote_state(
        &self,
        action: ChallengeAuthorizationAction,
        cur_state: &mut ManagedAuthorizationState,
    ) -> Result<AuthorizationState, AuthorizationActionError> {
        match &self {
            ChallengeAuthorizationState::ChallengeConnecting => match action {
                ChallengeAuthorizationAction::AddingNonce { nonce } => {
                    let new_state =
                        AuthorizationState::Challenge(ChallengeAuthorizationState::NonceSent {
                            nonce,
                        });
                    cur_state.remote_state = new_state.clone();
                    Ok(new_state)
                }
                _ => Err(AuthorizationActionError::InvalidMessageOrder(
                    AuthorizationState::Challenge(self.clone()),
                    AuthorizationAction::Challenge(action),
                )),
            },
            ChallengeAuthorizationState::NonceSent { .. } => match action {
                ChallengeAuthorizationAction::Submitting { public_key } => {
                    let new_state =
                        AuthorizationState::Challenge(ChallengeAuthorizationState::Identified {
                            public_key,
                        });
                    cur_state.remote_state = new_state.clone();
                    Ok(new_state)
                }
                _ => Err(AuthorizationActionError::InvalidMessageOrder(
                    AuthorizationState::Challenge(self.clone()),
                    AuthorizationAction::Challenge(action),
                )),
            },
            ChallengeAuthorizationState::Identified { public_key } => match action {
                ChallengeAuthorizationAction::Authorizing => {
                    let new_state = {
                        match &cur_state.local_state {
                            AuthorizationState::Challenge(
                                ChallengeAuthorizationState::Authorized {
                                    public_key: remote_public_key,
                                },
                            ) => {
                                cur_state.local_state =
                                    AuthorizationState::AuthComplete(Some(Identity::Challenge {
                                        public_key: remote_public_key.clone(),
                                    }));

                                AuthorizationState::AuthComplete(Some(Identity::Challenge {
                                    public_key: public_key.to_vec(),
                                }))
                            }
                            _ => AuthorizationState::Challenge(
                                ChallengeAuthorizationState::Authorized {
                                    public_key: public_key.to_vec(),
                                },
                            ),
                        }
                    };

                    cur_state.remote_state = new_state.clone();
                    Ok(new_state)
                }
                _ => Err(AuthorizationActionError::InvalidMessageOrder(
                    AuthorizationState::Challenge(self.clone()),
                    AuthorizationAction::Challenge(action),
                )),
            },
            _ => Err(AuthorizationActionError::InvalidMessageOrder(
                AuthorizationState::Challenge(self.clone()),
                AuthorizationAction::Challenge(action),
            )),
        }
    }
}
