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

use crate::admin::store::{AuthorizationType, Circuit, ProposedCircuit};
use crate::error::InvalidStateError;
use crate::peer::PeerAuthorizationToken;

use super::{admin_service_id, ListPeerAuthorizationTokens, PeerNode};

impl ListPeerAuthorizationTokens for ProposedCircuit {
    fn list_tokens(&self) -> Result<Vec<PeerAuthorizationToken>, InvalidStateError> {
        self.members()
            .iter()
            .map(|member| match self.authorization_type() {
                AuthorizationType::Trust => {
                    Ok(PeerAuthorizationToken::from_peer_id(member.node_id()))
                }
                #[cfg(feature = "challenge-authorization")]
                AuthorizationType::Challenge => {
                    if let Some(public_key) = member.public_key() {
                        Ok(PeerAuthorizationToken::from_public_key(public_key))
                    } else {
                        Err(InvalidStateError::with_message(format!(
                            "No public key set when circuit requries challenge \
                             authorization: {}",
                            self.circuit_id()
                        )))
                    }
                }
            })
            .collect::<Result<Vec<PeerAuthorizationToken>, InvalidStateError>>()
    }

    fn list_nodes(&self) -> Result<Vec<PeerNode>, InvalidStateError> {
        self.members()
            .iter()
            .map(|member| match self.authorization_type() {
                AuthorizationType::Trust => Ok(PeerNode {
                    token: PeerAuthorizationToken::from_peer_id(member.node_id()),
                    node_id: member.node_id().to_string(),
                    endpoints: member.endpoints().to_vec(),
                    admin_service: admin_service_id(member.node_id()),
                }),
                #[cfg(feature = "challenge-authorization")]
                AuthorizationType::Challenge => {
                    if let Some(public_key) = member.public_key() {
                        Ok(PeerNode {
                            token: PeerAuthorizationToken::from_public_key(public_key),
                            node_id: member.node_id().to_string(),
                            endpoints: member.endpoints().to_vec(),
                            admin_service: admin_service_id(member.node_id()),
                        })
                    } else {
                        Err(InvalidStateError::with_message(format!(
                            "No public key set when circuit requries challenge \
                             authorization: {}",
                            self.circuit_id()
                        )))
                    }
                }
            })
            .collect::<Result<Vec<PeerNode>, InvalidStateError>>()
    }

    fn get_node_token(
        &self,
        node_id: &str,
    ) -> Result<Option<PeerAuthorizationToken>, InvalidStateError> {
        match self
            .members()
            .iter()
            .find(|member| member.node_id() == node_id)
        {
            Some(member) => match self.authorization_type() {
                AuthorizationType::Trust => {
                    Ok(Some(PeerAuthorizationToken::from_peer_id(member.node_id())))
                }
                #[cfg(feature = "challenge-authorization")]
                AuthorizationType::Challenge => {
                    if let Some(public_key) = member.public_key() {
                        Ok(Some(PeerAuthorizationToken::from_public_key(public_key)))
                    } else {
                        Err(InvalidStateError::with_message(
                            "Public key not set when required by a circuit".to_string(),
                        ))
                    }
                }
            },
            None => Ok(None),
        }
    }
}

impl ListPeerAuthorizationTokens for Circuit {
    fn list_tokens(&self) -> Result<Vec<PeerAuthorizationToken>, InvalidStateError> {
        self.members()
            .iter()
            .map(|member| match self.authorization_type() {
                AuthorizationType::Trust => {
                    Ok(PeerAuthorizationToken::from_peer_id(member.node_id()))
                }
                #[cfg(feature = "challenge-authorization")]
                AuthorizationType::Challenge => {
                    if let Some(public_key) = member.public_key() {
                        Ok(PeerAuthorizationToken::from_public_key(public_key))
                    } else {
                        Err(InvalidStateError::with_message(format!(
                            "No public key set when circuit requries challenge \
                             authorization: {}",
                            self.circuit_id()
                        )))
                    }
                }
            })
            .collect::<Result<Vec<PeerAuthorizationToken>, InvalidStateError>>()
    }

    fn list_nodes(&self) -> Result<Vec<PeerNode>, InvalidStateError> {
        self.members()
            .iter()
            .map(|member| match self.authorization_type() {
                AuthorizationType::Trust => Ok(PeerNode {
                    token: PeerAuthorizationToken::from_peer_id(member.node_id()),
                    node_id: member.node_id().to_string(),
                    endpoints: member.endpoints().to_vec(),
                    admin_service: admin_service_id(member.node_id()),
                }),
                #[cfg(feature = "challenge-authorization")]
                AuthorizationType::Challenge => {
                    if let Some(public_key) = member.public_key() {
                        Ok(PeerNode {
                            token: PeerAuthorizationToken::from_public_key(public_key),
                            node_id: member.node_id().to_string(),
                            endpoints: member.endpoints().to_vec(),
                            admin_service: admin_service_id(member.node_id()),
                        })
                    } else {
                        Err(InvalidStateError::with_message(format!(
                            "No public key set when circuit requries challenge \
                             authorization: {}",
                            self.circuit_id()
                        )))
                    }
                }
            })
            .collect::<Result<Vec<PeerNode>, InvalidStateError>>()
    }

    fn get_node_token(
        &self,
        node_id: &str,
    ) -> Result<Option<PeerAuthorizationToken>, InvalidStateError> {
        match self
            .members()
            .iter()
            .find(|member| member.node_id() == node_id)
        {
            Some(member) => match self.authorization_type() {
                AuthorizationType::Trust => {
                    Ok(Some(PeerAuthorizationToken::from_peer_id(member.node_id())))
                }
                #[cfg(feature = "challenge-authorization")]
                AuthorizationType::Challenge => {
                    if let Some(public_key) = member.public_key() {
                        Ok(Some(PeerAuthorizationToken::from_public_key(public_key)))
                    } else {
                        Err(InvalidStateError::with_message(
                            "Public key not set when required by a circuit".to_string(),
                        ))
                    }
                }
            },
            None => Ok(None),
        }
    }
}
