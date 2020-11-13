// Copyright 2018-2020 Cargill Incorporated
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

//! Errors for the OAuthUserStore.

use std::error::Error;
use std::fmt;

use crate::error::InternalError;

type ConstraintViolation = Box<dyn Error + Send>;

/// Errors that may occur during OAuthUserStore operations.
#[derive(Debug)]
pub enum OAuthUserStoreError {
    InternalError(InternalError),
    ConstraintViolation(ConstraintViolation),
}

impl Error for OAuthUserStoreError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            OAuthUserStoreError::InternalError(err) => err.source(),
            OAuthUserStoreError::ConstraintViolation(err) => err.source(),
        }
    }
}

impl fmt::Display for OAuthUserStoreError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            OAuthUserStoreError::InternalError(err) => f.write_str(&err.to_string()),
            OAuthUserStoreError::ConstraintViolation(err) => f.write_str(&err.to_string()),
        }
    }
}

#[derive(Debug)]
pub struct InvalidStateError(pub String);

impl fmt::Display for InvalidStateError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Error for InvalidStateError {}
