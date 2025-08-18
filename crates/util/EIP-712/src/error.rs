// Copyright 2015-2020 Parity Technologies (UK) Ltd.
// This file is part of OpenEthereum.

// OpenEthereum is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// OpenEthereum is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with OpenEthereum.  If not, see <http://www.gnu.org/licenses/>.

use thiserror::Error;
use validator::{ValidationErrors, ValidationErrorsKind};

pub(crate) type Result<T> = ::std::result::Result<T, ErrorKind>;

#[derive(Error, Debug, PartialEq)]
pub enum ErrorKind {
    #[error("Expected type '{0}' for field '{1}'")]
    UnexpectedType(String, String),
    #[error("The given primaryType wasn't found in the types field")]
    NonExistentType,
    #[error("Address string should be a 0x-prefixed 40 character string, got '{0}'")]
    InvalidAddressLength(usize),
    #[error("Failed to parse hex '{0}'")]
    HexParseError(String),
    #[error("The field '{0}' has an unknown type '{1}'")]
    UnknownType(String, String),
    #[error("Unexpected token '{0}' while parsing typename '{1}'")]
    UnexpectedToken(String, String),
    #[error("Maximum depth for nested arrays is 10")]
    UnsupportedArrayDepth,
    #[error("{0}")]
    ValidationError(String),
    #[error("Expected {0} items for array type {1}, got {2} items")]
    UnequalArrayItems(u64, String, u64),
    #[error("Attempted to declare fixed size with length {0}")]
    InvalidArraySize(String),
}

pub(crate) fn serde_error(expected: &str, field: Option<&str>) -> ErrorKind {
    ErrorKind::UnexpectedType(expected.to_owned(), field.unwrap_or("").to_owned())
}

impl From<ValidationErrors> for ErrorKind {
    fn from(error: ValidationErrors) -> Self {
        let mut string: String = "".into();
        for (field_name, error_kind) in error.errors() {
            match error_kind {
                ValidationErrorsKind::Field(validation_errors) => {
                    for error in validation_errors {
                        let str_error = format!(
                            "the field '{}', has an invalid value {}",
                            field_name, error.params["value"]
                        );
                        string.push_str(&str_error);
                    }
                }
                _ => unreachable!(
                    "#[validate] is only used on fields for regex;\
				its impossible to get any other	ErrorKind; qed"
                ),
            }
        }
        ErrorKind::ValidationError(string)
    }
}
