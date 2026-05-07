// SPDX-License-Identifier: Apache-2.0

const MAX_NAME_LEN: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NameError {
    Empty,
    Whitespace,
    ReservedAny,
    TooLong,
    InvalidChars,
}

impl NameError {
    fn describe(self, label: &str) -> String {
        match self {
            Self::Empty => format!("{label} must not be empty"),
            Self::Whitespace => format!("{label} must not contain leading or trailing whitespace"),
            Self::ReservedAny => format!("{label} 'any' is reserved"),
            Self::TooLong => format!("{label} must be at most {MAX_NAME_LEN} bytes"),
            Self::InvalidChars => {
                format!("{label} must use ASCII letters, digits, '_', '-', or '.'")
            }
        }
    }
}

fn validate_name(value: &str, allow_any: bool) -> Result<(), NameError> {
    if value.is_empty() {
        return Err(NameError::Empty);
    }
    if value.trim() != value {
        return Err(NameError::Whitespace);
    }
    if value == "any" && !allow_any {
        return Err(NameError::ReservedAny);
    }
    if value.len() > MAX_NAME_LEN {
        return Err(NameError::TooLong);
    }
    if !value
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
    {
        return Err(NameError::InvalidChars);
    }

    Ok(())
}

pub fn validate_method_name(method: &str, allow_any: bool) -> Result<(), String> {
    validate_name(method, allow_any).map_err(|e| e.describe("method"))
}

pub fn validate_adapter_name(name: &str) -> Result<(), String> {
    validate_name(name, false).map_err(|e| e.describe("adapter name"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_protocol_method_names() {
        for method in ["fido2", "libfprint", "custom_a", "vendor.method-1"] {
            validate_method_name(method, false).expect("valid method");
        }
    }

    #[test]
    fn rejects_ambiguous_method_names() {
        for method in ["", " fido2", "fido2 ", "two words", "line\nbreak", "any"] {
            validate_method_name(method, false).expect_err("invalid method");
        }
    }

    #[test]
    fn allows_any_only_for_wildcard_selectors() {
        validate_method_name("any", true).expect("wildcard selector");
        validate_method_name("any", false).expect_err("reserved method");
    }

    #[test]
    fn validates_adapter_names_with_same_token_rules() {
        validate_adapter_name("fido2.main-1").expect("valid adapter name");
        assert!(validate_adapter_name("two words").is_err());
        assert!(validate_adapter_name("any").is_err());
    }
}
