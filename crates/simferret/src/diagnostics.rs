//! Value-free parser diagnostics.
//!
//! A parser error can quote the document it failed on, and a private artifact or
//! a guest frame can hold a launch environment value or an exact stream byte.
//! Every parser failure that can reach a shareable failure report or the CLI is
//! therefore reduced to a fixed context plus a numeric location. A parser
//! message is never reused: both serde and TOML format the offending value with
//! escaping that a redactor cannot reliably undo, so only the category and the
//! location survive.

use std::io;

use serde_json::error::Category;

/// Reduce one `serde_json` failure to a category and a location.
pub fn json_error(context: &str, error: &serde_json::Error) -> io::Error {
    let category = match error.classify() {
        Category::Io => "an I/O failure",
        Category::Syntax => "a syntax error",
        Category::Data => "a data error",
        Category::Eof => "unexpected end of input",
    };
    invalid(format!(
        "{context}: {category} at line {} column {}",
        error.line(),
        error.column()
    ))
}

/// Reduce one TOML failure to a location, because a TOML message can quote the
/// offending value.
pub fn toml_error(context: &str, error: &toml::de::Error) -> io::Error {
    match error.span() {
        Some(span) => invalid(format!(
            "{context}: invalid document at byte offset {}..{}",
            span.start, span.end
        )),
        None => invalid(format!("{context}: invalid document")),
    }
}

fn invalid(message: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

#[cfg(test)]
mod tests {
    use serde::Deserialize;

    use super::*;

    /// A probe whose type error quotes the offending value.
    #[derive(Debug, Deserialize)]
    struct Probe {
        #[allow(dead_code)]
        environment: Vec<String>,
    }

    #[test]
    fn json_failures_name_a_category_and_a_location_only() {
        let error =
            serde_json::from_str::<Probe>("{\"environment\": [\"SECRET=value\", 17]}").unwrap_err();
        let message = json_error("malformed manifest", &error).to_string();
        assert!(message.starts_with("malformed manifest: "), "{message}");
        assert!(message.contains("at line 1 column "), "{message}");
        assert!(!message.contains("SECRET"), "{message}");
        assert!(!message.contains("environment"), "{message}");
    }

    #[test]
    fn toml_failures_name_a_location_only() {
        for source in [
            // A type error whose value is a quoted string.
            "environment = [\"SECRET=value\", 17]",
            // A type error whose value embeds the delimiter the message quotes it
            // with, which a redactor cannot undo reliably.
            "environment = 'TOKEN=\"CANARY'",
        ] {
            let error = toml::from_str::<Probe>(source).unwrap_err();
            let message = toml_error("malformed workload specification", &error).to_string();
            assert!(!message.contains("SECRET"), "{message}");
            assert!(!message.contains("CANARY"), "{message}");
            assert!(!message.contains("TOKEN"), "{message}");
            assert!(message.contains("byte offset"), "{message}");
        }
    }
}
