//! Athena's types, as `Value`s.
//!
//! Everything arrives as a string — `Datum` holds a `VarCharValue` and nothing else — so
//! this is a decision about what to *promise* rather than about how to decode. Invariant
//! 10 settles the shape of that decision: an unrecognized type renders as a string, and
//! it must never abort a result set. So every branch here has a text fallback, and there
//! is no error path at all.

use quokka_core::Value;

/// One cell, given the type `ResultSetMetadata` declared for its column.
///
/// **What is deliberately left as text**, since a type-mapping table is mostly a list of
/// things not to be clever about:
///
/// - `decimal` — exact, and an `f64` is not. The spool keeps it as text and it
///   round-trips (§11.2's M2 evidence found the same for Postgres `numeric`).
/// - `date`, `timestamp`, `time` — Athena prints them in a fixed format; parsing them
///   into a number would lose the format and gain nothing this program can use, since
///   `Value` has no temporal variant.
/// - `varbinary` — printed by the engine as its own hex-ish rendering. Decoding it into
///   `Value::Blob` would mean guessing at an encoding the wire does not name.
/// - `array`, `map`, `row`, `json`, `ipaddress`, `uuid` and everything else — the string
///   the engine printed is exactly what the grid should show.
pub fn value_for_type(driver_type: &str, text: &str) -> Value {
    // `decimal(38,2)` and `array(varchar)` both carry their parameters in the name; the
    // decision is made on the head of it.
    let head = driver_type
        .split(['(', '<'])
        .next()
        .unwrap_or(driver_type)
        .trim()
        .to_ascii_lowercase();

    match head.as_str() {
        "boolean" => match text {
            "true" => Value::Bool(true),
            "false" => Value::Bool(false),
            // Not the two words Athena documents. Rather than pick one, say what came.
            _ => Value::Text(text.to_string()),
        },
        "tinyint" | "smallint" | "integer" | "int" | "bigint" => text
            .parse::<i64>()
            .map(Value::Int)
            .unwrap_or_else(|_| Value::Text(text.to_string())),
        "float" | "real" | "double" => text
            .parse::<f64>()
            .map(Value::Float)
            .unwrap_or_else(|_| Value::Text(text.to_string())),
        // Everything else, including every type this build has never heard of.
        _ => Value::Text(text.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_types_athena_names_come_back_typed() {
        assert_eq!(value_for_type("boolean", "true"), Value::Bool(true));
        assert_eq!(value_for_type("integer", "42"), Value::Int(42));
        assert_eq!(value_for_type("bigint", "-7"), Value::Int(-7));
        assert_eq!(value_for_type("double", "1.5"), Value::Float(1.5));
        assert_eq!(
            value_for_type("varchar", "hello"),
            Value::Text("hello".to_string())
        );
    }

    /// Invariant 10, at the level it is decided: a type nobody has heard of is a string.
    #[test]
    fn an_unrecognized_type_is_text_rather_than_a_failure() {
        assert_eq!(
            value_for_type("geometry", "POINT (1 2)"),
            Value::Text("POINT (1 2)".to_string())
        );
        assert_eq!(
            value_for_type("ipaddress", "10.0.0.1"),
            Value::Text("10.0.0.1".to_string())
        );
        assert_eq!(value_for_type("", "x"), Value::Text("x".to_string()));
    }

    /// The other half of invariant 10, and the one that actually bites: a *recognized*
    /// type carrying something that does not parse. An `integer` column holding
    /// `9999999999999999999999` must be a string in the grid, not a dead result set.
    #[test]
    fn a_value_that_does_not_fit_its_declared_type_degrades_to_text() {
        assert_eq!(
            value_for_type("integer", "9999999999999999999999"),
            Value::Text("9999999999999999999999".to_string())
        );
        assert_eq!(
            value_for_type("boolean", "TRUE"),
            Value::Text("TRUE".to_string())
        );
        assert_eq!(
            value_for_type("double", "not a number"),
            Value::Text("not a number".to_string())
        );
    }

    #[test]
    fn a_parameterized_type_is_judged_on_its_head() {
        assert_eq!(
            value_for_type("decimal(38,2)", "1.25"),
            Value::Text("1.25".to_string()),
            "exact numerics stay exact, which means text"
        );
        assert_eq!(
            value_for_type("array(varchar)", "[a, b]"),
            Value::Text("[a, b]".to_string())
        );
        assert_eq!(value_for_type("INTEGER", "3"), Value::Int(3));
    }

    /// Infinity and NaN are what a `double` column holds when the query produced them.
    /// They survive as floats, which the spool's tag byte and the JSON formatter already
    /// know how to carry (§11.2).
    #[test]
    fn the_awkward_doubles_stay_doubles() {
        assert_eq!(
            value_for_type("double", "Infinity"),
            Value::Float(f64::INFINITY)
        );
        let nan = value_for_type("double", "NaN");
        assert!(matches!(nan, Value::Float(f) if f.is_nan()), "{nan:?}");
    }
}
