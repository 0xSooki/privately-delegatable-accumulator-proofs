//! Error types returned by fallible accumulator operations.

use std::fmt;

/// Errors that can be returned by accumulator operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccumulatorError {
    /// A membership proof was requested for an element that is not in the set.
    ElementNotInSet,

    /// An element that is not coprime with the accumulator set product was
    NotCoprime,

    /// A proof update was requested with a negative delta.
    NegativeDelta,
}

impl fmt::Display for AccumulatorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ElementNotInSet => {
                write!(f, "element is not in the accumulator set")
            }
            Self::NotCoprime => {
                write!(f, "element is not coprime with the accumulator set product")
            }
            Self::NegativeDelta => {
                write!(f, "delta must be non-negative for a proof update")
            }
        }
    }
}

impl std::error::Error for AccumulatorError {}

pub type AccumulatorResult<T> = Result<T, AccumulatorError>;
