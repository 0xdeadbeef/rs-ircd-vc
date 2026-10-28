//! Wire protocol: message parsing/serialisation, numerics and casemapping.

pub mod message;
pub mod numeric;

pub use crate::casemap::CaseMapping;
pub use message::{Message, ParseError};
pub use numeric::Numeric;
