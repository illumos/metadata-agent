use serde::{Deserialize};

#[derive(Debug, Deserialize, Eq, PartialEq, Clone)]
#[serde(untagged)]
pub enum Multiformat {
    String(String),
    List(Vec<String>),
    Integer(i32),
}