use std::path::PathBuf;
use url::Url;
use serde::{Serialize, Deserialize};

// This will now compile perfectly!
#[derive(Debug, Serialize, Deserialize)]
pub enum InputSource {
    File(PathBuf),
    Url(Url),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Content {
    pub source: InputSource,
    pub data: Vec<u8>,
    pub content_type: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Policy {
    //to be implemented
}