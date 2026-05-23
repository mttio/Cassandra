use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use url::Url;


#[derive(Debug, Serialize, Deserialize)]
pub enum InputSource {
    File(PathBuf),
    Url(Url),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FetchedContent {
    pub source: InputSource,
    pub data: Vec<u8>,
    pub content_type: Option<String>,
}



#[derive(Debug, Serialize, Deserialize)]
pub struct Policy {
  pub html: PolicyHTML,
  pub urls: PolicyURLS,
  pub resources: PolicyResources,
  pub timeouts: PolicyTimeouts
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PolicyHTML {
    pub allow_scripts: Vec<String>,
    pub allow_origins: Vec<String>,
    pub strip_event_handlers: bool,
    pub rewrite_dangerous_uris: bool
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PolicyURLS {
    pub block_list: Vec<String>,
    pub rewrite_suspicious: bool,
    pub replace_homography: bool
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PolicyResources {
    pub fetch_sub_resources: bool,
    pub max_depth: usize,
    pub max_bytes: usize,
    pub max_requests: usize
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PolicyTimeouts {
    pub connection_timeout_secs: u64,
    pub overall_timeout_secs: u64,
}
