use serde::Serialize;

pub const SUCCESS: &str = "success";
pub const DEFAULT_PAGE_SIZE: i64 = 20;

#[derive(Debug, Deserialize, Serialize, PartialEq)]
pub struct Response<T> {
	pub code: u32,
	pub msg: String,
	pub data: T,
}
