use serde::Serialize;

pub const SUCCESS: &str = "success";

#[derive(Debug, Deserialize, Serialize, PartialEq)]
pub struct Response<T> {
	pub code: u32,
	pub msg: String,
	pub data: T,
}
