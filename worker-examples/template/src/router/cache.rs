use salvo_worker::salvo::*;
use time::OffsetDateTime;

// 短 TTL 缓存响应（TTL 见 router.rs: 60s）
#[handler]
pub async fn short() -> String {
    format!("short Hello World, my birth time is {}", OffsetDateTime::now_utc())
}

// 长 TTL 缓存响应（TTL 见 router.rs: 120s）
#[handler]
pub async fn long() -> String {
    format!("long Hello World, my birth time is {}", OffsetDateTime::now_utc())
}
