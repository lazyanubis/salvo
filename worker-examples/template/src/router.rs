//! 路由与服务装配。
//!
//! 每个功能对应一个 `xxx_router()` 构造函数，`init_router()` 只负责按顺序拼接，
//! 新增功能时追加到末尾即可。

use std::sync::{Arc, Mutex};

use once_cell::sync::Lazy;
use salvo_worker::WorkerService;
use salvo_worker::salvo::{
    cors::{Cors, CorsHandler},
    http::Method,
    *,
};

/// 全局共享的服务实例，只在首次访问时构建。
pub(crate) static WORKER_SERVICE: Lazy<Arc<WorkerService>> = Lazy::new(init_service);

mod affix_state;
mod basic_auth;
mod cache;
mod caching_headers;
mod catch_panic;
mod concurrency_limiter;
mod csrf;
mod flash_cookie;
mod flash_session;
mod open_api;
mod rate_limiter;
mod request_body;
mod request_id;
mod session;
mod timeout;

/// session / flash 共用的签名密钥（示例值，生产环境请替换为随机生成的密钥）。
const SESSION_SECRET: &[u8] = b"secretabsecretabsecretabsecretabsecretabsecretabsecretabsecretab"; // cspell: disable-line
/// CSRF 加解密密钥（示例值）。
const CSRF_SECRET: [u8; 32] = *b"01234567012345670123456701234567";
/// KV 命名空间绑定名，见 wrangler.toml。
const KV_BINDING: &str = "KV_TEST";
/// OpenAPI 文档的路径。
const OPEN_API_PATH: &str = "/api-doc/openapi.json";
/// 构建期嵌入的 OpenAPI 文档内容，可用 `update_open_api` 重新生成。
const OPEN_API_CONTENT: &str = include_str!("../docs/open-api.json");

/// 构建全局服务：CORS、日志、404/400 兜底都在这一层挂载。
fn init_service() -> Arc<WorkerService> {
    let service = WorkerService::from_router(Arc::new(init_router()))
        .cors(init_cors())
        .hoop(salvo::logging::Logger::new())
        .catch_bad_request_and_not_found();
    Arc::new(service)
}

fn init_cors() -> CorsHandler {
    Cors::new()
        .allow_origin(["http://127.0.0.1:5800", "http://localhost:5800"])
        .allow_methods(vec![Method::GET, Method::POST, Method::DELETE])
        .allow_headers("authorization")
        .into_handler()
}

/// 按顺序拼接所有功能路由。
///
/// 顺序即匹配优先级；OpenAPI 的 UI 最后 `unshift` 到最前面，避免被业务路由遮蔽。
fn init_router() -> Router {
    let mut router = Router::new()
        .push(request_body_router())
        .push(Router::with_path(OPEN_API_PATH).get(open_api_handler))
        .get(rate_limiter::hello)
        .push(affix_state_router())
        .push(basic_auth_router())
        .push(cache_router())
        .push(caching_headers_router())
        .push(catch_panic_router())
        .push(concurrency_limiter_router())
        .push(session_router())
        .push(csrf_router())
        .push(flash_cookie_router())
        .push(flash_session_router())
        .push(open_api_router())
        .push(proxy_router())
        .push(rate_limiter_router())
        .push(request_id_router())
        .push(size_limiter_router())
        .push(timeout_router())
        .push(trailing_slash_router());

    for ui in salvo_worker::open_api::ui_all(OPEN_API_PATH, None) {
        router = router.unshift(ui);
    }
    router
}

fn request_body_router() -> Router {
    Router::with_path("request_body").post(request_body::echo)
}

fn affix_state_router() -> Router {
    let config = affix_state::Config {
        username: "root".to_string(),
        password: "pwd".to_string(),
    };
    Router::with_path("affix_state")
        .hoop(
            salvo::affix_state::inject(config)
                // 注入共享状态
                .inject(Arc::new(affix_state::State {
                    fails: Mutex::new(Vec::new()),
                }))
                // 插入自定义数据
                .insert("custom_data", "I love this world!"),
        )
        .get(affix_state::hello)
        .push(Router::with_path("hello").get(affix_state::hello))
}

fn basic_auth_router() -> Router {
    let auth_handler = salvo::basic_auth::BasicAuth::new(basic_auth::Validator);
    Router::with_path("basic_auth").push(Router::with_hoop(auth_handler).goal(basic_auth::hello))
}

fn cache_router() -> Router {
    let short = salvo::cache::Cache::new(
        salvo::cache::WorkerStore::builder(KV_BINDING.into())
            .time_to_live(std::time::Duration::from_secs(60))
            .build(),
        salvo::cache::RequestIssuer::default(),
    );
    let long = salvo::cache::Cache::new(
        salvo::cache::WorkerStore::builder(KV_BINDING.into())
            .time_to_live(std::time::Duration::from_secs(120))
            .build(),
        salvo::cache::RequestIssuer::default(),
    );
    Router::with_path("cache")
        .push(Router::with_path("short").hoop(short).get(cache::short))
        .push(Router::with_path("long").hoop(long).get(cache::long))
}

fn caching_headers_router() -> Router {
    Router::with_path("caching_headers")
        .push(Router::with_hoop(salvo::caching_headers::CachingHeaders::new()).get(caching_headers::hello))
}

fn catch_panic_router() -> Router {
    Router::with_path("catch_panic")
        .hoop(salvo::catch_panic::CatchPanic::new())
        .get(catch_panic::hello)
}

fn concurrency_limiter_router() -> Router {
    Router::with_path("concurrency_limiter")
        .hoop(salvo::concurrency_limiter::max_concurrency(1))
        .get(concurrency_limiter::index)
}

fn session_router() -> Router {
    #[allow(clippy::unwrap_used)]
    let session_handler =
        salvo::session::SessionHandler::builder(salvo::session::CookieStore::new(), SESSION_SECRET)
            .build()
            .unwrap();
    Router::with_path("session")
        .hoop(session_handler)
        .get(session::home)
        .push(Router::with_path("login").get(session::login).post(session::login))
        .push(Router::with_path("logout").get(session::logout))
}

fn csrf_router() -> Router {
    let form_finder = salvo::csrf::FormFinder::new("csrf_token");
    let hmac = salvo::csrf::hmac_cookie_csrf(CSRF_SECRET, form_finder.clone());
    let aes_gcm = salvo::csrf::aes_gcm_cookie_csrf(CSRF_SECRET, form_finder.clone());
    let ccp = salvo::csrf::ccp_cookie_csrf(CSRF_SECRET, form_finder);
    Router::with_path("csrf")
        .get(csrf::home)
        // bcrypt-cipher 在 wasm 下不可用，默认未启用（见 salvo-worker 的 csrf features）
        .push(
            Router::with_hoop(hmac)
                .path("hmac")
                .get(csrf::get_page)
                .post(csrf::post_page),
        )
        .push(
            Router::with_hoop(aes_gcm)
                .path("aes_gcm")
                .get(csrf::get_page)
                .post(csrf::post_page),
        )
        .push(Router::with_hoop(ccp).path("ccp").get(csrf::get_page))
}

fn flash_cookie_router() -> Router {
    Router::with_path("flash_cookie")
        .hoop(salvo::flash::CookieStore::new().into_handler())
        .push(Router::with_path("get").get(flash_cookie::get_flash))
        .push(Router::with_path("set").get(flash_cookie::set_flash))
}

fn flash_session_router() -> Router {
    #[allow(clippy::unwrap_used)]
    let session_handler = salvo::session::SessionHandler::builder(
        salvo::session::MemoryStore::new(),
        SESSION_SECRET,
    )
    .build()
    .unwrap();
    Router::with_path("flash_session")
        .hoop(session_handler)
        .hoop(salvo::flash::SessionStore::new().into_handler())
        .push(Router::with_path("get").get(flash_session::get_flash))
        .push(Router::with_path("set").get(flash_session::set_flash))
}

fn open_api_router() -> Router {
    Router::with_path("open_api").push(
        Router::with_path("hello")
            .get(open_api::hello)
            .push(Router::with_path("{pet_id}").get(open_api::hello2)),
    )
}

fn proxy_router() -> Router {
    Router::with_path("proxy")
        .push(
            Router::new()
                .path("google/{**rest}")
                .goal(salvo::proxy::Proxy::<Vec<&str>, _>::new(
                    vec!["https://www.google.com"],
                    salvo::proxy::ReqwestClient::default(),
                )),
        )
        .push(
            Router::new()
                .path("baidu/{**rest}")
                .goal(salvo::proxy::Proxy::<Vec<&str>, _>::new(
                    vec!["https://www.baidu.com"],
                    salvo::proxy::ReqwestClient::default(),
                )),
        )
}

/// 从 Cloudflare 注入的 `CF-Connecting-IP` 取客户端 IP。
///
/// Worker 环境下 `remote_addr()` 拿不到地址，直接用 `RemoteIpIssuer` 会返回 `None`，
/// 限流器随即以 400 拒绝请求。
struct CfConnectingIpIssuer;

impl salvo::rate_limiter::RateIssuer for CfConnectingIpIssuer {
    type Key = String;

    async fn issue(&self, req: &mut Request, _depot: &Depot) -> Option<Self::Key> {
        req.header::<String>("cf-connecting-ip")
            .or_else(|| req.remote_addr().ip().map(|ip| ip.to_string()))
    }
}

fn rate_limiter_router() -> Router {
    let limiter = salvo::rate_limiter::RateLimiter::new(
        salvo::rate_limiter::FixedGuard::new(),
        salvo::rate_limiter::WorkerStore::new(KV_BINDING.into()),
        CfConnectingIpIssuer,
        salvo::rate_limiter::BasicQuota::new(10, time::Duration::seconds(10)),
    );
    Router::with_path("rate_limiter")
        .hoop(limiter)
        .get(rate_limiter::hello)
}

fn request_id_router() -> Router {
    Router::with_path("request_id")
        .hoop(RequestId::new())
        .get(request_id::hello)
}

fn size_limiter_router() -> Router {
    Router::with_path("size_limiter")
        .hoop(salvo::size_limiter::max_size(100))
        .post(rate_limiter::hello)
}

fn timeout_router() -> Router {
    Router::with_path("timeout")
        .hoop(salvo::timeout::Timeout::new(std::time::Duration::from_secs(5)))
        .push(Router::with_path("slow").get(timeout::slow))
        .push(Router::with_path("fast").get(timeout::fast))
}

fn trailing_slash_router() -> Router {
    Router::with_path("trailing_slash").push(
        Router::with_hoop(salvo::trailing_slash::add_slash())
            .push(Router::with_path("hello").get(rate_limiter::hello))
            .push(Router::with_path("hello.world").get(rate_limiter::hello)),
    )
}

#[handler]
async fn open_api_handler() -> &'static str {
    OPEN_API_CONTENT
}

#[cfg(test)]
mod tests {
    use super::*;

    const OPEN_API_FILE: &str = "docs/open-api.json"; // 子项目根目录

    /// 更新 open-api.json
    #[ignore]
    #[test]
    fn update_open_api() {
        salvo_worker::open_api::update_open_api(
            init_router(),
            "Template Api Docs",
            "0.0.1",
            OPEN_API_FILE,
        );
    }

    /// 使用 endpoint
    #[ignore]
    #[test]
    fn release_all_endpoints() {
        salvo_worker::open_api::release_all_endpoints("src");
    }

    /// 使用 handler
    #[ignore]
    #[test]
    fn release_all_handlers() {
        salvo_worker::open_api::release_all_handlers("src");
    }
}
