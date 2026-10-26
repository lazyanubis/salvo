//! 主入口

use worker::*;

mod durable;
mod router;

/// 初始化日志与全局服务。
#[event(start)]
fn start() {
    console_error_panic_hook::set_once();

    use tracing_subscriber::fmt::format::Pretty;
    use tracing_subscriber::fmt::time::UtcTime;
    use tracing_subscriber::prelude::*;
    use tracing_web::{MakeConsoleWriter, performance_layer};

    let fmt_layer = tracing_subscriber::fmt::layer()
        .json()
        .with_ansi(false) // Only partially supported across JavaScript runtime
        .with_timer(UtcTime::rfc_3339()) // std::time is not available in browsers
        .with_writer(MakeConsoleWriter); // write events to the console
    let perf_layer = performance_layer().with_details_from_fields(Pretty::default());
    tracing_subscriber::registry()
        .with(fmt_layer)
        .with(perf_layer)
        .init();

    // 提前构建服务，避免首次请求承担初始化开销
    let _ = router::WORKER_SERVICE.clone();
}

#[allow(clippy::future_not_send)]
mod future_warning {
    use super::*;

    /// 定时任务
    #[event(scheduled)]
    async fn scheduled(_event: ScheduledEvent, _env: Env, _ctx: ScheduleContext) {}

    /// 请求入口：`/durable*` 直接转发给 Durable Object，其余交给 Salvo。
    #[event(fetch)]
    async fn fetch(req: Request, env: Env, ctx: Context) -> Result<Response> {
        if req.path().starts_with("/durable") {
            return forward_to_durable(req, &env).await;
        }
        router::WORKER_SERVICE.handle(req, env, ctx).await
    }

    /// websocket 类型的 Durable Object 绑定。
    const WEBSOCKET_ROUTES: [(&str, &str); 2] = [
        ("/durable/websocket2", "MY_DURABLE_OBJECT_WEB_SOCKET2"),
        ("/durable/websocket", "MY_DURABLE_OBJECT_WEB_SOCKET"),
    ];

    /// 把 `/durable*` 请求转发给对应的 Durable Object。
    async fn forward_to_durable(req: Request, env: &Env) -> Result<Response> {
        let path = req.path();

        if let Some((_, binding)) = WEBSOCKET_ROUTES
            .iter()
            .find(|(prefix, _)| path.starts_with(prefix))
        {
            let is_websocket = req
                .headers()
                .get("Upgrade")?
                .is_some_and(|value| value == "websocket");
            if !is_websocket {
                return Response::from_bytes("Durable Object expected Upgrade: websocket".into())
                    .map(|resp| resp.with_status(426));
            }
            return salvo_worker::durable::get_do_binding(env, binding, "socket")?
                .fetch_with_request(req)
                .await;
        }

        salvo_worker::durable::get_do_binding(env, "MY_DURABLE_OBJECT", "durable")?
            .fetch_with_request(req)
            .await
    }
}
