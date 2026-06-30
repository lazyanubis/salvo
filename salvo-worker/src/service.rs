use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};

use bytes::Bytes;
use salvo_core::BoxedError;
use salvo_core::http::body::{Body, Frame, ReqBody, SizeHint};
use worker::*;

#[derive(Debug)]
struct WorkerReqBody(worker::Body);

impl Body for WorkerReqBody {
    type Data = Bytes;
    type Error = BoxedError;

    #[inline]
    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        std::pin::Pin::new(&mut self.0)
            .poll_frame(cx)
            .map_err(|err| Box::new(err) as BoxedError)
    }

    #[inline]
    fn is_end_stream(&self) -> bool {
        self.0.is_end_stream()
    }

    #[inline]
    fn size_hint(&self) -> SizeHint {
        self.0.size_hint()
    }
}

/// service
#[derive(Debug)]
pub struct WorkerService {
    service: salvo_core::Service,
}

impl WorkerService {
    /// 新建
    #[must_use]
    pub fn new(service: salvo_core::Service) -> Self {
        Self { service }
    }

    /// 路由
    #[must_use]
    pub fn from_router(router: Arc<salvo_core::Router>) -> Self {
        Self {
            service: salvo_core::Service::new(router),
        }
    }

    /// hoop
    #[must_use]
    pub fn hoop<H: salvo_core::Handler>(self, hoop: H) -> Self {
        Self {
            service: self.service.hoop(hoop),
        }
    }

    /// cors
    #[cfg(feature = "cors")]
    #[must_use]
    pub fn cors(self, cors: super::salvo::cors::CorsHandler) -> Self {
        Self {
            service: self.service.hoop(cors),
        }
    }

    /// cors
    #[cfg(feature = "cors")]
    #[must_use]
    pub fn catch_bad_request_and_not_found(self) -> Self {
        use salvo_core::catcher::Catcher;

        Self {
            service: self.service.catcher(
                Catcher::default()
                    .hoop(super::catch::bad_request)
                    .hoop(super::catch::not_found),
            ),
        }
    }
}

impl From<Arc<salvo_core::Router>> for WorkerService {
    fn from(value: Arc<salvo_core::Router>) -> Self {
        Self::from_router(value)
    }
}

impl WorkerService {
    /// 处理请求
    pub async fn handle(&self, req: Request, env: Env, ctx: Context) -> worker::Result<Response> {
        // parse request
        let request: HttpRequest = req.try_into()?;
        let (parts, body) = request.into_parts();
        let request = ::http::Request::from_parts(
            parts,
            ReqBody::Boxed {
                inner: Box::pin(WorkerReqBody(body)),
                #[cfg(not(target_family = "wasm"))]
                fusewire: None,
            },
        );
        let scheme = request
            .headers()
            .iter()
            .find(|(name, _)| name.as_str() == "cf-visitor")
            .and_then(|(_, value)| value.to_str().ok())
            .and_then(|v| match v {
                r#"{"scheme":"https"}"# => Some(http::uri::Scheme::HTTPS),
                r#"{"scheme":"http"}"# => Some(http::uri::Scheme::HTTP),
                _ => None,
            });

        // handle request by salvo
        let scheme = request
            .uri()
            .scheme()
            .cloned()
            .unwrap_or_else(|| scheme.unwrap_or(http::uri::Scheme::HTTP));
        let request = salvo_core::Request::from_hyper(request, scheme);
        let mut depot = salvo_core::Depot::new();
        depot.insert_typed(env);
        depot.insert_typed(ctx);
        let response = self.service.handle(request, Some(depot)).await;

        // parse response
        let response = crate::response::handle_response(response).await?;

        Ok(response)
    }
}
