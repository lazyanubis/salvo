use salvo_worker::salvo::{http::ParseError, *};

const MAX_BODY_BYTES: usize = 16 * 1024;

#[handler]
pub(crate) async fn echo(req: &mut Request, res: &mut Response) {
    match req.payload_with_max_size(MAX_BODY_BYTES).await {
        Ok(body) => {
            res.body(body.clone());
        }
        Err(ParseError::PayloadTooLarge) => {
            res.status_code(StatusCode::PAYLOAD_TOO_LARGE).body("request too large");
        }
        Err(_) => {
            res.status_code(StatusCode::BAD_REQUEST)
                .body("request body read failed");
        }
    }
}
