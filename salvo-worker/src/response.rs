use worker::*;

#[inline]
pub(crate) async fn handle_response(response: salvo_core::Response) -> worker::Result<Response> {
    response.into_hyper().try_into()
}
