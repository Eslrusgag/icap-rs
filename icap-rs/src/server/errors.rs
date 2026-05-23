use tokio::io::{AsyncWrite, AsyncWriteExt};

use crate::error::{Error, IcapResult};
use crate::{Response, StatusCode};

use super::Server;

impl Server {
    pub(super) async fn write_wire_parse_error_response<S>(
        socket: &mut S,
        err: &Error,
    ) -> IcapResult<()>
    where
        S: AsyncWrite + Unpin,
    {
        let (status, reason) = match err {
            Error::InvalidMethod(_) => (StatusCode::NOT_IMPLEMENTED, "Not Implemented"),
            _ => (StatusCode::BAD_REQUEST, "Bad Request"),
        };
        Self::write_wire_error_response(socket, status, reason).await
    }

    pub(super) async fn write_wire_error_response<S>(
        socket: &mut S,
        status: StatusCode,
        reason: &str,
    ) -> IcapResult<()>
    where
        S: AsyncWrite + Unpin,
    {
        let resp = Response::new(status, reason).add_header("Connection", "close");
        let bytes = resp.to_raw()?;
        socket.write_all(&bytes).await?;
        let _ = socket.shutdown().await;
        Ok(())
    }
}
