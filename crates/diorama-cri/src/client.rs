//! gRPC Unix domain socket client connection helper.

use hyper_util::rt::TokioIo;
use std::path::Path;
use tokio::net::UnixStream;
use tonic::transport::{Channel, Endpoint, Uri};
use tower::service_fn;

/// Connects to a Unix domain socket and returns a tonic gRPC `Channel`.
pub async fn connect_unix(path: impl AsRef<Path>) -> Result<Channel, tonic::transport::Error> {
    let path = path.as_ref().to_path_buf();
    Endpoint::try_from("http://[::]:50051")?
        .connect_with_connector(service_fn(move |_: Uri| {
            let path = path.clone();
            async move {
                let stream = UnixStream::connect(path).await?;
                Ok::<_, std::io::Error>(TokioIo::new(stream))
            }
        }))
        .await
}
