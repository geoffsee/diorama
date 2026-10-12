//! Unix domain socket gRPC transport helper for containerd and CRI services.
use std::path::{Path, PathBuf};
use tonic::transport::{Channel, Endpoint, Uri};
use tower::service_fn;

/// Connects to a Unix domain socket gRPC endpoint.
pub async fn connect_unix(
    socket_path: impl AsRef<Path>,
) -> Result<Channel, tonic::transport::Error> {
    let path: PathBuf = socket_path.as_ref().to_path_buf();
    Endpoint::try_from("http://localhost")?
        .connect_with_connector(service_fn(move |_: Uri| {
            let path = path.clone();
            async move {
                let stream = tokio::net::UnixStream::connect(path).await?;
                Ok::<_, std::io::Error>(hyper_util::rt::TokioIo::new(stream))
            }
        }))
        .await
}
