// /// Retrieve remote user information for the given username on the specified host.
// ///
// /// Returns None if the user does not exist or no information is available.
// async fn get_remote_user(username: &str, host: &str) -> anyhow::Result<Option<RawFingerResponse>> {
//     let addr = format!("{}:79", host);
//     let socket_addrs: Vec<SocketAddr> = addr.to_socket_addrs()?.collect();

//     if socket_addrs.is_empty() {
//         return Err(anyhow::anyhow!(
//             "Could not resolve address for host {}",
//             host
//         ));
//     }

//     let socket_addr = socket_addrs[0];

//     let mut stream = TcpStream::connect(socket_addr).await?;

//     let request = FingerRequest::new(false, username.to_string());
//     let request_bytes = request.to_bytes();
//     stream.write_all(&request_bytes).await?;

//     let mut response_bytes = Vec::new();
//     stream.read_to_end(&mut response_bytes).await?;

//     let response = RawFingerResponse::from_bytes(&response_bytes);

//     if response.is_empty() {
//         Ok(None)
//     } else {
//         Ok(Some(response))
//     }
// }
