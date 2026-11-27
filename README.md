<h1 align="center">
  <img src="assets/header.webp" alt="ls2" width="900">
</h1>
<p align="center"><strong>Async Luna Service 2 for webOS TV</strong></p>
<p align="center">
  <a href="#installation">Installation</a> ·
  <a href="#quick-start">Quick start</a> ·
  <a href="#hosting-a-service">Hosting a service</a> ·
  <a href="LICENSE">MIT license</a>
</p>

`ls2` is a pure Rust library for communicating over the local Luna bus on webOS TV. Call methods, subscribe to replies, register named services, and exchange broadcast signals from Tokio, smol, or another async executor.

## Installation

Requires Rust 1.85 or newer.

```sh
cargo add ls2
```

## Quick start

Connect to the local bus and call a method by its `luna://` URI. `call_raw` sends a UTF-8 string and returns the first reply as a `String`.

```rust
use ls2::Connection;

async fn system_time() -> Result<String, ls2::Error> {
    let bus = Connection::connect().await?;
    bus.call_raw("luna://com.palm.systemservice/time/getSystemTime", "{}").await
}
```

Clone `Connection` to share the same bus registration across tasks. Use `Connection::builder()` to set a custom timeout or hub socket path. Service payloads pass through as sent, so check fields such as `returnValue` according to the service’s contract.

## Firmware compatibility

`ls2` selects a wire profile from the installed LS2 ELF files before connecting. It checks the installed library’s transport symbols, file descriptor message numbers, and reply layout. Profiles are named for wire features and can span multiple firmware releases. Use `Connection::builder().protocol_profile(...)` to select a supported layout explicitly. A custom socket defaults to `ProtocolProfile::LengthPrefixedReplies` and accepts the same override.

## JSON with Serde

Enable the `serde` feature to serialize requests and deserialize replies, updates, and signals. The example uses `serde_json::Value`. Your own types can implement `Serialize` for requests and `Deserialize` for replies.

```toml
[dependencies]
ls2 = { version = "0.1", features = ["serde"] }
serde_json = "1"
```

```rust
use ls2::Connection;
use serde_json::{Value, json};

async fn system_time() -> Result<Value, ls2::Error> {
    let bus = Connection::connect().await?;
    bus.call_json("luna://com.palm.systemservice/time/getSystemTime", &json!({})).await
}
```

## Subscriptions and signals

Use `subscribe_raw` or `subscribe_json` to receive a method’s initial reply and subsequent updates as a stream. Include the parameters the service expects, such as `"subscribe": true`. Drop the stream to request cancellation, or call `cancel().await` to wait for the cancellation frame to be sent.

Use `watch_signal` with `SignalFilter::exact("/example", "changed")?` to receive broadcasts for one method, or `SignalFilter::category("/example")?` to receive all broadcasts in that category. From a named connection, publish with `emit_raw("/example", "changed", payload)` or `emit_json`.

## Hosting a service

Register a `Router` under a service name and keep the connection alive to accept requests. The echo handler below is available at `luna://org.example.echo/example/echo`.

```rust
use ls2::{Connection, Reply, Router};

async fn echo_service() -> Result<Connection, ls2::Error> {
    let mut router = Router::new();
    router.route("/example/echo", |request| async move {
        Ok(Reply::one(request.into_payload()))
    })?;
    Connection::builder().register("org.example.echo", router).await
}
```

Use `Router::with_state(state)` to share state across handlers. Add named async functions with `router.route(path, handler)` and have each function take the state followed by the `Request`. Pass the finished router to `register(name, router.into())`. The router clones the state for each call. Pass an `Arc` when handlers need to share mutable state.

Use `Reply::stream` for multiple updates and `MethodError` to send a Luna application error. With `serde`, use `Request::deserialize` and `Reply::json` in service handlers. Handlers run on the crate’s executor. Delegate work that requires a specific runtime to your application’s executor.

The webOS hub must authorize your executable, service name, and operations through its access-control configuration. `ls2` enforces the hub’s caller permissions and denies methods protected by TV privacy controls.
