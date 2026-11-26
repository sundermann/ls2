use std::collections::BTreeMap;
use std::fmt;
use std::future::Future;
use std::pin::Pin;

use futures_core::Stream;

use crate::Error;
use crate::address::split_path;

mod policy;

pub(crate) use policy::{PeerPolicy, ServicePolicy};

type HandlerResult = Result<Reply, MethodError>;
type HandlerFuture = Pin<Box<dyn Future<Output = HandlerResult> + Send>>;
type Handler = Box<dyn Fn(Request) -> HandlerFuture + Send + Sync>;
type Methods = BTreeMap<String, Handler>;
type Updates = Pin<Box<dyn Stream<Item = Result<String, MethodError>> + Send>>;

pub(crate) const PRIVATE_CATEGORY: &str = "/com/palm/luna/private";
pub(crate) const PING_METHOD: &str = "ping";
pub(crate) const INTROSPECTION_METHOD: &str = "introspection";

/// A table of async method handlers to register under a Luna service name.
#[derive(Default)]
pub struct Router {
    routes: BTreeMap<String, Methods>,
}

impl Router {
    /// Creates an empty routing table.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a method handler for a path such as `/session/status` or `/echo`.
    ///
    /// The connection polls handlers on its executor. Use futures that can run
    /// there or delegate runtime-specific work to your application's runtime.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid path, a reserved category, or a path that
    /// already has a handler.
    pub fn route<F, Fut>(&mut self, path: &str, handler: F) -> Result<&mut Self, Error>
    where
        F: Fn(Request) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<Reply, MethodError>> + Send + 'static,
    {
        let (category, method) = split_path(path)?;
        if category == PRIVATE_CATEGORY {
            return Err(Error::invalid(
                "Luna reserves the /com/palm/luna/private category",
            ));
        }
        let methods = self.routes.entry(category.to_owned()).or_default();
        if methods.contains_key(method) {
            return Err(Error::invalid(format!(
                "method path {path:?} is already registered"
            )));
        }
        methods.insert(
            method.to_owned(),
            Box::new(move |request| Box::pin(handler(request))),
        );
        Ok(self)
    }

    pub(crate) fn categories(&self) -> impl Iterator<Item = (&str, impl Iterator<Item = &str>)> {
        self.routes
            .iter()
            .map(|(category, methods)| (category.as_str(), methods.keys().map(String::as_str)))
    }

    pub(crate) async fn dispatch(
        &self,
        request: Request,
        policy: &ServicePolicy,
        peer: &PeerPolicy,
        public: bool,
    ) -> Result<Reply, DispatchError> {
        if request.category() == PRIVATE_CATEGORY
            && matches!(request.method(), INTROSPECTION_METHOD | PING_METHOD)
        {
            if !policy.permits(peer, PRIVATE_CATEGORY, request.method(), public) {
                return Err(DispatchError::PermissionDenied);
            }
            return Ok(match request.method() {
                PING_METHOD => Reply::one(r#"{"returnValue":true}"#),
                _ => self.introspection(request.payload(), policy),
            });
        }
        let handler = self
            .routes
            .get(request.category())
            .and_then(|methods| methods.get(request.method()))
            .ok_or(DispatchError::UnknownMethod)?;
        if !policy.permits(peer, request.category(), request.method(), public) {
            return Err(DispatchError::PermissionDenied);
        }
        handler(request).await.map_err(DispatchError::Method)
    }

    fn introspection(&self, payload: &str, policy: &ServicePolicy) -> Reply {
        let params = json::parse(payload).ok().filter(json::JsonValue::is_object);
        let description = match params {
            Some(params)
                if params.is_empty() || (params.len() == 1 && params["type"] == "flat") =>
            {
                false
            }
            Some(params) if params.len() == 1 && params["type"] == "description" => true,
            _ => {
                return Reply::one(
                    json::object! {
                        "returnValue": false,
                        "errorText": "Expected an object with an optional type of flat or description",
                    }
                    .dump(),
                );
            }
        };
        let mut categories = json::object! {};
        for (category, methods) in self.categories() {
            let mut entries = json::object! {};
            for method in methods {
                entries[method] = if description {
                    let (groups, _) = policy.provided_groups(category, method);
                    json::object! { "provides": groups.into_iter().collect::<Vec<_>>() }
                } else {
                    "METHOD".into()
                };
            }
            categories[category] = if description {
                json::object! { "methods": entries }
            } else {
                entries
            };
        }
        let response = if description {
            json::object! { "returnValue": true, "categories": categories }
        } else {
            categories
        };
        Reply::one(response.dump())
    }
}

impl fmt::Debug for Router {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Router")
            .field("categories", &self.routes.keys())
            .finish()
    }
}

/// A method call delivered to a registered service.
pub struct Request {
    category: String,
    method: String,
    payload: String,
    sender: Option<String>,
}

impl Request {
    pub(crate) fn new(
        category: String,
        method: String,
        payload: String,
        sender: Option<String>,
    ) -> Self {
        Self {
            category,
            method,
            payload,
            sender,
        }
    }

    /// Returns the category of the called method.
    #[must_use]
    pub fn category(&self) -> &str {
        &self.category
    }

    /// Returns the name of the called method within its category.
    #[must_use]
    pub fn method(&self) -> &str {
        &self.method
    }

    /// Returns the request payload as received from the caller.
    #[must_use]
    pub fn payload(&self) -> &str {
        &self.payload
    }

    /// Takes ownership of the original payload.
    #[must_use]
    pub fn into_payload(self) -> String {
        self.payload
    }

    /// Returns the caller's service name when the hub reports one.
    #[must_use]
    pub fn sender(&self) -> Option<&str> {
        self.sender.as_deref()
    }

    /// Deserializes the request payload as JSON.
    ///
    /// # Errors
    ///
    /// Returns a JSON error if the payload cannot be deserialized as `T`.
    #[cfg(feature = "serde")]
    pub fn deserialize<'a, T: serde::Deserialize<'a>>(&'a self) -> Result<T, Error> {
        serde_json::from_str(&self.payload).map_err(Error::json)
    }
}

impl fmt::Debug for Request {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Request")
            .field("category", &self.category)
            .field("method", &self.method)
            .field("sender", &self.sender)
            .finish_non_exhaustive()
    }
}

/// A single service reply or a stream of updates for a call.
#[must_use]
pub struct Reply(ReplyBody);

pub(crate) enum ReplyBody {
    One(String),
    Stream(Updates),
}

impl Reply {
    /// Replies once with the supplied raw text.
    pub fn one(payload: impl Into<String>) -> Self {
        Self(ReplyBody::One(payload.into()))
    }

    /// Streams raw replies in order until the stream ends or the caller cancels.
    ///
    /// A method error becomes the final reply. Ending a server-side stream does
    /// not send an end-of-stream frame to the caller because Luna has no such frame.
    pub fn stream<S>(updates: S) -> Self
    where
        S: Stream<Item = Result<String, MethodError>> + Send + 'static,
    {
        Self(ReplyBody::Stream(Box::pin(updates)))
    }

    /// Serializes a single reply as JSON.
    ///
    /// # Errors
    ///
    /// Returns a JSON error if the value cannot be serialized.
    #[cfg(feature = "serde")]
    pub fn json<T: serde::Serialize + ?Sized>(value: &T) -> Result<Self, Error> {
        serde_json::to_string(value)
            .map(Self::one)
            .map_err(Error::json)
    }

    /// Serializes each reply in a stream as JSON.
    ///
    /// A serialization failure becomes a final method error with code `-1`.
    #[cfg(feature = "serde")]
    pub fn json_stream<S, T>(updates: S) -> Self
    where
        S: Stream<Item = Result<T, MethodError>> + Send + 'static,
        T: serde::Serialize,
    {
        use futures_lite::StreamExt as _;

        Self::stream(updates.map(|result| {
            result.and_then(|value| {
                serde_json::to_string(&value)
                    .map_err(|_| MethodError::new(-1, "could not serialize service reply"))
            })
        }))
    }

    pub(crate) fn into_body(self) -> ReplyBody {
        self.0
    }
}

impl fmt::Debug for Reply {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            ReplyBody::One(_) => formatter.write_str("Reply::One(..)"),
            ReplyBody::Stream(_) => formatter.write_str("Reply::Stream(..)"),
        }
    }
}

/// An application error returned to a Luna caller in the standard JSON reply envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MethodError {
    code: i32,
    message: String,
}

impl MethodError {
    /// Creates a method error with the given application code and text.
    pub fn new(code: i32, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    /// Returns the value sent in the reply's `errorCode` field.
    #[must_use]
    pub fn code(&self) -> i32 {
        self.code
    }

    /// Returns the text sent in the reply's `errorText` field.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }

    pub(crate) fn into_payload(self) -> String {
        json::object! {
            "returnValue": false,
            "errorCode": self.code,
            "errorText": self.message,
        }
        .dump()
    }
}

impl fmt::Display for MethodError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{} (code {})", self.message, self.code)
    }
}

impl std::error::Error for MethodError {}

#[derive(Debug)]
pub(crate) enum DispatchError {
    UnknownMethod,
    PermissionDenied,
    Method(MethodError),
}

#[cfg(test)]
mod tests {
    use futures_lite::{StreamExt as _, future, stream};

    use super::*;

    #[test]
    fn only_authorized_requests_reach_the_handler() -> Result<(), Error> {
        future::block_on(async {
            let mut router = Router::new();
            router
                .route("/", |_| async { Ok(Reply::one("ignored")) })
                .unwrap_err();
            router.route("/echo", |request| async move {
                assert_eq!(request.sender(), Some("org.ls2.test.client"));
                Ok(Reply::one(request.into_payload()))
            })?;
            assert!(
                router
                    .route("/echo", |_| async { Ok(Reply::one("ignored")) })
                    .is_err()
            );

            let policy = ServicePolicy::from_hub(
                Some(r#"[{"category":"/echo","groups":["echo"]}]"#),
                None,
                0,
            )?;
            let allowed = PeerPolicy::from_hub(Some(r#"["echo"]"#), None, 1)?;
            let denied = PeerPolicy::from_hub(Some(r#"["other"]"#), None, 1)?;
            let request = |method: &str| {
                Request::new(
                    "/".into(),
                    method.into(),
                    "  raw text \n".into(),
                    Some("org.ls2.test.client".into()),
                )
            };

            let reply = router
                .dispatch(request("echo"), &policy, &allowed, false)
                .await
                .expect("allowed handler");
            assert!(
                matches!(reply.into_body(), ReplyBody::One(payload) if payload == "  raw text \n")
            );
            assert!(matches!(
                router
                    .dispatch(request("echo"), &policy, &denied, false)
                    .await,
                Err(DispatchError::PermissionDenied)
            ));
            assert!(matches!(
                router
                    .dispatch(request("absent"), &policy, &allowed, false)
                    .await,
                Err(DispatchError::UnknownMethod)
            ));
            let categories: Vec<_> = router
                .categories()
                .map(|(category, methods)| (category, methods.collect::<Vec<_>>()))
                .collect();
            assert_eq!(categories, [("/", vec!["echo"])]);
            Ok(())
        })
    }

    #[test]
    fn introspection_lists_routes_for_authorized_peers() -> Result<(), Error> {
        future::block_on(async {
            let mut router = Router::new();
            for path in ["/echo", "/test/nested"] {
                router.route(path, |_| async { panic!("introspection ran a handler") })?;
            }
            let policy = ServicePolicy::from_hub(
                Some(
                    r#"[
                        {"category":"/com/palm/luna/private/*","groups":["inspect"]},
                        {"category":"/echo","groups":["root"]},
                        {"category":"/test/","groups":["nested"]}
                    ]"#,
                ),
                None,
                0,
            )?;
            let request = |payload: &str| {
                Request::new(
                    PRIVATE_CATEGORY.into(),
                    INTROSPECTION_METHOD.into(),
                    payload.into(),
                    None,
                )
            };
            let allowed = PeerPolicy::from_hub(Some(r#"["inspect"]"#), None, 1)?;
            let denied = PeerPolicy::from_hub(Some(r#"["root"]"#), None, 1)?;
            for (payload, expected) in [
                (
                    "{}",
                    r#"{"/":{"echo":"METHOD"},"/test":{"nested":"METHOD"}}"#,
                ),
                (
                    r#"{"type":"description"}"#,
                    r#"{"returnValue":true,"categories":{
                        "/":{"methods":{"echo":{"provides":["root"]}}},
                        "/test":{"methods":{"nested":{"provides":["nested"]}}}
                    }}"#,
                ),
            ] {
                let reply = router
                    .dispatch(request(payload), &policy, &allowed, false)
                    .await
                    .expect("allowed introspection");
                let ReplyBody::One(body) = reply.into_body() else {
                    panic!("introspection returned a stream");
                };
                assert_eq!(json::parse(&body).unwrap(), json::parse(expected).unwrap());
            }
            assert!(matches!(
                router
                    .dispatch(request("{}"), &policy, &denied, false)
                    .await,
                Err(DispatchError::PermissionDenied)
            ));
            Ok(())
        })
    }

    #[test]
    fn private_ping_replies_only_to_authorized_peers() -> Result<(), Error> {
        future::block_on(async {
            let router = Router::new();
            let policy = ServicePolicy::from_hub(
                Some(r#"[{"category":"/com/palm/luna/private/ping","groups":["health"]}]"#),
                None,
                0,
            )?;
            let allowed = PeerPolicy::from_hub(Some(r#"["health"]"#), None, 1)?;
            let denied = PeerPolicy::from_hub(Some(r#"["other"]"#), None, 1)?;
            let request = || {
                Request::new(
                    PRIVATE_CATEGORY.into(),
                    PING_METHOD.into(),
                    r#"{"extra":true}"#.into(),
                    None,
                )
            };

            let reply = router
                .dispatch(request(), &policy, &allowed, false)
                .await
                .expect("authorized ping");
            assert!(matches!(
                reply.into_body(),
                ReplyBody::One(body) if body == r#"{"returnValue":true}"#
            ));
            assert!(matches!(
                router.dispatch(request(), &policy, &denied, false).await,
                Err(DispatchError::PermissionDenied)
            ));
            Ok(())
        })
    }

    #[test]
    fn reply_stream_produces_ordered_updates_and_method_errors() {
        future::block_on(async {
            let method_error = MethodError::new(18, "failure\n\"text\"");
            let reply = Reply::stream(stream::iter([
                Ok("first".into()),
                Ok("second".into()),
                Err(method_error.clone()),
            ]));
            let ReplyBody::Stream(mut updates) = reply.into_body() else {
                panic!("reply stream became a single reply");
            };
            assert_eq!(updates.next().await, Some(Ok("first".into())));
            assert_eq!(updates.next().await, Some(Ok("second".into())));
            assert_eq!(updates.next().await, Some(Err(method_error.clone())));
            assert_eq!(updates.next().await, None);

            let payload = method_error.into_payload();
            let json = json::parse(&payload).expect("valid JSON method error");
            assert_eq!(json["returnValue"], false);
            assert_eq!(json["errorCode"].as_i32(), Some(18));
            assert_eq!(json["errorText"], "failure\n\"text\"");
        });
    }

    #[cfg(feature = "serde")]
    #[test]
    fn typed_payloads_can_borrow_from_requests() -> Result<(), Error> {
        let request = Request::new("/".into(), "echo".into(), "\"hello\"".into(), None);
        let text: &str = request.deserialize()?;
        let reply = Reply::json(text)?;
        assert!(matches!(reply.into_body(), ReplyBody::One(payload) if payload == "\"hello\""));
        Ok(())
    }
}
