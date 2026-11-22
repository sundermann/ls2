mod driver;
#[cfg(test)]
mod tests;

use std::{
    fmt,
    future::Future,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU32, Ordering},
    },
    time::Duration,
};

use async_channel::{Receiver, Sender};
use async_io::Timer;
use futures_lite::future;

use crate::address::{self, Address};
use crate::service::{INTROSPECTION_METHOD, PRIVATE_CATEGORY, ServicePolicy};
use crate::stream::{self, Feed, FeedSender};
use crate::wire::{self, Frame, Kind, Listener, Socket};
use crate::{
    Error, ErrorKind, ProtocolProfile, Router, Signal, SignalFilter, SignalStream, Subscription,
};

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);
const COMMAND_CAPACITY: usize = 128;
pub(crate) const STREAM_CAPACITY: usize = 32;

/// A shared connection to the local Luna Service 2 hub.
///
/// Clones use the same bus registration. Calls and streams can progress concurrently.
#[derive(Clone)]
pub struct Connection {
    inner: Arc<Inner>,
}

impl fmt::Debug for Connection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Connection")
            .field("service_name", &self.service_name())
            .field("closed", &self.inner.commands.is_closed())
            .finish_non_exhaustive()
    }
}

/// Options for connecting a client or registering a named service.
#[derive(Clone, Debug)]
pub struct ConnectionBuilder {
    socket_path: Option<PathBuf>,
    profile: Option<ProtocolProfile>,
    timeout: Duration,
}

impl Default for ConnectionBuilder {
    fn default() -> Self {
        Self {
            socket_path: None,
            profile: None,
            timeout: DEFAULT_TIMEOUT,
        }
    }
}

impl ConnectionBuilder {
    /// Uses a custom hub socket and the [`ProtocolProfile::LengthPrefixedReplies`] profile by default.
    /// Select a different profile with [`Self::protocol_profile`].
    #[must_use]
    pub fn socket_path(mut self, path: impl AsRef<Path>) -> Self {
        self.socket_path = Some(path.as_ref().to_owned());
        self
    }

    /// Uses a specific firmware protocol instead of inspecting the installed LS2 binaries.
    #[must_use]
    pub fn protocol_profile(mut self, profile: ProtocolProfile) -> Self {
        self.profile = Some(profile);
        self
    }

    /// Sets the deadline for connection, calls, stream setup, and explicit cancellation.
    #[must_use]
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Opens an anonymous client connection.
    ///
    /// # Errors
    ///
    /// Returns an error if the firmware profile is unknown, the socket is unavailable,
    /// or the hub refuses registration.
    pub async fn connect(self) -> Result<Connection, Error> {
        self.open(None).await
    }

    /// Registers a named service and publishes the router's categories and methods.
    ///
    /// The service name and APIs must be authorized by the hub. Handlers run on the
    /// crate's background executor and may use runtime-neutral futures.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid name, connection failure, or rejected registration.
    pub async fn register(self, name: &str, router: Router) -> Result<Connection, Error> {
        address::service_name(name)?;
        self.open(Some((name, router))).await
    }

    async fn open(self, service: Option<(&str, Router)>) -> Result<Connection, Error> {
        if self.timeout.is_zero() {
            return Err(Error::invalid("Luna timeout must be greater than zero"));
        }
        let timeout = self.timeout;
        within(timeout, "connect to Luna hub", async move {
            let profile = match self.profile {
                Some(profile) => profile,
                None if self.socket_path.is_some() => ProtocolProfile::DEFAULT,
                None => async_global_executor::spawn_blocking(ProtocolProfile::detect).await?,
            };
            let path = self
                .socket_path
                .as_deref()
                .unwrap_or_else(|| profile.hub_path());
            let socket = Socket::connect(path, profile)
                .await
                .map_err(|error| Error::io("connect to Luna hub socket", error))?;
            let service_name = service.as_ref().map(|(name, _)| *name);
            let tokens = Arc::new(Tokens::default());
            let request =
                wire::request_name(profile, tokens.next()?, service_name).map_err(encode_error)?;
            write_setup(&socket, &request).await?;
            let mut reply = read_setup(&socket).await?;
            if reply.kind != Kind::RequestNameReply {
                return Err(Error::protocol("expected a Luna registration reply"));
            }
            let listener_fd = reply.fd.take();
            let registration = wire::registration(profile, &reply)
                .map_err(|error| Error::io("decode Luna registration", error))?
                .map_err(registration_error)?;
            let monitor = read_setup(&socket).await?;
            if !matches!(
                monitor.kind,
                Kind::MonitorConnected | Kind::MonitorNotConnected
            ) {
                return Err(Error::protocol(
                    "expected Luna monitor status during registration",
                ));
            }
            if registration.flags & 1 != 0 && registration.flags & 2 == 0 {
                return Err(Error::new(
                    ErrorKind::PermissionDenied,
                    "the Luna hub denied private bus registration",
                ));
            }
            let listener = if profile == ProtocolProfile::LocalListener {
                let fd = listener_fd.ok_or_else(|| {
                    Error::protocol("legacy Luna registration did not provide a listener")
                })?;
                Some(
                    Listener::from_hub(fd, &socket)
                        .map_err(|error| Error::io("adopt Luna listener", error))?,
                )
            } else {
                None
            };
            let unique_name = registration.unique_name.to_owned();
            if profile.sends_node_up() {
                if profile == ProtocolProfile::LocalListener {
                    let ready = Frame::new(Kind::NodeUp, tokens.next()?, false, Vec::new());
                    write_setup(&socket, &ready).await?;
                }
                let info = wire::client_info(tokens.next()?, service_name, &unique_name)
                    .map_err(encode_error)?;
                write_setup(&socket, &info).await?;
                if profile != ProtocolProfile::LocalListener {
                    let ready = Frame::new(Kind::NodeUp, tokens.next()?, false, Vec::new());
                    write_setup(&socket, &ready).await?;
                }
            }
            let local = service
                .map(|(name, router)| {
                    let policy = ServicePolicy::from_hub(
                        registration.provided_groups,
                        registration.provided_trust,
                        registration.flags,
                    )?;
                    Ok::<_, Error>(driver::LocalService {
                        name: name.to_owned(),
                        router,
                        policy,
                    })
                })
                .transpose()?;
            let name = local.as_ref().map(|service| service.name.as_str());
            if let Some(service) = &local {
                let frame = wire::append_category(
                    profile,
                    tokens.next()?,
                    PRIVATE_CATEGORY,
                    [INTROSPECTION_METHOD],
                )
                .map_err(encode_error)?;
                write_setup(&socket, &frame).await?;
                for (category, methods) in service.router.categories() {
                    let frame = wire::append_category(profile, tokens.next()?, category, methods)
                        .map_err(encode_error)?;
                    write_setup(&socket, &frame).await?;
                }
            }

            let (commands, requests) = async_channel::bounded(COMMAND_CAPACITY);
            // Cancellation is recorded per operation. One pending wake covers all of them.
            let (cancellations, cancelled) = async_channel::bounded(1);
            let (finished, done) = async_channel::bounded(1);
            let terminal = Arc::new(Mutex::new(None));
            let inner = Arc::new(Inner {
                commands,
                cancellations,
                done,
                terminal: Arc::clone(&terminal),
                tokens: Arc::clone(&tokens),
                service_name: name.map(str::to_owned),
                timeout,
                profile,
            });
            async_global_executor::spawn(async move {
                let driver = driver::Driver::new(socket, listener, unique_name, local, tokens);
                driver.run(requests, cancelled, terminal).await;
                finished.close();
            })
            .detach();
            Ok(Connection { inner })
        })
        .await
    }
}

impl Connection {
    /// Returns a builder that detects the TV protocol and uses a ten-second timeout.
    #[must_use]
    pub fn builder() -> ConnectionBuilder {
        ConnectionBuilder::default()
    }

    /// Opens an anonymous client connection to the local Luna hub.
    ///
    /// # Errors
    ///
    /// Returns an error if the socket is unavailable or the hub refuses registration.
    pub async fn connect() -> Result<Self, Error> {
        Self::builder().connect().await
    }

    /// Returns the firmware protocol selected for this connection.
    #[must_use]
    pub fn protocol_profile(&self) -> ProtocolProfile {
        self.inner.profile
    }

    /// Returns the registered service name for a named connection.
    pub fn service_name(&self) -> Option<&str> {
        self.inner.service_name.as_deref()
    }

    /// Calls a Luna method and returns the first reply as raw UTF-8 text.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid input, bus or peer rejection, a timeout, or disconnection.
    pub async fn call_raw(&self, uri: &str, payload: &str) -> Result<String, Error> {
        within(self.inner.timeout, "call Luna method", async {
            let (feed, mut cancel) = self.start_call(uri, payload, CallMode::Once).await?;
            let result = feed.first().await;
            cancel.disarm();
            result
        })
        .await
    }

    /// Starts a Luna method subscription and waits for its initial reply.
    ///
    /// The initial reply is yielded first. Include any subscription parameters the method
    /// expects in `payload`. Updates can arrive until cancellation or disconnection.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid input, bus or peer rejection, a timeout, or disconnection.
    pub async fn subscribe_raw(&self, uri: &str, payload: &str) -> Result<Subscription, Error> {
        self.subscribe(uri, payload, Ok).await
    }

    /// Registers a broadcast filter and waits for the hub to acknowledge it.
    ///
    /// The bus can forward multiple copies when category and exact filters overlap.
    ///
    /// # Errors
    ///
    /// Returns an error if the hub rejects the filter, disconnects, or fails to acknowledge it in time.
    pub async fn watch_signal(&self, filter: SignalFilter) -> Result<SignalStream, Error> {
        self.watch(filter, Ok).await
    }

    /// Sends a broadcast signal from this named service.
    ///
    /// The future completes when the frame is written to the hub socket.
    ///
    /// # Errors
    ///
    /// Returns an error if the connection is anonymous or the frame cannot be written.
    pub async fn emit_raw(&self, category: &str, method: &str, payload: &str) -> Result<(), Error> {
        if self.service_name().is_none() {
            return Err(Error::invalid(
                "emitting Luna signals requires a named connection",
            ));
        }
        address::validate_category(category)?;
        address::validate_method(method)?;
        address::validate_payload(payload)?;
        within(self.inner.timeout, "emit Luna signal", async {
            let (ack, written) = async_channel::bounded(1);
            self.submit(Command::Emit {
                category: category.to_owned(),
                method: method.to_owned(),
                payload: payload.to_owned(),
                ack,
            })
            .await?;
            self.inner.wait_ack(&written).await
        })
        .await
    }

    /// Closes this registration and waits for socket and handler cleanup.
    ///
    /// All connection clones and streams use the same registration.
    pub async fn close(&self) {
        self.inner.commands.close();
        let _ = self.inner.done.recv().await;
    }

    async fn submit(&self, command: Command) -> Result<(), Error> {
        self.inner
            .commands
            .send(command)
            .await
            .map_err(|_| self.inner.failure())
    }

    async fn start_call(
        &self,
        uri: &str,
        payload: &str,
        mode: CallMode,
    ) -> Result<(Feed<String>, Cancel), Error> {
        let address = Address::parse(uri)?;
        address::validate_payload(payload)?;
        let id = self.inner.tokens.next()?;
        let (replies, feed) = stream::feed();
        let state = Arc::new(CancelState::default());
        self.submit(Command::Call {
            id,
            address,
            payload: payload.to_owned(),
            replies,
            mode,
            state: Arc::clone(&state),
        })
        .await?;
        Ok((feed, Cancel::new(&self.inner, state)))
    }

    async fn subscribe<T>(
        &self,
        uri: &str,
        payload: &str,
        decode: fn(String) -> Result<T, Error>,
    ) -> Result<Subscription<T>, Error> {
        within(self.inner.timeout, "start Luna subscription", async {
            let (feed, cancel) = self.start_call(uri, payload, CallMode::Repeated).await?;
            let first = feed.first().await?;
            Ok(Subscription::new(feed, first, cancel, decode))
        })
        .await
    }

    async fn watch<T>(
        &self,
        filter: SignalFilter,
        decode: fn(String) -> Result<T, Error>,
    ) -> Result<SignalStream<T>, Error> {
        within(self.inner.timeout, "register Luna signal filter", async {
            let id = self.inner.tokens.next()?;
            let (signals, feed) = stream::feed();
            let (ack, ready) = async_channel::bounded(1);
            let state = Arc::new(CancelState::default());
            self.submit(Command::Watch {
                id,
                filter,
                signals,
                ack,
                state: Arc::clone(&state),
            })
            .await?;
            let cancel = Cancel::new(&self.inner, state);
            self.inner.wait_ack(&ready).await?;
            Ok(SignalStream::new(feed, cancel, decode))
        })
        .await
    }
}

#[cfg(feature = "serde")]
impl Connection {
    /// Serializes a request and deserializes one Luna reply as JSON.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # smol::block_on(async {
    /// let bus = ls2::Connection::connect().await?;
    /// let time: serde_json::Value = bus.call_json(
    ///     "luna://com.palm.systemservice/time/getSystemTime",
    ///     &serde_json::json!({}),
    /// ).await?;
    /// println!("{}", time["utc"]);
    /// # Ok::<(), ls2::Error>(())
    /// # })?;
    /// # Ok::<(), ls2::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// Returns a call error or a JSON conversion failure.
    pub async fn call_json<R: serde::de::DeserializeOwned>(
        &self,
        uri: &str,
        payload: &(impl serde::Serialize + ?Sized),
    ) -> Result<R, Error> {
        let payload = serde_json::to_string(payload).map_err(Error::json)?;
        decode_json(self.call_raw(uri, &payload).await?)
    }

    /// Serializes a subscription request and deserializes each reply as JSON.
    ///
    /// # Errors
    ///
    /// Returns a setup or serialization error. A malformed reply yields a stream item error.
    pub async fn subscribe_json<R: serde::de::DeserializeOwned>(
        &self,
        uri: &str,
        payload: &(impl serde::Serialize + ?Sized),
    ) -> Result<Subscription<R>, Error> {
        let payload = serde_json::to_string(payload).map_err(Error::json)?;
        self.subscribe(uri, &payload, decode_json).await
    }

    /// Registers a broadcast filter and deserializes each received payload as JSON.
    ///
    /// # Errors
    ///
    /// Returns a filter setup error. A malformed payload yields a stream item error.
    pub async fn watch_signal_json<R: serde::de::DeserializeOwned>(
        &self,
        filter: SignalFilter,
    ) -> Result<SignalStream<R>, Error> {
        self.watch(filter, decode_json).await
    }

    /// Serializes a broadcast payload as JSON and sends it to the hub.
    ///
    /// # Errors
    ///
    /// Returns a JSON conversion or signal publication error.
    pub async fn emit_json(
        &self,
        category: &str,
        method: &str,
        payload: &(impl serde::Serialize + ?Sized),
    ) -> Result<(), Error> {
        let payload = serde_json::to_string(payload).map_err(Error::json)?;
        self.emit_raw(category, method, &payload).await
    }
}

#[cfg(feature = "serde")]
fn decode_json<T: serde::de::DeserializeOwned>(raw: String) -> Result<T, Error> {
    serde_json::from_str(&raw).map_err(Error::json)
}

struct Inner {
    commands: Sender<Command>,
    cancellations: Sender<()>,
    done: Receiver<()>,
    terminal: Arc<Mutex<Option<Error>>>,
    tokens: Arc<Tokens>,
    service_name: Option<String>,
    timeout: Duration,
    profile: ProtocolProfile,
}

impl Inner {
    fn failure(&self) -> Error {
        self.terminal
            .lock()
            .expect("connection terminal mutex poisoned")
            .clone()
            .unwrap_or_else(|| Error::disconnected("Luna connection closed"))
    }

    async fn wait_ack(&self, ack: &Receiver<Result<(), Error>>) -> Result<(), Error> {
        ack.recv().await.map_err(|_| self.failure())?
    }
}

pub(crate) struct Cancel {
    inner: Arc<Inner>,
    state: Option<Arc<CancelState>>,
}

impl Cancel {
    fn new(inner: &Arc<Inner>, state: Arc<CancelState>) -> Self {
        Self {
            inner: Arc::clone(inner),
            state: Some(state),
        }
    }

    fn disarm(&mut self) {
        self.state = None;
    }

    pub(crate) async fn wait(mut self) -> Result<(), Error> {
        if let Some(state) = self.state.take() {
            let (ack, written) = async_channel::bounded(1);
            state.request(Some(ack));
            self.wake()?;
            within(
                self.inner.timeout,
                "cancel Luna operation",
                self.inner.wait_ack(&written),
            )
            .await?;
        }
        Ok(())
    }

    fn wake(&self) -> Result<(), Error> {
        match self.inner.cancellations.try_send(()) {
            Ok(()) | Err(async_channel::TrySendError::Full(())) => Ok(()),
            Err(async_channel::TrySendError::Closed(())) => Err(self.inner.failure()),
        }
    }
}

impl Drop for Cancel {
    fn drop(&mut self) {
        if let Some(state) = self.state.take() {
            state.request(None);
            let _ = self.wake();
        }
    }
}

type Ack = Sender<Result<(), Error>>;

#[derive(Default)]
struct CancelState {
    cancelled: AtomicBool,
    completion: Mutex<CancelCompletion>,
}

#[derive(Default)]
struct CancelCompletion {
    done: bool,
    ack: Option<Ack>,
}

impl CancelState {
    fn request(&self, ack: Option<Ack>) {
        let mut completion = self.completion.lock().expect("cancellation mutex poisoned");
        if completion.done {
            if let Some(ack) = ack {
                let _ = ack.try_send(Ok(()));
            }
            return;
        }
        completion.ack = ack;
        self.cancelled.store(true, Ordering::Release);
    }

    fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }

    fn complete(&self) -> Option<Ack> {
        let mut completion = self.completion.lock().expect("cancellation mutex poisoned");
        completion.done = true;
        completion.ack.take()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum CallMode {
    Once,
    Repeated,
}

enum Command {
    Call {
        id: u32,
        address: Address,
        payload: String,
        replies: FeedSender<String>,
        mode: CallMode,
        state: Arc<CancelState>,
    },
    Watch {
        id: u32,
        filter: SignalFilter,
        signals: FeedSender<Signal>,
        ack: Ack,
        state: Arc<CancelState>,
    },
    Emit {
        category: String,
        method: String,
        payload: String,
        ack: Ack,
    },
}

struct Tokens(AtomicU32);

impl Default for Tokens {
    fn default() -> Self {
        Self(AtomicU32::new(1))
    }
}

impl Tokens {
    fn next(&self) -> Result<u32, Error> {
        let mut current = self.0.load(Ordering::Relaxed);
        loop {
            let next = current
                .checked_add(1)
                .ok_or_else(|| Error::protocol("Luna message tokens exhausted"))?;
            match self
                .0
                .compare_exchange_weak(current, next, Ordering::Relaxed, Ordering::Relaxed)
            {
                Ok(id) => return Ok(id),
                Err(observed) => current = observed,
            }
        }
    }
}

fn registration_error(code: i32) -> Error {
    let (kind, message) = match code {
        -1 => (
            ErrorKind::PermissionDenied,
            "Luna service registration denied",
        ),
        -2 => (
            ErrorKind::Rejected,
            "Luna service name is already registered",
        ),
        -3 => (
            ErrorKind::Protocol,
            "Luna hub uses a different protocol version",
        ),
        _ => (ErrorKind::Rejected, "Luna hub refused registration"),
    };
    Error::bus(kind, Some(code), message)
}

async fn read_setup(socket: &Socket) -> Result<wire::Frame, Error> {
    socket
        .recv()
        .await
        .map_err(|error| Error::io("read Luna registration frame", error))
}

async fn write_setup(socket: &Socket, frame: &wire::Frame) -> Result<(), Error> {
    socket
        .send(frame)
        .await
        .map_err(|error| Error::io("write Luna registration frame", error))
}

fn encode_error(error: std::io::Error) -> Error {
    Error::invalid(error.to_string())
}

async fn within<T>(
    timeout: Duration,
    name: &str,
    operation: impl Future<Output = Result<T, Error>>,
) -> Result<T, Error> {
    future::or(operation, async {
        Timer::after(timeout).await;
        Err(Error::new(
            ErrorKind::Timeout,
            format!("timed out while attempting to {name}"),
        ))
    })
    .await
}
