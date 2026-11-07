//! Android-only JNI bootstrap and native socket ownership boundary.
//!
//! This crate keeps Android/JVM integration out of the portable transport core.

#[cfg(target_os = "android")]
mod android {
    use std::collections::HashMap;
    use std::ffi::c_void;
    use std::net::{SocketAddr, UdpSocket};
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::raw::c_int;
    use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
    use std::sync::{Mutex, OnceLock};

    use ghoncha_transport_turn::{DatagramReceive, DatagramSocketError, TurnDatagramSocket};
    use jni::EnvUnowned;
    use jni::errors::ThrowRuntimeExAndDefault;
    use jni::jni_mangle;
    use jni::objects::{JClass, JObject};

    static ANDROID_VERIFIER_INITIALIZED: AtomicBool = AtomicBool::new(false);
    static NEXT_SOCKET_HANDLE: AtomicU32 = AtomicU32::new(1);
    static UDP_SOCKETS: OnceLock<Mutex<HashMap<i64, OwnedFd>>> = OnceLock::new();

    const F_GETFD: c_int = 1;
    const F_SETFD: c_int = 2;
    const FD_CLOEXEC: c_int = 1;
    const F_GETFL: c_int = 3;
    const F_SETFL: c_int = 4;
    const O_NONBLOCK: c_int = 0x800;
    const SOL_SOCKET: c_int = 1;
    const SO_TYPE: c_int = 3;
    const SOCK_DGRAM: c_int = 2;

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct PollFd {
        fd: c_int,
        events: i16,
        revents: i16,
    }

    const POLLIN: i16 = 0x001;
    const POLLOUT: i16 = 0x004;
    const POLLERR: i16 = 0x008;
    const POLLHUP: i16 = 0x010;
    const POLLNVAL: i16 = 0x020;

    unsafe extern "C" {
        fn dup(oldfd: c_int) -> c_int;
        fn fcntl(fd: c_int, cmd: c_int, ...) -> c_int;
        fn poll(fds: *mut PollFd, nfds: usize, timeout_ms: c_int) -> c_int;
        fn getsockopt(
            fd: c_int,
            level: c_int,
            optname: c_int,
            optval: *mut c_void,
            optlen: *mut u32,
        ) -> c_int;
    }

    fn socket_table() -> &'static Mutex<HashMap<i64, OwnedFd>> {
        UDP_SOCKETS.get_or_init(|| Mutex::new(HashMap::new()))
    }

    /// Duplicates and validates an Android UDP socket descriptor.
    ///
    /// The caller retains ownership of the supplied descriptor. Rust owns only
    /// the duplicate and stores it behind an opaque positive handle. The
    /// duplicate shares the kernel socket and file-status flags with the source.
    fn duplicate_udp_socket(source_fd: c_int) -> Option<i64> {
        if source_fd < 0 {
            return None;
        }

        // SAFETY: dup does not take ownership of source_fd and returns a new fd.
        let duplicated_fd = unsafe { dup(source_fd) };
        if duplicated_fd < 0 {
            return None;
        }

        // SAFETY: duplicated_fd is a fresh descriptor returned by dup.
        let owned_fd = unsafe { OwnedFd::from_raw_fd(duplicated_fd) };
        let fd = duplicated_fd;

        // Verify that this is a datagram socket, not a file or stream socket.
        let mut socket_type: c_int = 0;
        let mut option_len = std::mem::size_of::<c_int>() as u32;
        // SAFETY: pointers reference writable values of the advertised lengths.
        let socket_type_result = unsafe {
            getsockopt(
                fd,
                SOL_SOCKET,
                SO_TYPE,
                (&mut socket_type as *mut c_int).cast(),
                &mut option_len,
            )
        };
        if socket_type_result != 0 || socket_type != SOCK_DGRAM {
            return None;
        }

        // Set close-on-exec on the duplicate without changing the source fd's
        // descriptor flags. O_NONBLOCK is a shared open-file-description flag.
        // SAFETY: fcntl is called with valid commands and scalar arguments.
        let descriptor_flags = unsafe { fcntl(fd, F_GETFD) };
        if descriptor_flags < 0
            // SAFETY: descriptor_flags came from F_GETFD above.
            || unsafe { fcntl(fd, F_SETFD, descriptor_flags | FD_CLOEXEC) } < 0
        {
            return None;
        }

        // Ensure the descriptor can be integrated into a poll/epoll reactor.
        // This status flag is shared with the Java duplicate; after adoption the
        // Java socket must not be used for I/O.
        // SAFETY: fcntl is called with valid commands and scalar arguments.
        let status_flags = unsafe { fcntl(fd, F_GETFL) };
        if status_flags < 0
            // SAFETY: status_flags came from F_GETFL above.
            || unsafe { fcntl(fd, F_SETFL, status_flags | O_NONBLOCK) } < 0
        {
            return None;
        }

        let handle = i64::from(NEXT_SOCKET_HANDLE.fetch_add(1, Ordering::Relaxed));
        if handle <= 0 {
            return None;
        }

        let mut sockets = socket_table().lock().ok()?;
        if sockets.contains_key(&handle) {
            return None;
        }
        sockets.insert(handle, owned_fd);
        Some(handle)
    }

    /// Removes a socket from the native registry and transfers ownership to
    /// the Rust reactor. Returns None for unknown or already-consumed handles.
    pub fn take_udp_socket(handle: i64) -> Option<OwnedFd> {
        if handle <= 0 {
            return None;
        }
        socket_table().lock().ok()?.remove(&handle)
    }

    /// A protected Android UDP socket adopted by the Rust TURN driver.
    ///
    /// The underlying descriptor has already been marked non-blocking by the
    /// adoption boundary. The wrapper keeps the native socket alive and maps
    /// OS readiness operations into the portable TURN socket contract.
    pub struct AndroidUdpSocket {
        socket: UdpSocket,
        local_addr: SocketAddr,
    }

    #[derive(Debug)]
    pub enum AndroidSocketAdoptionError {
        UnknownHandle,
        LocalAddressUnavailable,
        NonblockingConfigurationFailed,
    }

    /// Consumes a JNI registry handle and wraps its OwnedFd as a TURN UDP socket.
    ///
    /// After this call succeeds, the JNI handle no longer exists and Kotlin must
    /// not attempt to close it. Dropping this wrapper closes the native socket.
    pub fn take_android_udp_socket(
        handle: i64,
    ) -> Result<AndroidUdpSocket, AndroidSocketAdoptionError> {
        let owned_fd = take_udp_socket(handle).ok_or(AndroidSocketAdoptionError::UnknownHandle)?;
        let socket = UdpSocket::from(owned_fd);
        socket
            .set_nonblocking(true)
            .map_err(|_| AndroidSocketAdoptionError::NonblockingConfigurationFailed)?;
        let local_addr = socket
            .local_addr()
            .map_err(|_| AndroidSocketAdoptionError::LocalAddressUnavailable)?;
        Ok(AndroidUdpSocket { socket, local_addr })
    }

    /// A non-blocking protected UDP socket adopted by the Rust TURN driver.
    pub struct AndroidUdpSocket {
        socket: UdpSocket,
        local_addr: SocketAddr,
    }

    impl AndroidUdpSocket {
        /// Returns the raw descriptor for readiness registration only.
        /// The caller must not read, write, close, or take ownership of it.
        pub fn raw_fd(&self) -> c_int {
            self.socket.as_raw_fd()
        }
    }

    /// One readiness result from the bounded poller.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct AndroidPollEvent {
        pub token: u64,
        pub readable: bool,
        pub writable: bool,
        pub error: bool,
        pub hangup: bool,
        pub invalid: bool,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct PollRegistration {
        token: u64,
        fd: c_int,
        events: i16,
    }

    /// Errors from registering or polling Android UDP sockets.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub enum AndroidPollerError {
        InvalidToken,
        NoReadinessInterest,
        CapacityReached,
        DuplicateToken,
        UnknownToken,
        SystemError(i32),
    }

    /// Fixed-capacity level-triggered poll reactor for protected UDP sockets.
    ///
    /// The caller owns TURN protocol drivers and timers. It computes the poll
    /// timeout from the earliest TURN deadline, calls wait, then services the
    /// matching TurnUdpDriver with the returned readiness. Registration tokens,
    /// rather than raw fd numbers, identify drivers so stale fd reuse cannot
    /// silently target a different driver.
    pub struct AndroidUdpPoller<const CAPACITY: usize> {
        registrations: [Option<PollRegistration>; CAPACITY],
    }

    impl<const CAPACITY: usize> AndroidUdpPoller<CAPACITY> {
        pub fn new() -> Self {
            Self {
                registrations: [None; CAPACITY],
            }
        }

        pub fn register(
            &mut self,
            token: u64,
            socket: &AndroidUdpSocket,
            readable: bool,
            writable: bool,
        ) -> Result<(), AndroidPollerError> {
            if token == 0 {
                return Err(AndroidPollerError::InvalidToken);
            }
            if !readable && !writable {
                return Err(AndroidPollerError::NoReadinessInterest);
            }
            if self
                .registrations
                .iter()
                .flatten()
                .any(|entry| entry.token == token)
            {
                return Err(AndroidPollerError::DuplicateToken);
            }
            let slot = self
                .registrations
                .iter_mut()
                .find(|entry| entry.is_none())
                .ok_or(AndroidPollerError::CapacityReached)?;
            *slot = Some(PollRegistration {
                token,
                fd: socket.raw_fd(),
                events: readiness_flags(readable, writable),
            });
            Ok(())
        }

        pub fn update(
            &mut self,
            token: u64,
            readable: bool,
            writable: bool,
        ) -> Result<(), AndroidPollerError> {
            if !readable && !writable {
                return Err(AndroidPollerError::NoReadinessInterest);
            }
            let registration = self
                .registrations
                .iter_mut()
                .flatten()
                .find(|entry| entry.token == token)
                .ok_or(AndroidPollerError::UnknownToken)?;
            registration.events = readiness_flags(readable, writable);
            Ok(())
        }

        /// Unregisters before the socket is dropped or its fd can be reused.
        pub fn unregister(&mut self, token: u64) -> Result<(), AndroidPollerError> {
            let registration = self
                .registrations
                .iter_mut()
                .find(|entry| entry.is_some_and(|entry| entry.token == token))
                .ok_or(AndroidPollerError::UnknownToken)?;
            *registration = None;
            Ok(())
        }

        /// Waits for readiness and writes at most output.len() events.
        ///
        /// Poll is level-triggered: if output storage is smaller than the
        /// number of ready descriptors, unreported descriptors remain ready
        /// and will be returned by the next call. Interrupted waits return
        /// zero events so the caller can re-evaluate protocol deadlines.
        pub fn wait(
            &self,
            timeout: std::time::Duration,
            output: &mut [AndroidPollEvent],
        ) -> Result<usize, AndroidPollerError> {
            let mut descriptors = [PollFd {
                fd: -1,
                events: 0,
                revents: 0,
            }; CAPACITY];
            let mut tokens = [0_u64; CAPACITY];
            let mut count = 0;

            for registration in self.registrations.iter().flatten() {
                descriptors[count] = PollFd {
                    fd: registration.fd,
                    events: registration.events,
                    revents: 0,
                };
                tokens[count] = registration.token;
                count += 1;
            }

            let timeout_ms = timeout.as_millis().min(c_int::MAX as u128) as c_int;
            // SAFETY: descriptors contains count initialized pollfd entries;
            // the kernel writes only their revents fields.
            let result = unsafe { poll(descriptors.as_mut_ptr(), count, timeout_ms) };
            if result < 0 {
                let error = std::io::Error::last_os_error();
                if error.kind() == std::io::ErrorKind::Interrupted {
                    return Ok(0);
                }
                return Err(AndroidPollerError::SystemError(
                    error.raw_os_error().unwrap_or(-1),
                ));
            }

            let mut written = 0;
            for index in 0..count {
                let flags = descriptors[index].revents;
                if flags == 0 || written == output.len() {
                    continue;
                }
                output[written] = AndroidPollEvent {
                    token: tokens[index],
                    readable: flags & POLLIN != 0,
                    writable: flags & POLLOUT != 0,
                    error: flags & POLLERR != 0,
                    hangup: flags & POLLHUP != 0,
                    invalid: flags & POLLNVAL != 0,
                };
                written += 1;
            }
            Ok(written)
        }
    }

    impl<const CAPACITY: usize> Default for AndroidUdpPoller<CAPACITY> {
        fn default() -> Self {
            Self::new()
        }
    }

    fn readiness_flags(readable: bool, writable: bool) -> i16 {
        (if readable { POLLIN } else { 0 }) | (if writable { POLLOUT } else { 0 })
    }

    impl TurnDatagramSocket for AndroidUdpSocket {
        fn local_addr(&self) -> SocketAddr {
            self.local_addr
        }

        fn send_to(
            &mut self,
            destination: SocketAddr,
            datagram: &[u8],
        ) -> Result<usize, DatagramSocketError> {
            self.socket.send_to(datagram, destination).map_err(|error| {
                if error.kind() == std::io::ErrorKind::WouldBlock {
                    DatagramSocketError::WouldBlock
                } else {
                    DatagramSocketError::Failed
                }
            })
        }

        fn recv_from(&mut self, buffer: &mut [u8]) -> Result<DatagramReceive, DatagramSocketError> {
            self.socket
                .recv_from(buffer)
                .map(|(len, from)| DatagramReceive {
                    len,
                    from,
                    // std::net does not expose MSG_TRUNC. Treat a full buffer
                    // conservatively rather than parsing a possibly truncated
                    // TURN datagram as complete.
                    truncated: len == buffer.len(),
                })
                .map_err(|error| {
                    if error.kind() == std::io::ErrorKind::WouldBlock {
                        DatagramSocketError::WouldBlock
                    } else {
                        DatagramSocketError::Failed
                    }
                })
        }
    }

    /// Closes a socket handle that has not been transferred to the reactor.
    fn close_udp_socket(handle: i64) -> bool {
        take_udp_socket(handle).is_some()
    }

    /// Initializes the Android system-trust verifier before any TLS connection starts.
    ///
    /// The verifier stores process-lifetime references to the Android runtime. Any
    /// initialization error is surfaced as a Java RuntimeException; callers must not
    /// continue with TLS or fall back to an unverified certificate configuration.
    #[jni_mangle("org.ghoncha.app.NativeBootstrap")]
    pub fn initialize<'caller>(
        mut unowned_env: EnvUnowned<'caller>,
        _class: JClass<'caller>,
        context: JObject<'caller>,
    ) {
        let outcome = unowned_env.with_env(|env| -> jni::errors::Result<()> {
            rustls_platform_verifier::android::init_with_env(env, context)?;
            ANDROID_VERIFIER_INITIALIZED.store(true, Ordering::Release);
            Ok(())
        });
        outcome.resolve::<ThrowRuntimeExAndDefault>();
    }

    /// Duplicates a ParcelFileDescriptor fd and returns an opaque native handle.
    ///
    /// Returns zero on validation or allocation failure. The Java-owned fd must
    /// still be closed by the caller regardless of the result.
    #[jni_mangle("org.ghoncha.app.NativeBootstrap")]
    #[allow(non_snake_case)]
    pub fn adoptUdpSocket(_unowned_env: EnvUnowned<'_>, _class: JClass<'_>, source_fd: i32) -> i64 {
        duplicate_udp_socket(source_fd)
            .filter(|handle| *handle > 0)
            .unwrap_or(0)
    }

    /// Closes a native UDP handle that has not been transferred to a reactor.
    #[jni_mangle("org.ghoncha.app.NativeBootstrap")]
    #[allow(non_snake_case)]
    pub fn closeUdpSocket(_unowned_env: EnvUnowned<'_>, _class: JClass<'_>, handle: i64) -> bool {
        close_udp_socket(handle)
    }

    /// Builds a Rustls client configuration backed by Android's system trust manager.
    ///
    /// Must only be called after initialization completed successfully. The returned
    /// configuration uses the selected Rustls crypto provider and never enables 0-RTT.
    pub fn platform_tls_client_config() -> Result<rustls::ClientConfig, rustls::Error> {
        if !ANDROID_VERIFIER_INITIALIZED.load(Ordering::Acquire) {
            return Err(rustls::Error::General(
                "Android platform verifier is not initialized".to_owned(),
            ));
        }

        use rustls_platform_verifier::ConfigVerifierExt;

        let mut config = rustls::ClientConfig::with_platform_verifier()?;
        config.enable_early_data = false;
        Ok(config)
    }
}

#[cfg(target_os = "android")]
pub use android::{
    AndroidPollEvent, AndroidPollerError, AndroidSocketAdoptionError, AndroidUdpPoller,
    AndroidUdpSocket, platform_tls_client_config, take_android_udp_socket, take_udp_socket,
};
