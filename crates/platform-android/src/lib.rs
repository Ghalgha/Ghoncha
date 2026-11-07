//! Android-only JNI bootstrap for platform certificate verification.
//!
//! This crate keeps Android/JVM integration out of the portable transport core.

#[cfg(target_os = "android")]
mod android {
    use std::sync::atomic::{AtomicBool, Ordering};

    use jni::EnvUnowned;
    use jni::errors::ThrowRuntimeExAndDefault;
    use jni::jni_mangle;
    use jni::objects::{JClass, JObject};

    static ANDROID_VERIFIER_INITIALIZED: AtomicBool = AtomicBool::new(false);

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
        let result = unowned_env
            .with_env(|env| rustls_platform_verifier::android::init_with_env(env, context));
        if result.is_ok() {
            ANDROID_VERIFIER_INITIALIZED.store(true, Ordering::Release);
        }
        result.resolve::<ThrowRuntimeExAndDefault>();
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
