//! Android-only JNI bootstrap for platform certificate verification.
//!
//! This crate keeps Android/JVM integration out of the portable transport core.

#[cfg(target_os = "android")]
mod android {
    use jni::errors::ThrowRuntimeExAndDefault;
    use jni::jni_mangle;
    use jni::objects::{JClass, JObject};
    use jni::EnvUnowned;

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
        unowned_env
            .with_env(|env| rustls_platform_verifier::android::init_with_env(env, context))
            .resolve::<ThrowRuntimeExAndDefault>();
    }
}
