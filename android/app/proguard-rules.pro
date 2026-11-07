# rustls-platform-verifier is accessed from Rust through JNI.
# Keep the Kotlin bridge and its descriptors from R8/ProGuard removal.
-keep, includedescriptorclasses class org.rustls.platformverifier.** { *; }
-keep class org.ghoncha.app.NativeBootstrap { *; }
