import org.gradle.api.provider.ValueSource
import org.gradle.api.provider.ValueSourceParameters
import org.gradle.api.file.RegularFileProperty

plugins {
    id("com.android.application")
}

abstract class RustlsAndroidArtifactVersion :
    ValueSource<String, RustlsAndroidArtifactVersion.Parameters> {
    interface Parameters : ValueSourceParameters {
        val cargoLock: RegularFileProperty
    }

    override fun obtain(): String {
        val crateName = "rustls-platform-verifier-android"
        val lines = parameters.cargoLock.get().asFile.readLines()
        val nameIndex = lines.indexOfFirst { it.trim() == "name = \"$crateName\"" }
        val version = if (nameIndex < 0) {
            null
        } else {
            lines.drop(nameIndex + 1)
                .firstOrNull { it.trimStart().startsWith("version = ") }
                ?.substringAfter('"', "")
                ?.substringBefore('"', "")
                ?.takeIf { it.isNotEmpty() }
        }
        return version ?: error("$crateName is missing from Cargo.lock")
    }
}

val rustlsAndroidArtifactVersion = providers.of(RustlsAndroidArtifactVersion::class.java) {
    parameters.cargoLock.set(layout.projectDirectory.file("../../Cargo.lock"))
}

configurations.configureEach {
    resolutionStrategy.eachDependency {
        if (
            requested.name == "rustls-platform-verifier" &&
            requested.group in setOf("rustls", "org.rustls")
        ) {
            useVersion(rustlsAndroidArtifactVersion.get())
            because("Android verifier AAR must match the Cargo-locked native shim version")
        }
    }
}

android {
    namespace = "org.ghoncha.app"
    compileSdk = 36

    defaultConfig {
        applicationId = "org.ghoncha.app"
        minSdk = 26
        targetSdk = 36
        versionCode = 1
        versionName = "0.1.0"
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro",
            )
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    sourceSets.getByName("main").jniLibs.srcDir("build/generated/rustJniLibs")
}

dependencies {
    implementation("org.rustls:rustls-platform-verifier")
}

val rustWorkspaceDir = rootProject.projectDir.parentFile
val rustJniLibsDir = layout.buildDirectory.dir("generated/rustJniLibs")

val cargoMetadata = tasks.register<Exec>("cargoMetadata") {
    workingDir = rustWorkspaceDir
    commandLine("cargo", "metadata", "--format-version", "1")
}

val installRustAndroidTargets = tasks.register<Exec>("installRustAndroidTargets") {
    workingDir = rustWorkspaceDir
    commandLine(
        "rustup",
        "target",
        "add",
        "aarch64-linux-android",
        "armv7-linux-androideabi",
        "x86_64-linux-android",
        "i686-linux-android",
    )
}

val buildRustAndroid = tasks.register<Exec>("buildRustAndroid") {
    dependsOn(cargoMetadata, installRustAndroidTargets)
    workingDir = rustWorkspaceDir
    commandLine(
        "cargo",
        "ndk",
        "-P",
        "26",
        "-t",
        "arm64-v8a",
        "-t",
        "armeabi-v7a",
        "-t",
        "x86_64",
        "-t",
        "x86",
        "-o",
        rustJniLibsDir.get().asFile.absolutePath,
        "build",
        "--release",
        "--locked",
        "--package",
        "ghoncha-platform-android",
    )
}

tasks.named("preBuild") {
    dependsOn(buildRustAndroid)
}
