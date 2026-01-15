# Multipass Android Build Guide

This guide explains how to compile the `multipass` Rust library for Android and generate the required Kotlin bindings.

## Prerequisites

1.  **Rust & Cargo**: Installed via [rustup](https://rustup.rs/).
2.  **Android NDK**: Installed (usually via Android Studio SDK Manager).
3.  **cargo-ndk**: Install with `cargo install cargo-ndk`.

## 1. Setup Build Targets

Add the Android architectures you want to support (typically ARM64 and ARMv7):

```bash
rustup target add aarch64-linux-android
rustup target add armeabi-v7a
rustup target add x86_64-linux-android  # For Emulator
```

## 2. Compile Shared Libraries (.so)

Use `cargo-ndk` to build the libraries and output them to a standard Android folders structure (`jniLibs`).

```bash
# Verify you are in the multipass directory
cd multipass

# Build for all targets and strip symbols for size
cargo ndk -t aarch64-linux-android -t armeabi-v7a -t x86_64-linux-android -o ./android/jniLibs build --release
```

**Output**: You will see a directory `android/jniLibs/` containing subfolders like `arm64-v8a/libmultipass.so`.

## 3. Generate Kotlin Bindings

We use the `uniffi-bindgen` tool (included in dependencies) to generate the Kotlin code that talks to the Rust library.

```bash
# Generate bindings using the library we just built
cargo run --features=uniffi/cli --bin uniffi-bindgen -- generate --library ./target/aarch64-linux-android/release/libmultipass.so --language kotlin --out-dir ./android/java
```

**Output**: You will see `android/java/com/getspookyid/multipass/multipass.kt`.

## 4. Import into Android Studio

1.  **Copy Native Libs**:
    Copy the contents of `multipass/android/jniLibs/` into your Android Studio project at `app/src/main/jniLibs/`.

2.  **Copy Kotlin Code**:
    Copy `multipass/android/java/com/getspookyid/multipass/multipass.kt` to `app/src/main/java/com/getspookyid/multipass/multipass.kt`.

3.  **Update `build.gradle` (Module: app)**:
    Ensure you have the JNA (Java Native Access) dependency, which UniFFI uses:

    ```groovy
    dependencies {
        implementation "net.jna:jna:5.13.0@aar"
        // ... other dependencies
    }
    ```

## 5. Usage Example (Kotlin)

```kotlin
import com.getspookyid.multipass.*

// 1. Generate a Keypair
val secretKey = generateSecretKey() // You'll need to implement this or use helper
val publicKey = getPublicKey(secretKey)

// 2. Sign Messages
val messages = listOf("Message1".toByteArray(), "Message2".toByteArray())
try {
    val signature = sign(secretKey, publicKey, messages)
    println("Signature generated: ${signature.toHex()}")
} catch (e: Exception) {
    println("Error: ${e.message}")
}
```
