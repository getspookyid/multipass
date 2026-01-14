# SpookyID: Multipass

**Official Core Library for SpookyID.**

This library implements the "Multipass" cryptographic protocols, including:
- **BBS+ Signatures** (BLS12-381)
- **Attribute-Based Credentials** (ABC)
- **Leasing & Delegation Logic**
- **Hardware Attestation Verification** (StrongBox / Keymaster)
- **Shamir's Sovereign Recovery**

## Usage

```toml
[dependencies]
smultipass = { git = "https://github.com/getspookyid/smultipass" }
```

## Features

- Pure Rust implementation
- No heavy web/database dependencies
- Suitable for embedded or portable use

## License

MIT / Apache-2.0
