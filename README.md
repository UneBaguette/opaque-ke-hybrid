# opaque-ke-hybrid

A **post-quantum** hybrid extension for [`opaque-ke`](https://crates.io/crates/opaque-ke), adding **ML-KEM-768** to the **AKE** layer via **HKDF** combination.

## What it does

Runs **ML-KEM-768** in parallel with **OPAQUE**'s TripleDH key exchange, combining both shared secrets via **HKDF-SHA512**:

`session_key = HKDF-SHA512(opaque_ss || mlkem_ss, "opaque-ke-hybrid-v1")`

This provides classical security from **OPAQUE** and **post-quantum** hardening from **ML-KEM**. So, if **either** is compromised, the other still holds.

## Security Warning

- `opaque-ke` was **audited** by NCC Group (2021, sponsored by WhatsApp).
- `ml-kem` is **unaudited**. Check out their [security warning](https://crates.io/crates/ml-kem).
- This crate itself is **unaudited**.

## Usage

```rust
// Client start
let client_start = HybridClientLogin::<MySuite>::start(&mut rng, password)?;
let opaque_bytes = client_start.opaque_message.serialize().to_vec();
let request = HybridCredentialRequest::new(opaque_bytes, *client_start.message.mlkem_ek());

// Server start
let server_start = HybridServerLogin::<MySuite>::start(
    &mut rng, &server_setup, Some(password_file),
    opaque_request, request.mlkem_ek(), username,
    ServerLoginParameters::default(),
)?;

// Client finish
let client_finish = client_start.state.finish(
    &mut rng, password, opaque_response,
    response.mlkem_ct(),
    ClientLoginFinishParameters::default(),
)?;

// Server finish
let server_finish = server_start.state.finish(
    opaque_finalization,
    ServerLoginParameters::default(),
)?;

assert_eq!(client_finish.session_key.as_ref(), server_finish.session_key.as_ref());
```

## Limitations

This crate wraps **opaque-ke 4.0.x** by combining the **OPAQUE** session
key with an **ML-KEM-768** shared secret via **HKDF-SHA512** after the
fact. This is a parallel hybrid. 

**ML-KEM** material is not mixed into
the **OPAQUE** transcript or key derivation directly.

`opaque-ke 4.1` will ship `TripleDhKem`, which integrates **ML-KEM**
as a fourth input alongside the three **Diffie-Hellman** secrets in the
core key derivation, with the **KEM** ciphertext absorbed into the
protocol transcript. This provides stronger security guarantees than
this crate's external approach.

**This crate is a practical bridge for `opaque-ke 4.0.x` users who
need post-quantum hardening today.** For new projects, wait for
`opaque-ke 4.1` and use `TripleDhKem` directly.

## License

This implementation is dual-licensed under the [MIT License](LICENSE-MIT) and the [Apache-2.0 License](LICENSE-APACHE).