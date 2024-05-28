# `embedded-dtls`

> `embedded-dtls` implements a `#![no_std]` server and client for DTLS 1.3, with support for hardware acceleration by cryptographic coprocessors on the client.

## Aims

* `no_std` `async` library with goals of user-friendliness.
* Initially only PSK support, many on server, single on client.

## Current support

* Generic parsing and encoding of DTLS datagrams, ready for extension.
* Pre-shared key with ECDHE X25519 exchange.
* Trait for wrapping cryptographic accelerators.

If you want more support, let's discuss!

## License

All source code (including code snippets) is licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or
  [https://www.apache.org/licenses/LICENSE-2.0][L1])
- MIT license ([LICENSE-MIT](LICENSE-MIT) or
  [https://opensource.org/licenses/MIT][L2])

[L1]: https://www.apache.org/licenses/LICENSE-2.0
[L2]: https://opensource.org/licenses/MIT

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
licensed as above, without any additional terms or conditions.
