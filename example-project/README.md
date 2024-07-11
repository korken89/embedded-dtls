# Example project based on e-dtls + postcard-rpc

⚠️ WIP ⚠️

Point of this project is to be a template/example of how to create more than trivial applications that use RPC through the encrypted channel.

This example includes
- `pc-app` bin-crate containing the program running on a `std` platform
- `firmware` bin-crate containing the program running on a `no-std` platform
    - currently, based on a custom STM32F407 board
- `rpc-definition` lib-crate shared between `pc-app` and `firmware` which contains RPC type definitions

In terms of RPC, `pc-app` is a client that sends commands to `firmware` - a server.
In terms of e-dtls, `pc-app` is a server that `firmware` tries to establish a connection to.

## Firmware

To run:
```sh
cd firmware
DEFMT_LOG=<level> cargo run --release
```
TODO: Server IP is hardcoded in a firmware, for now manual adjustement is necessary.

## PC App

To run:
```sh
cd pc-app
RUST_LOG=<level> cargo run --release
```
