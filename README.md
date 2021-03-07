[![QUARTIQ Matrix Chat](https://img.shields.io/matrix/quartiq:matrix.org)](https://matrix.to/#/#quartiq:matrix.org)

# MiniMQ

A minimal `no_std` MQTT v5.0 client implementation.

MiniMQ provides a `no_std` client for interfacing with MQTT v5.0 brokers.

## Usage

There is an example targeting the Nucleo-H743zi2 board that can be used as a reference design.

There is also an example on a standard computer in `tests/integration_test.rs`

## Not yet implemented features.

- Support all QoS levels
- Support maintained session states
- Allow batch subscriptions to multiple topics
