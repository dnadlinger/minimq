# Changelog

This document describes the changes to Minimq between releases.

# Unrelease
* Client ID may now be unspecified to allow the broker to automatically assign an ID.
* Strict client ID check removed to allow broker-validated IDs.
* Updated `generic-array` dependencies to address security vulnerability.
* Implemented keep-alive ping requests (and connection termination on lack of response).
* Broker connection attempts are now rate-limited to 1 per second.

# Version 0.2.0
Version 0.2.0 was published on 2021-02-15

* Updating the `MqttClient::poll()` function to take a `FnMut` closure to allow internal state
  mutation.
* Use the `std-embedded-nal` crate as a dependency to provide a standard `NetworkStack` for
  integration tests.
* Updating `read()` to not block when no data is available. Updating `write()` to progate network
  stack errors out to the user.
* Updating library to re-export `generic-array` publicly.

## Version 0.1.0
Version 0.1.0 was published on 2020-08-27

* Initial library release and publish to crates.io
