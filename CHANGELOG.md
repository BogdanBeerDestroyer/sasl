# Changelog

All notable changes to this project will be documented in this file.


## Unreleased

### Added

- Support for tls-exporter channel binding method as defined in [RFC 9266].


### Fixed

- Return an error if no tls-unique channel binding (CB) data is present in the
  TLS connection state (or no connection state exists) and we use SCRAM with CB.


[RFC 9266]: https://datatracker.ietf.org/doc/html/rfc9266
