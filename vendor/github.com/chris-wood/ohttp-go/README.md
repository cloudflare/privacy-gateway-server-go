# Oblivious HTTP Go Library

[![GoDoc](https://godoc.org/github.com/cloudflare/circl?status.svg)](https://pkg.go.dev/github.com/chris-wood/ohttp-go?tab=overview)
[![Go Report Card](https://goreportcard.com/badge/github.com/cloudflare/circl)](https://goreportcard.com/report/github.com/chris-wood/ohttp-go)

This library contains an implementation of [Oblivious HTTP](https://datatracker.ietf.org/doc/draft-thomson-http-oblivious/) and binary representations of HTTP messages ([RFC9292](https://datatracker.ietf.org/doc/html/rfc9292)). Binary HTTP support is limited to known-length messages. Indeterminate-length messages are not currently supported.

## Security Disclaimer

🚨 This library is offered as-is, and without a guarantee. Therefore, it is expected that changes in the code, repository, and API occur in the future. We recommend to take caution before using this library in a production application since part of its content is experimental.
