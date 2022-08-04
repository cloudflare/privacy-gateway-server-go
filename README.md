# App Relay Gateway

This project contains a gateway implementation for an [Oblivious HTTP](https://datatracker.ietf.org/doc/html/draft-ietf-ohai-ohttp-02) (OHTTP) gateway in Go. 

# Overview

This gateway implements a simple version of the Oblivious Gateway Resource as described in [the specification](https://datatracker.ietf.org/doc/html/draft-ietf-ohai-ohttp-02). In particular, it accepts encapsulated [Binary HTTP](https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-binary-message) requests and then uses the corresponding HTTP requests to fetch a Target resource. The response from this Target is encapsulated back to the original client of the encapsulated request.

By default, the gateway exposes the following API endpoints:

- "/gateway": An endpoint that will accept OHTTP requests, fetch the corresponding target resource, and return an OHTTP response.
- "/gateway-echo": An endpoint that will echo the contents of the encapsulated OHTTP request back in an OHTTP response.
- "/ohttp-configs": An endpoint that will provide an [encoded KeyConfig](https://datatracker.ietf.org/doc/html/draft-ietf-ohai-ohttp-02#section-3.1).
- "/health": An endpoint for inspecting the health of the gateway (returns 200 in normal conditions).

# Custom Configuration

The gateway can be configured to service [Binary HTTP](https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-binary-message) messages or custom application payloads. To use custom applciation payloads, you must specify the type of application request and response encodings using the CUSTOM_REQUEST_TYPE and CUSTOM_RESPONSE_TYPE environment variables. For example, if you were using [protobuf](https://developers.google.com/protocol-buffers) as the application data encoding, you might set CUSTOM_REQUEST_TYPE="message/protobuf req" and CUSTOM_RESPONSE_TYPE="message/protobuf rep". See [the OHTTP](https://github.com/chris-wood/ohttp-go) library and [OHTTP standard](https://datatracker.ietf.org/doc/html/draft-ietf-ohai-ohttp-02#section-10) for additional information about choosing custom content types.

When specifying a custom application format, it also makes sense to specify a new handler for the format. This can be done as follows:

1. Add a new `ContentType` handler that implements the logic for producing an application response for your application request. As an example, if the custom content type corresponded to DNS messages, the handler might resolve the DNS query and produce an encoded DNS response.
2. Wire up the handler to the gateway HTTP request router based on a new path. As an example, if the custom content type corresponded to DNS messages, the new path might be "/gateway-dns".

That's it!

# Deployment

This section describes deployment instructions for the gateway.

## Local development

To deploy the server locally, first acquire a TLS certificate using [mkcert](https://github.com/FiloSottile/mkcert) as follows:

~~~
$ mkcert -key-file key.pem -cert-file cert.pem 127.0.0.1 localhost
~~~

Then build and run the server as follows:

~~~
$ make all
$ CERT=cert.pem KEY=key.pem PORT=4567 ./gateway
~~~

## Preconfigured deployments

[![Deploy](https://www.herokucdn.com/deploy/button.svg)](https://heroku.com/deploy)
[![deploy to Scalingo](https://cdn.scalingo.com/deploy/button.svg)](https://my.scalingo.com/deploy)

## Manual deployment

This server can also be manually deployed on any bare metal machine, or in cloud providers such
as GCP. Instructions for both follow.

### Bare metal

Deployment on bare metal servers, such as [Equinix](https://metal.equinix.com/), can be done following
the instructions below. These steps assume that `git` and `go` are both installed on the metal.

1. Configure a certificate on the metal using [certbot](https://certbot.eff.org/all-instructions).
Once complete, the output should be something like the following, assuming the server domain name
is "example.com":

```
Successfully received certificate.
Certificate is saved at: /etc/letsencrypt/live/example.com/fullchain.pem
Key is saved at:         /etc/letsencrypt/live/example.com/privkey.pem
```

You must configure certbot to renew this certificate periodically. The simplest way to do this is
via a cron job:

```
$ 00 00 1 * 1 certbot renew
```

2. Configure two environment variables to reference these files:

```
$ export CERT=/etc/letsencrypt/live/example.com/fullchain.pem
$ export KEY=/etc/letsencrypt/live/example.com/privkey.pem
```

3. Clone and build the server:

```
$ git clone git@github.com:cloudflare/app-relay-gateway-go.git
$ cd app-relay-gateway-go
$ go build ./...
```

4. Run the server:

```
$ PORT=443 ./gateway &
```

This will run the server until completion. You must configure the server to restart should it
terminate prematurely.

### GCP

To deploy, run:

~~~
$ gcloud app deploy
~~~

To check on its status, run:

~~~
$ gcloud app browse
~~~

To stream logs when deployed, run

~~~
$ gcloud app logs tail -s default
~~~
