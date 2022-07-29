# App Relay Gateway

This project contains a server implementation for an [Oblivious HTTP](https://datatracker.ietf.org/doc/html/draft-ietf-ohai-ohttp-02) gateway in Go. 

# Local development

To deploy the server locally, first acquire a TLS certificate using [mkcert](https://github.com/FiloSottile/mkcert) as follows:

~~~
$ mkcert -key-file key.pem -cert-file cert.pem 127.0.0.1 localhost
~~~

Then build and run the server as follows:

~~~
$ make all
$ CERT=cert.pem KEY=key.pem PORT=4567 ./gateway
~~~

# Deployment

This section describes deployment instructions for the gateway.

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
