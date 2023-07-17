FROM golang:1.20-bookworm as build

WORKDIR /app

COPY go.* ./
RUN go mod download

COPY . ./

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
      -ldflags='-w -s -extldflags "-static"' -a \
      -o /privacy-gateway-server

FROM gcr.io/distroless/static

COPY --from=build /privacy-gateway-server /privacy-gateway-server

EXPOSE 8080

CMD ["/privacy-gateway-server"]
