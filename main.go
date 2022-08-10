// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/DataDog/datadog-go/v5/statsd"
	"github.com/chris-wood/ohttp-go"
	"github.com/cisco/go-hpke"
	"google.golang.org/protobuf/proto"
)

const (
	// keying material (seed) should have as many bits of entropy as the bit
	// length of the x25519 secret key
	defaultSeedLength = 32

	// HTTP constants. Fill in your proxy and target here.
	defaultPort      = "8080"
	gatewayEndpoint  = "/gateway"
	echoEndpoint     = "/gateway-echo"
	metadataEndpoint = "/gateway-metadata"
	healthEndpoint   = "/health"
	configEndpoint   = "/ohttp-configs"

	// Environment variables
	secretSeedEnvironmentVariable  = "SEED_SECRET_KEY"
	targetOriginAllowList          = "ALLOWED_TARGET_ORIGINS"
	customRequestEncodingType      = "CUSTOM_REQUEST_TYPE"
	customResponseEncodingType     = "CUSTOM_RESPONSE_TYPE"
	certificateEnvironmentVariable = "CERT"
	keyEnvironmentVariable         = "KEY"
	statsdHostVariable             = "MONITORING_STATSD_HOST"
	statsdPortVariable             = "MONITORING_STATSD_PORT"
	statsdTimeoutVariable          = "MONITORING_STATSD_TIMEOUT_MS"
)

type gatewayServer struct {
	requestLabel   string
	responseLabel  string
	endpoints      map[string]string
	target         *gatewayResource
	metricsFactory MetricsFactory
}

type ExtendedContentHandler func(metricsCollectorFactory MetricsFactory, request *http.Request, requestBody []byte, filter TargetFilter) ([]byte, error)

func (s gatewayServer) indexHandler(w http.ResponseWriter, r *http.Request) {
	metrics := s.metricsFactory("index")
	log.Printf("%s Handling %s\n", r.Method, r.URL.Path)
	fmt.Fprint(w, "OHTTP Gateway\n")
	fmt.Fprint(w, "----------------\n")
	fmt.Fprintf(w, "Config endpoint: https://%s%s\n", r.Host, s.endpoints["Config"])
	fmt.Fprintf(w, "Target endpoint: https://%s%s\n", r.Host, s.endpoints["Target"])
	fmt.Fprintf(w, "   Request content type:  %s\n", s.requestLabel)
	fmt.Fprintf(w, "   Response content type: %s\n", s.responseLabel)
	fmt.Fprintf(w, "Echo endpoint: https://%s%s\n", r.Host, s.endpoints["Echo"])
	fmt.Fprint(w, "----------------\n")
	metrics.Fire("success")
}

func (s gatewayServer) healthCheckHandler(w http.ResponseWriter, r *http.Request) {
	metrics := s.metricsFactory("health_check")
	log.Printf("%s Handling %s\n", r.Method, r.URL.Path)
	fmt.Fprint(w, "ok")
	metrics.Fire("success")
}

func echoHandler(_ MetricsFactory, request *http.Request, requestBody []byte, filter TargetFilter) ([]byte, error) {
	return requestBody, nil
}

func metadataHandler(metricsFactory MetricsFactory, request *http.Request, requestBody []byte, filter TargetFilter) ([]byte, error) {
	metrics := metricsFactory("metadata_handler")

	response, err := httputil.DumpRequest(request, true)

	if err != nil {
		metrics.Fire("metadata_dump_request_error")
		return nil, err
	}

	return response, nil
}

func bhttpHandler(metricsCollectorFactory MetricsFactory, request *http.Request, binaryRequest []byte, filter TargetFilter) ([]byte, error) {
	metrics := metricsCollectorFactory("content_bhttp_handler")

	request, err := ohttp.UnmarshalBinaryRequest(binaryRequest)
	if err != nil {
		metrics.Fire("request_unmarshal_error")
		return nil, err
	}

	if !filter(request.Host) {
		metrics.Fire("request_forbidden_error")
		return nil, TargetForbiddenError
	}

	client := &http.Client{}
	targetResponse, err := client.Do(request)
	if err != nil {
		metrics.Fire("request_external_services_error")
		return nil, err
	}

	binaryResponse := ohttp.CreateBinaryResponse(targetResponse)

	response, err := binaryResponse.Marshal()

	if err != nil {
		metrics.Fire("response_marshal_error")
		return nil, err
	}

	metrics.Fire("success")
	return response, nil
}

func protobufHandler(metricsFactory MetricsFactory, request *http.Request, binaryRequest []byte, filter TargetFilter) ([]byte, error) {
	metrics := metricsFactory("content_protobuf_handler")

	req := &Request{}
	if err := proto.Unmarshal(binaryRequest, req); err != nil {
		metrics.Fire("request_unmarshal_error")
		return nil, err
	}

	targetRequest, err := protoHTTPToRequest(req)
	if err != nil {
		metrics.Fire("protobuf_decode_error")
		return nil, err
	}

	if !filter(targetRequest.Host) {
		metrics.Fire("request_forbidden_error")
		return nil, TargetForbiddenError
	}

	client := &http.Client{}
	targetResponse, err := client.Do(targetRequest)
	if err != nil {
		metrics.Fire("request_external_services_error")
		return nil, err
	}

	protoResponse, err := responseToProtoHTTP(targetResponse)
	if err != nil {
		metrics.Fire("protobuf_encode_error")
		return nil, err
	}

	response, err := proto.Marshal(protoResponse)

	if err != nil {
		metrics.Fire("response_marshal_error")
		return nil, err
	}

	metrics.Fire("success")
	return response, nil
}

func customHandler(_ MetricsFactory, request *http.Request, requestBody []byte, filter TargetFilter) ([]byte, error) {
	return nil, fmt.Errorf("Not implemented")
}

func metricsContentHandlerWrapper(metricsFactory MetricsFactory, handler ExtendedContentHandler) ContentHandler {
	return func(request *http.Request, requestBody []byte, filter TargetFilter) ([]byte, error) {
		return handler(metricsFactory, request, requestBody, filter)
	}
}

func getStatsDClient() (statsd.ClientInterface, error) {
	host := os.Getenv(statsdHostVariable)
	port := os.Getenv(statsdPortVariable)

	timeout, err := strconv.ParseInt(os.Getenv(statsdTimeoutVariable), 10, 64)

	if err != nil {
		log.Print("Can't parse timeout -- use the default value (100 ms)")
		timeout = 100
	}

	if host == "" || port == "" {
		return &statsd.NoOpClient{}, nil
	}

	return statsd.New(host+":"+port, statsd.WithWriteTimeout(time.Duration(timeout)*time.Millisecond), statsd.WithoutTelemetry())
}

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = defaultPort
	}

	var seed []byte
	if seedHex := os.Getenv(secretSeedEnvironmentVariable); seedHex != "" {
		log.Printf("Using Secret Key Seed : [%v]", seedHex)
		var err error
		seed, err = hex.DecodeString(seedHex)
		if err != nil {
			panic(err)
		}
	} else {
		seed = make([]byte, defaultSeedLength)
		rand.Read(seed)
	}

	var allowedOrigins map[string]bool
	var originAllowList string
	if originAllowList = os.Getenv(targetOriginAllowList); originAllowList != "" {
		origins := strings.Split(originAllowList, ",")
		allowedOrigins := make(map[string]bool)
		for _, origin := range origins {
			allowedOrigins[origin] = true
		}
	}

	var certFile string
	if certFile = os.Getenv(certificateEnvironmentVariable); certFile == "" {
		certFile = "cert.pem"
	}

	var keyFile string
	enableTLSServe := true
	if keyFile = os.Getenv(keyEnvironmentVariable); keyFile == "" {
		keyFile = "key.pem"
		enableTLSServe = false
	}

	keyID := uint8(0x00)
	config, err := ohttp.NewConfigFromSeed(keyID, hpke.DHKEM_X25519, hpke.KDF_HKDF_SHA256, hpke.AEAD_AESGCM128, seed)
	if err != nil {
		log.Fatalf("Failed to create gateway configuration from seed: %s", err)
	}

	var gateway ohttp.Gateway
	var targetHandler ExtendedContentHandler
	requestLabel := os.Getenv(customRequestEncodingType)
	responseLabel := os.Getenv(customResponseEncodingType)
	if requestLabel == "" || responseLabel == "" || requestLabel == responseLabel {
		gateway = ohttp.NewDefaultGateway(config)
		requestLabel = "message/bhttp request"
		responseLabel = "message/bhttp response"
		targetHandler = bhttpHandler
	} else if requestLabel == "message/protohttp request" && responseLabel == "message/protohttp response" {
		gateway = ohttp.NewCustomGateway(config, requestLabel, responseLabel)
		targetHandler = protobufHandler
	} else {
		gateway = ohttp.NewCustomGateway(config, requestLabel, responseLabel)
		targetHandler = customHandler
	}

	statsd_client, err := getStatsDClient()
	if err != nil {
		log.Fatalf("Failed to create statsd client: %s", err)
	}
	metricsFactory := CreateStatsDMetricsFactory("ohttp_gateway", statsd_client)

	handlers := make(map[string]ContentHandler)
	handlers[gatewayEndpoint] = metricsContentHandlerWrapper(metricsFactory, targetHandler)    // Content-specific handler
	handlers[echoEndpoint] = metricsContentHandlerWrapper(metricsFactory, echoHandler)         // Content-agnostic handler
	handlers[metadataEndpoint] = metricsContentHandlerWrapper(metricsFactory, metadataHandler) // Metadata handler
	target := &gatewayResource{
		verbose:        true,
		keyID:          keyID,
		gateway:        gateway,
		allowedOrigins: allowedOrigins,
		handlers:       handlers,
	}

	endpoints := make(map[string]string)
	endpoints["Target"] = gatewayEndpoint
	endpoints["Health"] = healthEndpoint
	endpoints["Config"] = configEndpoint

	server := gatewayServer{
		requestLabel:   requestLabel,
		responseLabel:  responseLabel,
		endpoints:      endpoints,
		target:         target,
		metricsFactory: metricsFactory,
	}

	http.HandleFunc(gatewayEndpoint, server.target.gatewayHandler)
	http.HandleFunc(echoEndpoint, server.target.gatewayHandler)
	http.HandleFunc(metadataEndpoint, server.target.gatewayHandler)
	http.HandleFunc(healthEndpoint, server.healthCheckHandler)
	http.HandleFunc(configEndpoint, target.configHandler)
	http.HandleFunc("/", server.indexHandler)

	if enableTLSServe {
		log.Printf("Listening on port %v with cert %v and key %v\n", port, certFile, keyFile)
		log.Fatal(http.ListenAndServeTLS(fmt.Sprintf(":%s", port), certFile, keyFile, nil))
	} else {
		log.Printf("Listening on port %v without enabling TLS\n", port)
		log.Fatal(http.ListenAndServe(fmt.Sprintf(":%s", port), nil))
	}

}
