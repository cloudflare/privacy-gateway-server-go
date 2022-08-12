// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/chris-wood/ohttp-go"
	"github.com/cisco/go-hpke"
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
)

type gatewayServer struct {
	requestLabel  string
	responseLabel string
	endpoints     map[string]string
	target        *gatewayResource
}

func (s gatewayServer) indexHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("%s Handling %s\n", r.Method, r.URL.Path)
	fmt.Fprint(w, "OHTTP Gateway\n")
	fmt.Fprint(w, "----------------\n")
	fmt.Fprintf(w, "Config endpoint: https://%s%s\n", r.Host, s.endpoints["Config"])
	fmt.Fprintf(w, "Target endpoint: https://%s%s\n", r.Host, s.endpoints["Target"])
	fmt.Fprintf(w, "   Request content type:  %s\n", s.requestLabel)
	fmt.Fprintf(w, "   Response content type: %s\n", s.responseLabel)
	fmt.Fprintf(w, "Echo endpoint: https://%s%s\n", r.Host, s.endpoints["Echo"])
	fmt.Fprintf(w, "Metadata endpoint: https://%s%s\n", r.Host, s.endpoints["Metadata"])
	fmt.Fprint(w, "----------------\n")
}

func (s gatewayServer) healthCheckHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("%s Handling %s\n", r.Method, r.URL.Path)
	fmt.Fprint(w, "ok")
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

	keyID := uint8(0x00) // XXX(caw): make this an environment variable, too, or derive it from the seed
	config, err := ohttp.NewConfigFromSeed(keyID, hpke.DHKEM_X25519, hpke.KDF_HKDF_SHA256, hpke.AEAD_AESGCM128, seed)
	if err != nil {
		log.Fatalf("Failed to create gateway configuration from seed: %s", err)
	}

	// Create the default HTTP handler
	httpHandler := FilteredHttpRequestHandler{
		client:         &http.Client{},
		allowedOrigins: allowedOrigins,
	}

	// Create the default gateway and its request handler chain
	var gateway ohttp.Gateway
	var targetHandler EncapsulationHandler
	requestLabel := os.Getenv(customRequestEncodingType)
	responseLabel := os.Getenv(customResponseEncodingType)
	if requestLabel == "" || responseLabel == "" || requestLabel == responseLabel {
		gateway = ohttp.NewDefaultGateway(config)
		requestLabel = "message/bhttp request"
		responseLabel = "message/bhttp response"
		targetHandler = DefaultEncapsulationHandler{
			keyID:   keyID,
			gateway: gateway,
			appHandler: BinaryHTTPAppHandler{
				httpHandler: httpHandler,
			},
		}
	} else if requestLabel == "message/protohttp request" && responseLabel == "message/protohttp response" {
		gateway = ohttp.NewCustomGateway(config, requestLabel, responseLabel)
		targetHandler = DefaultEncapsulationHandler{
			keyID:   keyID,
			gateway: gateway,
			appHandler: ProtoHTTPEncapsulationHandler{
				httpHandler: httpHandler,
			},
		}
	} else {
		panic("Unsupported application content handler")
	}

	// Create the echo handler chain
	echoHandler := DefaultEncapsulationHandler{
		keyID:      keyID,
		gateway:    gateway,
		appHandler: EchoAppHandler{},
	}

	// Create the metadata handler chain
	metadataHandler := MetadataEncapsulationHandler{
		keyID:   keyID,
		gateway: gateway,
	}

	handlers := make(map[string]EncapsulationHandler)
	handlers[gatewayEndpoint] = targetHandler    // Content-specific handler
	handlers[echoEndpoint] = echoHandler         // Content-agnostic handler
	handlers[metadataEndpoint] = metadataHandler // Metadata handler
	target := &gatewayResource{
		verbose:               true,
		keyID:                 keyID,
		gateway:               gateway,
		encapsulationHandlers: handlers,
	}

	endpoints := make(map[string]string)
	endpoints["Target"] = gatewayEndpoint
	endpoints["Health"] = healthEndpoint
	endpoints["Config"] = configEndpoint
	endpoints["Echo"] = echoEndpoint
	endpoints["Metadata"] = metadataEndpoint

	server := gatewayServer{
		requestLabel:  requestLabel,
		responseLabel: responseLabel,
		endpoints:     endpoints,
		target:        target,
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
