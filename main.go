// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"runtime/debug"
	"strconv"
	"strings"

	"github.com/chris-wood/ohttp-go"
	"github.com/cloudflare/circl/hpke"
)

const (
	// keying material (seed) should have as many bits of entropy as the bit
	// length of the x25519 secret key
	defaultSeedLength = 32

	// HTTP constants. Fill in your proxy and target here.
	defaultPort                 = "8080"
	defaultGatewayEndpoint      = "/gateway"
	defaultConfigEndpoint       = "/ohttp-keys"
	defaultLegacyConfigEndpoint = "/ohttp-configs"
	defaultEchoEndpoint         = "/gateway-echo"
	defaultMetadataEndpoint     = "/gateway-metadata"
	defaultHealthEndpoint       = "/health"

	// service name to be reported as a label to monitoring subsystem
	defaultMonitoringServiceName = "ohttp_gateway"

	// Environment variables
	gatewayEndpointEnvVariable               = "GATEWAY_ENDPOINT"
	configEndpointEnvVariable                = "CONFIG_ENDPOINT"
	legacyConfigEndpointEnvVariable          = "LEGACY_CONFIG_ENDPOINT"
	echoEndpointEnvVariable                  = "ECHO_ENDPOINT"
	metadataEndpointEnvVariable              = "METADATA_ENDPOINT"
	healthEndpointEnvVariable                = "HEALTH_ENDPOINT"
	configurationIdEnvironmentVariable       = "CONFIGURATION_ID"
	secretSeedEnvironmentVariable            = "SEED_SECRET_KEY"
	targetOriginAllowList                    = "ALLOWED_TARGET_ORIGINS"
	customRequestEncodingType                = "CUSTOM_REQUEST_TYPE"
	customResponseEncodingType               = "CUSTOM_RESPONSE_TYPE"
	certificateEnvironmentVariable           = "CERT"
	keyEnvironmentVariable                   = "KEY"
	statsdHostVariable                       = "MONITORING_STATSD_HOST"
	statsdPortVariable                       = "MONITORING_STATSD_PORT"
	statsdTimeoutVariable                    = "MONITORING_STATSD_TIMEOUT_MS"
	monitoringServiceNameEnvironmentVariable = "MONITORING_SERVICE_NAME"
	gatewayDebugEnvironmentVariable          = "GATEWAY_DEBUG"
	logSecretsEnvironmentVariable            = "LOG_SECRETS"
	logLevelEnvironmentVariable              = "LOG_LEVEL"
	logFormatEnvironmentVariable             = "LOG_FORMAT"
	targetRewritesVariables                  = "TARGET_REWRITES"
	prometheusConfigVariable                 = "PROMETHEUS_CONFIG"
	configKeyRotationInterval                = "KEY_ROTATION_INTERVAL"

	// Values for LOG_FORMAT environment variable
	logFormatDefault = "default"
	logFormatJSON    = "json"
)

var versionFlag = flag.Bool("version", false, "print name and version to stdout")

type gatewayServer struct {
	requestLabel   string
	responseLabel  string
	endpoints      map[string]string
	target         *gatewayResource
	metricsFactory MetricsFactory
}

func (s gatewayServer) formatConfiguration(w io.Writer) {
	fmt.Fprint(w, "OHTTP Gateway\n")
	fmt.Fprint(w, "----------------\n")
	fmt.Fprintf(w, "Config endpoint: %s\n", s.endpoints["Config"])
	fmt.Fprintf(w, "Legacy config endpoint: %s\n", s.endpoints["LegacyConfig"])
	fmt.Fprintf(w, "Target endpoint: %s\n", s.endpoints["Target"])
	fmt.Fprintf(w, "   Request content type:  %s\n", s.requestLabel)
	fmt.Fprintf(w, "   Response content type: %s\n", s.responseLabel)
	fmt.Fprintf(w, "Echo endpoint: %s\n", s.endpoints["Echo"])
	fmt.Fprintf(w, "Metadata endpoint: %s\n", s.endpoints["Metadata"])
	fmt.Fprint(w, "----------------\n")
}

func (s gatewayServer) indexHandler(w http.ResponseWriter, r *http.Request) {
	s.formatConfiguration(w)
}

func (s gatewayServer) healthCheckHandler(w http.ResponseWriter, r *http.Request) {
	slog.Debug("HTTP request", "method", r.Method, "path", r.URL.Path)
	fmt.Fprint(w, "ok")
}

func getUintEnv(key string, defaultVal uint64) uint64 {
	val := os.Getenv(key)
	if val == "" {
		return defaultVal
	}

	ret, err := strconv.ParseUint(val, 10, 64)
	if err != nil {
		return defaultVal
	}
	return ret
}

func getBoolEnv(key string, defaultVal bool) bool {
	val := os.Getenv(key)
	if val == "" {
		return defaultVal
	}

	ret, err := strconv.ParseBool(val)
	if err != nil {
		return defaultVal
	}
	return ret
}

func getStringEnv(key string, defaultVal string) string {
	val := os.Getenv(key)
	if val == "" {
		return defaultVal
	}
	return val
}

func main() {
	flag.Parse()

	var logLevel slog.Level
	if err := logLevel.UnmarshalText([]byte(getStringEnv(logLevelEnvironmentVariable, "info"))); err != nil {
		slog.Error("invalid log level")
		os.Exit(1)
	}

	handlerOptions := slog.HandlerOptions{Level: logLevel}
	var handler slog.Handler

	switch logFormat := getStringEnv(logFormatEnvironmentVariable, logFormatDefault); logFormat {
	case logFormatDefault:
		handler = slog.NewTextHandler(os.Stdout, &handlerOptions)
	case logFormatJSON:
		handler = slog.NewJSONHandler(os.Stdout, &handlerOptions)
	default:
		slog.Error("invalid log format", "format", logFormat)
		os.Exit(1)
	}

	slog.SetDefault(slog.New(handler))

	if *versionFlag {
		buildInfo, ok := debug.ReadBuildInfo()
		if !ok {
			slog.Error("could not determine build info")
			os.Exit(1)
		}
		slog.Info(os.Args[0], "buildInfo", buildInfo)
		os.Exit(0)
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = defaultPort
	}

	logSecrets := getBoolEnv(logSecretsEnvironmentVariable, false)

	var seed []byte
	if seedHex := os.Getenv(secretSeedEnvironmentVariable); seedHex != "" {
		if logSecrets {
			slog.Info("Using Secret Key Seed", "seed", seedHex)
		} else {
			slog.Info("Using Secret Key Seed provided in environment variable")
		}
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
		allowedOrigins = make(map[string]bool)
		for _, origin := range origins {
			allowedOrigins[origin] = true
		}
	}

	var targetRewrites map[string]TargetRewrite
	if targetRewritesJson := os.Getenv(targetRewritesVariables); targetRewritesJson != "" {
		if err := json.Unmarshal([]byte(targetRewritesJson), &targetRewrites); err != nil {
			slog.Error("Failed to parse target rewrites", "error", err)
			os.Exit(1)
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

	debugResponse := getBoolEnv(gatewayDebugEnvironmentVariable, false)

	configID := uint8(getUintEnv(configurationIdEnvironmentVariable, 0))
	config, err := ohttp.NewConfigFromSeed(configID, hpke.KEM_X25519_KYBER768_DRAFT00, hpke.KDF_HKDF_SHA256, hpke.AEAD_AES128GCM, seed)
	if err != nil {
		slog.Error("Failed to create gateway configuration from seed", "error", err)
		os.Exit(1)
	}

	// From the primary configuration ID, create a key ID for the legacy configuration that old
	// clients will use for obtaining configuration material. This will eventually be removed once all
	// clients have been updated to support the primary configuration ID.
	legacyConfigID := uint8((configID - 128) % 255)
	seed[len(seed)-1] ^= 0xFF
	legacyConfig, err := ohttp.NewConfigFromSeed(legacyConfigID, hpke.KEM_X25519_HKDF_SHA256, hpke.KDF_HKDF_SHA256, hpke.AEAD_AES128GCM, seed)
	if err != nil {
		slog.Error("Failed to create legacy gateway configuration from seed", "error", err)
		os.Exit(1)
	}

	// Create the default HTTP handler
	httpHandler := FilteredHttpRequestHandler{
		client:         HTTPClientRequestHandler{client: &http.Client{}},
		allowedOrigins: allowedOrigins,
		targetRewrites: targetRewrites,
	}

	// Create the default gateway and its request handler chain
	var gateway ohttp.Gateway
	var targetHandler EncapsulationHandler
	requestLabel := os.Getenv(customRequestEncodingType)
	responseLabel := os.Getenv(customResponseEncodingType)
	if requestLabel == "" || responseLabel == "" || requestLabel == responseLabel {
		gateway = ohttp.NewDefaultGateway([]ohttp.PrivateConfig{config, legacyConfig})
		requestLabel = "message/bhttp request"
		responseLabel = "message/bhttp response"
		targetHandler = DefaultEncapsulationHandler{
			gateway: gateway,
			appHandler: BinaryHTTPAppHandler{
				httpHandler: httpHandler,
			},
		}
	} else if requestLabel == "message/protohttp request" && responseLabel == "message/protohttp response" {
		gateway = ohttp.NewCustomGateway([]ohttp.PrivateConfig{config, legacyConfig}, requestLabel, responseLabel)
		targetHandler = DefaultEncapsulationHandler{
			gateway: gateway,
			appHandler: ProtoHTTPAppHandler{
				httpHandler: httpHandler,
			},
		}
	} else {
		panic("Unsupported application content handler")
	}

	// Create the echo handler chain
	echoHandler := DefaultEncapsulationHandler{
		gateway:    gateway,
		appHandler: EchoAppHandler{},
	}

	// Create the metadata handler chain
	metadataHandler := MetadataEncapsulationHandler{
		gateway: gateway,
	}

	// Configure metrics
	var metricsFactory MetricsFactory

	if prometheusConfigJSON := os.Getenv(prometheusConfigVariable); prometheusConfigJSON != "" {
		var prometheusConfig PrometheusConfig
		if err := json.Unmarshal([]byte(prometheusConfigJSON), &prometheusConfig); err != nil {
			slog.Error("Failed to parse Prometheus config", "error", err)
			os.Exit(1)
		}

		metricsFactory, err = NewPrometheusMetricsFactory(prometheusConfig)
		if err != nil {
			slog.Error("Failed to configure Prometheus metrics", "error", err)
			os.Exit(1)
		}
	} else {
		// Default to StatsD metrics
		monitoringServiceName := getStringEnv(monitoringServiceNameEnvironmentVariable, defaultMonitoringServiceName)
		metricsHost := os.Getenv(statsdHostVariable)
		metricsPort := os.Getenv(statsdPortVariable)
		metricsTimeout, err := strconv.ParseInt(getStringEnv(statsdTimeoutVariable, "100"), 10, 64)
		if err != nil {
			slog.Error("Failed parsing metrics timeout", "error", err)
			os.Exit(1)
		}
		client, err := createStatsDClient(metricsHost, metricsPort, int(metricsTimeout))
		if err != nil {
			slog.Error("Failed to create statsd client", "error", err)
			os.Exit(1)
		}
		defer client.Close()

		metricsFactory = &StatsDMetricsFactory{
			serviceName: monitoringServiceName,
			metricsName: "ohttp_gateway_duration",
			client:      client,
		}
	}

	// Load endpoint configuration defaults
	gatewayEndpoint := getStringEnv(gatewayEndpointEnvVariable, defaultGatewayEndpoint)
	configEndpoint := getStringEnv(configEndpointEnvVariable, defaultConfigEndpoint)
	legacyConfigEndpoint := getStringEnv(legacyConfigEndpointEnvVariable, defaultLegacyConfigEndpoint)
	echoEndpoint := getStringEnv(echoEndpointEnvVariable, defaultEchoEndpoint)
	metadataEndpoint := getStringEnv(metadataEndpointEnvVariable, defaultMetadataEndpoint)
	healthEndpoint := getStringEnv(healthEndpointEnvVariable, defaultHealthEndpoint)

	// Interval in days for the renewing of the public and private key pair of the gateway.
	// If 0, it never expire.
	keyRotationInterval := uint8(getUintEnv(configKeyRotationInterval, 0))

	// Install configuration endpoints
	handlers := make(map[string]EncapsulationHandler)
	handlers[gatewayEndpoint] = targetHandler    // Content-specific handler
	handlers[echoEndpoint] = echoHandler         // Content-agnostic handler
	handlers[metadataEndpoint] = metadataHandler // Metadata handler
	target := &gatewayResource{
		legacyKeyID:           legacyConfigID,
		gateway:               gateway,
		encapsulationHandlers: handlers,
		debugResponse:         debugResponse,
		metricsFactory:        metricsFactory,
		keyRotationInteval:    keyRotationInterval,
	}

	endpoints := make(map[string]string)
	endpoints["Target"] = gatewayEndpoint
	endpoints["Health"] = healthEndpoint
	endpoints["Config"] = configEndpoint
	endpoints["LegacyConfig"] = legacyConfigEndpoint
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
	http.HandleFunc(legacyConfigEndpoint, target.legacyConfigHandler)
	http.HandleFunc(configEndpoint, target.configHandler)
	http.HandleFunc("/", server.indexHandler)

	var b bytes.Buffer
	server.formatConfiguration(io.Writer(&b))
	slog.Debug(b.String())

	if enableTLSServe {
		slog.Debug("Listening", "cert", certFile, "key", "keyFile", "port", port)
		slog.Error("error serving TLS", "error", http.ListenAndServeTLS(fmt.Sprintf(":%s", port), certFile, keyFile, nil))
		os.Exit(1)
	} else {
		slog.Debug("Listening without enabling TLS", "port", port)
		slog.Error("error serving non-TLS", "error", http.ListenAndServe(fmt.Sprintf(":%s", port), nil))
		os.Exit(1)
	}
}
