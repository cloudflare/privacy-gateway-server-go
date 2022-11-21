// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/chris-wood/ohttp-go"
	"github.com/cisco/go-hpke"
	"google.golang.org/protobuf/proto"
)

var (
	FIXED_KEY_ID     = uint8(0x00)
	FORBIDDEN_TARGET = "forbidden.example"
	ALLOWED_TARGET   = "allowed.example"
	GATEWAY_DEBUG    = true
)

func copyFixedSeed() []byte {
	seed := make([]byte, 32)
	for i := 0; i < len(seed); i++ {
		seed[i] = byte(i)
	}
	return seed
}

func mustCreateConfig(t *testing.T) ohttp.PrivateConfig {
	config, err := ohttp.NewConfigFromSeed(FIXED_KEY_ID, hpke.DHKEM_X25519, hpke.KDF_HKDF_SHA256, hpke.AEAD_AESGCM128, copyFixedSeed())
	if err != nil {
		t.Fatal("Failed to create a valid config. Exiting now.")
	}
	return config
}

type MockMetrics struct {
	eventName    string
	resultLabels map[string]int
}

func (s *MockMetrics) ResponseStatus(prefix string, status int) {
	s.Fire(fmt.Sprintf("%s_response_status_%d", prefix, status))
}

func (s *MockMetrics) Fire(result string) {
	counter, exists := s.resultLabels[result]
	if !exists {
		counter = 0
	}
	if counter > 2 {
		panic("Metrics.Fire called more than twice for TryBothEncapsulationHandler")
	}
	s.resultLabels[result] = counter + 1
}

type MockMetricsFactory struct {
	metrics []*MockMetrics
}

func (f *MockMetricsFactory) Create(eventName string) Metrics {
	metrics := &MockMetrics{
		eventName:    eventName,
		resultLabels: map[string]int{},
	}
	f.metrics = append(f.metrics, metrics)
	return metrics
}

type ForbiddenCheckHttpRequestHandler struct {
	forbidden string
}

func mustGetMetricsFactory(t *testing.T, gateway gatewayResource) *MockMetricsFactory {
	factory, ok := gateway.metricsFactory.(*MockMetricsFactory)
	if !ok {
		panic("Failed to get metrics factory")
	}
	return factory
}

func (h ForbiddenCheckHttpRequestHandler) Handle(req *http.Request, metrics Metrics) (*http.Response, error) {
	if req.Host == h.forbidden {
		metrics.Fire(metricsResultTargetRequestForbidden)
		return nil, GatewayTargetForbiddenError
	}

	metrics.Fire(metricsResultSuccess)
	return &http.Response{
		StatusCode: http.StatusOK,
	}, nil
}

func createMockEchoGatewayServer(t *testing.T) gatewayResource {
	config := mustCreateConfig(t)
	gateway := ohttp.NewDefaultGateway(config)
	echoEncapHandler := DefaultEncapsulationHandler{
		keyID:      FIXED_KEY_ID,
		gateway:    gateway,
		appHandler: EchoAppHandler{},
	}
	mockProtoHTTPFilterHandler := DefaultEncapsulationHandler{
		keyID:   FIXED_KEY_ID,
		gateway: gateway,
		appHandler: BinaryHTTPAppHandler{
			httpHandler: ForbiddenCheckHttpRequestHandler{
				FORBIDDEN_TARGET,
			},
		},
	}

	encapHandlers := make(map[string]EncapsulationHandler)
	encapHandlers[echoEndpoint] = echoEncapHandler
	encapHandlers[gatewayEndpoint] = mockProtoHTTPFilterHandler
	return gatewayResource{
		publicConfig:          config.Config(),
		encapsulationHandlers: encapHandlers,
		debugResponse:         GATEWAY_DEBUG,
		metricsFactory:        &MockMetricsFactory{},
	}
}

func createMockTrialEchoGatewayServer(t *testing.T) gatewayResource {
	config := mustCreateConfig(t)
	gateway := ohttp.NewDefaultGateway(config)
	protohttpGateway := ohttp.NewCustomGateway(config, "message/protohttp request", "message/protohttp response")

	echoEncapHandler := DefaultEncapsulationHandler{
		keyID:      FIXED_KEY_ID,
		gateway:    gateway,
		appHandler: EchoAppHandler{},
	}
	gatewayHandler := TrialEncapsulationHandler{
		bhttpHandler: DefaultEncapsulationHandler{
			keyID:   FIXED_KEY_ID,
			gateway: gateway,
			appHandler: BinaryHTTPAppHandler{
				httpHandler: ForbiddenCheckHttpRequestHandler{
					FORBIDDEN_TARGET,
				},
			},
		},
		protohttpHandler: DefaultEncapsulationHandler{
			keyID:   FIXED_KEY_ID,
			gateway: protohttpGateway,
			appHandler: ProtoHTTPAppHandler{
				httpHandler: ForbiddenCheckHttpRequestHandler{
					FORBIDDEN_TARGET,
				},
			},
		},
	}

	encapHandlers := make(map[string]EncapsulationHandler)
	encapHandlers[echoEndpoint] = echoEncapHandler
	encapHandlers[gatewayEndpoint] = gatewayHandler
	return gatewayResource{
		publicConfig:          config.Config(),
		encapsulationHandlers: encapHandlers,
		debugResponse:         GATEWAY_DEBUG,
		metricsFactory:        &MockMetricsFactory{},
	}
}

func TestConfigHandler(t *testing.T) {
	target := createMockEchoGatewayServer(t)
	marshalledConfig := target.publicConfig.Marshal()

	handler := http.HandlerFunc(target.configHandler)

	request, err := http.NewRequest("GET", configEndpoint, nil)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, request)

	if status := rr.Code; status != http.StatusOK {
		t.Fatal(fmt.Errorf("Failed request with error code: %d", status))
	}

	body, err := ioutil.ReadAll(rr.Result().Body)
	if err != nil {
		t.Fatal("Failed to read body:", err)
	}

	if !bytes.Equal(body, marshalledConfig) {
		t.Fatal("Received invalid config")
	}

	// checking correct header exists
	// Cache-Control: max-age=%d, private
	cctrl := rr.Header().Get("Cache-Control")

	if strings.HasPrefix(cctrl, "max-age=") && strings.HasSuffix(cctrl, ", private") {
		maxAge := strings.TrimPrefix(strings.TrimSuffix(cctrl, ", private"), "max-age=")
		age, err := strconv.Atoi(maxAge)
		if err != nil {
			t.Fatal("max-age value should be int", err)
		}
		if age < twelveHours || age > twelveHours+twentyFourHours {
			t.Fatal("age should be between 12 and 36 hours")
		}
	} else {
		t.Fatal("Cache-Control format should be 'max-age=86400, private'")
	}
}

func testBodyContainsError(t *testing.T, resp *http.Response, expectedText string) {
	body, err := io.ReadAll(resp.Body)
	if err == nil {
		if !strings.Contains(string(body), expectedText) {
			t.Fatal(fmt.Errorf("Failed to return expected text (%s) in response. Body text is: %s",
				expectedText, body))
		}
	}
}

func testMetricsContainsResult(t *testing.T, metricsCollector *MockMetricsFactory, event string, result string) {
	for _, metric := range metricsCollector.metrics {
		if metric.eventName == event {
			_, exists := metric.resultLabels[result]
			if !exists {
				t.Fatalf("Expected event %s/%s was not fired. resultLabels len=%d", event, result, len(metric.resultLabels))
			} else {
				return
			}
		}
	}
	t.Fatalf("Expected metric for event %s was not initialized", event)
}

func TestQueryHandlerInvalidContentType(t *testing.T) {
	testConfigs := []struct {
		target gatewayResource
	}{
		{target: createMockEchoGatewayServer(t)},
		{target: createMockTrialEchoGatewayServer(t)},
	}

	for _, test := range testConfigs {
		target := test.target

		handler := http.HandlerFunc(target.gatewayHandler)

		request, err := http.NewRequest(http.MethodPost, gatewayEndpoint, nil)
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Add("Content-Type", "application/not-the-droids-youre-looking-for")

		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, request)

		if status := rr.Result().StatusCode; status != http.StatusBadRequest {
			t.Fatal(fmt.Errorf("Result did not yield %d, got %d instead", http.StatusBadRequest, status))
		}

		testBodyContainsError(t, rr.Result(), "Invalid content type: application/not-the-droids-youre-looking-for")
		testMetricsContainsResult(t, mustGetMetricsFactory(t, target), metricsEventGatewayRequest, metricsResultInvalidContentType)
	}
}

type ClientFactory interface {
	CreateClient(t gatewayResource) ohttp.Client
}

type DefaultClientFactory struct {
}

func (d DefaultClientFactory) CreateClient(t gatewayResource) ohttp.Client {
	return ohttp.NewDefaultClient(t.publicConfig)
}

type ProtoHTTPClientFactory struct {
}

func (d ProtoHTTPClientFactory) CreateClient(t gatewayResource) ohttp.Client {
	return ohttp.NewCustomClient(t.publicConfig, "message/protohttp request", "message/protohttp response")
}

func TestGatewayHandlerWithInvalidMethod(t *testing.T) {
	testConfigs := []struct {
		clientFactory ClientFactory
		target        gatewayResource
	}{
		{clientFactory: DefaultClientFactory{}, target: createMockEchoGatewayServer(t)},
		{clientFactory: DefaultClientFactory{}, target: createMockTrialEchoGatewayServer(t)},
	}

	for _, test := range testConfigs {
		target := test.target

		handler := http.HandlerFunc(target.gatewayHandler)
		client := test.clientFactory.CreateClient(target)

		testMessage := []byte{0xCA, 0xFE}
		req, _, err := client.EncapsulateRequest(testMessage)

		request, err := http.NewRequest(http.MethodGet, gatewayEndpoint, bytes.NewReader(req.Marshal()))
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Add("Content-Type", "message/ohttp-req")

		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, request)

		if status := rr.Result().StatusCode; status != http.StatusBadRequest {
			t.Fatal(fmt.Errorf("Result did not yield %d, got %d instead", http.StatusBadRequest, status))
		}

		testMetricsContainsResult(t, mustGetMetricsFactory(t, target), metricsEventGatewayRequest, metricsResultInvalidMethod)
	}
}

func TestGatewayHandlerWithInvalidKey(t *testing.T) {
	testConfigs := []struct {
		clientFactory ClientFactory
		target        gatewayResource
	}{
		{clientFactory: DefaultClientFactory{}, target: createMockEchoGatewayServer(t)},
		{clientFactory: DefaultClientFactory{}, target: createMockTrialEchoGatewayServer(t)},
	}

	for _, test := range testConfigs {
		target := test.target

		handler := http.HandlerFunc(target.gatewayHandler)

		// Generate a new config that's different from the target's
		privateConfig, err := ohttp.NewConfig(FIXED_KEY_ID, hpke.DHKEM_X25519, hpke.KDF_HKDF_SHA256, hpke.AEAD_AESGCM128)
		if err != nil {
			t.Fatal("Failed to create a valid config.")
		}
		client := ohttp.NewDefaultClient(privateConfig.Config())

		testMessage := []byte{0xCA, 0xFE}
		req, _, err := client.EncapsulateRequest(testMessage)

		request, err := http.NewRequest(http.MethodPost, gatewayEndpoint, bytes.NewReader(req.Marshal()))
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Add("Content-Type", "message/ohttp-req")

		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, request)

		if status := rr.Result().StatusCode; status != http.StatusBadRequest {
			t.Fatal(fmt.Errorf("Result did not yield %d, got %d instead", http.StatusBadRequest, status))
		}

		testMetricsContainsResult(t, mustGetMetricsFactory(t, target), metricsEventGatewayRequest, metricsResultDecapsulationFailed)
	}
}

func TestGatewayHandlerWithUnknownKey(t *testing.T) {
	testConfigs := []struct {
		clientFactory ClientFactory
		target        gatewayResource
	}{
		{clientFactory: DefaultClientFactory{}, target: createMockEchoGatewayServer(t)},
		{clientFactory: DefaultClientFactory{}, target: createMockTrialEchoGatewayServer(t)},
	}

	for _, test := range testConfigs {
		target := test.target

		handler := http.HandlerFunc(target.gatewayHandler)

		// Generate a new config that's different from the target's in the key ID
		privateConfig, err := ohttp.NewConfig(FIXED_KEY_ID^0xFF, hpke.DHKEM_X25519, hpke.KDF_HKDF_SHA256, hpke.AEAD_AESGCM128)
		if err != nil {
			t.Fatal("Failed to create a valid config.")
		}
		client := ohttp.NewDefaultClient(privateConfig.Config())

		testMessage := []byte{0xCA, 0xFE}
		req, _, err := client.EncapsulateRequest(testMessage)

		request, err := http.NewRequest(http.MethodPost, gatewayEndpoint, bytes.NewReader(req.Marshal()))
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Add("Content-Type", "message/ohttp-req")

		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, request)

		if status := rr.Result().StatusCode; status != http.StatusUnauthorized {
			t.Fatal(fmt.Errorf("Result did not yield %d, got %d instead", http.StatusUnauthorized, status))
		}

		testMetricsContainsResult(t, mustGetMetricsFactory(t, target), metricsEventGatewayRequest, metricsResultConfigurationMismatch)
	}
}

func TestGatewayHandlerWithCorruptContent(t *testing.T) {
	testConfigs := []struct {
		clientFactory ClientFactory
		target        gatewayResource
	}{
		{clientFactory: DefaultClientFactory{}, target: createMockEchoGatewayServer(t)},
		{clientFactory: DefaultClientFactory{}, target: createMockTrialEchoGatewayServer(t)},
	}

	for _, test := range testConfigs {
		target := test.target

		handler := http.HandlerFunc(target.gatewayHandler)
		client := test.clientFactory.CreateClient(target)

		// Corrupt the message
		testMessage := []byte{0xCA, 0xFE}
		req, _, err := client.EncapsulateRequest(testMessage)
		reqEnc := req.Marshal()
		reqEnc[len(reqEnc)-1] ^= 0xFF

		request, err := http.NewRequest(http.MethodPost, gatewayEndpoint, bytes.NewReader(reqEnc))
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Add("Content-Type", "message/ohttp-req")

		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, request)

		if status := rr.Result().StatusCode; status != http.StatusBadRequest {
			t.Fatal(fmt.Errorf("Result did not yield %d, got %d instead", http.StatusBadRequest, status))
		}

		testMetricsContainsResult(t, mustGetMetricsFactory(t, target), metricsEventGatewayRequest, metricsResultDecapsulationFailed)
	}
}

type TestMessageCodec interface {
	EncodeRequest(req *http.Request) ([]byte, error)
	DecodeResponse(resp []byte) (bool, int, error)
}

type ProtoHTTPMessageCodec struct{}

func (h ProtoHTTPMessageCodec) EncodeRequest(req *http.Request) ([]byte, error) {
	protoReq, err := requestToProtoHTTP(req)
	if err != nil {
		return nil, err
	}
	return proto.Marshal(protoReq)
}

func (h ProtoHTTPMessageCodec) DecodeResponse(binaryResp []byte) (bool, int, error) {
	protoResp := &Response{}
	if err := proto.Unmarshal(binaryResp, protoResp); err != nil {
		return false, 0, err
	}
	return true, int(protoResp.StatusCode), nil
}
func TestGatewayHandlerProtoHTTPRequestWithForbiddenTarget(t *testing.T) {
	testConfigs := []struct {
		codec         TestMessageCodec
		clientFactory ClientFactory
		target        gatewayResource
	}{
		{
			codec:         ProtoHTTPMessageCodec{},
			clientFactory: ProtoHTTPClientFactory{},
			target:        createMockTrialEchoGatewayServer(t),
		},
	}

	for _, test := range testConfigs {
		target := test.target

		handler := http.HandlerFunc(target.gatewayHandler)
		client := test.clientFactory.CreateClient(target)

		httpRequest, err := http.NewRequest(http.MethodPost, fmt.Sprintf("http://%s%s", FORBIDDEN_TARGET, gatewayEndpoint), nil)
		if err != nil {
			t.Fatal(err)
		}

		encodedRequest, err := test.codec.EncodeRequest(httpRequest)
		if err != nil {
			t.Fatal(err)
		}

		req, context, err := client.EncapsulateRequest(encodedRequest)
		if err != nil {
			t.Fatal(err)
		}

		reqEnc := req.Marshal()

		request, err := http.NewRequest(http.MethodPost, gatewayEndpoint, bytes.NewReader(reqEnc))
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Add("Content-Type", "message/ohttp-req")

		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, request)

		if status := rr.Result().StatusCode; status != http.StatusOK {
			t.Fatal(fmt.Errorf("Result did not yield %d, got %d instead", http.StatusOK, status))
		}

		bodyBytes, err := ioutil.ReadAll(rr.Body)
		if err != nil {
			t.Fatal(err)
		}

		encapResp, err := ohttp.UnmarshalEncapsulatedResponse(bodyBytes)
		if err != nil {
			t.Fatal(err)
		}

		binaryResp, err := context.DecapsulateResponse(encapResp)
		if err != nil {
			t.Fatal(err)
		}

		ok, statusCode, err := test.codec.DecodeResponse(binaryResp)
		if !ok {
			t.Fatal(err)
		}
		if statusCode != http.StatusForbidden {
			t.Fatal(fmt.Errorf("Encapsulated result did not yield %d, got %d instead", http.StatusForbidden, statusCode))
		}

		testMetricsContainsResult(t, mustGetMetricsFactory(t, target), metricsEventGatewayRequest, metricsResultTargetRequestForbidden)
	}
}

func TestGatewayHandlerProtoHTTPRequestWithAllowedTarget(t *testing.T) {
	testConfigs := []struct {
		codec         TestMessageCodec
		clientFactory ClientFactory
		target        gatewayResource
	}{
		{
			codec:         ProtoHTTPMessageCodec{},
			clientFactory: ProtoHTTPClientFactory{},
			target:        createMockTrialEchoGatewayServer(t),
		},
	}

	for _, test := range testConfigs {
		target := test.target

		handler := http.HandlerFunc(target.gatewayHandler)
		client := test.clientFactory.CreateClient(target)

		httpRequest, err := http.NewRequest(http.MethodPost, fmt.Sprintf("http://%s%s", ALLOWED_TARGET, gatewayEndpoint), nil)
		if err != nil {
			t.Fatal(err)
		}

		binaryRequest, err := requestToProtoHTTP(httpRequest)
		if err != nil {
			t.Fatal(err)
		}

		encodedRequest, err := proto.Marshal(binaryRequest)
		if err != nil {
			t.Fatal(err)
		}
		req, context, err := client.EncapsulateRequest(encodedRequest)
		if err != nil {
			t.Fatal(err)
		}
		reqEnc := req.Marshal()

		request, err := http.NewRequest(http.MethodPost, gatewayEndpoint, bytes.NewReader(reqEnc))
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Add("Content-Type", "message/ohttp-req")

		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, request)

		if status := rr.Result().StatusCode; status != http.StatusOK {
			t.Fatal(fmt.Errorf("Result did not yield %d, got %d instead", http.StatusOK, status))
		}

		if status := rr.Result().StatusCode; status != http.StatusOK {
			t.Fatal(fmt.Errorf("Result did not yield %d, got %d instead", http.StatusOK, status))
		}

		bodyBytes, err := ioutil.ReadAll(rr.Body)
		if err != nil {
			t.Fatal(err)
		}

		encapResp, err := ohttp.UnmarshalEncapsulatedResponse(bodyBytes)
		if err != nil {
			t.Fatal(err)
		}

		binaryResp, err := context.DecapsulateResponse(encapResp)
		if err != nil {
			t.Fatal(err)
		}

		ok, statusCode, err := test.codec.DecodeResponse(binaryResp)
		if !ok {
			t.Fatal(err)
		}
		if statusCode != http.StatusOK {
			t.Fatal(fmt.Errorf("Encapsulated result did not yield %d, got %d instead", http.StatusOK, statusCode))
		}

		testMetricsContainsResult(t, mustGetMetricsFactory(t, target), metricsEventGatewayRequest, metricsResultSuccess)
	}
}
