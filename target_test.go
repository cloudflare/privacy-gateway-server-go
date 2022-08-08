// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/chris-wood/ohttp-go"
	"github.com/cisco/go-hpke"
)

var (
	FIXED_KEY_ID     = uint8(0x00)
	FORBIDDEN_TARGET = "forbidden.example"
	ALLOWED_TARGET   = "allowed.example"
)

func createGateway(t *testing.T) ohttp.Gateway {
	config, err := ohttp.NewConfig(FIXED_KEY_ID, hpke.DHKEM_X25519, hpke.KDF_HKDF_SHA256, hpke.AEAD_AESGCM128)
	if err != nil {
		t.Fatal("Failed to create a valid config. Exiting now.")
	}

	return ohttp.NewDefaultGateway(config)
}

func testEchoHandler(request []byte, filter TargetFilter) ([]byte, error) {
	return request, nil
}

func testForbiddenEchoHandler(request []byte, filter TargetFilter) ([]byte, error) {
	return nil, TargetForbiddenError
}

func testBhttpHandler(binaryRequest []byte, filter TargetFilter) ([]byte, error) {
	request, err := ohttp.UnmarshalBinaryRequest(binaryRequest)
	if err != nil {
		return nil, err
	}

	if !filter(request.Host) {
		return nil, TargetForbiddenError
	}

	return binaryRequest, nil
}

func createMockEchoGatewayServer(t *testing.T) gatewayResource {
	handlers := make(map[string]ContentHandler)
	handlers[echoEndpoint] = testEchoHandler
	handlers[gatewayEndpoint] = testForbiddenEchoHandler
	return gatewayResource{
		gateway:  createGateway(t),
		handlers: handlers,
		allowedOrigins: map[string]bool{
			ALLOWED_TARGET: true,
		},
	}
}

func createMockBhttpGatewayServer(t *testing.T) gatewayResource {
	handlers := make(map[string]ContentHandler)
	handlers[echoEndpoint] = testEchoHandler
	handlers[gatewayEndpoint] = testBhttpHandler
	return gatewayResource{
		gateway:  createGateway(t),
		handlers: handlers,
		allowedOrigins: map[string]bool{
			ALLOWED_TARGET: true,
		},
	}
}

func TestConfigHandler(t *testing.T) {
	target := createMockEchoGatewayServer(t)
	config, err := target.gateway.Config(FIXED_KEY_ID)
	if err != nil {
		t.Fatal(err)
	}
	marshalledConfig := config.Marshal()

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
}

func TestQueryHandlerInvalidContentType(t *testing.T) {
	target := createMockEchoGatewayServer(t)

	handler := http.HandlerFunc(target.gatewayHandler)

	request, err := http.NewRequest("GET", gatewayEndpoint, nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Add("Content-Type", "application/not-the-droids-youre-looking-for")

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, request)

	if status := rr.Result().StatusCode; status != http.StatusBadRequest {
		t.Fatal(fmt.Errorf("Result did not yield %d, got %d instead", http.StatusBadRequest, status))
	}
}

func TestGatewayHandler(t *testing.T) {
	target := createMockEchoGatewayServer(t)

	handler := http.HandlerFunc(target.gatewayHandler)

	config, err := target.gateway.Config(FIXED_KEY_ID)
	if err != nil {
		t.Fatal(err)
	}
	client := ohttp.NewDefaultClient(config)

	testMessage := []byte{0xCA, 0xFE}
	req, _, err := client.EncapsulateRequest(testMessage)

	request, err := http.NewRequest(http.MethodPost, echoEndpoint, bytes.NewReader(req.Marshal()))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Add("Content-Type", "message/ohttp-req")

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, request)

	if status := rr.Result().StatusCode; status != http.StatusOK {
		t.Fatal(fmt.Errorf("Result did not yield %d, got %d instead", http.StatusOK, status))
	}
	if rr.Result().Header.Get("Content-Type") != "message/ohttp-res" {
		t.Fatal("Invalid content type response")
	}
}

func TestGatewayHandlerWithInvalidMethod(t *testing.T) {
	target := createMockEchoGatewayServer(t)

	handler := http.HandlerFunc(target.gatewayHandler)

	config, err := target.gateway.Config(FIXED_KEY_ID)
	if err != nil {
		t.Fatal(err)
	}
	client := ohttp.NewDefaultClient(config)

	testMessage := []byte{0xCA, 0xFE}
	req, _, err := client.EncapsulateRequest(testMessage)

	request, err := http.NewRequest(http.MethodGet, echoEndpoint, bytes.NewReader(req.Marshal()))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Add("Content-Type", "message/ohttp-req")

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, request)

	if status := rr.Result().StatusCode; status != http.StatusBadRequest {
		t.Fatal(fmt.Errorf("Result did not yield %d, got %d instead", http.StatusBadRequest, status))
	}
}

func TestGatewayHandlerWithInvalidKey(t *testing.T) {
	target := createMockEchoGatewayServer(t)

	handler := http.HandlerFunc(target.gatewayHandler)

	// Generate a new config that's different from the target's
	privateConfig, err := ohttp.NewConfig(FIXED_KEY_ID, hpke.DHKEM_X25519, hpke.KDF_HKDF_SHA256, hpke.AEAD_AESGCM128)
	if err != nil {
		t.Fatal("Failed to create a valid config. Exiting now.")
	}
	client := ohttp.NewDefaultClient(privateConfig.Config())

	testMessage := []byte{0xCA, 0xFE}
	req, _, err := client.EncapsulateRequest(testMessage)

	request, err := http.NewRequest(http.MethodPost, echoEndpoint, bytes.NewReader(req.Marshal()))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Add("Content-Type", "message/ohttp-req")

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, request)

	if status := rr.Result().StatusCode; status != http.StatusBadRequest {
		t.Fatal(fmt.Errorf("Result did not yield %d, got %d instead", http.StatusBadRequest, status))
	}
}

func TestGatewayHandlerWithCorruptContent(t *testing.T) {
	target := createMockEchoGatewayServer(t)

	handler := http.HandlerFunc(target.gatewayHandler)

	config, err := target.gateway.Config(FIXED_KEY_ID)
	if err != nil {
		t.Fatal(err)
	}
	client := ohttp.NewDefaultClient(config)

	// Corrupt the message
	testMessage := []byte{0xCA, 0xFE}
	req, _, err := client.EncapsulateRequest(testMessage)
	reqEnc := req.Marshal()
	reqEnc[len(reqEnc)-1] ^= 0xFF

	request, err := http.NewRequest(http.MethodPost, echoEndpoint, bytes.NewReader(reqEnc))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Add("Content-Type", "message/ohttp-req")

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, request)

	if status := rr.Result().StatusCode; status != http.StatusBadRequest {
		t.Fatal(fmt.Errorf("Result did not yield %d, got %d instead", http.StatusBadRequest, status))
	}
}

func TestGatewayHandlerWithForbiddenTarget(t *testing.T) {
	target := createMockEchoGatewayServer(t)

	handler := http.HandlerFunc(target.gatewayHandler)

	config, err := target.gateway.Config(FIXED_KEY_ID)
	if err != nil {
		t.Fatal(err)
	}
	client := ohttp.NewDefaultClient(config)

	testMessage := []byte{0xCA, 0xFE}
	req, _, err := client.EncapsulateRequest(testMessage)
	reqEnc := req.Marshal()

	request, err := http.NewRequest(http.MethodPost, gatewayEndpoint, bytes.NewReader(reqEnc))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Add("Content-Type", "message/ohttp-req")

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, request)

	if status := rr.Result().StatusCode; status != http.StatusForbidden {
		t.Fatal(fmt.Errorf("Result did not yield %d, got %d instead", http.StatusForbidden, status))
	}
}

func TestGatewayHandlerBHTTPRequestWithForbiddenTarget(t *testing.T) {
	target := createMockBhttpGatewayServer(t)

	handler := http.HandlerFunc(target.gatewayHandler)

	config, err := target.gateway.Config(FIXED_KEY_ID)
	if err != nil {
		t.Fatal(err)
	}
	client := ohttp.NewDefaultClient(config)

	httpRequest, err := http.NewRequest(http.MethodPost, fmt.Sprintf("http://%s%s", FORBIDDEN_TARGET, gatewayEndpoint), nil)
	if err != nil {
		t.Fatal(err)
	}

	binaryRequest := ohttp.BinaryRequest(*httpRequest)
	encodedRequest, err := binaryRequest.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	req, _, err := client.EncapsulateRequest(encodedRequest)
	reqEnc := req.Marshal()

	request, err := http.NewRequest(http.MethodPost, gatewayEndpoint, bytes.NewReader(reqEnc))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Add("Content-Type", "message/ohttp-req")

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, request)

	if status := rr.Result().StatusCode; status != http.StatusForbidden {
		t.Fatal(fmt.Errorf("Result did not yield %d, got %d instead", http.StatusForbidden, status))
	}
}

func TestGatewayHandlerBHTTPRequestWithAllowedTarget(t *testing.T) {
	target := createMockBhttpGatewayServer(t)

	handler := http.HandlerFunc(target.gatewayHandler)

	config, err := target.gateway.Config(FIXED_KEY_ID)
	if err != nil {
		t.Fatal(err)
	}
	client := ohttp.NewDefaultClient(config)

	httpRequest, err := http.NewRequest(http.MethodPost, fmt.Sprintf("http://%s%s", ALLOWED_TARGET, gatewayEndpoint), nil)
	if err != nil {
		t.Fatal(err)
	}

	binaryRequest := ohttp.BinaryRequest(*httpRequest)
	encodedRequest, err := binaryRequest.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	req, _, err := client.EncapsulateRequest(encodedRequest)
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
}
