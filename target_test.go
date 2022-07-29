// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/chris-wood/ohttp-go"
)

var (
	FIXED_KEY_ID = uint8(0x00)
)

func createGateway(t *testing.T) ohttp.Gateway {
	seed := make([]byte, defaultSeedLength)
	rand.Read(seed)

	gateway, err := ohttp.NewGateway(FIXED_KEY_ID, seed)
	if err != nil {
		t.Fatal("Failed to create a gateway. Exiting now.")
	}

	return gateway
}

func createTarget(t *testing.T) gatewayResource {
	return gatewayResource{
		gateway: createGateway(t),
	}
}

func TestConfigHandler(t *testing.T) {
	target := createTarget(t)
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

// func TestQueryHandlerInvalidContentType(t *testing.T) {
// 	target := createTarget(t)

// 	handler := http.HandlerFunc(target.targetQueryHandler)

// 	request, err := http.NewRequest("GET", queryEndpoint, nil)
// 	if err != nil {
// 		t.Fatal(err)
// 	}
// 	request.Header.Add("Content-Type", "application/not-the-droids-youre-looking-for")

// 	rr := httptest.NewRecorder()
// 	handler.ServeHTTP(rr, request)

// 	if status := rr.Result().StatusCode; status != http.StatusBadRequest {
// 		t.Fatal(fmt.Errorf("Result did not yield %d, got %d instead", http.StatusBadRequest, status))
// 	}
// }

// func TestQueryHandlerDoHWithPOST(t *testing.T) {
// 	target := createTarget(t)

// 	handler := http.HandlerFunc(target.targetQueryHandler)

// 	q := r.queries[0]
// 	request, err := http.NewRequest(http.MethodPost, queryEndpoint, bytes.NewReader([]byte(q)))
// 	if err != nil {
// 		t.Fatal(err)
// 	}
// 	request.Header.Add("Content-Type", dnsMessageContentType)

// 	rr := httptest.NewRecorder()
// 	handler.ServeHTTP(rr, request)

// 	if status := rr.Result().StatusCode; status != http.StatusOK {
// 		t.Fatal(fmt.Errorf("Result did not yield %d, got %d instead", http.StatusOK, status))
// 	}
// 	if rr.Result().Header.Get("Content-Type") != dnsMessageContentType {
// 		t.Fatal("Invalid content type response")
// 	}

// 	responseBody, err := ioutil.ReadAll(rr.Result().Body)
// 	if err != nil {
// 		t.Fatal(err)
// 	}
// 	if !bytes.Equal(responseBody, r.queryResponseMap[q]) {
// 		t.Fatal("Incorrect response received")
// 	}
// }

// func TestQueryHandlerDoHWithGET(t *testing.T) {
// 	target := createTarget(t)

// 	handler := http.HandlerFunc(target.targetQueryHandler)

// 	q := r.queries[0]
// 	encodedQuery := base64.RawURLEncoding.EncodeToString([]byte(q))

// 	request, err := http.NewRequest(http.MethodGet, queryEndpoint+"?dns="+encodedQuery, nil)
// 	if err != nil {
// 		t.Fatal(err)
// 	}
// 	request.Header.Add("Content-Type", dnsMessageContentType)

// 	rr := httptest.NewRecorder()
// 	handler.ServeHTTP(rr, request)

// 	if status := rr.Result().StatusCode; status != http.StatusOK {
// 		t.Fatal(fmt.Errorf("Result did not yield %d, got %d instead", http.StatusOK, status))
// 	}
// 	if rr.Result().Header.Get("Content-Type") != dnsMessageContentType {
// 		t.Fatal("Invalid content type response")
// 	}

// 	responseBody, err := ioutil.ReadAll(rr.Result().Body)
// 	if err != nil {
// 		t.Fatal(err)
// 	}
// 	if !bytes.Equal(responseBody, r.queryResponseMap[q]) {
// 		t.Fatal("Incorrect response received")
// 	}
// }

// func TestQueryHandlerDoHWithInvalidMethod(t *testing.T) {
// 	target := createTarget(t)

// 	handler := http.HandlerFunc(target.targetQueryHandler)

// 	q := r.queries[0]
// 	encodedQuery := base64.RawURLEncoding.EncodeToString([]byte(q))
// 	request, err := http.NewRequest(http.MethodPut, queryEndpoint+"?dns="+encodedQuery, nil)
// 	if err != nil {
// 		t.Fatal(err)
// 	}
// 	request.Header.Add("Content-Type", dnsMessageContentType)

// 	rr := httptest.NewRecorder()
// 	handler.ServeHTTP(rr, request)

// 	if status := rr.Result().StatusCode; status != http.StatusBadRequest {
// 		t.Fatal(fmt.Errorf("Result did not yield %d, got %d instead", http.StatusBadRequest, status))
// 	}
// }

// func TestQueryHandlerODoHWithInvalidMethod(t *testing.T) {
// 	target := createTarget(t)

// 	handler := http.HandlerFunc(target.targetQueryHandler)

// 	q := r.queries[0]
// 	obliviousQuery := odoh.CreateObliviousDNSQuery([]byte(q), 0)
// 	encryptedQuery, _, err := target.odohKeyPair.Config.Contents.EncryptQuery(obliviousQuery)
// 	if err != nil {
// 		t.Fatal(err)
// 	}

// 	request, err := http.NewRequest(http.MethodGet, queryEndpoint, bytes.NewReader(encryptedQuery.Marshal()))
// 	if err != nil {
// 		t.Fatal(err)
// 	}
// 	request.Header.Add("Content-Type", odohMessageContentType)

// 	rr := httptest.NewRecorder()
// 	handler.ServeHTTP(rr, request)

// 	if status := rr.Result().StatusCode; status != http.StatusBadRequest {
// 		t.Fatal(fmt.Errorf("Result did not yield %d, got %d instead", http.StatusBadRequest, status))
// 	}
// }

// func TestQueryHandlerODoH(t *testing.T) {
// 	target := createTarget(t)

// 	handler := http.HandlerFunc(target.targetQueryHandler)

// 	q := r.queries[0]
// 	obliviousQuery := odoh.CreateObliviousDNSQuery([]byte(q), 0)
// 	encryptedQuery, context, err := target.odohKeyPair.Config.Contents.EncryptQuery(obliviousQuery)
// 	if err != nil {
// 		t.Fatal(err)
// 	}

// 	request, err := http.NewRequest(http.MethodPost, queryEndpoint, bytes.NewReader(encryptedQuery.Marshal()))
// 	if err != nil {
// 		t.Fatal(err)
// 	}
// 	request.Header.Add("Content-Type", odohMessageContentType)

// 	rr := httptest.NewRecorder()
// 	handler.ServeHTTP(rr, request)

// 	if status := rr.Result().StatusCode; status != http.StatusOK {
// 		t.Fatal(fmt.Errorf("Result did not yield %d, got %d instead", http.StatusOK, status))
// 	}
// 	if rr.Result().Header.Get("Content-Type") != odohMessageContentType {
// 		t.Fatal("Invalid content type response")
// 	}

// 	responseBody, err := ioutil.ReadAll(rr.Result().Body)
// 	if err != nil {
// 		t.Fatal(err)
// 	}

// 	odohQueryResponse, err := odoh.UnmarshalDNSMessage(responseBody)
// 	if err != nil {
// 		t.Fatal(err)
// 	}

// 	response, err := context.OpenAnswer(odohQueryResponse)
// 	if err != nil {
// 		t.Fatal(err)
// 	}

// 	if !bytes.Equal(response, r.queryResponseMap[q]) {
// 		t.Fatal(fmt.Errorf("Incorrect response received. Got %v, expected %v", response, r.queryResponseMap[q]))
// 	}
// }

// func TestQueryHandlerODoHWithInvalidKey(t *testing.T) {
// 	target := createTarget(t)

// 	handler := http.HandlerFunc(target.targetQueryHandler)

// 	differentKeyPair := createKeyPair(t)
// 	q := r.queries[0]
// 	obliviousQuery := odoh.CreateObliviousDNSQuery([]byte(q), 0)
// 	encryptedQuery, _, err := differentKeyPair.Config.Contents.EncryptQuery(obliviousQuery)
// 	if err != nil {
// 		t.Fatal(err)
// 	}

// 	request, err := http.NewRequest(http.MethodPost, queryEndpoint, bytes.NewReader(encryptedQuery.Marshal()))
// 	if err != nil {
// 		t.Fatal(err)
// 	}
// 	request.Header.Add("Content-Type", odohMessageContentType)

// 	rr := httptest.NewRecorder()
// 	handler.ServeHTTP(rr, request)

// 	if status := rr.Result().StatusCode; status != http.StatusBadRequest {
// 		t.Fatal(fmt.Errorf("Result did not yield %d, got %d instead", http.StatusBadRequest, status))
// 	}
// }

// func TestQueryHandlerODoHWithCorruptCiphertext(t *testing.T) {
// 	target := createTarget(t)

// 	handler := http.HandlerFunc(target.targetQueryHandler)

// 	q := r.queries[0]
// 	obliviousQuery := odoh.CreateObliviousDNSQuery([]byte(q), 0)
// 	encryptedQuery, _, err := target.odohKeyPair.Config.Contents.EncryptQuery(obliviousQuery)
// 	if err != nil {
// 		t.Fatal(err)
// 	}
// 	queryBytes := encryptedQuery.Marshal()
// 	queryBytes[len(queryBytes)-1] ^= 0xFF

// 	request, err := http.NewRequest(http.MethodPost, queryEndpoint, bytes.NewReader(queryBytes))
// 	if err != nil {
// 		t.Fatal(err)
// 	}
// 	request.Header.Add("Content-Type", odohMessageContentType)

// 	rr := httptest.NewRecorder()
// 	handler.ServeHTTP(rr, request)

// 	if status := rr.Result().StatusCode; status != http.StatusBadRequest {
// 		t.Fatal(fmt.Errorf("Result did not yield %d, got %d instead", http.StatusBadRequest, status))
// 	}
// }
