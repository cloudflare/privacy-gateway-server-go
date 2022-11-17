// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"time"

	"github.com/chris-wood/ohttp-go"
)

type gatewayResource struct {
	verbose               bool
	keyID                 uint8
	gateway               ohttp.Gateway
	encapsulationHandlers map[string]EncapsulationHandler
	debugResponse         bool
	metricsFactory        MetricsFactory
}

type HTTPError struct {
	StatusCode int
	Message    string
}

func (e *HTTPError) Error() string {
	return fmt.Sprintf("HTTPError(%d, %s)", e.StatusCode, e.Message)
}

const (
	ohttpRequestContentType  = "message/ohttp-req"
	ohttpResponseContentType = "message/ohttp-res"
	twelveHours              = 12 * 3600
	twentyFourHours          = 24 * 3600

	// Metrics constants
	metricsEventGatewayRequest      = "gateway_request"
	metricsEventConfigsRequest      = "configs_request"
	metricsResultConfigsUnavalable  = "configs_unavailable"
	metricsResultInvalidMethod      = "invalid_method"
	metricsResultInvalidContentType = "invalid_content_type"
	metricsResultInvalidContent     = "invalid_content"
)

func (s *gatewayResource) httpError(status int, debugMessage string) (ohttp.EncapsulatedResponse, HTTPError) {
	var msg = http.StatusText(status)
	if s.debugResponse {
		msg = debugMessage
	}
	return ohttp.EncapsulatedResponse{}, HTTPError{status, msg}
}

func (s *gatewayResource) gatewayHandlerLogic(r *http.Request, metrics Metrics) (ohttp.EncapsulatedResponse, HTTPError) {
	if r.Method != http.MethodPost {
		metrics.Fire(metricsResultInvalidMethod)
		return s.httpError(http.StatusBadRequest, fmt.Sprintf("Invalid method: %s", r.Method))
	}
	if r.Header.Get("Content-Type") != ohttpRequestContentType {
		metrics.Fire(metricsResultInvalidContentType)
		return s.httpError(http.StatusBadRequest, fmt.Sprintf("Invalid content type: %s", r.Header.Get("Content-Type")))
	}
	var encapHandler EncapsulationHandler
	var ok bool
	if encapHandler, ok = s.encapsulationHandlers[r.URL.Path]; !ok {
		metrics.Fire(metricsResultInvalidContentType)
		return s.httpError(http.StatusBadRequest, fmt.Sprintf("Unknown handler"))
	}
	defer r.Body.Close()
	// TODO: Use config to define this at startup time
	const maxRequestBodyBytes = 8 * 1024 * 1024
	lr := io.LimitReader(r.Body, maxRequestBodyBytes)
	encryptedMessageBytes, err := ioutil.ReadAll(lr)
	if err != nil {
		metrics.Fire(metricsResultInvalidContent)
		return s.httpError(http.StatusBadRequest, fmt.Sprintf("Reading request body failed"))
	}
	encapsulatedReq, err := ohttp.UnmarshalEncapsulatedRequest(encryptedMessageBytes)
	if err != nil {
		metrics.Fire(metricsResultInvalidContent)
		return s.httpError(http.StatusBadRequest, fmt.Sprintf("Reading request body failed"))
	}
	encapsulatedResp, err := encapHandler.Handle(r, encapsulatedReq, metrics)
	if err != nil {
		if s.verbose {
			log.Printf(err.Error())
		}
		errorStatusCode := encapsulationErrorToGatewayStatusCode(err)
		return s.httpError(errorStatusCode, http.StatusText(errorStatusCode))
	}
	return encapsulatedResp, HTTPError{http.StatusOK, ""}
}

func (s *gatewayResource) gatewayHandler(w http.ResponseWriter, r *http.Request) {
	if s.verbose {
		log.Printf("%s Handling %s\n", r.Method, r.URL.Path)
	}
	metrics := s.metricsFactory.Create(metricsEventGatewayRequest)

	encapsulatedResp, httpErr := s.gatewayHandlerLogic(r, metrics)

	if httpErr.StatusCode != http.StatusOK {
		metrics.ResponseStatus(r.Method, httpErr.StatusCode)
		if s.verbose {
			log.Println(httpErr.Message)
		}
		http.Error(w, httpErr.Message, httpErr.StatusCode)
	} else {
		metrics.ResponseStatus(r.Method, http.StatusOK)
		w.Header().Set("Content-Type", ohttpResponseContentType)
		w.Header().Set("Connection", "Keep-Alive")
		packedResponse := encapsulatedResp.Marshal()
		w.Write(packedResponse)
	}
}

func (s *gatewayResource) configHandler(w http.ResponseWriter, r *http.Request) {
	if s.verbose {
		log.Printf("%s Handling %s\n", r.Method, r.URL.Path)
	}
	metrics := s.metricsFactory.Create(metricsEventConfigsRequest)

	config, err := s.gateway.Config(s.keyID)
	if err != nil {
		log.Printf("Config unavailable")
		metrics.Fire(metricsResultConfigsUnavalable)
		_, httpErr := s.httpError(http.StatusInternalServerError, "Config unavailable")
		http.Error(w, httpErr.Message, httpErr.StatusCode)
		return
	}

	// Make expiration time even/random throughout interval 12-36h
	rand.Seed(time.Now().UnixNano())
	maxAge := twelveHours + rand.Intn(twentyFourHours)
	w.Header().Set("Cache-Control", fmt.Sprintf("max-age=%d, private", maxAge))

	w.Write(config.Marshal())

	metrics.ResponseStatus(r.Method, http.StatusOK)
}
