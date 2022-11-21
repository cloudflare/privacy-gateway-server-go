// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"time"

	"github.com/chris-wood/ohttp-go"
)

type gatewayResource struct {
	verbose               bool
	publicConfig          ohttp.PublicConfig
	encapsulationHandlers map[string]EncapsulationHandler
	debugResponse         bool
	metricsFactory        MetricsFactory
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

func (s *gatewayResource) httpError(w http.ResponseWriter, status int, debugMessage string, metrics Metrics, metricsPrefix string) {
	if s.verbose {
		log.Println(debugMessage)
	}
	if s.debugResponse {
		http.Error(w, debugMessage, status)
	} else {
		http.Error(w, http.StatusText(status), status)
	}
	metrics.ResponseStatus(metricsPrefix, status)
}

func (s *gatewayResource) gatewayHandler(w http.ResponseWriter, r *http.Request) {
	if s.verbose {
		log.Printf("%s Handling %s\n", r.Method, r.URL.Path)
	}

	metrics := s.metricsFactory.Create(metricsEventGatewayRequest)

	if r.Method != http.MethodPost {
		metrics.Fire(metricsResultInvalidMethod)
		s.httpError(w, http.StatusBadRequest, fmt.Sprintf("Invalid method: %s", r.Method), metrics, r.Method)
		return
	}
	if r.Header.Get("Content-Type") != ohttpRequestContentType {
		metrics.Fire(metricsResultInvalidContentType)
		s.httpError(w, http.StatusBadRequest, fmt.Sprintf("Invalid content type: %s", r.Header.Get("Content-Type")), metrics, r.Method)
		return
	}

	var encapHandler EncapsulationHandler
	var ok bool
	if encapHandler, ok = s.encapsulationHandlers[r.URL.Path]; !ok {
		s.httpError(w, http.StatusBadRequest, fmt.Sprintf("Unknown handler"), metrics, r.Method)
		return
	}

	defer r.Body.Close()
	encryptedMessageBytes, err := ioutil.ReadAll(r.Body)
	if err != nil {
		metrics.Fire(metricsResultInvalidContent)
		s.httpError(w, http.StatusBadRequest, fmt.Sprintf("Reading request body failed"), metrics, r.Method)
		return
	}

	encapsulatedReq, err := ohttp.UnmarshalEncapsulatedRequest(encryptedMessageBytes)
	if err != nil {
		metrics.Fire(metricsResultInvalidContent)
		s.httpError(w, http.StatusBadRequest, fmt.Sprintf("Reading request body failed"), metrics, r.Method)
		return
	}

	encapsulatedResp, err := encapHandler.Handle(r, encapsulatedReq, metrics)
	if err != nil {
		if s.verbose {
			log.Printf(err.Error())
		}

		errorCode := encapsulationErrorToGatewayStatusCode(err)
		s.httpError(w, errorCode, http.StatusText(errorCode), metrics, r.Method)
		return
	}

	packedResponse := encapsulatedResp.Marshal()

	w.Header().Set("Content-Type", ohttpResponseContentType)
	w.Header().Set("Connection", "Keep-Alive")
	w.Write(packedResponse)
	metrics.ResponseStatus(r.Method, http.StatusOK)
}

func (s *gatewayResource) configHandler(w http.ResponseWriter, r *http.Request) {
	if s.verbose {
		log.Printf("%s Handling %s\n", r.Method, r.URL.Path)
	}
	metrics := s.metricsFactory.Create(metricsEventConfigsRequest)

	// Make expiration time even/random throughout interval 12-36h
	rand.Seed(time.Now().UnixNano())
	maxAge := twelveHours + rand.Intn(twentyFourHours)
	w.Header().Set("Cache-Control", fmt.Sprintf("max-age=%d, private", maxAge))

	w.Write(s.publicConfig.Marshal())

	metrics.ResponseStatus(r.Method, http.StatusOK)
}
