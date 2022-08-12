// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/chris-wood/ohttp-go"
)

type TargetFilter func(targetOrigin string) bool
type ContentHandler func(request *http.Request, requestBody []byte, filter TargetFilter, metricsFactory MetricsFactory) ([]byte, error)

var TargetForbiddenError = errors.New("Target forbidden")

type gatewayResource struct {
	verbose        bool
	keyID          uint8
	gateway        ohttp.Gateway
	handlers       map[string]ContentHandler
	allowedOrigins map[string]bool
	metricsFactory MetricsFactory
}

const (
	ohttpRequestContentType  = "message/ohttp-req"
	ohttpResponseContentType = "message/ohttp-res"
)

func (s *gatewayResource) parseEncapsulatedRequestFromContent(r *http.Request) (ohttp.EncapsulatedRequest, error) {
	if r.Method != http.MethodPost {
		return ohttp.EncapsulatedRequest{}, fmt.Errorf("Unsupported HTTP method for Oblivious DNS query: %s", r.Method)
	}

	defer r.Body.Close()
	encryptedMessageBytes, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return ohttp.EncapsulatedRequest{}, err
	}

	return ohttp.UnmarshalEncapsulatedRequest(encryptedMessageBytes)
}

func (s *gatewayResource) checkAllowList(targetOrigin string) bool {
	if s.allowedOrigins != nil {
		_, ok := s.allowedOrigins[targetOrigin]
		return ok // Allow if the origin is in the allowed list
	}
	return true
}

func (s *gatewayResource) gatewayHandler(w http.ResponseWriter, r *http.Request) {
	metrics := s.metricsFactory("gateway")

	if s.verbose {
		log.Printf("%s Handling %s\n", r.Method, r.URL.Path)
	}

	if r.Header.Get("Content-Type") != ohttpRequestContentType {
		log.Printf("Invalid content type: %s", r.Header.Get("Content-Type"))
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		metrics.Fire("invalid_content_type")
		return
	}

	encapsulatedRequest, err := s.parseEncapsulatedRequestFromContent(r)
	if err != nil {
		log.Println("parseEncapsulatedRequestFromContent failed:", err)
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		metrics.Fire("invalid_encapsulated_request")
		return
	}

	if encapsulatedRequest.KeyID != s.keyID {
		log.Printf("Invalid request key")
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		metrics.Fire("decapsulate_request_invalid_key_error")
		return
	}

	binaryRequest, context, err := s.gateway.DecapsulateRequest(encapsulatedRequest)
	if err != nil {
		log.Println("DecapsulateRequest failed:", err)
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		metrics.Fire("decapsulate_request_error")
		return
	}

	var handler ContentHandler
	var ok bool
	if handler, ok = s.handlers[r.URL.Path]; !ok {
		log.Printf("Unknown handler for %s", r.URL.Path)
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		metrics.Fire("unknown_handler")
		return
	}

	// Dispatch to the content handler bound to the URL path
	binaryResponse, err := handler(r, binaryRequest, s.checkAllowList, s.metricsFactory)
	if err != nil {
		if err == TargetForbiddenError {
			log.Println("Target forbidden:", err)
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			metrics.Fire("forbidden_target")
			return
		} else {
			log.Println("Content handler failed:", err)
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			metrics.Fire("content_handler_error")
			return
		}
	}

	encapsulatedResponse, err := context.EncapsulateResponse(binaryResponse)
	if err != nil {
		log.Println("EncapsulateResponse failed:", err)
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		metrics.Fire("encapsulate_response_error")
		return
	}
	packedResponse := encapsulatedResponse.Marshal()

	if s.verbose {
		log.Printf("Target response: %x", packedResponse)
	}

	w.Header().Set("Content-Type", ohttpResponseContentType)
	w.Write(packedResponse)
	metrics.Fire("success")
}

func (s *gatewayResource) configHandler(w http.ResponseWriter, r *http.Request) {
	metrics := s.metricsFactory("config")

	log.Printf("%s Handling %s\n", r.Method, r.URL.Path)

	config, err := s.gateway.Config(s.keyID)
	if err != nil {
		log.Printf("Config unavailable")
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		metrics.Fire("config_unavailable_error")
		return
	}

	w.Write(config.Marshal())
	metrics.Fire("success")
}
