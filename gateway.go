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
type ContentHandler func(request *http.Request, requestBody []byte, filter TargetFilter) ([]byte, error)

var TargetForbiddenError = errors.New("Target forbidden")

type gatewayResource struct {
	verbose        bool
	keyID          uint8
	gateway        ohttp.Gateway
	handlers       map[string]ContentHandler
	allowedOrigins map[string]bool
	debugResponse  bool
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

func (s *gatewayResource) httpError(w http.ResponseWriter, status int, debugMessage string) {
	log.Println(debugMessage)
	if s.debugResponse {
		http.Error(w, debugMessage, status)
	} else {
		http.Error(w, http.StatusText(status), status)
	}
}

func (s *gatewayResource) gatewayHandler(w http.ResponseWriter, r *http.Request) {
	if s.verbose {
		log.Printf("%s Handling %s\n", r.Method, r.URL.Path)
	}

	if r.Header.Get("Content-Type") != ohttpRequestContentType {
		s.httpError(w, http.StatusBadRequest, fmt.Sprintf("Invalid content type: %s", r.Header.Get("Content-Type")))
		return
	}

	encapsulatedRequest, err := s.parseEncapsulatedRequestFromContent(r)
	if err != nil {
		s.httpError(w, http.StatusBadRequest, fmt.Sprintf("parseEncapsulatedRequestFromContent failed: %s", err.Error()))
		return
	}

	if encapsulatedRequest.KeyID != s.keyID {
		s.httpError(w, http.StatusUnauthorized, "Invalid request key")
		return
	}

	binaryRequest, context, err := s.gateway.DecapsulateRequest(encapsulatedRequest)
	if err != nil {
		s.httpError(w, http.StatusBadRequest, fmt.Sprintf("DecapsulateRequest failed: %s", err.Error()))
		return
	}

	var handler ContentHandler
	var ok bool
	if handler, ok = s.handlers[r.URL.Path]; !ok {
		s.httpError(w, http.StatusBadRequest, fmt.Sprintf("Unknown handler for %s", r.URL.Path))
		return
	}

	// Dispatch to the content handler bound to the URL path
	binaryResponse, err := handler(r, binaryRequest, s.checkAllowList)
	if err != nil {
		if err == TargetForbiddenError {
			s.httpError(w, http.StatusForbidden, fmt.Sprintf("Target forbidden: %s", err.Error()))
			return
		} else {
			s.httpError(w, http.StatusBadRequest, fmt.Sprintf("Content handler failed: %s", err.Error()))
			return
		}
	}

	encapsulatedResponse, err := context.EncapsulateResponse(binaryResponse)
	if err != nil {
		s.httpError(w, http.StatusBadRequest, fmt.Sprintf("EncapsulateResponse failed: %s", err.Error()))
		return
	}
	packedResponse := encapsulatedResponse.Marshal()

	if s.verbose {
		log.Printf("Target response: %x", packedResponse)
	}

	w.Header().Set("Content-Type", ohttpResponseContentType)
	w.Write(packedResponse)
}

func (s *gatewayResource) configHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("%s Handling %s\n", r.Method, r.URL.Path)

	config, err := s.gateway.Config(s.keyID)
	if err != nil {
		s.httpError(w, http.StatusInternalServerError, "Config unavailable")
		return
	}

	w.Write(config.Marshal())
}
