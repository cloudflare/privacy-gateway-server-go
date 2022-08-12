// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"time"

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
	if s.verbose {
		log.Printf("%s Handling %s\n", r.Method, r.URL.Path)
	}

	if r.Header.Get("Content-Type") != ohttpRequestContentType {
		log.Printf("Invalid content type: %s", r.Header.Get("Content-Type"))
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	encapsulatedRequest, err := s.parseEncapsulatedRequestFromContent(r)
	if err != nil {
		log.Println("parseEncapsulatedRequestFromContent failed:", err)
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	if encapsulatedRequest.KeyID != s.keyID {
		log.Printf("Invalid request key")
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}

	binaryRequest, context, err := s.gateway.DecapsulateRequest(encapsulatedRequest)
	if err != nil {
		log.Println("DecapsulateRequest failed:", err)
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	var handler ContentHandler
	var ok bool
	if handler, ok = s.handlers[r.URL.Path]; !ok {
		log.Printf("Unknown handler for %s", r.URL.Path)
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	// Dispatch to the content handler bound to the URL path
	binaryResponse, err := handler(r, binaryRequest, s.checkAllowList)
	if err != nil {
		if err == TargetForbiddenError {
			log.Println("Target forbidden:", err)
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		} else {
			log.Println("Content handler failed:", err)
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
	}

	encapsulatedResponse, err := context.EncapsulateResponse(binaryResponse)
	if err != nil {
		log.Println("EncapsulateResponse failed:", err)
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
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
		log.Printf("Config unavailable")
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	// Make expiration time even/random throughout interval 12-36h
	// So the avg will be 24h but without spikes of the requests for the key renewal
	rand.Seed(time.Now().UnixNano())
	maxAge := 12*3600 + rand.Intn(24*3600)
	w.Header().Set("Cache-Control", fmt.Sprintf("max-age=%d, private", maxAge))

	w.Write(config.Marshal())
}
