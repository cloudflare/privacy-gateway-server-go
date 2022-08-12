// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"io/ioutil"
	"fmt"
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
}

const (
	ohttpRequestContentType  = "message/ohttp-req"
	ohttpResponseContentType = "message/ohttp-res"
	twelveHours              = 12 * 3600
	twentyFourHours          = 24 * 3600
)

func (s *gatewayResource) parseEncapsulatedRequestFromContent(r *http.Request) (ohttp.EncapsulatedRequest, error) {
	defer r.Body.Close()
	encryptedMessageBytes, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return ohttp.EncapsulatedRequest{}, err
	}

	return ohttp.UnmarshalEncapsulatedRequest(encryptedMessageBytes)
}

func (s *gatewayResource) gatewayHandler(w http.ResponseWriter, r *http.Request) {
	if s.verbose {
		log.Printf("%s Handling %s\n", r.Method, r.URL.Path)
	}
	if r.Method != http.MethodPost {
		log.Printf("Unsupported HTTP method: %s", r.Method)
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	if r.Header.Get("Content-Type") != ohttpRequestContentType {
		log.Printf("Invalid content type: %s", r.Header.Get("Content-Type"))
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	var encapHandler EncapsulationHandler
	var ok bool
	if encapHandler, ok = s.encapsulationHandlers[r.URL.Path]; !ok {
		log.Printf("Unknown handler for %s", r.URL.Path)
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	encapsulatedReq, err := s.parseEncapsulatedRequestFromContent(r)
	if err != nil {
		log.Println("parseEncapsulatedRequestFromContent failed:", err)
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	encapsulatedResp, err := encapHandler.Handle(r, encapsulatedReq)
	if err != nil {
		if s.verbose {
			log.Println(err)
		}
		if err == ConfigMismatchError {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		} else {
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
	}

	packedResponse := encapsulatedResp.Marshal()

	if s.verbose {
		log.Printf("Gateway response: %x", packedResponse)
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
	rand.Seed(time.Now().UnixNano())
	maxAge := twelveHours + rand.Intn(twentyFourHours)
	w.Header().Set("Cache-Control", fmt.Sprintf("max-age=%d, private", maxAge))

	w.Write(config.Marshal())
}
