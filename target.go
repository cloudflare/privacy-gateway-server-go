// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httputil"

	"github.com/chris-wood/ohttp-go"
)

type gatewayResource struct {
	verbose            bool
	keyID              uint8
	gateway            ohttp.Gateway
	serverInstanceName string
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

func (s *gatewayResource) gatewayRequestHandler(w http.ResponseWriter, r *http.Request) {
	encapsulatedRequest, err := s.parseEncapsulatedRequestFromContent(r)
	if err != nil {
		log.Println("parseEncapsulatedRequestFromContent failed:", err)
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	binaryRequest, context, err := s.gateway.DecapsulateRequest(encapsulatedRequest)
	if err != nil {
		log.Println("DecapsulateRequest failed:", err)
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	request, err := ohttp.UnmarshalBinaryRequest(binaryRequest)
	if err != nil {
		log.Println("UnmarshalBinaryRequest failed:", err)
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	if s.verbose {
		encRequest, err := httputil.DumpRequest(request, true)
		if err != nil {
			log.Println("DumpRequest failed:", err)
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		log.Println("Decoded request:", string(encRequest))
	}

	client := &http.Client{}
	response, err := client.Do(request)
	if err != nil {
		log.Println("Target fetch failed:", err)
		http.Error(w, http.StatusText(http.StatusBadGateway), http.StatusBadGateway) // XXX(caw): pick a better name for this
		return
	}

	binaryResponse := ohttp.CreateBinaryResponse(response)
	encodedResponse, err := binaryResponse.Marshal()
	if err != nil {
		log.Println("Binary response encoding failed:", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	encapsulatedResponse, err := context.EncapsulateResponse(encodedResponse)
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

func (s *gatewayResource) echoRequestHandler(w http.ResponseWriter, r *http.Request) {
	encapsulatedRequest, err := s.parseEncapsulatedRequestFromContent(r)
	if err != nil {
		log.Println("parseEncapsulatedRequestFromContent failed:", err)
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	binaryRequest, context, err := s.gateway.DecapsulateRequest(encapsulatedRequest)
	if err != nil {
		log.Println("DecapsulateRequest failed:", err)
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	encapsulatedResponse, err := context.EncapsulateResponse(binaryRequest)
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

func (s *gatewayResource) targetQueryHandler(w http.ResponseWriter, r *http.Request) {
	if s.verbose {
		log.Printf("%s Handling %s\n", r.Method, r.URL.Path)
	}

	if r.Header.Get("Content-Type") == ohttpRequestContentType {
		s.gatewayRequestHandler(w, r)
	} else {
		log.Printf("Invalid content type: %s", r.Header.Get("Content-Type"))
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
	}
}

func (s *gatewayResource) echoQueryHandler(w http.ResponseWriter, r *http.Request) {
	if s.verbose {
		log.Printf("%s Handling %s\n", r.Method, r.URL.Path)
	}

	if r.Header.Get("Content-Type") == ohttpRequestContentType {
		s.echoRequestHandler(w, r)
	} else {
		log.Printf("Invalid content type: %s", r.Header.Get("Content-Type"))
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
	}
}

func (s *gatewayResource) configHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("%s Handling %s\n", r.Method, r.URL.Path)

	config, err := s.gateway.Config(s.keyID)
	if err != nil {
		log.Printf("Config unavailable")
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	w.Write(config.Marshal())
}
