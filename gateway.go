// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"bufio"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"github.com/golang/protobuf/proto"
	"io"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/chris-wood/ohttp-go"
)

type gatewayResource struct {
	verbose               bool
	keyID                 uint8
	gateway               ohttp.Gateway
	encapsulationHandlers map[string]EncapsulationHandler
	debug                 bool
	metricsFactory        MetricsFactory
}

const (
	ohttpRequestContentType  = "message/ohttp-req"
	ohttpResponseContentType = "message/ohttp-res"
	twelveHours              = 12 * 3600
	twentyFourHours          = 24 * 3600

	// Metrics constants
	metricsEventMarshalRequest      = "marshal_request"
	metricsEventGatewayRequest      = "gateway_request"
	metricsResultInvalidMethod      = "invalid_method"
	metricsResultInvalidContentType = "invalid_content_type"
	metricsResultInvalidContent     = "invalid_content"
)

func (s *gatewayResource) httpError(w http.ResponseWriter, status int, debugMessage string) {
	if s.verbose {
		log.Println(debugMessage)
	}
	if s.debug {
		http.Error(w, debugMessage, status)
	} else {
		http.Error(w, http.StatusText(status), status)
	}
}

func (s *gatewayResource) gatewayHandler(w http.ResponseWriter, r *http.Request) {
	if s.verbose {
		log.Printf("%s Handling %s\n", r.Method, r.URL.Path)
	}

	metrics := s.metricsFactory.Create(metricsEventGatewayRequest)

	if r.Method != http.MethodPost {
		metrics.Fire(metricsResultInvalidMethod)
		s.httpError(w, http.StatusBadRequest, fmt.Sprintf("Invalid method: %s", r.Method))
		return
	}
	if r.Header.Get("Content-Type") != ohttpRequestContentType {
		metrics.Fire(metricsResultInvalidContentType)
		s.httpError(w, http.StatusBadRequest, fmt.Sprintf("Invalid content type: %s", r.Header.Get("Content-Type")))
		return
	}

	var encapHandler EncapsulationHandler
	var ok bool
	if encapHandler, ok = s.encapsulationHandlers[r.URL.Path]; !ok {
		s.httpError(w, http.StatusBadRequest, fmt.Sprintf("Unknown handler"))
		return
	}

	defer r.Body.Close()
	encryptedMessageBytes, err := ioutil.ReadAll(r.Body)
	if err != nil {
		metrics.Fire(metricsResultInvalidContent)
		s.httpError(w, http.StatusBadRequest, fmt.Sprintf("Reading request body failed"))
		return
	}

	if s.verbose {
		log.Printf("Request body: %s\n", hex.EncodeToString(encryptedMessageBytes))
	}

	encapsulatedReq, err := ohttp.UnmarshalEncapsulatedRequest(encryptedMessageBytes)
	if err != nil {
		metrics.Fire(metricsResultInvalidContent)
		s.httpError(w, http.StatusBadRequest, fmt.Sprintf("Reading request body failed"))
		return
	}

	encapsulatedResp, err := encapHandler.Handle(r, encapsulatedReq, metrics)
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

	w.Header().Set("Content-Type", ohttpResponseContentType)
	w.Write(packedResponse)
}

func (s *gatewayResource) marshalHandler(w http.ResponseWriter, r *http.Request) {
	if !s.debug {
		s.httpError(w, http.StatusForbidden, "Forbidden. Allowed in debug mode only.")
	}

	if s.verbose {
		log.Printf("%s Handling %s\n", r.Method, r.URL.Path)
	}

	metrics := s.metricsFactory.Create(metricsEventMarshalRequest)
	metrics.Fire(metricsResultRequested)

	if r.Method != http.MethodPost {
		s.httpError(w, http.StatusBadRequest, fmt.Sprintf("Invalid method: %s", r.Method))
		return
	}

	defer r.Body.Close()
	bodyBytes, err := ioutil.ReadAll(r.Body)
	if err != nil {
		s.httpError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if s.verbose {
		log.Printf("Body to parse: %s", string(bodyBytes))
	}

	var decoder = base64.NewDecoder(base64.StdEncoding, strings.NewReader(string(bodyBytes)))
	var reader1 = bufio.NewReader(decoder)
	var decodedBody = ""
	if b, err := io.ReadAll(reader1); err == nil {
		decodedBody = string(b)
		if s.verbose {
			log.Printf("Body to parse base64 decoded: %s", decodedBody)
		}
	}

	var parsedReq, er = http.ReadRequest(bufio.NewReader(strings.NewReader(decodedBody)))
	if er != nil {
		s.httpError(w, http.StatusBadRequest, fmt.Sprintf("Reading request body failed: %s", er.Error()))
		return
	}

	protoRequest, err := requestToProtoHTTP(parsedReq)
	if err != nil {
		s.httpError(w, http.StatusInternalServerError, "Protobuf marshalling failed")
		return
	}
	protoMarshalled, err := proto.Marshal(protoRequest)

	config, err := s.gateway.Config(s.keyID)
	if err != nil {
		log.Printf("Config unavailable")
		s.httpError(w, http.StatusInternalServerError, "Config unavailable")
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	// todo: get labels there instead of hardcode
	ohttpClient := ohttp.NewCustomClient(config, "message/protohttp request", "message/protohttp response")
	encapsulated, _, err := ohttpClient.EncapsulateRequest(protoMarshalled)

	packedRequest := encapsulated.Marshal()

	w.Header().Set("Content-Type", ohttpResponseContentType)
	w.Header().Set("Content-Length", strconv.Itoa(len(packedRequest)))
	w.Write(packedRequest)

	metrics.Fire(metricsResultSuccess)
}

func (s *gatewayResource) configHandler(w http.ResponseWriter, r *http.Request) {
	if s.verbose {
		log.Printf("%s Handling %s\n", r.Method, r.URL.Path)
	}

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
