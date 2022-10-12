package main

import (
	"bufio"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/chris-wood/ohttp-go"
	"google.golang.org/protobuf/proto"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
)

// This is only load-tests related functionality.

// The intent of the MarshalEncapsulationHandler is
// to compose a valid OHTTP-encapsulated request that would be performed by the load test over the gateway
// emulating client behaviour.
// Marshal handler is called only once per load test during the initialization phase.
// Later this request is performed thousands of times within the load test.
type MarshalEncapsulationHandler struct {
	keyID      uint8
	gateway    ohttp.Gateway
	appHandler AppContentHandler
}

func (h MarshalEncapsulationHandler) BadRequest(details string) (ohttp.EncapsulatedResponse, error) {
	return ohttp.EncapsulatedResponse{}, errors.New(details)
}

// Here the outerRequest request is NOT OHTTP-encapsulated one.
// But instead it is a base64 encoded(encapsulated) text representation of the HTTP request.
// The handler parses this payload text HTTP request into in-memory HTTP request object
//    but instead of performing it over Target flo server,
// The handler returns OHTTP-encapsulated request in a same form as if it is created by mobile client.
func (h MarshalEncapsulationHandler) Handle(r *http.Request, noData ohttp.EncapsulatedRequest, metrics Metrics) (ohttp.EncapsulatedResponse, error) {
	metrics.Fire(metricsResultSuccess)

	defer r.Body.Close()
	bodyBytes, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return h.BadRequest("Invalid request body")
	}

	log.Printf("Body to parse: %s", string(bodyBytes))

	var decoder = base64.NewDecoder(base64.StdEncoding, strings.NewReader(string(bodyBytes)))
	var reader1 = bufio.NewReader(decoder)
	var decodedBody = ""
	if b, errr := io.ReadAll(reader1); errr == nil {
		decodedBody = string(b)
		log.Printf("Body to parse base64 decoded: %s", decodedBody)
	} else if errr != nil {
		log.Printf("ReadAll error: %s", errr)
		return h.BadRequest("ReadAll error")
	}

	decapsulatedBytes := []byte(decodedBody)

	protoMarshalled, err := h.appHandler.Handle(decapsulatedBytes, metrics)
	if err != nil {
		details := fmt.Sprintf("MarshalAppHandler error: %s", err.Error())
		log.Printf(details)
		return h.BadRequest(details)
	}

	config, err := h.gateway.Config(h.keyID)
	if err != nil {
		details := fmt.Sprintf("Config unavailable: %s", err.Error())
		log.Printf(details)
		return h.BadRequest(details)
	}

	// todo: get labels there instead of hardcode
	ohttpClient := ohttp.NewCustomClient(config, "message/protohttp request", "message/protohttp response")
	encapsulated, _, err := ohttpClient.EncapsulateRequest(protoMarshalled)

	packedRequest := encapsulated.Marshal()

	// non-intuitive naming but here we just return packedRequest in accordance to method signature
	return ohttp.UnmarshalEncapsulatedResponse(packedRequest)
}

// EchoAppHandler is an AppContentHandler that returns the application request as the response.
type MarshalAppHandler struct {
}

// Handle returns the input request as the response.
func (h MarshalAppHandler) Handle(binaryRequest []byte, metrics Metrics) ([]byte, error) {
	var parsedReq, er = http.ReadRequest(bufio.NewReader(strings.NewReader(string(binaryRequest))))
	if er != nil {
		details := fmt.Sprintf("http text request to in-mem request object parsing failed: %s", er.Error())
		return nil, errors.New(details)
	}

	protoRequest, err := requestToProtoHTTP(parsedReq)
	if err != nil {
		details := fmt.Sprintf("in-mem http req object to Protobuf object conversion failed: %s", err.Error())
		return nil, errors.New(details)
	}

	protoMarshalled, err := proto.Marshal(protoRequest)
	if err != nil {
		details := fmt.Sprintf("Protobuf marshalling failed: %s", err.Error())
		return nil, errors.New(details)
	}

	return protoMarshalled, nil
}
