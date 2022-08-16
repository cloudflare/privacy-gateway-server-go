// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
)

var requestMethodMap = map[Request_Method]string{
	Request_GET:     "GET",
	Request_HEAD:    "HEAD",
	Request_DELETE:  "DELETE",
	Request_POST:    "POST",
	Request_PUT:     "PUT",
	Request_PATCH:   "PATCH",
	Request_OPTIONS: "OPTIONS",
	Request_TRACE:   "TRACE",
}

var requestSchemeMap = map[Request_Scheme]string{
	Request_HTTP:  "http",
	Request_HTTPS: "https",
}

func requestToProtoHTTP(request *http.Request) (*Request, error) {
	req := &Request{}

	switch request.Method {
	case http.MethodGet:
		req.Method = Request_GET
	case http.MethodHead:
		req.Method = Request_HEAD
	case http.MethodPost:
		req.Method = Request_POST
	case http.MethodOptions:
		req.Method = Request_OPTIONS
	case http.MethodPut:
		req.Method = Request_PUT
	case http.MethodDelete:
		req.Method = Request_DELETE
	default:
		break
	}

	if request.URL.Scheme == "http" || request.URL.Scheme == "HTTP" {
		req.Scheme = Request_HTTP
	} else {
		req.Scheme = Request_HTTPS
	}

	req.Authority = request.Host

	req.Headers = []*HeaderNameValue{}
	for name, value := range request.Header {
		for _, val := range value {
			var nv = new(HeaderNameValue)
			nv.Name = name
			nv.Value = val
			req.Headers = append(req.Headers, nv)
		}
	}
	if request.Body != nil {
		body, err := ioutil.ReadAll(request.Body)
		if err != nil {
			return nil, err
		}

		req.Body = body
	}

	return req, nil
}

func protoHTTPToRequest(request *Request) (*http.Request, error) {
	var ok bool
	var method string
	if method, ok = requestMethodMap[request.Method]; !ok {
		return nil, fmt.Errorf("Unsupported request method: %s", request.Method)
	}
	var scheme string
	if scheme, ok = requestSchemeMap[request.Scheme]; !ok {
		return nil, fmt.Errorf("Unsupported request scheme: %s", request.Scheme)
	}

	authority := request.Authority
	if authority == "" {
		for i := range request.Headers {
			if request.Headers[i].Name == "Host" || request.Headers[i].Name == "host" {
				authority = request.Headers[i].Value
			}
		}
	}
	url, err := url.Parse(fmt.Sprintf("%s://%s%s", scheme, authority, request.Path))
	if err != nil {
		return nil, err
	}

	targetRequest, err := http.NewRequest(method, url.String(), bytes.NewBuffer(request.Body))
	if err != nil {
		return nil, err
	}
	for _, nv := range request.Headers {
		targetRequest.Header.Add(nv.Name, nv.Value)
	}

	return targetRequest, nil
}

func responseToProtoHTTP(targetResponse *http.Response) (*Response, error) {
	var responseContent []byte
	var err error
	if targetResponse.Body != nil {
		defer targetResponse.Body.Close()
		responseContent, err = io.ReadAll(targetResponse.Body)
		if err != nil {
			return nil, err
		}
	}

	responseHeaders := []*HeaderNameValue{}
	for name, value := range targetResponse.Header {
		for _, val := range value {
			var nv = new(HeaderNameValue)
			nv.Name = name
			nv.Value = val
			responseHeaders = append(responseHeaders, nv)
		}
	}

	return &Response{
		StatusCode: int32(targetResponse.StatusCode),
		Headers:    responseHeaders,
		Body:       responseContent,
	}, nil
}
