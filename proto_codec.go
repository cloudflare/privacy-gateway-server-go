// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"bytes"
	"fmt"
	"io"
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
		authority = request.Headers["Host"]
		if authority == "" {
			authority = request.Headers["host"]
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
	for name, value := range request.Headers {
		targetRequest.Header.Set(name, value)
	}

	return targetRequest, nil
}

func responseToProtoHTTP(targetResponse *http.Response) (*Response, error) {
	defer targetResponse.Body.Close()
	responseContent, err := io.ReadAll(targetResponse.Body)
	if err != nil {
		return nil, err
	}

	responseHeaders := make(map[string]string)
	for name, _ := range targetResponse.Header {
		responseHeaders[name] = targetResponse.Header.Get(name)
	}

	return &Response{
		StatusCode: int32(targetResponse.StatusCode),
		Headers:    responseHeaders,
		Body:       responseContent,
	}, nil
}
