package ohttp

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
)

type BinaryRequest http.Request
type BinaryResponse http.Response

type frameIndicator uint64

const (
	knownLengthRequestFrame    = frameIndicator(0)
	knownLengthResponseFrame   = frameIndicator(1)
	unknownLengthRequestFrame  = frameIndicator(2)
	unknownLengthResponseFrame = frameIndicator(3)
)

func (f frameIndicator) Marshal() []byte {
	b := new(bytes.Buffer)
	Write(b, uint64(f))
	return b.Bytes()
}

func UnmarshalFrameIndicator(b io.ByteReader) (frameIndicator, error) {
	val, err := Read(b)
	if err != nil {
		return 0, err
	}
	return frameIndicator(val), nil
}

func encodeVarintSlice(b *bytes.Buffer, data []byte) {
	Write(b, uint64(len(data)))
	b.Write([]byte(data))
}

func readVarintSlice(b *bytes.Buffer) ([]byte, error) {
	len, err := Read(b)
	if err != nil {
		return nil, err
	}
	value := make([]byte, len)
	_, err = b.Read(value)
	if err != nil {
		return nil, err
	}

	return value, nil
}

// Request with Known-Length {
// 	Framing Indicator (i) = 0,
// 	Request Control Data (..),
// 	Known-Length Field Section (..),
// 	Known-Length Content (..),
// 	Known-Length Field Section (..),
// 	Padding (..),
// }
func (r *BinaryRequest) Marshal() ([]byte, error) {
	b := new(bytes.Buffer)

	// Framing
	b.Write(knownLengthRequestFrame.Marshal())

	// Control data
	controlData := createRequestControlData(r)
	b.Write(controlData.Marshal())

	// Header fields
	fields := requestHeaderFields(r)
	encodeVarintSlice(b, fields.Marshal())

	// Content
	if r.Body != nil {
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			return nil, err
		}
		encodeVarintSlice(b, body)
	} else {
		encodeVarintSlice(b, []byte{})
	}

	// Trailer fields
	// Note: trailer fields are currently not supported
	Write(b, uint64(0))

	return b.Bytes(), nil
}

func UnmarshalBinaryRequest(data []byte) (*http.Request, error) {
	b := bytes.NewBuffer(data)

	// Framing
	indicator, err := UnmarshalFrameIndicator(b)
	if err != nil {
		return nil, err
	}

	// Filter based on the type of frame
	switch indicator {
	case knownLengthRequestFrame:
		break
	case knownLengthResponseFrame:
		return nil, fmt.Errorf("Expected binary HTTP request, not binary HTTP response")
	case unknownLengthRequestFrame:
	case unknownLengthResponseFrame:
	default:
		return nil, fmt.Errorf("Unsupported binary HTTP message type")
	}

	// Control data
	controlData, err := UnmarshalRequestControlData(b)
	if err != nil {
		return nil, err
	}

	// Sanity check the method
	switch controlData.method {
	case http.MethodGet:
		break
	case http.MethodPost:
		break
	default:
		return nil, fmt.Errorf("Unsupported binary HTTP message request method: %s", controlData.method)
	}

	// Header fields
	fields := new(fieldList)
	encodedFieldData, err := readVarintSlice(b)
	if err != nil {
		return nil, err
	}
	err = fields.Unmarshal(bytes.NewBuffer(encodedFieldData))
	if err != nil {
		return nil, err
	}
	headerMap := make(map[string]string)
	for _, field := range fields.fields {
		headerMap[field.name] = field.value
	}

	// Reconstruct the URL from Scheme, Authority, and Path
	authority := controlData.authority
	if authority == "" {
		authority = headerMap["Host"]
		if authority == "" {
			authority = headerMap["host"]
		}
	}
	url, err := url.Parse(fmt.Sprintf("%s://%s%s", controlData.scheme, authority, controlData.path))
	if err != nil {
		return nil, err
	}

	// Content
	content, err := readVarintSlice(b)
	if err != nil {
		return nil, err
	}

	// Trailer
	// XXX(caw): this is currently unsupported

	// Construct the raw request
	request, err := http.NewRequest(controlData.method, url.String(), bytes.NewBuffer(content))
	if err != nil {
		return nil, err
	}
	for _, field := range fields.fields {
		request.Header.Set(field.name, field.value)
	}

	return request, nil
}

// Request Control Data {
// 	Method Length (i),
// 	Method (..),
// 	Scheme Length (i),
// 	Scheme (..),
// 	Authority Length (i),
// 	Authority (..),
// 	Path Length (i),
// 	Path (..),
// }
type requestControlData struct {
	method    string
	scheme    string
	authority string
	path      string
}

func createRequestControlData(r *BinaryRequest) requestControlData {
	return requestControlData{
		method:    r.Method,
		scheme:    r.URL.Scheme,
		authority: r.Host,
		path:      r.URL.Path,
	}
}

func (d requestControlData) Marshal() []byte {
	b := new(bytes.Buffer)

	encodeVarintSlice(b, []byte(d.method))
	encodeVarintSlice(b, []byte(d.scheme))
	encodeVarintSlice(b, []byte(d.authority))
	encodeVarintSlice(b, []byte(d.path))

	return b.Bytes()
}

func UnmarshalRequestControlData(b *bytes.Buffer) (requestControlData, error) {
	method, err := readVarintSlice(b)
	if err != nil {
		return requestControlData{}, err
	}

	scheme, err := readVarintSlice(b)
	if err != nil {
		return requestControlData{}, err
	}

	authority, err := readVarintSlice(b)
	if err != nil {
		return requestControlData{}, err
	}

	path, err := readVarintSlice(b)
	if err != nil {
		return requestControlData{}, err
	}

	return requestControlData{
		method:    string(method),
		scheme:    string(scheme),
		authority: string(authority),
		path:      string(path),
	}, nil
}

// Final Response Control Data {
// 	Status Code (i) = 200..599,
//   }
type responseControlData struct {
	statusCode int
}

func createResponseControlData(r *BinaryResponse) responseControlData {
	return responseControlData{
		statusCode: r.StatusCode,
	}
}

func (d responseControlData) Marshal() []byte {
	b := new(bytes.Buffer)
	Write(b, uint64(d.statusCode))
	return b.Bytes()
}

func UnmarshalResponseControlData(b *bytes.Buffer) (responseControlData, error) {
	statusCode, err := Read(b)
	if err != nil {
		return responseControlData{}, err
	}
	return responseControlData{
		statusCode: int(statusCode),
	}, nil
}

type field struct {
	name  string
	value string
}

func createHeaderFields(h http.Header) fieldList {
	fields := make([]field, len(h))

	i := 0
	for h, v := range h {
		// Convert the list of values to a string
		b := new(bytes.Buffer)
		for _, s := range v {
			b.Write([]byte(s))
			b.Write([]byte(" "))
		}

		fields[i] = field{
			name:  strings.ToLower(h),
			value: string(b.Bytes()),
		}

		i++
	}

	return fieldList{fields}
}

func requestHeaderFields(r *BinaryRequest) fieldList {
	return createHeaderFields(r.Header)
}

func responseHeaderFields(r *BinaryResponse) fieldList {
	return createHeaderFields(r.Header)
}

func (f field) Marshal() []byte {
	b := new(bytes.Buffer)

	encodeVarintSlice(b, []byte(f.name))
	encodeVarintSlice(b, []byte(f.value))

	return b.Bytes()
}

func (f *field) Unmarshal(b *bytes.Buffer) error {
	name, err := readVarintSlice(b)
	if err != nil {
		return err
	}

	value, err := readVarintSlice(b)
	if err != nil {
		return err
	}

	f.name = strings.ToLower(string(name))
	f.value = string(value)

	return nil
}

type fieldList struct {
	fields []field
}

func (l fieldList) Marshal() []byte {
	b := new(bytes.Buffer)
	for _, f := range l.fields {
		b.Write(f.Marshal())
	}
	return b.Bytes()
}

func (l *fieldList) Unmarshal(b *bytes.Buffer) error {
	fields := make([]field, 0)
	for {
		if b.Len() == 0 {
			break
		}

		field := new(field)
		err := field.Unmarshal(b)
		if err != nil {
			return err
		}

		fields = append(fields, *field)
	}

	l.fields = fields

	return nil
}

///////
// Responses

type finalResponseControlData struct {
	statusCode int // 200..599
}

func (d finalResponseControlData) Marshal() []byte {
	b := new(bytes.Buffer)
	Write(b, uint64(d.statusCode))
	return b.Bytes()
}

type infoResponseControlData struct {
	statusCode int // 100..199
}

func (d infoResponseControlData) Marshal() []byte {
	b := new(bytes.Buffer)
	Write(b, uint64(d.statusCode))
	return b.Bytes()
}

// Response with Known-Length {
// 	Framing Indicator (i) = 1,
// 	Known-Length Informational Response (..) ...,
// 	Final Response Control Data (..),
// 	Known-Length Field Section (..),
// 	Known-Length Content (..),
// 	Known-Length Field Section (..),
// 	Padding (..),
//   }
func (r *BinaryResponse) Marshal() ([]byte, error) {
	b := new(bytes.Buffer)

	// Framing
	b.Write(knownLengthResponseFrame.Marshal())

	// Response control data
	controlData := finalResponseControlData{r.StatusCode}
	b.Write(controlData.Marshal())

	// Header fields
	fields := responseHeaderFields(r)
	encodeVarintSlice(b, fields.Marshal())

	// Content
	if r.Body != nil {
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			return nil, err
		}
		encodeVarintSlice(b, body)
	} else {
		encodeVarintSlice(b, []byte{})
	}

	return b.Bytes(), nil
}

func CreateBinaryResponse(resp *http.Response) BinaryResponse {
	return BinaryResponse(*resp)
}
