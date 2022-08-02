package ohttp

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"

	"github.com/cisco/go-hpke"

	"golang.org/x/crypto/cryptobyte"
)

var (
	defaultLabelRequest  = "message/bhttp request"
	defaultLabelResponse = "message/bhttp response"
	labelResponseKey     = "key"
	labelResponseNonce   = "nonce"
)

type ConfigCipherSuite struct {
	KDFID  hpke.KDFID
	AEADID hpke.AEADID
}

type PublicConfig struct {
	ID             uint8
	KEMID          hpke.KEMID
	Suites         []ConfigCipherSuite
	PublicKeyBytes []byte
}

func (c PublicConfig) IsEqual(o PublicConfig) bool {
	if c.ID != o.ID {
		return false
	}
	if c.KEMID != o.KEMID {
		return false
	}
	if !bytes.Equal(c.PublicKeyBytes, o.PublicKeyBytes) {
		return false
	}
	if len(c.Suites) != len(o.Suites) {
		return false
	}
	for i, s := range c.Suites {
		if s.KDFID != o.Suites[i].KDFID {
			return false
		}
		if s.AEADID != o.Suites[i].AEADID {
			return false
		}
	}

	return true
}

type PrivateConfig struct {
	seed   []byte
	config PublicConfig
	sk     hpke.KEMPrivateKey
	pk     hpke.KEMPublicKey
}

func (c PrivateConfig) Config() PublicConfig {
	return c.config
}

func (c PrivateConfig) PrivateKey() hpke.KEMPrivateKey {
	return c.sk
}

func NewConfigFromSeed(keyID uint8, kemID hpke.KEMID, kdfID hpke.KDFID, aeadID hpke.AEADID, seed []byte) (PrivateConfig, error) {
	suite, err := hpke.AssembleCipherSuite(kemID, kdfID, aeadID)
	if err != nil {
		return PrivateConfig{}, err
	}

	sk, pk, err := suite.KEM.DeriveKeyPair(seed)
	if err != nil {
		return PrivateConfig{}, err
	}

	cs := ConfigCipherSuite{
		KDFID:  kdfID,
		AEADID: aeadID,
	}

	publicConfig := PublicConfig{
		ID:             keyID,
		KEMID:          kemID,
		Suites:         []ConfigCipherSuite{cs},
		PublicKeyBytes: suite.KEM.SerializePublicKey(pk),
	}

	return PrivateConfig{
		seed:   seed,
		config: publicConfig,
		sk:     sk,
		pk:     pk,
	}, nil
}

func NewConfig(keyID uint8, kemID hpke.KEMID, kdfID hpke.KDFID, aeadID hpke.AEADID) (PrivateConfig, error) {
	suite, err := hpke.AssembleCipherSuite(kemID, kdfID, aeadID)
	if err != nil {
		return PrivateConfig{}, err
	}

	ikm := make([]byte, suite.KEM.PrivateKeySize())
	rand.Reader.Read(ikm)

	return NewConfigFromSeed(keyID, kemID, kdfID, aeadID, ikm)
}

func (c PublicConfig) Marshal() []byte {
	b := cryptobyte.NewBuilder(nil)

	b.AddUint8(c.ID)
	b.AddUint16(uint16(c.KEMID))
	b.AddBytes(c.PublicKeyBytes)
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		for _, s := range c.Suites {
			b.AddUint16(uint16(s.KDFID))
			b.AddUint16(uint16(s.AEADID))
		}
	})

	return b.BytesOrPanic()
}

func UnmarshalPublicConfig(data []byte) (PublicConfig, error) {
	s := cryptobyte.String(data)

	var id uint8
	var kemID uint16
	if !s.ReadUint8(&id) ||
		!s.ReadUint16(&kemID) {
		return PublicConfig{}, fmt.Errorf("Invalid config")
	}

	kem := hpke.KEMID(kemID)
	suite, err := hpke.AssembleCipherSuite(kem, hpke.KDF_HKDF_SHA256, hpke.AEAD_AESGCM128)
	if err != nil {
		return PublicConfig{}, fmt.Errorf("Invalid config")
	}

	publicKeyBytes := make([]byte, suite.KEM.PublicKeySize())
	if !s.ReadBytes(&publicKeyBytes, len(publicKeyBytes)) {
		return PublicConfig{}, fmt.Errorf("Invalid config")
	}

	var cipherSuites cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&cipherSuites) {
		return PublicConfig{}, fmt.Errorf("Invalid config")
	}
	suites := []ConfigCipherSuite{}
	for !cipherSuites.Empty() {
		var kdfID uint16
		var aeadID uint16
		if !cipherSuites.ReadUint16(&kdfID) ||
			!cipherSuites.ReadUint16(&aeadID) {
			return PublicConfig{}, fmt.Errorf("Invalid config")
		}

		// Sanity check validity of the KDF and AEAD values
		kdf := hpke.KDFID(kdfID)
		aead := hpke.AEADID(aeadID)
		_, err := hpke.AssembleCipherSuite(kem, kdf, aead)
		if err != nil {
			return PublicConfig{}, fmt.Errorf("Invalid config")
		}

		suites = append(suites, ConfigCipherSuite{
			KDFID:  kdf,
			AEADID: aead,
		})
	}

	return PublicConfig{
		ID:             id,
		KEMID:          kem,
		PublicKeyBytes: publicKeyBytes,
		Suites:         suites,
	}, nil
}

type EncapsulatedRequest struct {
	keyID  uint8
	kemID  hpke.KEMID
	kdfID  hpke.KDFID
	aeadID hpke.AEADID
	enc    []byte
	ct     []byte
}

// Encapsulated Request {
// 	Key Identifier (8),
// 	KEM Identifier (16),
// 	KDF Identifier (16),
// 	AEAD Identifier (16),
// 	Encapsulated KEM Shared Secret (8*Nenc),
// 	AEAD-Protected Request (..),
// }
func (r EncapsulatedRequest) Marshal() []byte {
	b := cryptobyte.NewBuilder(nil)

	b.AddUint8(r.keyID)
	b.AddUint16(uint16(r.kemID))
	b.AddUint16(uint16(r.kdfID))
	b.AddUint16(uint16(r.aeadID))
	b.AddBytes(r.enc)
	b.AddBytes(r.ct)

	return b.BytesOrPanic()
}

func UnmarshalEncapsulatedRequest(enc []byte) (EncapsulatedRequest, error) {
	b := bytes.NewBuffer(enc)

	keyID, err := b.ReadByte()
	if err != nil {
		return EncapsulatedRequest{}, err
	}

	kemIDBuffer := make([]byte, 2)
	_, err = b.Read(kemIDBuffer)
	if err != nil {
		return EncapsulatedRequest{}, err
	}
	kemID := hpke.KEMID(binary.BigEndian.Uint16(kemIDBuffer))

	kdfIDBuffer := make([]byte, 2)
	_, err = b.Read(kdfIDBuffer)
	if err != nil {
		return EncapsulatedRequest{}, err
	}
	kdfID := hpke.KDFID(binary.BigEndian.Uint16(kdfIDBuffer))

	aeadIDBuffer := make([]byte, 2)
	_, err = b.Read(aeadIDBuffer)
	if err != nil {
		return EncapsulatedRequest{}, err
	}
	aeadID := hpke.AEADID(binary.BigEndian.Uint16(aeadIDBuffer))

	suite, err := hpke.AssembleCipherSuite(kemID, kdfID, aeadID)
	if err != nil {
		return EncapsulatedRequest{}, err
	}

	key := make([]byte, suite.KEM.PublicKeySize())
	_, err = b.Read(key)
	if err != nil {
		return EncapsulatedRequest{}, err
	}

	ct := b.Bytes()

	return EncapsulatedRequest{
		keyID:  uint8(keyID),
		kemID:  kemID,
		kdfID:  kdfID,
		aeadID: aeadID,
		enc:    key,
		ct:     ct,
	}, nil
}

type EncapsulatedRequestContext struct {
	responseLabel []byte
	enc           []byte
	suite         hpke.CipherSuite
	context       *hpke.SenderContext
}

type EncapsulatedResponse struct {
	raw []byte
}

// Encapsulated Response {
// 	Nonce (Nk),
// 	AEAD-Protected Response (..),
// }
func (r EncapsulatedResponse) Marshal() []byte {
	return r.raw
}

func UnmarshalEncapsulatedResponse(enc []byte) (EncapsulatedResponse, error) {
	return EncapsulatedResponse{
		raw: enc,
	}, nil
}

type EncapsulatedResponseContext struct {
}

type Client struct {
	requestLabel  []byte
	responseLabel []byte
	config        PublicConfig
	skE           hpke.KEMPrivateKey
}

func NewDefaultClient(config PublicConfig) Client {
	return Client{
		requestLabel:  []byte(defaultLabelRequest),
		responseLabel: []byte(defaultLabelResponse),
		config:        config,
	}
}

func NewCustomClient(config PublicConfig, requestLabel, responseLabel string) Client {
	return Client{
		requestLabel:  []byte(requestLabel),
		responseLabel: []byte(responseLabel),
		config:        config,
	}
}

func (c Client) EncapsulateRequest(request []byte) (EncapsulatedRequest, EncapsulatedRequestContext, error) {
	kemID := c.config.KEMID
	kdfID := c.config.Suites[0].KDFID
	aeadID := c.config.Suites[0].AEADID

	suite, err := hpke.AssembleCipherSuite(c.config.KEMID, kdfID, aeadID)
	if err != nil {
		return EncapsulatedRequest{}, EncapsulatedRequestContext{}, err
	}

	pkR, err := suite.KEM.DeserializePublicKey(c.config.PublicKeyBytes)
	if err != nil {
		return EncapsulatedRequest{}, EncapsulatedRequestContext{}, err
	}

	// if c.skE != nil {
	// 	suite.KEM.SetEphemeralKeyPair(c.skE)
	// }

	info := c.requestLabel
	info = append(info, 0x00)
	info = append(info, c.config.ID)
	buffer := make([]byte, 2)
	binary.BigEndian.PutUint16(buffer, uint16(kemID))
	info = append(info, buffer...)
	binary.BigEndian.PutUint16(buffer, uint16(kdfID))
	info = append(info, buffer...)
	binary.BigEndian.PutUint16(buffer, uint16(aeadID))
	info = append(info, buffer...)

	enc, context, err := hpke.SetupBaseS(suite, rand.Reader, pkR, info)
	if err != nil {
		return EncapsulatedRequest{}, EncapsulatedRequestContext{}, err
	}

	ct := context.Seal(nil, request)

	return EncapsulatedRequest{
			keyID:  c.config.ID,
			kdfID:  kdfID,
			kemID:  kemID,
			aeadID: aeadID,
			enc:    enc,
			ct:     ct,
		}, EncapsulatedRequestContext{
			responseLabel: []byte(c.responseLabel),
			enc:           enc,
			suite:         suite,
			context:       context,
		}, nil
}

func (c EncapsulatedRequestContext) DecapsulateResponse(response EncapsulatedResponse) ([]byte, error) {
	// secret = context.Export("message/bhttp response", Nk)
	secret := c.context.Export(c.responseLabel, c.suite.AEAD.KeySize())

	// response_nonce = random(max(Nn, Nk)), taken from the encapsualted response
	responseNonceLen := max(c.suite.AEAD.KeySize(), c.suite.AEAD.NonceSize())
	responseNonce := make([]byte, responseNonceLen)
	_, err := rand.Read(responseNonce)
	if err != nil {
		return nil, err
	}

	// salt = concat(enc, response_nonce)
	salt := append(c.enc, response.raw[:responseNonceLen]...)

	// prk = Extract(salt, secret)
	prk := c.suite.KDF.Extract(salt, secret)

	// aead_key = Expand(prk, "key", Nk)
	key := c.suite.KDF.Expand(prk, []byte(labelResponseKey), c.suite.AEAD.KeySize())

	// aead_nonce = Expand(prk, "nonce", Nn)
	nonce := c.suite.KDF.Expand(prk, []byte(labelResponseNonce), c.suite.AEAD.NonceSize())

	cipher, err := c.suite.AEAD.New(key)
	if err != nil {
		return nil, err
	}

	// reponse, error = Open(aead_key, aead_nonce, "", ct)
	return cipher.Open(nil, nonce, response.raw[c.suite.AEAD.KeySize():], nil)
}

type Gateway struct {
	requestLabel  []byte
	responseLabel []byte
	// map from IDs to private key(s)
	keyMap map[uint8]PrivateConfig
}

func (g Gateway) Config(keyID uint8) (PublicConfig, error) {
	if config, ok := g.keyMap[keyID]; ok {
		return config.Config(), nil
	}
	return PublicConfig{}, fmt.Errorf("Unknown keyID %d", keyID)
}

func NewDefaultGateway(config PrivateConfig) Gateway {
	return Gateway{
		requestLabel:  []byte(defaultLabelRequest),
		responseLabel: []byte(defaultLabelResponse),
		keyMap: map[uint8]PrivateConfig{
			config.config.ID: config,
		},
	}
}

func NewCustomGateway(config PrivateConfig, requestLabel, responseLabel string) Gateway {
	return Gateway{
		requestLabel:  []byte(requestLabel),
		responseLabel: []byte(responseLabel),
		keyMap: map[uint8]PrivateConfig{
			config.config.ID: config,
		},
	}
}

type DecapsulateRequestContext struct {
	responseLabel []byte
	enc           []byte
	suite         hpke.CipherSuite
	context       *hpke.ReceiverContext
}

func (s Gateway) DecapsulateRequest(req EncapsulatedRequest) ([]byte, DecapsulateRequestContext, error) {
	config, ok := s.keyMap[req.keyID]
	if !ok {
		return nil, DecapsulateRequestContext{}, fmt.Errorf("Unknown key ID")
	}

	suite, err := hpke.AssembleCipherSuite(config.config.KEMID, req.kdfID, req.aeadID)
	if err != nil {
		return nil, DecapsulateRequestContext{}, err
	}

	info := s.requestLabel
	info = append(info, 0x00)
	info = append(info, req.keyID)
	buffer := make([]byte, 2)
	binary.BigEndian.PutUint16(buffer, uint16(req.kemID))
	info = append(info, buffer...)
	binary.BigEndian.PutUint16(buffer, uint16(req.kdfID))
	info = append(info, buffer...)
	binary.BigEndian.PutUint16(buffer, uint16(req.aeadID))
	info = append(info, buffer...)

	context, err := hpke.SetupBaseR(suite, config.sk, req.enc, info)
	if err != nil {
		return nil, DecapsulateRequestContext{}, err
	}

	raw, err := context.Open(nil, req.ct)
	if err != nil {
		return nil, DecapsulateRequestContext{}, err
	}

	return raw, DecapsulateRequestContext{
		responseLabel: s.responseLabel,
		enc:           req.enc,
		suite:         suite,
		context:       context,
	}, nil
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func encapsulateResponse(context *hpke.ReceiverContext, response, responseNonce []byte, enc []byte, suite hpke.CipherSuite, responseLabel []byte) (EncapsulatedResponse, error) {
	// secret = context.Export("message/bhttp response", Nk)
	secret := context.Export(responseLabel, suite.AEAD.KeySize())

	// salt = concat(enc, response_nonce)
	salt := append(append(enc, responseNonce...))

	// prk = Extract(salt, secret)
	prk := suite.KDF.Extract(salt, secret)

	// aead_key = Expand(prk, "key", Nk)
	key := suite.KDF.Expand(prk, []byte(labelResponseKey), suite.AEAD.KeySize())

	// aead_nonce = Expand(prk, "nonce", Nn)
	nonce := suite.KDF.Expand(prk, []byte(labelResponseNonce), suite.AEAD.NonceSize())

	// ct = Seal(aead_key, aead_nonce, "", response)
	cipher, err := suite.AEAD.New(key)
	if err != nil {
		return EncapsulatedResponse{}, err
	}
	ct := cipher.Seal(nil, nonce, response, nil)

	// enc_response = concat(response_nonce, ct)
	return EncapsulatedResponse{
		raw: append(responseNonce, ct...),
	}, nil
}

func (c DecapsulateRequestContext) EncapsulateResponse(response []byte) (EncapsulatedResponse, error) {
	// response_nonce = random(max(Nn, Nk))
	responseNonceLen := max(c.suite.AEAD.KeySize(), c.suite.AEAD.NonceSize())
	responseNonce := make([]byte, responseNonceLen)
	_, err := rand.Read(responseNonce)
	if err != nil {
		return EncapsulatedResponse{}, err
	}

	return encapsulateResponse(c.context, response, responseNonce, c.enc, c.suite, c.responseLabel)
}

func (c DecapsulateRequestContext) encapsulateResponseWithResponseNonce(response []byte, responseNonce []byte) (EncapsulatedResponse, error) {
	return encapsulateResponse(c.context, response, responseNonce, c.enc, c.suite, c.responseLabel)
}
