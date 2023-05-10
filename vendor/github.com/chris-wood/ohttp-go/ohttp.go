package ohttp

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"

	"github.com/cloudflare/circl/hpke"
	"github.com/cloudflare/circl/kem"

	"golang.org/x/crypto/cryptobyte"
)

var (
	defaultLabelRequest  = "message/bhttp request"
	defaultLabelResponse = "message/bhttp response"
	labelResponseKey     = "key"
	labelResponseNonce   = "nonce"
)

type ConfigCipherSuite struct {
	KDFID  hpke.KDF
	AEADID hpke.AEAD
}

type PublicConfig struct {
	ID             uint8
	KEMID          hpke.KEM
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
	seed         []byte
	publicConfig PublicConfig
	sk           kem.PrivateKey
	pk           kem.PublicKey
}

func (c PrivateConfig) Config() PublicConfig {
	return c.publicConfig
}

func (c PrivateConfig) PrivateKey() kem.PrivateKey {
	return c.sk
}

func NewConfigFromSeed(keyID uint8, kemID hpke.KEM, kdfID hpke.KDF, aeadID hpke.AEAD, seed []byte) (PrivateConfig, error) {
	if !kemID.IsValid() || !kdfID.IsValid() || !aeadID.IsValid() {
		return PrivateConfig{}, fmt.Errorf("invalid ciphersuite")
	}

	pk, sk := kemID.Scheme().DeriveKeyPair(seed)
	cs := ConfigCipherSuite{
		KDFID:  kdfID,
		AEADID: aeadID,
	}

	pkEnc, err := pk.MarshalBinary()
	if err != nil {
		return PrivateConfig{}, err
	}

	publicConfig := PublicConfig{
		ID:             keyID,
		KEMID:          kemID,
		Suites:         []ConfigCipherSuite{cs},
		PublicKeyBytes: pkEnc,
	}

	return PrivateConfig{
		seed:         seed,
		publicConfig: publicConfig,
		sk:           sk,
		pk:           pk,
	}, nil
}

func NewConfig(keyID uint8, kemID hpke.KEM, kdfID hpke.KDF, aeadID hpke.AEAD) (PrivateConfig, error) {
	if !kemID.IsValid() || !kdfID.IsValid() || !aeadID.IsValid() {
		return PrivateConfig{}, fmt.Errorf("invalid ciphersuite")
	}
	ikm := make([]byte, kemID.Scheme().SeedSize())
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
		return PublicConfig{}, fmt.Errorf("invalid config")
	}

	kem := hpke.KEM(kemID)
	if !kem.IsValid() {
		return PublicConfig{}, fmt.Errorf("invalid KEM")
	}

	publicKeyBytes := make([]byte, kem.Scheme().PublicKeySize())
	if !s.ReadBytes(&publicKeyBytes, len(publicKeyBytes)) {
		return PublicConfig{}, fmt.Errorf("invalid config")
	}

	var cipherSuites cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&cipherSuites) {
		return PublicConfig{}, fmt.Errorf("invalid config")
	}
	suites := []ConfigCipherSuite{}
	for !cipherSuites.Empty() {
		var kdfID uint16
		var aeadID uint16
		if !cipherSuites.ReadUint16(&kdfID) ||
			!cipherSuites.ReadUint16(&aeadID) {
			return PublicConfig{}, fmt.Errorf("invalid config")
		}

		// Sanity check validity of the KDF and AEAD values
		kdf := hpke.KDF(kdfID)
		if !kdf.IsValid() {
			return PublicConfig{}, fmt.Errorf("invalid KDF")
		}
		aead := hpke.AEAD(aeadID)
		if !aead.IsValid() {
			return PublicConfig{}, fmt.Errorf("invalid AEAD")
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
	KeyID  uint8
	kemID  hpke.KEM
	kdfID  hpke.KDF
	aeadID hpke.AEAD
	enc    []byte
	ct     []byte
}

//	Encapsulated Request {
//		Key Identifier (8),
//		KEM Identifier (16),
//		KDF Identifier (16),
//		AEAD Identifier (16),
//		Encapsulated KEM Shared Secret (8*Nenc),
//		AEAD-Protected Request (..),
//	}
func (r EncapsulatedRequest) Marshal() []byte {
	b := cryptobyte.NewBuilder(nil)

	b.AddUint8(r.KeyID)
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
	kemID := hpke.KEM(binary.BigEndian.Uint16(kemIDBuffer))

	kdfIDBuffer := make([]byte, 2)
	_, err = b.Read(kdfIDBuffer)
	if err != nil {
		return EncapsulatedRequest{}, err
	}
	kdfID := hpke.KDF(binary.BigEndian.Uint16(kdfIDBuffer))

	aeadIDBuffer := make([]byte, 2)
	_, err = b.Read(aeadIDBuffer)
	if err != nil {
		return EncapsulatedRequest{}, err
	}
	aeadID := hpke.AEAD(binary.BigEndian.Uint16(aeadIDBuffer))

	key := make([]byte, kemID.Scheme().PublicKeySize())
	_, err = b.Read(key)
	if err != nil {
		return EncapsulatedRequest{}, err
	}

	ct := b.Bytes()

	return EncapsulatedRequest{
		KeyID:  uint8(keyID),
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
	suite         hpke.Suite
	context       hpke.Sealer
}

type EncapsulatedResponse struct {
	raw []byte
}

//	Encapsulated Response {
//		Nonce (Nk),
//		AEAD-Protected Response (..),
//	}
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
	skE           kem.PrivateKey
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
	suite := hpke.NewSuite(kemID, kdfID, aeadID)

	pkR, err := kemID.Scheme().UnmarshalBinaryPublicKey(c.config.PublicKeyBytes)
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

	sender, err := suite.NewSender(pkR, info)
	if err != nil {
		return EncapsulatedRequest{}, EncapsulatedRequestContext{}, err
	}
	enc, context, err := sender.Setup(rand.Reader)
	if err != nil {
		return EncapsulatedRequest{}, EncapsulatedRequestContext{}, err
	}

	ct, err := context.Seal(request, nil)
	if err != nil {
		return EncapsulatedRequest{}, EncapsulatedRequestContext{}, err
	}

	return EncapsulatedRequest{
			KeyID:  c.config.ID,
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
	_, KDF, AEAD := c.suite.Params()

	secret := c.context.Export(c.responseLabel, AEAD.KeySize())

	// response_nonce = random(max(Nn, Nk)), taken from the encapsualted response
	responseNonceLen := max(int(AEAD.KeySize()), 12)
	responseNonce := make([]byte, responseNonceLen)
	_, err := rand.Read(responseNonce)
	if err != nil {
		return nil, err
	}

	// salt = concat(enc, response_nonce)
	salt := append(c.enc, response.raw[:responseNonceLen]...)

	// prk = Extract(salt, secret)
	prk := KDF.Extract(secret, salt)

	// aead_key = Expand(prk, "key", Nk)
	key := KDF.Expand(prk, []byte(labelResponseKey), AEAD.KeySize())

	// aead_nonce = Expand(prk, "nonce", Nn)
	nonce := KDF.Expand(prk, []byte(labelResponseNonce), 12)

	cipher, err := AEAD.New(key)
	if err != nil {
		return nil, err
	}

	// reponse, error = Open(aead_key, aead_nonce, "", ct)
	return cipher.Open(nil, nonce, response.raw[AEAD.KeySize():], nil)
}

type Gateway struct {
	requestLabel  []byte
	responseLabel []byte
	// map from IDs to private key(s)
	keys   []uint8
	keyMap map[uint8]PrivateConfig
}

func (g Gateway) Config(keyID uint8) (PublicConfig, error) {
	if config, ok := g.keyMap[keyID]; ok {
		return config.Config(), nil
	}
	return PublicConfig{}, fmt.Errorf("unknown keyID %d", keyID)
}

func (g Gateway) Client(keyID uint8) (Client, error) {
	config, err := g.Config(keyID)
	if err != nil {
		return Client{}, err
	}
	return Client{
		requestLabel:  g.requestLabel,
		responseLabel: g.responseLabel,
		config:        config,
	}, nil
}

func createConfigMap(configs []PrivateConfig) ([]uint8, map[uint8]PrivateConfig) {
	configMap := make(map[uint8]PrivateConfig)
	keys := make([]uint8, 0)
	for _, config := range configs {
		_, exists := configMap[config.publicConfig.ID]
		if exists {
			panic("Duplicate config key IDs")
		}
		configMap[config.publicConfig.ID] = config
		keys = append(keys, config.publicConfig.ID)
	}
	return keys, configMap
}

func NewDefaultGateway(configs []PrivateConfig) Gateway {
	keys, keyMap := createConfigMap(configs)
	return Gateway{
		requestLabel:  []byte(defaultLabelRequest),
		responseLabel: []byte(defaultLabelResponse),
		keys:          keys,
		keyMap:        keyMap,
	}
}

func NewCustomGateway(configs []PrivateConfig, requestLabel, responseLabel string) Gateway {
	if requestLabel == "" || responseLabel == "" || requestLabel == responseLabel {
		panic("Invalid request and response labels")
	}

	keys, keyMap := createConfigMap(configs)
	return Gateway{
		requestLabel:  []byte(requestLabel),
		responseLabel: []byte(responseLabel),
		keys:          keys,
		keyMap:        keyMap,
	}
}

type DecapsulateRequestContext struct {
	responseLabel []byte
	enc           []byte
	suite         hpke.Suite
	context       hpke.Opener
}

func (s Gateway) MatchesConfig(req EncapsulatedRequest) bool {
	_, ok := s.keyMap[req.KeyID]
	return ok
}

func (s Gateway) MarshalConfigs() []byte {
	b := cryptobyte.NewBuilder(nil)

	for _, id := range s.keys {
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddBytes(s.keyMap[id].publicConfig.Marshal())
		})
	}
	return b.BytesOrPanic()
}

func (s Gateway) DecapsulateRequest(req EncapsulatedRequest) ([]byte, DecapsulateRequestContext, error) {
	config, ok := s.keyMap[req.KeyID]
	if !ok {
		return nil, DecapsulateRequestContext{}, fmt.Errorf("unknown key ID")
	}

	if !config.publicConfig.KEMID.IsValid() || !req.kdfID.IsValid() || !req.aeadID.IsValid() {
		return nil, DecapsulateRequestContext{}, fmt.Errorf("invalid ciphersuite")
	}
	suite := hpke.NewSuite(config.publicConfig.KEMID, req.kdfID, req.aeadID)

	info := s.requestLabel
	info = append(info, 0x00)
	info = append(info, req.KeyID)
	buffer := make([]byte, 2)
	binary.BigEndian.PutUint16(buffer, uint16(req.kemID))
	info = append(info, buffer...)
	binary.BigEndian.PutUint16(buffer, uint16(req.kdfID))
	info = append(info, buffer...)
	binary.BigEndian.PutUint16(buffer, uint16(req.aeadID))
	info = append(info, buffer...)

	receiver, err := suite.NewReceiver(config.sk, info)
	if err != nil {
		return nil, DecapsulateRequestContext{}, err
	}
	context, err := receiver.Setup(req.enc)
	if err != nil {
		return nil, DecapsulateRequestContext{}, err
	}

	raw, err := context.Open(req.ct, nil)
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

func encapsulateResponse(context hpke.Opener, response, responseNonce []byte, enc []byte, suite hpke.Suite, responseLabel []byte) (EncapsulatedResponse, error) {
	_, KDF, AEAD := suite.Params()

	// secret = context.Export("message/bhttp response", Nk)
	secret := context.Export(responseLabel, AEAD.KeySize())

	// salt = concat(enc, response_nonce)
	salt := append(enc, responseNonce...)

	// prk = Extract(salt, secret)
	prk := KDF.Extract(secret, salt)

	// aead_key = Expand(prk, "key", Nk)
	key := KDF.Expand(prk, []byte(labelResponseKey), AEAD.KeySize())

	// aead_nonce = Expand(prk, "nonce", Nn)
	nonce := KDF.Expand(prk, []byte(labelResponseNonce), 12)

	// ct = Seal(aead_key, aead_nonce, "", response)
	cipher, err := AEAD.New(key)
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
	_, _, AEAD := c.suite.Params()

	// response_nonce = random(max(Nn, Nk))
	responseNonceLen := max(int(AEAD.KeySize()), 12)
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
