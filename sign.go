package dkim

import (
	"encoding/base64"
	"fmt"
	"strings"
	"time"
)

var DefaultHeaders []string = []string{"From", "To", "Subject", "Date", "Cc", "Reply-To", "Message-ID"}

type SignPayload struct {
	RawMail      string
	Domain       string
	Selector     string
	Headers      []string
	HeadersCanon Canonicalization
	BodyCanon    Canonicalization
	Timestamp    int64
	Expiration   int64
	PrivateKey   string
}

func SimpleSign(rawMail, domain, selector, privateKeyPem string) (signedMail string, err error) {
	signPayload := SignPayload{
		RawMail:      rawMail,
		Domain:       domain,
		Selector:     selector,
		Headers:      DefaultHeaders,
		HeadersCanon: Relaxed,
		BodyCanon:    Relaxed,
		Timestamp:    time.Now().Unix(),
		Expiration:   time.Now().Add(48 * time.Hour).Unix(),
		PrivateKey:   privateKeyPem,
	}
	return signPayload.Sign()
}

func (p SignPayload) Sign() (signedMail string, err error) {
	for i := 0; i < len(p.Headers); i++ {
		p.Headers[i] = strings.ToLower(p.Headers[i])
	}

	canonTuple := CanonicalizationTuple{p.HeadersCanon, p.BodyCanon}

	canonicalizedHeaders, canonicalizedBody, err := CanonicalizeEmail(canonTuple, p.RawMail)
	if err != nil {
		return
	}

	bodyHash, err := computeHash(RSASHA256, []byte(canonicalizedBody))
	if err != nil {
		return
	}

	signatueMessage, err := extractSignatureMessage(&DKIMHeader{
		a:  RSASHA256,
		bh: bodyHash,
		c:  canonTuple,
		d:  p.Domain,
		h:  p.Headers,
	}, canonicalizedHeaders+"\r\n")
	if err != nil {
		return
	}

	if p.HeadersCanon == Relaxed {
		signatueMessage += fmt.Sprintf("dkim-signature:v=1; a=rsa-sha256; t=%d; x=%d; c=%s; d=%s; s=%s; h=%s; bh=%s; b=",
			p.Timestamp,
			p.Expiration,
			canonTuple,
			p.Domain,
			p.Selector,
			strings.Join(p.Headers, ":"),
			base64.StdEncoding.EncodeToString(bodyHash))
	} else {
		signatueMessage += fmt.Sprintf("DKIM-Signature: v=1; a=rsa-sha256; t=%d; x=%d; c=%s; d=%s; s=%s; h=%s; bh=%s; b=",
			p.Timestamp,
			p.Expiration,
			canonTuple,
			p.Domain,
			p.Selector,
			strings.Join(p.Headers, ":"),
			base64.StdEncoding.EncodeToString(bodyHash))
	}

	signature, err := createSignatureRsaSha256(signatueMessage, p.PrivateKey)
	if err != nil {
		return
	}

	signedMail = fmt.Sprintf("DKIM-Signature: v=1; a=rsa-sha256; t=%d; x=%d; c=%s; d=%s; s=%s; h=%s; bh=%s; b=%s\r\n",
		p.Timestamp,
		p.Expiration,
		canonTuple,
		p.Domain,
		p.Selector,
		strings.Join(p.Headers, ":"),
		base64.StdEncoding.EncodeToString(bodyHash),
		base64.StdEncoding.EncodeToString(signature)) + p.RawMail

	return
}
