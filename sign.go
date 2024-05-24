package main

import (
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"strings"
)

type SignPayload struct {
	RawMail    string
	Domain     string
	Selector   string
	Headers    []string
	PrivateKey *rsa.PrivateKey
}

func (p SignPayload) Sign() (signedMail string, err error) {
	for i := 0; i < len(p.Headers); i++ {
		p.Headers[i] = strings.ToLower(p.Headers[i])
	}

	canonicalizedHeaders, canonicalizedBody, err := CanonicalizeEmail(CanonicalizationTuple{Relaxed, Relaxed}, p.RawMail)
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
		c:  CanonicalizationTuple{Relaxed, Relaxed},
		d:  p.Domain,
		h:  p.Headers,
	}, canonicalizedHeaders+"\r\n")
	if err != nil {
		return
	}

	signatueMessage += fmt.Sprintf("dkim-signature: v=1 a=rsa-sha256 c=relaxed/relaxed d=%s s=%s h=%s bh=%s b=",
		p.Domain,
		p.Selector,
		strings.Join(p.Headers, ":"),
		base64.StdEncoding.EncodeToString(bodyHash))

	fmt.Printf("%#v", signatueMessage)

	signature, err := createSignatureRsaSha256(signatueMessage, p.PrivateKey)
	if err != nil {
		return
	}

	signedMail = fmt.Sprintf("DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=%s; s=%s; h=%s; bh=%s; b=%s\r\n",
		p.Domain,
		p.Selector,
		strings.Join(p.Headers, ":"),
		base64.StdEncoding.EncodeToString(bodyHash),
		base64.StdEncoding.EncodeToString(signature)) + p.RawMail

	return
}
