package main

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"
)

/*
This file is for functions which contain crypto related tasks.
*/

func computeHash(algo SigningAlgorithm, input []byte) (hash []byte, err error) {
	switch algo {
	case RSASHA1:
		h := sha1.New()
		h.Write(input)
		hash = h.Sum(nil)
	case RSASHA256:
		h := sha256.New()
		h.Write(input)
		hash = h.Sum(nil)
	default:
		err = fmt.Errorf("unknown body hashing algorithm '%#v'", algo)
	}
	return
}

// FIXME
// This is the problem!!!!
// checkSignature seems to work (mabye more tests)
// the body hash works so canonicalization is likely not the problem? (although mabye headers???)

// TODO
// "The DKIM-Signature header field MUST NOT be included in its own h= tag"
func buildSignatureMessage(dkimHeader *DKIMHeader, canonicalizedHeaders string, canonicalization Canonicalization) (signatureMessage string, err error) {
	if canonicalization == Simple {
		// todo
	} else if canonicalization == Relaxed {
		allHeadersSplit := strings.Split(canonicalizedHeaders, "\r\n")
		allHeaders := map[string]string{}
		for _, header := range allHeadersSplit {
			headerSplit := strings.SplitN(header, ":", 2)
			if len(headerSplit) == 2 { // TODO mabye catch this err better
				allHeaders[headerSplit[0]] = headerSplit[1]
			}
		}
		dkimHeader.h = append(dkimHeader.h, "dkim-signature")
		for _, header := range dkimHeader.h {
			header := strings.ToLower(header)
			signatureMessage += header + ":" + allHeaders[header] + "\r\n"
		}
		signatureMessage = RgxDkimSigTag.ReplaceAllString(signatureMessage, "b=")
	} else {
		err = fmt.Errorf("unknown canonicalization '%#v' when building signature message", canonicalization)
		return
	}
	return
}

func checkSignature(algo SigningAlgorithm,
	publicKeyType KeyType,
	publicKeyPem,
	signatureMessage string,
	signature []byte) (err error) {

	signatureMessageHash, err := computeHash(algo, []byte(signatureMessage))
	if err != nil {
		return err
	}

	if publicKeyType == RSA {

		block, _ := pem.Decode([]byte(publicKeyPem))
		if block == nil {
			err = fmt.Errorf("failed to parse pem data from public key bytes")
			return
		}
		publicKey, _err := x509.ParsePKIXPublicKey(block.Bytes)
		if _err != nil {
			err = _err
			return
		}
		rsaPublicKey, ok := publicKey.(*rsa.PublicKey)
		if !ok {
			return
		}

		switch algo {
		case RSASHA1:
			err = rsa.VerifyPKCS1v15(rsaPublicKey, crypto.SHA1, signatureMessageHash, signature)
		case RSASHA256:
			err = rsa.VerifyPKCS1v15(rsaPublicKey, crypto.SHA256, signatureMessageHash, signature)
		default:
			err = fmt.Errorf("unknown rsa signing algorithm '%#v'", algo)
		}
	} else {
		err = fmt.Errorf("unknown public key type '%#v'", publicKeyType)
	}
	return
}

func computeBodyHash(
	algo SigningAlgorithm,
	canonicalizedBody string,
	bodyTrimLen uint64) (hash []byte, err error) {
	if bodyTrimLen > 0 {
		canonicalizedBody = canonicalizedBody[:bodyTrimLen]
	}
	if !strings.HasSuffix(canonicalizedBody, "\r\n") {
		canonicalizedBody += "\r\n"
	}
	return computeHash(algo, []byte(canonicalizedBody))
}
