package main

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

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

func checkSignature(algo SigningAlgorithm, publicKeyType KeyType, publicKeyRaw, signatureMessage, signature []byte) (err error) {
	if publicKeyType == RSA {

		// Parse public key bytes to object
		block, _ := pem.Decode(publicKeyRaw)
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
			err = rsa.VerifyPKCS1v15(rsaPublicKey, crypto.SHA1, signatureMessage, signature)
		case RSASHA256:
			err = rsa.VerifyPKCS1v15(rsaPublicKey, crypto.SHA256, signatureMessage, signature)
		default:
			err = fmt.Errorf("unknown signing algorithm '%#v'", algo)
		}
	} else {
		err = fmt.Errorf("unknown public key type '%#v'", publicKeyType)
	}
	return
}

func computeBodyHash(algo SigningAlgorithm, canon Canonicalization, rawBody string, bodyTrimLen uint64) (hash []byte, err error) {
	if canon == Relaxed {
		rawBody = RgxConsecSpace.ReplaceAllString(rawBody, " ")
		rawBody = RgxNewLineSpace.ReplaceAllString(rawBody, "\r\n")
		rawBody = RgxConsecEndingCRLF.ReplaceAllString(rawBody, "\r\n")
	}
	if bodyTrimLen > 0 {
		rawBody = rawBody[:bodyTrimLen]
	}
	bodyLen := len(rawBody)
	if bodyLen > 2 && rawBody[bodyLen-2:] != "\r\n" {
		rawBody += "\r\n"
	}
	return computeHash(algo, []byte(rawBody))
}
