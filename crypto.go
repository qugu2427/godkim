package main

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"regexp"
	"strings"
)

/*
This file is for functions which contain crypto related tasks.
*/

var (
	RgxDkimSigTag *regexp.Regexp = regexp.MustCompile(`b=([A-Za-z0-9+/= \t]+)`)
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
		err = fmt.Errorf("unknown hashing algorithm '%#v'", algo)
	}
	return
}

// TODO FIXME
func buildSignatureMessage(dkimHeader *DKIMHeader, canonicalizedHeaders string, canonicalization Canonicalization) (signatureMessage string, err error) {
	if canonicalization == Simple {
		// todo
	} else if canonicalization == Relaxed {
		allHeadersSplit := strings.Split(canonicalizedHeaders, "\r\n")
		allHeaders := map[string]string{}

		// "The header fields specified by the "h=" tag, in the order specified in that tag, and canonicalized using the header canonicalization algorithm specified in the "c=" tag"
		for _, header := range allHeadersSplit {
			headerSplit := strings.SplitN(header, ":", 2)
			if len(headerSplit) == 2 { // TODO mabye catch this err better
				allHeaders[headerSplit[0]] = headerSplit[1]
			}
		}

		// "The DKIM-Signature header field that exists (verifying) or will be inserted (signing) in the message"
		dkimHeader.h = append(dkimHeader.h, "dkim-signature")
		for _, header := range dkimHeader.h {
			header := strings.ToLower(header)
			if allHeaders[header] != "" {
				signatureMessage += header + ":" + allHeaders[header] + "\r\n" // "Each header field MUST be terminated with a single CRLF."
			}
		}

		// remove the b tag
		// "header field are included in the cryptographic hash with the sole exception of the value portion of the "b=""
		signatureMessage = RgxDkimSigTag.ReplaceAllString(signatureMessage, "b=")

		signatureMessage = strings.TrimSuffix(signatureMessage, "\r\n")
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
