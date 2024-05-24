package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"regexp"
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

func createSignatureRsaSha256(signatureMessage string, privKey *rsa.PrivateKey) (signature []byte, err error) {
	signatureMessageHash, err := computeHash(RSASHA256, []byte(signatureMessage))
	if err != nil {
		return nil, err
	}

	signature, err = rsa.SignPKCS1v15(rand.Reader, privKey, crypto.SHA256, signatureMessageHash)
	if err != nil {
		return nil, err
	}

	return
}
