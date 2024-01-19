package main

import (
	"fmt"
	"reflect"
	"time"
)

func VerifyEmailDKIM(rawEmail string) (err error) {
	dkimHeader, err := extractDKIMHeader(rawEmail)
	if err != nil {
		return err
	}

	dkimRecord, err := fetchDKIMRecord(dkimHeader.s, dkimHeader.d)
	if err != nil {
		return err
	}
	fmt.Sprintf("%v", dkimRecord)

	// Check body hash
	rawBody, err := extractBody(rawEmail)
	if err != nil {
		return err
	}
	bodyHash, err := computeBodyHash(dkimHeader.a, dkimHeader.c.bodyCanon, rawBody, dkimHeader.l)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(bodyHash, dkimHeader.bh) {
		err = fmt.Errorf("body hashes do not match")
		return
	}

	// Check timestamp and expiration
	if !dkimHeader.t.IsZero() && dkimHeader.t.After(time.Now()) {
		err = fmt.Errorf("timestamp is in the future")
		return
	}
	if !dkimHeader.x.IsZero() && time.Now().After(dkimHeader.x) {
		err = fmt.Errorf("expiration is in the past")
		return
	}

	// Verify signature
	signatureMessage, err := extractSignatureMessage(dkimHeader.c.headerCanon, dkimHeader.h, rawEmail)
	if err != nil {
		return
	}
	fmt.Println(signatureMessage)
	err = checkSignature(dkimHeader.a, dkimRecord.k, dkimRecord.p, []byte(signatureMessage), dkimHeader.b)
	if err != nil {
		return
	}

	// fmt.Println(base64.StdEncoding.EncodeToString(bodyHash))
	// fmt.Println(base64.StdEncoding.EncodeToString(dkimHeader.bh))

	fmt.Println("wooo")

	return
}
