package dkim

import (
	"fmt"
	"reflect"
	"strings"
	"time"
)

var (
	SignatureLimit  int  = 4    // The max number of signatures Verify() will verify
	CheckExpiration bool = true // Whether or not the check the expiration date on signatures
)

// Checks that the agent (i=) is a subdomain or matches domain
func (d *DKIMHeader) VerifyAgent(dkimRecord DKIMRecord) (err error) {
	if d.i == "" {
		return
	} else if strings.Contains(dkimRecord.t, "s") && !strings.HasSuffix(d.i, "@"+d.d) {
		err = fmt.Errorf("agent %s (i) does not end in %s (strict match per t=s)", d.i, "@"+d.d)
	} else if !strings.HasSuffix(d.i, d.d) {
		err = fmt.Errorf("agent %s (i) does not end in %s, d.i, d.d)", d.i, d.d)
	}
	return
}

// Check that the dkim timestamp (t=) is not in the future. If no timestamp is specified, no error will be returned since it is not a required tag.
func (d *DKIMHeader) VerifyTimestamp() (err error) {
	if !d.t.IsZero() && d.t.After(time.Now()) {
		err = fmt.Errorf("dkim header timestamp in future")
		return
	}
	return
}

// Check that the dkim expiration (x=) is not in the past. If no expiration is specified, no error will be returned since it is not a required tag.
func (d *DKIMHeader) VerifyExpiration() (err error) {
	if !d.x.IsZero() && time.Now().After(d.x) && CheckExpiration {
		err = fmt.Errorf("dkim header expired")
		return
	}
	return
}

// Check that the dkim body hash (bh=) matches the hash of the *canonicalized* body
func (d *DKIMHeader) VerifyBodyHash(canonicalizedBody string) (err error) {
	// "canonicalized using the body canonicalization algorithm specified in the "c=" tag and then truncated to the length specified in the "l=" tag"
	if d.l > len(canonicalizedBody) {
		err = fmt.Errorf("body length count larger than canonicalized body")
		return
	}
	if d.l > 0 {
		canonicalizedBody = canonicalizedBody[:d.l]
	}
	bodyHash, err := computeHash(d.a, []byte(canonicalizedBody))
	if err != nil {
		return
	}

	if !reflect.DeepEqual(bodyHash, d.bh) {
		err = fmt.Errorf("body hashes do not match")
		return
	}
	return
}

// Check that the signature (b=) matches the computed signature of headers
func (d *DKIMHeader) VerifySignature(dkimRecord DKIMRecord, canonicalizedHeaders string) (err error) {
	signatureMessage, err := extractSignatureMessage(d, canonicalizedHeaders)
	if err != nil {
		return err
	}
	err = checkSignature(d.a, dkimRecord.k, dkimRecord.p, signatureMessage, d.b)
	if err != nil {
		return err
	}
	return
}

type VerifyResult struct {
	Result VerificationResult
	Err    error
	Domain string
}

func (v VerifyResult) String() string {
	return fmt.Sprintf("{%s,\"%s\",%s}", v.Result, v.Err, v.Domain)
}

func Verify(rawMail string) (results []VerifyResult, err error) {
	var dkimHeaders []DKIMHeader
	dkimHeaders, err = extractDKIMHeaders(rawMail)
	if err != nil {
		return nil, err
	}
	if len(dkimHeaders) > SignatureLimit {
		return nil, fmt.Errorf("too many signatures (%d) in mail, limit is %d", len(dkimHeaders), SignatureLimit)
	}

	overallSuccess := true
	for i, dkimHeader := range dkimHeaders {
		results = append(results, VerifyResult{Success, nil, dkimHeader.d})

		var dkimRecord DKIMRecord
		dkimRecord, results[i].Err = fetchDKIMRecord(dkimHeader.s, dkimHeader.d)
		if results[i].Err != nil {
			results[i].Result = TempFail
			overallSuccess = false
			continue
		}

		// Check agent
		results[i].Err = dkimHeader.VerifyAgent(dkimRecord)
		if results[i].Err != nil {
			results[i].Result = PermFail
			overallSuccess = false
			continue
		}

		// Check timestamp and expiration
		results[i].Err = dkimHeader.VerifyTimestamp()
		if results[i].Err != nil {
			results[i].Result = PermFail
			overallSuccess = false
			continue
		}
		results[i].Err = dkimHeader.VerifyExpiration()
		if results[i].Err != nil {
			results[i].Result = PermFail
			overallSuccess = false
			continue
		}

		// Canonicalize email
		var headersCanonicalized, bodyCanonicalized string
		headersCanonicalized, bodyCanonicalized, results[i].Err = CanonicalizeEmail(dkimHeader.c, rawMail)
		if results[i].Err != nil {
			results[i].Result = PermFail
			overallSuccess = false
			continue
		}

		// Check body hash
		results[i].Err = dkimHeader.VerifyBodyHash(bodyCanonicalized)
		if results[i].Err != nil {
			results[i].Result = PermFail
			overallSuccess = false
			continue
		}

		// Check signature
		results[i].Err = dkimHeader.VerifySignature(dkimRecord, headersCanonicalized)
		if results[i].Err != nil {
			results[i].Result = PermFail
			overallSuccess = false
			continue
		}
	}

	if !overallSuccess {
		err = fmt.Errorf("one or more failed signatures")
	}

	return
}
