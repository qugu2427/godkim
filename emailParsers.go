package dkim

import (
	"fmt"
	"regexp"
	"strings"
)

var (
	RgxEmailBodyEnd     *regexp.Regexp = regexp.MustCompile(`\r\n.\r\n$`)
	RgxConsecEndingCRLF *regexp.Regexp = regexp.MustCompile(`(\r\n){2,}$`)
	RgxConsecSpace      *regexp.Regexp = regexp.MustCompile(`[ \t]{2,}`)
	RgxEOLWhiteSpace    *regexp.Regexp = regexp.MustCompile(`[\t ]\r\n`)
	RgxHeaderColon      *regexp.Regexp = regexp.MustCompile(`\s?:\s?`)
)

/*
This file is for function which help to parse information from a raw email.
*/

// Returns string map of headers given a raw email
//
// weird function because regexs cant handle lookback, so I casnt split on \r\n\S
func extractHeaders(rawEmail string) (headers map[string][]string, err error) {
	headersEndpoint := strings.Index(rawEmail, "\r\n\r\n")
	if headersEndpoint == -1 {
		err = fmt.Errorf("unable to find find end of headers section")
		return
	}
	headerPortion := rawEmail[:headersEndpoint]
	headerLines := strings.Split(headerPortion, "\r\n")
	currentHeader := ""
	headers = map[string][]string{}
	for _, headerLine := range headerLines {
		if (headerLine[0] == '\t' || headerLine[0] == ' ') && len(headerLine) > 1 {
			if _, exists := headers[currentHeader]; !exists || len(headers[currentHeader]) == 0 {
				err = fmt.Errorf("unable to parse header line %#v", headerLine)
				return
			}
			headers[currentHeader][len(headers[currentHeader])-1] += "\r\n" + headerLine
		} else if strings.Contains(headerLine, ":") {
			headerLineSplit := strings.SplitN(headerLine, ":", 2)
			currentHeader = headerLineSplit[0]
			headers[currentHeader] = append(headers[currentHeader], "")
			headers[currentHeader][len(headers[currentHeader])-1] = headerLineSplit[1]
		}
	}
	return
}

// Returns a dkim header objects given a raw email
func extractDKIMHeaders(rawEmail string) (dkimHeaders []DKIMHeader, err error) {
	headers, err := extractHeaders(rawEmail)
	if err != nil {
		return
	}
	dkimHeaderVals, exists := headers["DKIM-Signature"]
	if !exists {
		err = fmt.Errorf("dkim header not found")
		return
	}
	for _, dkimHeaderTxt := range dkimHeaderVals {
		var dkimHeader DKIMHeader
		dkimHeader, err = ParseDKIMHeader(dkimHeaderTxt)
		if err != nil {
			return
		}
		dkimHeaders = append(dkimHeaders, dkimHeader)
	}
	return
}

// Returns raw body portion of raw email
func extractBody(rawEmail string) (rawBody string, err error) {
	rawEmailSplit := strings.SplitN(rawEmail, "\r\n\r\n", 2)
	if len(rawEmailSplit) != 2 {
		err = fmt.Errorf("unable to extract body from email")
		return
	}
	rawBody = rawEmailSplit[1]
	bodyEnd := RgxEmailBodyEnd.FindStringIndex(rawBody)
	if bodyEnd == nil {
		return
	}
	rawBody = rawBody[:bodyEnd[0]]
	return
}

// Returns the headers part of the signature message and the last dkim header (or "" if not present)
//
// If signature is found within headers it will append the signature to the signature message
func extractSignatureMessage(dkimHeader *DKIMHeader, canonicalizedHeaders string) (signatureMessage string, err error) {
	headers, err := extractHeaders(canonicalizedHeaders + "\r\n")
	if err != nil {
		return
	}

	// "The header fields specified by the "h=" tag, in the order specified in that tag, and canonicalized using the header canonicalization algorithm specified in the "c=" tag"
	includesFrom := false
	dkimHeaderVal := ""
	for _, headerKey := range dkimHeader.h {
		if strings.ToLower(headerKey) == "from" {
			includesFrom = true
		}
		if headers[headerKey] != nil {
			headerVal := headers[headerKey][len(headers[headerKey])-1]
			if headerVal != "" {
				signatureMessage += headerKey + ":" + headerVal + "\r\n" // "Each header field MUST be terminated with a single CRLF."
			}
		}
	}

	// add the dkim signature to message if it exists
	signatureKey := "DKIM-Signature"
	signatures := headers[signatureKey]
	if signatures == nil {
		signatureKey = strings.ToLower(signatureKey)
		signatures = headers[signatureKey]
	}
	for _, signatureVal := range signatures {
		if strings.Contains(signatureVal, dkimHeader.d) {
			// "header field are included in the cryptographic hash with the sole exception of the value portion of the "b=""
			dkimHeaderVal = RgxDkimSigTag.ReplaceAllString(signatureVal, "b=")
			dkimHeaderVal = strings.TrimSuffix(dkimHeaderVal, "\r\n")
			signatureMessage += signatureKey + ":" + dkimHeaderVal
		}
	}

	if !includesFrom {
		return "", fmt.Errorf("from header not included")
	}

	return
}

// Returns canonicazlized version of email head & body given canonicalization algorithm tuple
//
// This function is a pain in the ass
func CanonicalizeEmail(canonTuple CanonicalizationTuple, rawEmail string) (canonicalizedHeader, canonicalizedBody string, err error) {
	// Canoicalize headers
	headers, err := extractHeaders(rawEmail)
	if err != nil {
		err = fmt.Errorf("unable to extract headers from email (%s)", err)
		return
	}
	if canonTuple.headerCanon == Simple {
		// "The "simple" header canonicalization algorithm does not change header fields in any way"
		for headerKey, headerVals := range headers {
			for _, headerVal := range headerVals {
				canonicalizedHeader += headerKey + ":" + headerVal + "\r\n"
			}
		}
	} else if canonTuple.headerCanon == Relaxed {
		for headerKey, headerVals := range headers {
			for _, headerVal := range headerVals {
				// "Convert all header field names (not the header field values) tolowercase."
				headerKey = strings.ToLower(headerKey)

				// "Unfold all header field continuation lines"
				headerVal = unfoldString(headerVal)

				// "Convert all sequences of one or more WSP characters to a single SP"
				headerVal = RgxConsecSpace.ReplaceAllString(headerVal, " ")

				// "Delete all WSP characters at the end of each unfolded header field value"
				headerVal = RgxEOLWhiteSpace.ReplaceAllString(headerVal, "\r\n")

				// "Delete any WSP characters remaining before and after the colon separating the header field name from the header field value."
				headerKey = strings.TrimSpace(headerKey)
				headerVal = strings.TrimSpace(headerVal) // BUG triming not specified in rfc but works in test

				canonicalizedHeader += headerKey + ":" + headerVal + "\r\n"
			}
		}
	} else {
		err = fmt.Errorf("unknown header canonicalization '%#v'", canonTuple.headerCanon)
		return
	}

	// Canonicalize body
	body, err := extractBody(rawEmail)
	if err != nil {
		err = fmt.Errorf("unable to extract body from email (%s)", err)
		return
	}
	if canonTuple.bodyCanon == Simple {
		// "...ignores all empty lines at the end of the message body"
		// "... converts "*CRLF" at the end of the body to a single "CRLF""
		canonicalizedBody = RgxConsecEndingCRLF.ReplaceAllString(body, "\r\n")
	} else if canonTuple.bodyCanon == Relaxed {

		// "Ignore all whitespace at the end of lines.  Implementations MUST NOT remove the CRLF at the end of the line.""
		canonicalizedBody = RgxEOLWhiteSpace.ReplaceAllString(body, "\r\n")

		// "Reduce all sequences of WSP within a line to a single SP character."
		canonicalizedBody = RgxConsecSpace.ReplaceAllString(canonicalizedBody, " ")

		// "Ignore all empty lines at the end of the message body. If the body is non-empty but does not end with a CRLF, a CRLF is added.""
		canonicalizedBody = RgxConsecEndingCRLF.ReplaceAllString(canonicalizedBody, "\r\n")
		if canonicalizedBody != "" && !strings.HasSuffix(canonicalizedBody, "\r\n") {
			canonicalizedBody += "\r\n"
		}
	} else {
		err = fmt.Errorf("unknown body canonicalization '%#v'", canonTuple.bodyCanon)
	}

	return
}
