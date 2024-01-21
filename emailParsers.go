package main

import (
	"fmt"
	"strings"
)

/*
This file is for function which help to parse information from a raw email.
*/

// Returns string map of headers given a raw email
func getHeadersFromEmail(rawEmail string) (headers map[string]string, err error) {
	headersEndpoint := strings.Index(rawEmail, "\r\n\r\n")
	if headersEndpoint == -1 {
		err = fmt.Errorf("unable to find find end of headers section")
		return
	}
	headerPortion := rawEmail[:headersEndpoint]
	headerLines := strings.Split(headerPortion, "\r\n")
	headers = map[string]string{}
	currentHeader := ""
	for _, headerLine := range headerLines {
		if (headerLine[0] == '\t' || headerLine[0] == ' ') && len(headerLine) > 1 {
			if _, exists := headers[currentHeader]; !exists {
				err = fmt.Errorf("unable to parse header")
				return
			}
			headers[currentHeader] += "\r\n" + headerLine
		} else if strings.Contains(headerLine, ":") {
			headerLineSplit := strings.SplitN(headerLine, ":", 2)
			currentHeader = RgxNotHeader.ReplaceAllString(headerLineSplit[0], "")
			headers[currentHeader] = strings.TrimSpace(headerLineSplit[1])
		}
	}
	return
}

// Returns a dkim header object given a raw email
func getDKIMHeaderFromEmail(rawEmail string) (dkimHeader DKIMHeader, err error) {
	headers, err := getHeadersFromEmail(rawEmail)
	if err != nil {
		return
	}
	dkimHeaderTxt, exists := headers["DKIM-Signature"]
	if !exists || dkimHeaderTxt == "" {
		err = fmt.Errorf("dkim header not found")
		return
	}
	dkimHeader, err = ParseDKIMHeader(dkimHeaderTxt)
	return
}

// Returns raw body portion of raw email
func getBodyFromEmail(rawEmail string) (rawBody string, err error) {
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

// Returns canoniczlized version of email heade & body given canonicalization algorithm tuple
// This function is a pain in the ass
func CanonicalizeEmail(canonTuple CanonicalizationTuple, rawEmail string) (canonicalizedHeader, canonicalizedBody string, err error) {

	// Canoicalize headers
	headers, err := getHeadersFromEmail(rawEmail)
	if err != nil {
		err = fmt.Errorf("unable to extract headers from email (%s)", err)
		return
	}
	if canonTuple.headerCanon == Simple {
		// "The "simple" header canonicalization algorithm does not change header fields in any way"
		for _, header := range headers {
			canonicalizedHeader += header + ":" + headers[header]
			if !strings.HasSuffix(canonicalizedHeader, "\r\n") {
				canonicalizedHeader += "\r\n"
			}
		}
	} else if canonTuple.headerCanon == Relaxed {
		for header, headerVal := range headers {

			// "Convert all header field names (not the header field values) tolowercase."
			header = strings.ToLower(header)

			// "Unfold all header field continuation lines"
			headerVal = unfoldString(headerVal)

			// "Convert all sequences of one or more WSP characters to a single SP"
			headerVal = RgxConsecSpace.ReplaceAllString(headerVal, " ")

			// "Delete all WSP characters at the end of each unfolded header field value"
			headerVal = RgxEOLWhiteSpace.ReplaceAllString(headerVal, "\r\n")

			// "Delete any WSP characters remaining before and after the colon separating the header field name from the header field value."
			headerVal = strings.TrimSpace(headerVal)

			canonicalizedHeader += header + ":" + headerVal + "\r\n"
		}
	} else {
		err = fmt.Errorf("unknown header canonicalization '%#v'", canonTuple.headerCanon)
		return
	}

	// Canonicalize body
	body, err := getBodyFromEmail(rawEmail)
	if err != nil {
		err = fmt.Errorf("unable to extract body from email (%s)", err)
		return
	}
	if canonTuple.bodyCanon == Simple {
		// "...ignores all empty lines at the end of the message body"
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
		return
	}

	return
}
