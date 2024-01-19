package main

import (
	"fmt"
	"net"
	"strings"
)

func fetchDKIMRecord(selector, domain string) (dkimRecord DKIMDNSRecord, err error) {
	dkimDomain := selector + "._domainkey." + domain
	txtRecords, err := net.LookupTXT(dkimDomain)
	foundDKIMRecord := false
	if err != nil {
		return
	} else {
		for _, txtRecord := range txtRecords {
			if RgxDKIMRecord.MatchString(txtRecord) {
				if foundDKIMRecord {
					err = fmt.Errorf("more than one dkim record found for %s", domain)
					return
				} else {
					dkimRecord, err = ParseDKIMRecord(txtRecord)
					foundDKIMRecord = true
				}
			}
		}
	}
	if !foundDKIMRecord {
		err = fmt.Errorf("no dkim record found for %s", dkimDomain)
	}
	return
}

func extractHeadersFromEmail(rawEmail string) (headers map[string]string, err error) {
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

func extractDKIMHeader(rawEmail string) (dkimHeader DKIMHeader, err error) {
	headers, err := extractHeadersFromEmail(rawEmail)
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
func extractBody(rawEmail string) (rawBody string, err error) {
	rawEmailSplit := strings.SplitN(rawEmail, "\r\n\r\n", 2)
	if len(rawEmailSplit) != 2 {
		err = fmt.Errorf("unable to extract body from email")
		return
	}
	rawBody = rawEmailSplit[1]
	bodyEnd := RgxEmailBodyEnd.FindStringIndex(rawBody)
	if bodyEnd == nil {
		err = fmt.Errorf("unable to find end of email body")
		return
	}
	rawBody = rawBody[:bodyEnd[0]]
	return
}

// Removes whitepace and coverts to lowercase
func normalizeString(str string) (normStr string) {
	normStr = strings.ToLower(str)
	return RgxNotNormal.ReplaceAllString(normStr, "")
}

// TODO fix
func extractSignatureMessage(canon Canonicalization, headersToExtract []string, rawEmail string) (signatureMessage string, err error) {
	headers, err := extractHeadersFromEmail(rawEmail)
	if err != nil {
		err = fmt.Errorf("unable to extract headers from email")
		return
	}

	if canon == Simple {
		for _, headerToExtract := range headersToExtract {
			headerToExtractVal, _ := headers[headerToExtract]
			signatureMessage += headerToExtract + ":" + headerToExtractVal
		}
	} else if canon == Relaxed {
		for _, headerToExtract := range headersToExtract {
			headerToExtractVal, _ := headers[headerToExtract]
			signatureMessage += headerToExtract + ":" + headerToExtractVal
		}
	} else {
		err = fmt.Errorf("unknown canonicalization '%#v' when extracting signature message", canon)
		return
	}

	return
}
