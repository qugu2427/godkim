package main

import (
	"fmt"
	"net"
	"regexp"
	"strings"
)

var (
	RgxDKIMRecord *regexp.Regexp = regexp.MustCompile(`^v=DKIM`)
	RgxNotNormal  *regexp.Regexp = regexp.MustCompile(`[^a-z0-9\-\/]`)
)

/*
This file contains misc function which dont fit anywhere else.
*/

func fetchDKIMRecord(selector, domain string) (dkimRecord DKIMRecord, err error) {
	dkimDomain := selector + "._domainkey." + domain
	txtRecords, err := net.LookupTXT(dkimDomain)
	if err != nil {
		return
	} else {
		for _, txtRecord := range txtRecords {
			if RgxDKIMRecord.MatchString(txtRecord) {
				dkimRecord, err = ParseDKIMRecord(txtRecord)
				return
			}
		}
	}
	err = fmt.Errorf("no dkim record found for '%s'", dkimDomain)
	return
}

// Removes whitepace and coverts to lowercase
func normalizeString(str string) (normStr string) {
	normStr = strings.ToLower(str)
	return RgxNotNormal.ReplaceAllString(normStr, "")
}

func unfoldString(str string) (unfoldStr string) {
	unfoldStr = strings.ReplaceAll(str, "\r\n ", " ")
	unfoldStr = strings.ReplaceAll(unfoldStr, "\r\n\t", " ")
	return
}
