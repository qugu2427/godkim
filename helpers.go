package main

import (
	"fmt"
	"net"
	"strings"
)

/*
This file contains misc function which dont fit anywhere else.
*/

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
