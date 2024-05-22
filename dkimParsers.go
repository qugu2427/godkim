package main

import (
	"encoding/base64"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var (
	RgxDKIMDelim *regexp.Regexp = regexp.MustCompile(`;(\s+)`)
	RgxNotBase64 *regexp.Regexp = regexp.MustCompile(`[^A-Za-z0-9+/=]`) // FIXME why is it like this
	RgxNotHeader *regexp.Regexp = regexp.MustCompile(`[^A-Za-z0-9\-]`)
	RgxEndColon  *regexp.Regexp = regexp.MustCompile(`^:|:$`)
)

/*
This contains function which parse dkim string values to workable values.
*/

func parseServiceType(txtServiceType string) (parsedServiceType ServiceType, err error) {
	txtServiceType = normalizeString(txtServiceType)
	switch txtServiceType {
	case "*":
		parsedServiceType = All
	case "email":
		parsedServiceType = Email
	default:
		err = fmt.Errorf("unknown service type '%s'", txtServiceType)
	}
	return
}

func parseKeyType(txtKeyType string) (parsedKeyType KeyType, err error) {
	txtKeyType = normalizeString(txtKeyType)
	switch txtKeyType {
	case "rsa":
		parsedKeyType = RSA
	default:
		err = fmt.Errorf("unknown key type '%s'", txtKeyType)
	}
	return
}

func parseSigningAlgorithm(txtAlgo string) (parsedAlgo SigningAlgorithm, err error) {
	txtAlgo = normalizeString(txtAlgo)
	switch txtAlgo {
	case "rsa-sha1":
		parsedAlgo = RSASHA1
	case "rsa-sha256":
		parsedAlgo = RSASHA256
	default:
		err = fmt.Errorf("unknown signature algorithm '%s'", txtAlgo)
	}
	return
}

func parseCanonicalization(txtCanon string) (parsedCanon Canonicalization, err error) {
	txtCanon = normalizeString(txtCanon)
	switch txtCanon {
	case "simple":
		parsedCanon = Simple
	case "relaxed":
		parsedCanon = Relaxed
	default:
		err = fmt.Errorf("unknown canonicalization '%s", txtCanon)
	}
	return
}

func parseCanonicalizationTuple(txtCanonTuple string) (parsedCanonTuple CanonicalizationTuple, err error) {
	txtCanonTuple = normalizeString(txtCanonTuple)
	txtCanonTupleSplit := strings.Split(txtCanonTuple, "/")
	if len(txtCanonTupleSplit) != 2 {
		if len(txtCanonTupleSplit) == 1 {
			parsedCanonTuple.bodyCanon = Simple
			parsedCanonTuple.headerCanon, err = parseCanonicalization(txtCanonTupleSplit[0])
			return
		}
		err = fmt.Errorf("unable to split canonicalization tuple '%s'", txtCanonTuple)
		return
	}
	parsedCanonTuple.headerCanon, err = parseCanonicalization(txtCanonTupleSplit[0])
	if err != nil {
		return
	}
	parsedCanonTuple.bodyCanon, err = parseCanonicalization(txtCanonTupleSplit[1])
	if err != nil {
		return
	}
	return
}

func parseBase64(encodedStr string) (buffer []byte, err error) {
	encodedStr = RgxNotBase64.ReplaceAllString(encodedStr, "")
	return base64.StdEncoding.DecodeString(encodedStr)
}

func parseTagsToMap(txt string) (txtMap map[string]string, err error) {
	txt = strings.TrimSpace(txt)
	txt = RgxDKIMDelim.ReplaceAllString(txt, ";")
	txtSplit := strings.Split(txt, ";")
	txtMap = map[string]string{}
	for _, word := range txtSplit {
		if word == "" {
			continue
		}
		wordSplit := strings.SplitN(word, "=", 2)
		if len(wordSplit) != 2 {
			err = fmt.Errorf("failed to parse word '%s' to key value pair, expected key=value format", word)
			return
		}
		txtMap[wordSplit[0]] = wordSplit[1]
	}
	return
}

func parseHeaderList(headerListTxt string) (headerList []string, err error) {
	usedHeaders := make(map[string]bool)
	RgxEndColon.ReplaceAllString(headerListTxt, "")
	headerSplit := strings.Split(headerListTxt, ":")
	for _, header := range headerSplit {
		header := RgxNotHeader.ReplaceAllString(header, "")
		if _, exists := usedHeaders[header]; !exists {
			usedHeaders[header] = true
			headerList = append(headerList, header)
		}
	}
	return
}

func ParseDKIMHeader(txtHeader string) (parsedHeader DKIMHeader, err error) {
	txtHeaderMap, err := parseTagsToMap(txtHeader)
	if err != nil {
		return
	}

	// Version (v=1)
	v, exists := txtHeaderMap["v"]
	if !exists {
		err = fmt.Errorf("no version (v) specified in dkim header")
		return
	}
	if v != "1" {
		err = fmt.Errorf("unsupported dkim version in header '%s', expected version to be '1'", v)
		return
	}
	parsedHeader.v = "1"

	// Sig algorithm (a)
	a, exists := txtHeaderMap["a"]
	if !exists {
		err = fmt.Errorf("no signature algorithm (a) specified in dkim header")
		return
	}
	parsedHeader.a, err = parseSigningAlgorithm(a)
	if err != nil {
		return
	}

	// Sig (b) and body hash (bh)
	b, exists := txtHeaderMap["b"]
	if !exists {
		err = fmt.Errorf("no signature (b) specified in dkim header")
		return
	}
	parsedHeader.b, err = parseBase64(b)
	if err != nil {
		return
	}
	bh, exists := txtHeaderMap["bh"]
	if !exists {
		err = fmt.Errorf("no body hash (bh) specified in dkim header")
		return
	}
	parsedHeader.bh, err = parseBase64(bh)
	if err != nil {
		return
	}

	// Canon (c)
	c, exists := txtHeaderMap["c"]
	if !exists {
		parsedHeader.c = CanonicalizationTuple{Simple, Simple}
	} else {
		parsedHeader.c, err = parseCanonicalizationTuple(c)
		if err != nil {
			return
		}
	}

	// Domain (d)
	d, exists := txtHeaderMap["d"]
	if !exists {
		err = fmt.Errorf("no domain (d) specified in dkim header")
		return
	}
	parsedHeader.d = d

	// Headers (h)
	h, exists := txtHeaderMap["h"]
	if !exists {
		err = fmt.Errorf("no headers (h) specified in dkim header")
		return
	}
	parsedHeader.h, err = parseHeaderList(h)
	if err != nil {
		return
	}

	// Agent (i)
	// this isnt used other than checking it against d
	i, exists := txtHeaderMap["i"]
	if exists {
		iSplit := strings.Split(i, "@")
		if len(iSplit) == 2 {
			err = fmt.Errorf("invalid agent (i) not in form local@domain")
			return
		}
		if !strings.HasSuffix(iSplit[1], parsedHeader.d) {
			if len(iSplit) == 2 {
				err = fmt.Errorf("agent (i) %s not a subdomain of %s", iSplit[1], parsedHeader.d)
				return
			}
		}
		parsedHeader.i = i
	}

	// Body Length Count (l)
	l, exists := txtHeaderMap["i"]
	if exists {
		lNum, _err := strconv.Atoi(l)
		if _err != nil {
			err = _err
			return
		}
		if lNum < 1 {
			err = fmt.Errorf("body length count (l) less than 1")
		}
		parsedHeader.l = lNum
	}

	// q is unused since it is always dns/txt

	// Selectors (s)
	s, exists := txtHeaderMap["s"]
	if !exists {
		err = fmt.Errorf("no selector (s) specified in dkim header")
		return
	}
	parsedHeader.s = s

	// Time (t) and expiration (x)
	t, exists := txtHeaderMap["t"]
	if exists {
		tNum, _err := strconv.ParseInt(t, 10, 64)
		if _err != nil {
			err = _err
			return
		}
		parsedHeader.t = time.Unix(tNum, 0)
	}
	x, exists := txtHeaderMap["x"]
	if exists {
		xNum, _err := strconv.ParseInt(x, 10, 64)
		if _err != nil {
			err = _err
			return
		}
		parsedHeader.x = time.Unix(xNum, 0)
	}

	// Copied header fields (z)
	z, exists := txtHeaderMap["z"]
	if exists {
		parsedHeader.z = strings.Split(z, "|")
	}

	return
}

func ParseDKIMRecord(txtRecord string) (parsedRecord DKIMRecord, err error) {
	txtRecordMap, err := parseTagsToMap(txtRecord)
	if err != nil {
		return
	}

	// Check version (v=DKIM1)
	v, exists := txtRecordMap["v"]
	if !exists {
		parsedRecord.v = "DKIM1"
	} else {
		if strings.ToUpper(v) != "DKIM1" {
			err = fmt.Errorf("unsupported dkim version in dns record '%s', expected version to be 'DKIM1'", v)
			return
		}
		parsedRecord.v = strings.ToUpper(v)
	}

	// Acceptable hash algos (h)
	// TODO: check that this matches a
	h, exists := txtRecordMap["h"]
	if exists {
		parsedRecord.h, err = parseHeaderList(h)
		if err != nil {
			return
		}
	}

	// Key type (k)
	k, exists := txtRecordMap["k"]
	if !exists {
		parsedRecord.k = RSA
	} else {
		parsedRecord.k, err = parseKeyType(k)
		if err != nil {
			return
		}
	}

	// Notes (n)
	n, exists := txtRecordMap["n"]
	if exists {
		parsedRecord.n = n
	}

	// Public key (p)
	p, exists := txtRecordMap["p"]
	if !exists {
		err = fmt.Errorf("no public key (p) specified in dkim header")
		return
	}
	p = "-----BEGIN PUBLIC KEY-----\n" + p + "\n-----END PUBLIC KEY-----"
	parsedRecord.p = p

	// Service type (s)
	s, exists := txtRecordMap["s"]
	if exists {
		parsedRecord.s, err = parseServiceType(s)
		if err != nil {
			return
		}
	}

	// Flags (t)
	t, exists := txtRecordMap["t"]
	if exists {
		parsedRecord.t = t
	}

	return
}
