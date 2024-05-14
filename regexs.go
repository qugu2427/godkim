package main

import "regexp"

var (
	RgxDKIMDelim        *regexp.Regexp = regexp.MustCompile(`;(\s+)`)
	RgxDKIMRecord       *regexp.Regexp = regexp.MustCompile(`^v=DKIM`)
	RgxWhiteSpace       *regexp.Regexp = regexp.MustCompile(`\s`)
	RgxEmailBodyEnd     *regexp.Regexp = regexp.MustCompile(`\r\n.\r\n$`)
	RgxConsecEndingCRLF *regexp.Regexp = regexp.MustCompile(`(\r\n){2,}$`)
	RgxConsecSpace      *regexp.Regexp = regexp.MustCompile(`[ \t]{2,}`)
	RgxNewLineSpace     *regexp.Regexp = regexp.MustCompile(`\r\n( +)`)
	RgxNotBase64        *regexp.Regexp = regexp.MustCompile(`[^A-Za-z0-9+/=]`)
	RgxNotNormal        *regexp.Regexp = regexp.MustCompile(`[^a-z0-9\-\/]`)
	RgxNotHeader        *regexp.Regexp = regexp.MustCompile(`[^A-Za-z0-9\-]`)
	RgxEndColon         *regexp.Regexp = regexp.MustCompile(`^:|:$`)
	RgxDkimSigTag       *regexp.Regexp = regexp.MustCompile(`b=([A-Za-z0-9+/= \t]+)`)
	RgxFold             *regexp.Regexp = regexp.MustCompile(`\r\n\s`)
	RgxEOLWhiteSpace    *regexp.Regexp = regexp.MustCompile(`[\t ]\r\n`)
)
