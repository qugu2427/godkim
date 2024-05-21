package main

import (
	"reflect"
	"time"
)

type DKIMRecord struct {
	v string      // rec. dkim version (def 'DKIM1')
	h []string    // opt. hash algorithms
	k KeyType     // opt. (def 'RSA')
	n string      // opt. notes
	p string      // req. pub key
	s ServiceType // opt. service type (def 'all')
	t string      // opt. flags
}

func (d1 DKIMRecord) Equals(d2 DKIMRecord) bool {
	return d1.v == d2.v &&
		reflect.DeepEqual(d1, d2) &&
		d1.k == d2.k &&
		d1.n == d2.n &&
		d1.p == d2.p &&
		d1.s == d2.s &&
		d1.t == d2.t
}

type CanonicalizationTuple struct {
	headerCanon Canonicalization
	bodyCanon   Canonicalization
}

type DKIMHeader struct {
	v  string                // req. dkim version (should be '1')
	a  SigningAlgorithm      // req. digital signature algorithm
	b  []byte                // req. digital signature
	bh []byte                // req. hash of the email body
	c  CanonicalizationTuple // opt. def simple/simple message canonicalization
	d  string                // req. domain of sender
	h  []string              // req. headers used to create signature
	i  string                // opt. todo
	l  uint64                // opt. body len count
	q  string                // opt. query method always dns/txt
	s  string                // req. selector
	t  time.Time             // rec. signature timestamp
	x  time.Time             // rec. signature expiration
	z  []string              // opt. copied header fields
}
