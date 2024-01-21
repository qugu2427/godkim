package main

import "testing"

func TestCanonicalizeEmail(t *testing.T) {

	type test struct {
		canonHeaders    Canonicalization
		canonBody       Canonicalization
		rawEmail        string
		expectedHeaders string
		expectedBody    string
	}

	tests := []test{
		{
			Relaxed,
			Relaxed,
			"A: X\r\nB : Y\t\r\n\tZ  \r\n\r\n C \r\nD \t E\r\n\r\n\r\n",
			"a:X\r\nb:Y Z\r\n",
			" C\r\nD E\r\n",
		},
	}

	for _, test := range tests {
		gotHeaders, gotBody, err := CanonicalizeEmail(CanonicalizationTuple{test.canonHeaders, test.canonBody}, test.rawEmail)
		if err != nil {
			t.Fatalf("error canonicalizing email %#v (%s)", test.rawEmail, err)
		} else if gotHeaders != test.expectedHeaders {
			t.Fatalf("canonicalized headers of %#v resulted in %#v, expect %#v", test.rawEmail, gotHeaders, test.expectedHeaders)
		} else if gotBody != test.expectedBody {
			t.Fatalf("canonicalized body of %#v resulted in %#v, expected %#v", test.rawEmail, gotBody, test.expectedBody)
		}
	}
}
