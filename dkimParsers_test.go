package main

import "testing"

func TestParseDKIMRecord(t *testing.T) {
	type test struct {
		txtRecord      string
		expectedRecord DKIMRecord
	}
	tests := []test{
		{
			"v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAiB9xMzToz+El7oDglrlHbZk7Tmz0cfxNPR5nzZSAeKBWlH7DMt/FiVGE8C2Qhgrqad3OMAddixm9s4UyztMWj5rXqIy0IK+ALH5JdVCPuNAXHHLXF1B4QizNj6PKVVcAJ6hnvuslV7hKDv4+9zUVJa2FSrgrEUEockpSmN6cJB2qWlef6xYKN1IEDCg/4Q8OmDiiu5RaB+lzFDrAE9vTrKKa58Ms8QcX4TRF1f9kzVvrpEMGdOk6d6v0Zmva/bLV0Hr/79keJZuDOa1KQp/KQVDssHVuPAuwVG6PSO6AwT7DWPcMoUPJm5moIMbIo2/ldg9BsTUW4DWBGZfG85q55QIDAQAB",
			DKIMRecord{
				v: "DKIM1",
				h: nil,
				k: RSA,
				n: "",
				p: "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAiB9xMzToz+El7oDglrlHbZk7Tmz0cfxNPR5nzZSAeKBWlH7DMt/FiVGE8C2Qhgrqad3OMAddixm9s4UyztMWj5rXqIy0IK+ALH5JdVCPuNAXHHLXF1B4QizNj6PKVVcAJ6hnvuslV7hKDv4+9zUVJa2FSrgrEUEockpSmN6cJB2qWlef6xYKN1IEDCg/4Q8OmDiiu5RaB+lzFDrAE9vTrKKa58Ms8QcX4TRF1f9kzVvrpEMGdOk6d6v0Zmva/bLV0Hr/79keJZuDOa1KQp/KQVDssHVuPAuwVG6PSO6AwT7DWPcMoUPJm5moIMbIo2/ldg9BsTUW4DWBGZfG85q55QIDAQAB\n-----END PUBLIC KEY-----",
				s: All,
				t: "",
			},
		},
	}
	for _, test := range tests {
		gotRecord, err := ParseDKIMRecord(test.txtRecord)
		if err != nil {
			t.Fatalf("error when parsing dkim record %#v (%s)", test.txtRecord, err)
		} else if !gotRecord.Equals(test.expectedRecord) {
			t.Fatalf("got dkim record (\n%#v\n) does not match expected (\n%#v\n)", gotRecord, test.expectedRecord)
		}
	}
}
