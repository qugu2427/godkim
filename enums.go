package dkim

type VerificationResult uint8

const (
	Success VerificationResult = iota
	PermFail
	TempFail
)

func (v VerificationResult) String() string {
	switch v {
	case Success:
		return "Success"
	case PermFail:
		return "PermFail"
	case TempFail:
		return "TempFail"
	default:
		panic("unknown verification result")
	}
}

type SigningAlgorithm uint8

const (
	RSASHA1 SigningAlgorithm = iota
	RSASHA256
)

func (s SigningAlgorithm) String() string {
	switch s {
	case RSASHA1:
		return "rsa-sha1"
	case RSASHA256:
		return "rsa-sha256"
	default:
		panic("unknown signing algorithm")
	}
}

type Canonicalization uint8

const (
	Simple Canonicalization = iota
	Relaxed
)

func (c Canonicalization) String() string {
	switch c {
	case Simple:
		return "simple"
	case Relaxed:
		return "relaxed"
	default:
		panic("unknown canonicalization")
	}
}

type KeyType uint8

const (
	RSA KeyType = iota
)

func (k KeyType) String() string {
	switch k {
	case RSA:
		return "RSA"
	default:
		panic("unknown key type")
	}
}

type ServiceType uint8

const (
	All ServiceType = iota
	Email
)

func (s ServiceType) String() string {
	switch s {
	case All:
		return "All"
	case Email:
		return "Email"
	default:
		panic("unknown service type")
	}
}
