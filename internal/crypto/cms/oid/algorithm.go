package oid

import (
	"crypto/x509"
	"encoding/asn1"
)

// ToSignatureAlgorithm converts ASN.1 digest and signature algorithm
// identifiers to golang signature algorithms.
func ToSignatureAlgorithm(digestAlg, sigAlg asn1.ObjectIdentifier) x509.SignatureAlgorithm {
	switch {
	case RSA.Equal(sigAlg):
		switch {
		case SHA1.Equal(digestAlg):
			return x509.SHA1WithRSA
		case SHA256.Equal(digestAlg):
			return x509.SHA256WithRSA
		case SHA384.Equal(digestAlg):
			return x509.SHA384WithRSA
		case SHA512.Equal(digestAlg):
			return x509.SHA512WithRSA
		}
	case SHA1WithRSA.Equal(sigAlg):
		return x509.SHA1WithRSA
	case SHA256WithRSA.Equal(sigAlg):
		return x509.SHA256WithRSA
	case SHA384WithRSA.Equal(sigAlg):
		return x509.SHA384WithRSA
	case SHA512WithRSA.Equal(sigAlg):
		return x509.SHA512WithRSA
	case ECDSAWithSHA1.Equal(sigAlg):
		return x509.ECDSAWithSHA1
	case ECDSAWithSHA256.Equal(sigAlg):
		return x509.ECDSAWithSHA256
	case ECDSAWithSHA384.Equal(sigAlg):
		return x509.ECDSAWithSHA384
	case ECDSAWithSHA512.Equal(sigAlg):
		return x509.ECDSAWithSHA512
	}
	return x509.UnknownSignatureAlgorithm
}
