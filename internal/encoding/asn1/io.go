package asn1

import "io"

// valueWriter is the interface for writing a value.
type valueWriter interface {
	io.ReaderFrom
	io.ByteWriter
}
