package asn1

import "io"

// ValueWriter is the interface for writing a value.
type ValueWriter interface {
	io.ReaderFrom
	io.ByteWriter
}
