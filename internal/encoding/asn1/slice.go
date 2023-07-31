package asn1

import "io"

// readOnlySlice is an interface that represents a read-only slice of bytes.
type readOnlySlice interface {
	io.ByteReader
	io.Reader

	// Length returns the length of the slice.
	Length() int

	// Offset returns the current offset of the slice.
	Offset() int

	// Seek sets the current offset of the slice to the given value.
	Seek(offset int) error

	// Slice returns a new ReadOnlySlice that represents a sub-slice of the current slice.
	// The sub-slice starts at the given begin index and ends at the given end index (exclusive).
	Slice(begin int, end int) (readOnlySlice, error)
}

// byteSlice is a struct that implements the ReadOnlySlice interface.
type byteSlice struct {
	data   []byte
	offset int
}

// newReadOnlySlice creates a new ReadOnlySlice from the given byte slice.
func newReadOnlySlice(data []byte) readOnlySlice {
	return &byteSlice{
		data:   data,
		offset: 0,
	}
}

// ReadByte reads and returns a single byte from the slice.
// If the end of the slice has been reached, it returns an error.
func (r *byteSlice) ReadByte() (byte, error) {
	if r.offset >= len(r.data) {
		return 0, ErrEarlyEOF
	}
	b := r.data[r.offset]
	r.offset++
	return b, nil
}

// Read reads up to len(p) bytes from the slice into p.
func (r *byteSlice) Read(p []byte) (int, error) {
	if r.offset >= len(r.data) {
		return 0, io.EOF
	}
	n := copy(p, r.data[r.offset:])
	r.offset += n
	return n, nil
}

// Length returns the length of the slice.
func (r *byteSlice) Length() int {
	return len(r.data)
}

// Offset returns the current offset of the slice.
func (r *byteSlice) Offset() int {
	return r.offset
}

// Seek sets the current offset of the slice to the given value.
func (r *byteSlice) Seek(offset int) error {
	if offset < 0 || offset > len(r.data) {
		return ErrInvalidOffset
	}
	r.offset = offset
	return nil
}

// Slice returns a new ReadOnlySlice that represents a sub-slice of the current slice.
func (r *byteSlice) Slice(begin int, end int) (readOnlySlice, error) {
	if begin < 0 || end < 0 || begin > end || end > len(r.data) {
		return nil, ErrInvalidSlice
	}
	return &byteSlice{
		data:   r.data[begin:end],
		offset: 0,
	}, nil
}
