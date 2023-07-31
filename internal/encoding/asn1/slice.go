package asn1

import "io"

type ReadOnlySlice interface {
	io.ByteReader
	io.Reader
	Length() int
	Offset() int
	Seek(offset int) error
	Slice(begin int, end int) (ReadOnlySlice, error)
}

type readOnlySlice struct {
	data   []byte
	offset int
}

func newReadOnlySlice(data []byte) ReadOnlySlice {
	return &readOnlySlice{
		data:   data,
		offset: 0,
	}
}

func (r *readOnlySlice) ReadByte() (byte, error) {
	if r.offset >= len(r.data) {
		return 0, ErrEarlyEOF
	}
	defer func() { r.offset++ }()
	return r.data[r.offset], nil
}

func (r *readOnlySlice) Read(p []byte) (int, error) {
	if r.offset >= len(r.data) {
		return 0, io.EOF
	}
	n := copy(p, r.data[r.offset:])
	r.offset += n
	return n, nil
}

func (r *readOnlySlice) Length() int {
	return len(r.data)
}

func (r *readOnlySlice) Offset() int {
	return r.offset
}

func (r *readOnlySlice) Seek(offset int) error {
	if offset < 0 || offset > len(r.data) {
		return ErrInvalidOffset
	}
	r.offset = offset
	return nil
}

func (r *readOnlySlice) Slice(begin int, end int) (ReadOnlySlice, error) {
	if begin < 0 || end < 0 || begin > end || end > len(r.data) {
		return nil, ErrInvalidSlice
	}
	return &readOnlySlice{
		data:   r.data[begin:end],
		offset: 0,
	}, nil
}
