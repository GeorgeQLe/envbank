package nativehost

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
)

const MaxRequestBytes = 64 << 10

func ReadMessage(r io.Reader, value any) error {
	var header [4]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return err
	}
	size := binary.LittleEndian.Uint32(header[:])
	if size == 0 || size > MaxRequestBytes {
		return errors.New("native message length is invalid")
	}
	payload := make([]byte, size)
	if _, err := io.ReadFull(r, payload); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytesReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return errors.New("native message is invalid JSON")
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return errors.New("native message must contain one JSON value")
	}
	return nil
}

func WriteMessage(w io.Writer, value any) error {
	payload, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if len(payload) > MaxRequestBytes {
		return errors.New("native response is too large")
	}
	var header [4]byte
	binary.LittleEndian.PutUint32(header[:], uint32(len(payload)))
	if _, err := w.Write(header[:]); err != nil {
		return err
	}
	_, err = w.Write(payload)
	return err
}

type byteReader struct {
	data   []byte
	offset int
}

func bytesReader(data []byte) *byteReader { return &byteReader{data: data} }
func (r *byteReader) Read(p []byte) (int, error) {
	if r.offset == len(r.data) {
		return 0, io.EOF
	}
	n := copy(p, r.data[r.offset:])
	r.offset += n
	return n, nil
}
