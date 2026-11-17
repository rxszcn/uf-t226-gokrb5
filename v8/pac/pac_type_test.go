package pac

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"
	"testing"

	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/test/testdata"
	"github.com/jcmturner/gokrb5/v8/types"
	"github.com/stretchr/testify/assert"
)

func TestPACTypeVerify(t *testing.T) {
	t.Parallel()
	b, err := hex.DecodeString(testdata.MarshaledPAC_AD_WIN2K_PAC)
	if err != nil {
		t.Fatalf("Test vector read error: %v", err)
	}
	var pac PACType
	err = pac.Unmarshal(b)
	if err != nil {
		t.Fatalf("Error unmarshaling test data: %v", err)
	}

	b, _ = hex.DecodeString(testdata.KEYTAB_SYSHTTP_TEST_GOKRB5)
	kt := keytab.New()
	kt.Unmarshal(b)
	pn, _ := types.ParseSPNString("sysHTTP")
	key, _, err := kt.GetEncryptionKey(pn, "TEST.GOKRB5", 2, 18)
	if err != nil {
		t.Fatalf("Error getting key: %v", err)
	}
	w := bytes.NewBufferString("")
	l := log.New(w, "", 0)
	err = pac.ProcessPACInfoBuffers(key, l)
	if err != nil {
		t.Fatalf("Processing reference pac error: %v", err)
	}

	pacInvalidServerSig := pac
	// Check the signature to force failure
	pacInvalidServerSig.ServerChecksum.Signature[0] ^= 0xFF
	pacInvalidNilKerbValidationInfo := pac
	pacInvalidNilKerbValidationInfo.KerbValidationInfo = nil
	pacInvalidNilServerSig := pac
	pacInvalidNilServerSig.ServerChecksum = nil
	pacInvalidNilKdcSig := pac
	pacInvalidNilKdcSig.KDCChecksum = nil
	pacInvalidClientInfo := pac
	pacInvalidClientInfo.ClientInfo = nil

	var pacs = []struct {
		pac PACType
	}{
		{pacInvalidServerSig},
		{pacInvalidNilKerbValidationInfo},
		{pacInvalidNilServerSig},
		{pacInvalidNilKdcSig},
		{pacInvalidClientInfo},
	}
	for i, s := range pacs {
		v, _ := s.pac.verify(key)
		assert.False(t, v, fmt.Sprintf("Validation should have failed for test %v", i))
	}

}

func TestPACTypeProcessPACInfoBuffers_OffsetOutOfBounds(t *testing.T) {
	t.Parallel()
	w := bytes.NewBufferString("")
	l := log.New(w, "", 0)
	key := types.EncryptionKey{}

	malformedPAC := func(ulType, cbBufferSize uint32, offset uint64) []byte {
		b := make([]byte, 8+16)
		binary.LittleEndian.PutUint32(b[0:4], 1)           // CBuffers
		binary.LittleEndian.PutUint32(b[4:8], 0)           // Version
		binary.LittleEndian.PutUint32(b[8:12], ulType)     // ULType
		binary.LittleEndian.PutUint32(b[12:16], cbBufferSize) // CBBufferSize
		binary.LittleEndian.PutUint64(b[16:24], offset)    // Offset
		return b
	}

	tests := []struct {
		name string
		data []byte
	}{
		{"offset beyond data length", malformedPAC(10, 16, 0x1000)},
		{"offset plus size overflows data length", malformedPAC(10, 0x1000, 16)},
		{"offset plus size overflows uint64", malformedPAC(6, 16, 0xFFFFFFFFFFFFFFF8)},
	}
	for _, tc := range tests {
		var pac PACType
		err := pac.Unmarshal(tc.data)
		if err != nil {
			t.Fatalf("%s: error unmarshaling malformed PAC: %v", tc.name, err)
		}
		err = pac.ProcessPACInfoBuffers(key, l)
		assert.Error(t, err, fmt.Sprintf("%s: processing a PAC with an out of bounds info buffer should error, not panic", tc.name))
	}
}

func TestPACTypeUnmarshal_CBuffersTooLarge(t *testing.T) {
	t.Parallel()
	// CBuffers declares more info buffer headers than can fit in the data.
	b := make([]byte, 8)
	binary.LittleEndian.PutUint32(b[0:4], 0x10000000) // CBuffers
	binary.LittleEndian.PutUint32(b[4:8], 0)          // Version
	var pac PACType
	err := pac.Unmarshal(b)
	assert.Error(t, err, "unmarshaling a PAC whose CBuffers exceeds the data length should error, not allocate")
}
