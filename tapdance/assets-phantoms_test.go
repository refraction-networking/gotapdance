package tapdance

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"testing"

	ps "github.com/refraction-networking/gotapdance/tapdance/phantoms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAssetsPhantomsBasics(t *testing.T) {
	phantomSet := Assets().GetPhantomSubnets()
	assert.NotNil(t, phantomSet)
}

func TestAssetsPhantoms(t *testing.T) {
	var b bytes.Buffer
	logHolder := bufio.NewWriter(&b)
	oldLoggerOut := Logger().Out
	Logger().Out = logHolder
	defer func() {
		Logger().Out = oldLoggerOut
		if t.Failed() {
			// logHolder.Flush()
			// fmt.Printf("TapDance log was:\n%s\n", b.String())
		}
	}()
	oldpath := Assets().path

	dir1 := t.TempDir()

	var testPhantoms = ps.GetDefaultPhantomSubnets()

	AssetsSetDir(dir1)
	err := Assets().SetPhantomSubnets(testPhantoms)
	if err != nil {
		t.Fatal(err)
	}

	seed, err := hex.DecodeString("5a87133b68da3468988a21659a12ed2ece07345c8c1a5b08459ffdea4218d12f")
	require.Nil(t, err)

	addr4, addr6, err := SelectPhantom(seed, both)
	require.Nil(t, err)
	require.Equal(t, "192.122.190.178", addr4.String())
	require.Equal(t, "2001:48a8:687f:1:b292:3bab:bade:351f", addr6.String())

	addr4, addr6, err = SelectPhantom(seed, v6)
	require.Nil(t, err)
	require.Nil(t, addr4)
	require.Equal(t, "2001:48a8:687f:1:b292:3bab:bade:351f", addr6.String())

	addr4, addr6, err = SelectPhantom(seed, v4)
	require.Nil(t, err)
	require.Equal(t, "192.122.190.178", addr4.String())
	require.Nil(t, addr6)

	AssetsSetDir(oldpath)
}
