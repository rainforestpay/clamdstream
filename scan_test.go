package clamdstream

import (
	"bytes"
	"crypto/rand"
	"io"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockConn struct {
	reader bytes.Buffer
	writer bytes.Buffer
}

func (c *mockConn) Read(data []byte) (int, error) {
	return c.reader.Read(data)
}

func (c *mockConn) Write(data []byte) (int, error) {
	return c.writer.Write(data)
}

func (c *mockConn) Close() error {
	return nil
}

func TestClient_Scan(t *testing.T) {
	t.Run("single_chunk_found", func(t *testing.T) {
		conn := new(mockConn)
		conn.reader.WriteString("stream: FakeVirus FOUND\x00")
		client := Client{
			socketFunc: func() (io.ReadWriteCloser, error) {
				return conn, nil
			},
		}
		sampleData := bytes.NewBufferString("sampledata")

		scanResult, err := client.Scan(sampleData)
		require.NoError(t, err)
		assert.EqualValues(t, []byte("zINSTREAM\x00\x00\x00\x00\x0asampledata\x00\x00\x00\x00"), conn.writer.Bytes())
		assert.True(t, scanResult.VirusFound)
		assert.Equal(t, "FakeVirus", scanResult.VirusName)
	})

	t.Run("single_chunk_not_found", func(t *testing.T) {
		conn := new(mockConn)
		conn.reader.WriteString("stream: OK\x00")
		client := Client{
			socketFunc: func() (io.ReadWriteCloser, error) {
				return conn, nil
			},
		}
		sampleData := bytes.NewBufferString("sampledata")

		scanResult, err := client.Scan(sampleData)
		require.NoError(t, err)
		assert.EqualValues(t, []byte("zINSTREAM\x00\x00\x00\x00\x0asampledata\x00\x00\x00\x00"), conn.writer.Bytes())
		assert.False(t, scanResult.VirusFound)
		assert.Empty(t, scanResult.VirusName)
	})

	t.Run("multi_chunk_found", func(t *testing.T) {
		conn := new(mockConn)
		conn.reader.WriteString("stream: FakeVirus FOUND\x00")
		client := Client{
			socketFunc: func() (io.ReadWriteCloser, error) {
				return conn, nil
			},
		}
		sampleData := make([]byte, 3000)
		n, err := rand.Read(sampleData)
		require.NoError(t, err)
		assert.Equal(t, 3000, n)

		scanResult, err := client.Scan(bytes.NewBuffer(sampleData))
		require.NoError(t, err)
		assert.EqualValues(t, slices.Concat(
			[]byte("zINSTREAM\x00\x00\x00\x08\x00"), // first block is 2048 bytes
			sampleData[:2048],
			[]byte("\x00\x00\x03\xb8"), // next block is 3000 - 2048 = 952 bytes
			sampleData[2048:],
			[]byte("\x00\x00\x00\x00")), conn.writer.Bytes())
		assert.True(t, scanResult.VirusFound)
		assert.Equal(t, "FakeVirus", scanResult.VirusName)
	})
}
