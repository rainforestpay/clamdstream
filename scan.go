package clamdstream

import (
	"bytes"
	"encoding/binary"
	"io"
	"regexp"
	"strings"
)

var responseRegex = regexp.MustCompile(`(\w+): (.+) (\w+)`)

const (
	maxChunkSize    = 2048
	instreamCommand = "zINSTREAM\x00"
	clamdFound      = "FOUND"
)

// ScanResult is the result of a clamd scan.
//
// If a virus is detected, VirusFound will be set to true, and VirusName will be set.
//
// Message is the raw, unparsed response from clamd.
type ScanResult struct {
	VirusFound bool
	VirusName  string
	Message    string
}

// Scan opens a TCP connection, and streams the data from the provided reader to the clamd daemon.
// It returns a ScanResult generated from the clamd response.
func (c *Client) Scan(r io.Reader) (ScanResult, error) {
	var empty ScanResult
	socket, err := c.socketFunc()
	if err != nil {
		return empty, err
	}
	defer socket.Close()

	if _, err := socket.Write([]byte(instreamCommand)); err != nil {
		return empty, err
	}

	finishedReading := false
	for !finishedReading {
		var buf bytes.Buffer
		n, err := io.CopyN(&buf, r, maxChunkSize)
		if err == io.EOF {
			finishedReading = true
		} else if err != nil {
			return empty, err
		}

		// Write the size of the chunk
		size := make([]byte, 4)
		binary.BigEndian.PutUint32(size, uint32(n))
		if _, err = socket.Write(size); err != nil {
			return empty, err
		}
		// Write the data
		if _, err = io.Copy(socket, &buf); err != nil {
			return empty, nil
		}
	}

	// Terminate the request with a zero word
	if _, err := socket.Write([]byte{0, 0, 0, 0}); err != nil {
		return empty, err
	}

	response, err := io.ReadAll(socket)
	if err != nil {
		return empty, err
	}

	strResponse := string(bytes.Trim(response, "\x00"))
	if strings.Contains(strResponse, clamdFound) {
		scanResult := ScanResult{
			VirusFound: true,
			Message:    strResponse,
		}
		matches := responseRegex.FindStringSubmatch(strResponse)
		if len(matches) == 4 {
			scanResult.VirusName = matches[2]
		}
		return scanResult, nil
	}

	return ScanResult{
		VirusFound: false,
		Message:    strResponse,
	}, nil
}
