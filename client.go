package clamdstream

import (
	"fmt"
	"io"
	"net"
)

// Client is a connection to the clamd daemon.
type Client struct {
	socketFunc func() (io.ReadWriteCloser, error)
}

// NewClient initializes a new Client. It does not open a connection.
func NewClient(host string, port uint) (*Client, error) {
	socketFunc := func() (io.ReadWriteCloser, error) {
		conn, err := net.Dial("tcp", fmt.Sprintf("%s:%d", host, port))
		if err != nil {
			return nil, err
		}
		return conn, nil
	}
	return &Client{
		socketFunc: socketFunc,
	}, nil
}
