# clamdstream
![](https://github.com/rainforestpay/clamdstream/actions/workflows/run_tests.yml/badge.svg)
[![Go Reference](https://pkg.go.dev/badge/github.com/rainforestpay/clamdstream.svg)](https://pkg.go.dev/github.com/rainforestpay/clamdstream)

**clamdstream** is a simple go library that streams data to the [ClamAV](https://www.clamav.net/) scanning daemon, clamd.
This is useful for scanning in cloud settings, where clamd may not be running on the same machine as the requesting 
service.

**clamdstream** can also be run as a CLI tool.

## Installing
To install the library:
```bash
go install github.com/rainforestpay/clamdstream
```
To install the CLI tool:
```bash
go install github.com/rainforestpay/clamdstream/cmd/clamdstream@latest
```

## Example
### Library
```go
package main

func main() {
	client, err := clamdstream.NewClient("localhost", 3310)
	if err != nil {
		log.Fatal(err)
	}

	file, err := os.Open("file_to_scan.exe")
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	scanResult, err := client.Scan(file)
	if err != nil {
		log.Fatal(err)
	}

	if scanResult.VirusFound {
		log.Printf("Virus Found: %s", scanResult.VirusName)
	} else {
		log.Printf("No virus detected")
	}
}
```
### CLI
If clamd is running on localhost on port 3310:
```bash
clamdstream file_to_scan.exe
```
If clamd is running on a different host and/or port:
```bash
clamdstream -host my-clamd -port 3310 file_to_scan.exe
```