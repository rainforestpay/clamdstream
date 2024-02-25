package main

import (
	"flag"
	"fmt"
	"os"
	"runtime"
	"runtime/debug"

	"github.com/rainforestpay/clamdstream"
)

func main() {
	var (
		host string
		port uint

		version bool
	)

	flag.StringVar(&host, "host", "localhost", "clamd host")
	flag.UintVar(&port, "port", 3310, "clamd port")
	flag.BoolVar(&version, "version", false, "get version")
	flag.Parse()

	if version {
		printVersion()
		os.Exit(0)
	}

	args := flag.Args()
	if len(args) != 1 {
		fmt.Println("usage: clamdstream [options] [filename]")
		os.Exit(1)
	}
	filename := args[0]

	file, err := os.Open(filename)
	if err != nil {
		fmt.Printf("Error: %s", err)
		os.Exit(1)
	}
	defer file.Close()

	client, err := clamdstream.NewClient(host, port)
	if err != nil {
		fmt.Printf("Error: %s", err)
		os.Exit(1)
	}

	scanResult, err := client.Scan(file)
	if err != nil {
		fmt.Printf("Error: %s", err)
		os.Exit(1)
	}

	fmt.Printf("Scan result for %s\n", filename)
	if scanResult.VirusFound {
		fmt.Printf("\tVirus Found: %s\n", scanResult.VirusName)
	} else {
		fmt.Println("\tNo Viruses Detected")
	}
	fmt.Printf("\tMessage: %s\n", scanResult.Message)

	if scanResult.VirusFound {
		os.Exit(1)
	} else {
		os.Exit(0)
	}
}

func printVersion() {
	gitCommit := func() string {
		if info, ok := debug.ReadBuildInfo(); ok {
			for _, setting := range info.Settings {
				if setting.Key == "vcs.revision" {
					return setting.Value[:7]
				}
			}
		}

		return "unknown"
	}

	fmt.Printf("clamdscan\n\tgit commit: %s\n\tgo runtime: %s\n", gitCommit(), runtime.Version())
}
