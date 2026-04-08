package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"goscan/pkg/portscan"
	"goscan/pkg/subdomain"
	"goscan/pkg/websocket"
	"goscan/pkg/http2"
	"goscan/pkg/race"
)

type Result struct {
	Type     string `json:"type"`
	Severity string `json:"severity"`
	Param    string `json:"param"`
	Payload  string `json:"payload"`
	Detail   string `json:"detail"`
}

func main() {
	module := flag.String("module", "", "Module to run (portscan, subdomain, websocket, http2, race)")
	target := flag.String("target", "", "Target URL or hostname")
	threads := flag.Int("threads", 100, "Number of concurrent threads")
	output := flag.String("output", "json", "Output format (json, text)")
	flag.Parse()

	if *target == "" {
		fmt.Println("Error: target is required")
		os.Exit(1)
	}

	var results []Result

	switch *module {
	case "portscan":
		results = portscan.Scan(*target, *threads)
	case "subdomain":
		results = subdomain.Enumerate(*target, *threads)
	case "websocket":
		results = websocket.Test(*target)
	case "http2":
		results = http2.Test(*target)
	case "race":
		results = race.Test(*target, *threads)
	default:
		fmt.Printf("Unknown module: %s\n", *module)
		os.Exit(1)
	}

	// Output results
	if *output == "json" {
		jsonData, _ := json.MarshalIndent(results, "", "  ")
		fmt.Println(string(jsonData))
	} else {
		for _, r := range results {
			fmt.Printf("[%s] %s - %s: %s\n", r.Severity, r.Type, r.Param, r.Detail)
		}
	}
}
