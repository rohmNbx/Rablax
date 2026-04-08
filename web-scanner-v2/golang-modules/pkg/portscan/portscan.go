package portscan

import (
	"fmt"
	"net"
	"sync"
	"time"
)

type Result struct {
	Type     string `json:"type"`
	Severity string `json:"severity"`
	Param    string `json:"param"`
	Payload  string `json:"payload"`
	Detail   string `json:"detail"`
}

var commonPorts = []int{
	21, 22, 23, 25, 53, 80, 110, 143, 443, 445,
	3306, 3389, 5432, 5900, 6379, 8080, 8443, 27017,
}

var serviceNames = map[int]string{
	21:    "FTP",
	22:    "SSH",
	23:    "Telnet",
	25:    "SMTP",
	53:    "DNS",
	80:    "HTTP",
	110:   "POP3",
	143:   "IMAP",
	443:   "HTTPS",
	445:   "SMB",
	3306:  "MySQL",
	3389:  "RDP",
	5432:  "PostgreSQL",
	5900:  "VNC",
	6379:  "Redis",
	8080:  "HTTP-Alt",
	8443:  "HTTPS-Alt",
	27017: "MongoDB",
}

// Scan performs ultra-fast port scanning using goroutines
func Scan(target string, maxThreads int) []Result {
	var results []Result
	var wg sync.WaitGroup
	var mu sync.Mutex

	// Semaphore untuk limit concurrent connections
	sem := make(chan struct{}, maxThreads)

	for _, port := range commonPorts {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			sem <- struct{}{}        // Acquire
			defer func() { <-sem }() // Release

			address := fmt.Sprintf("%s:%d", target, p)
			conn, err := net.DialTimeout("tcp", address, 1*time.Second)

			if err == nil {
				conn.Close()

				service := serviceNames[p]
				severity := "MEDIUM"
				if p == 23 || p == 21 || p == 3389 || p == 5900 {
					severity = "HIGH"
				}

				mu.Lock()
				results = append(results, Result{
					Type:     "Open Port",
					Severity: severity,
					Param:    fmt.Sprintf("Port %d", p),
					Payload:  "-",
					Detail:   fmt.Sprintf("Service: %s", service),
				})
				mu.Unlock()
			}
		}(port)
	}

	wg.Wait()
	return results
}

// ScanRange scans a range of ports
func ScanRange(target string, startPort, endPort, maxThreads int) []Result {
	var results []Result
	var wg sync.WaitGroup
	var mu sync.Mutex

	sem := make(chan struct{}, maxThreads)

	for port := startPort; port <= endPort; port++ {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			address := fmt.Sprintf("%s:%d", target, p)
			conn, err := net.DialTimeout("tcp", address, 500*time.Millisecond)

			if err == nil {
				conn.Close()

				service := serviceNames[p]
				if service == "" {
					service = "Unknown"
				}

				mu.Lock()
				results = append(results, Result{
					Type:     "Open Port",
					Severity: "MEDIUM",
					Param:    fmt.Sprintf("Port %d", p),
					Payload:  "-",
					Detail:   fmt.Sprintf("Service: %s", service),
				})
				mu.Unlock()
			}
		}(port)
	}

	wg.Wait()
	return results
}

// ScanTop1000 scans top 1000 most common ports
func ScanTop1000(target string, maxThreads int) []Result {
	// Top 1000 ports list (abbreviated for example)
	top1000 := []int{
		80, 443, 22, 21, 25, 3389, 110, 445, 139, 143,
		53, 135, 3306, 8080, 1723, 111, 995, 993, 5900, 1025,
		// ... add more ports
	}

	var results []Result
	var wg sync.WaitGroup
	var mu sync.Mutex

	sem := make(chan struct{}, maxThreads)

	for _, port := range top1000 {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			address := fmt.Sprintf("%s:%d", target, p)
			conn, err := net.DialTimeout("tcp", address, 500*time.Millisecond)

			if err == nil {
				conn.Close()

				mu.Lock()
				results = append(results, Result{
					Type:     "Open Port",
					Severity: "MEDIUM",
					Param:    fmt.Sprintf("Port %d", p),
					Payload:  "-",
					Detail:   fmt.Sprintf("Port is open"),
				})
				mu.Unlock()
			}
		}(port)
	}

	wg.Wait()
	return results
}
