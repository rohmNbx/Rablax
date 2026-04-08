package race

import (
	"fmt"
	"io"
	"net/http"
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

// Test performs race condition testing with concurrent requests
func Test(target string, numRequests int) []Result {
	var results []Result
	var wg sync.WaitGroup
	var mu sync.Mutex

	responses := make([]int, 0, numRequests)
	responseBodies := make([]string, 0, numRequests)
	startTime := time.Now()

	// Create HTTP client with connection pooling
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:        numRequests,
			MaxIdleConnsPerHost: numRequests,
			IdleConnTimeout:     30 * time.Second,
		},
	}

	// Synchronization barrier untuk memastikan semua goroutine start bersamaan
	barrier := make(chan struct{})

	for i := 0; i < numRequests; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			// Wait at barrier
			<-barrier

			resp, err := client.Get(target)
			if err != nil {
				return
			}
			defer resp.Body.Close()

			body, _ := io.ReadAll(resp.Body)

			mu.Lock()
			responses = append(responses, resp.StatusCode)
			responseBodies = append(responseBodies, string(body)[:min(100, len(body))])
			mu.Unlock()
		}(i)
	}

	// Release all goroutines simultaneously
	close(barrier)

	wg.Wait()
	elapsed := time.Since(startTime)

	// Analyze results
	successCount := 0
	for _, code := range responses {
		if code >= 200 && code < 300 {
			successCount++
		}
	}

	// Check for race condition indicators
	if successCount > 1 {
		// Check if responses are different (indicating state changes)
		uniqueResponses := make(map[string]bool)
		for _, body := range responseBodies {
			uniqueResponses[body] = true
		}

		severity := "HIGH"
		if successCount > numRequests/2 {
			severity = "CRITICAL"
		}

		results = append(results, Result{
			Type:     "Race Condition Detected",
			Severity: severity,
			Param:    "Concurrent Requests",
			Payload:  fmt.Sprintf("%d simultaneous requests", numRequests),
			Detail: fmt.Sprintf(
				"Success: %d/%d, Unique responses: %d, Time: %v",
				successCount, numRequests, len(uniqueResponses), elapsed,
			),
		})
	}

	// Check for timing anomalies
	if elapsed < time.Duration(numRequests)*10*time.Millisecond {
		results = append(results, Result{
			Type:     "Possible Race Condition",
			Severity: "MEDIUM",
			Param:    "Response Timing",
			Payload:  "-",
			Detail: fmt.Sprintf(
				"Suspiciously fast responses: %v for %d requests",
				elapsed, numRequests,
			),
		})
	}

	return results
}

// TestPOST performs race condition testing with POST requests
func TestPOST(target string, data string, numRequests int) []Result {
	var results []Result
	var wg sync.WaitGroup
	var mu sync.Mutex

	responses := make([]int, 0, numRequests)
	barrier := make(chan struct{})

	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:        numRequests,
			MaxIdleConnsPerHost: numRequests,
		},
	}

	for i := 0; i < numRequests; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-barrier

			resp, err := client.Post(target, "application/x-www-form-urlencoded", nil)
			if err != nil {
				return
			}
			defer resp.Body.Close()

			mu.Lock()
			responses = append(responses, resp.StatusCode)
			mu.Unlock()
		}()
	}

	close(barrier)
	wg.Wait()

	// Analyze
	successCount := 0
	for _, code := range responses {
		if code >= 200 && code < 300 {
			successCount++
		}
	}

	if successCount > 1 {
		results = append(results, Result{
			Type:     "Race Condition (POST)",
			Severity: "CRITICAL",
			Param:    "POST Request",
			Payload:  data,
			Detail:   fmt.Sprintf("%d successful POST requests", successCount),
		})
	}

	return results
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
