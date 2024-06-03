package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/crytic/medusa/compilation/platforms"
	"github.com/crytic/medusa/fuzzing"
	"github.com/crytic/medusa/fuzzing/api/handlers"
	"github.com/crytic/medusa/fuzzing/api/middleware"
	"github.com/crytic/medusa/fuzzing/api/routes"
	"github.com/crytic/medusa/fuzzing/config"
	"github.com/crytic/medusa/fuzzing/coverage"
	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestGetFileHandler(t *testing.T) {
	fuzzer, err := initializeFuzzer()
	if err != nil {
		t.Fatal(err)
	}
	router := initializeRouter(fuzzer)

	defer fuzzer.Stop()

	pathToTestFile := "testdata/test_contract.sol"

	req, err := http.NewRequest("GET", fmt.Sprintf("/file?path=%s", url.QueryEscape(pathToTestFile)), nil)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if status := rr.Code; status != http.StatusOK {
		t.Fatalf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}

	// Read the file content
	data, err := os.ReadFile(pathToTestFile)
	if err != nil {
		t.Fatal(err)
	}

	// Compare file content with the response body
	if bytes.Compare(rr.Body.Bytes(), data) != 0 {
		t.Errorf("handler returned wrong body: got %v want %v", rr.Body.String(), string(data))
	}
}

func TestEnvHandler(t *testing.T) {
	fuzzer, err := initializeFuzzer()
	if err != nil {
		t.Fatal(err)
	}
	router := initializeRouter(fuzzer)

	defer fuzzer.Stop()

	req, err := http.NewRequest("GET", "/env", nil)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}

	// Read the response body
	var body map[string]any
	err = json.Unmarshal(rr.Body.Bytes(), &body)
	if err != nil {
		t.Fatal(err)
	}

	if _, ok := body["config"]; !ok {
		t.Fatalf("handler did not return config information: got %v", body)
	}
	if systemInterfaces, ok := body["system"].([]interface{}); ok {
		systemInfo := make([]string, len(systemInterfaces))
		for i, v := range systemInterfaces {
			systemInfo[i] = v.(string)
		}

		if !reflect.DeepEqual(systemInfo, os.Environ()) {
			t.Fatalf("handler returned wrong system information: got %v want %v", systemInfo, os.Environ())
		}
	} else {
		t.Fatalf("handler did not return system information: got %v", body)
	}

	if solcVersion, ok := body["solcVersion"]; ok {
		v, _ := platforms.GetSystemSolcVersion()
		if solcVersion != v.String() {
			t.Fatalf("handler returned wrong solc version information: got %v want %v", solcVersion, v.String())
		}
	} else {
		t.Fatalf("handler did not return solc version: got %v", body)
	}

	if medusaVersion, ok := body["medusaVersion"]; ok {
		if medusaVersion != "0.1.3" {
			t.Fatalf("handler returned wrong medusa version: got %v want %v", medusaVersion, "0.1.3")
		}
	} else {
		t.Fatalf("handler did not return medusa version: got %v", body)
	}
}

func TestFuzzingHandler(t *testing.T) {
	fuzzer, err := initializeFuzzer()
	if err != nil {
		t.Fatal(err)
	}
	router := initializeRouter(fuzzer)

	defer fuzzer.Stop()

	req, err := http.NewRequest("GET", "/fuzzing", nil)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}

	// Read the response body
	var body map[string]any
	err = json.Unmarshal(rr.Body.Bytes(), &body)
	if err != nil {
		t.Fatal(err)
	}

	if _, ok := body["metrics"]; !ok {
		t.Fatalf("handler did not return fuzzer metrics: got %v", body)
	}
	if _, ok := body["testCases"]; !ok {
		t.Fatalf("handler did not return fuzzer metrics: got %v", body)
	}
}

func TestLogsHandler(t *testing.T) {
	fuzzer, err := initializeFuzzer()
	if err != nil {
		t.Fatal(err)
	}
	router := initializeRouter(fuzzer)

	defer fuzzer.Stop()

	req, err := http.NewRequest("GET", "/logs", nil)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}

	// Read the response body
	var body map[string]any
	err = json.Unmarshal(rr.Body.Bytes(), &body)
	if err != nil {
		t.Fatal(err)
	}

	if _, ok := body["logs"]; !ok {
		t.Fatalf("handler did not return logs: got %v", body)
	}
}

func TestCoverageHandler(t *testing.T) {
	fuzzer, err := initializeFuzzer()
	if err != nil {
		t.Fatal(err)
	}
	router := initializeRouter(fuzzer)

	defer fuzzer.Stop()

	req, err := http.NewRequest("GET", "/coverage", nil)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}

	var body *coverage.SourceAnalysis
	err = json.Unmarshal(rr.Body.Bytes(), &body)
	if err != nil {
		t.Fatal(err)
	}
}

func TestCorpusHandler(t *testing.T) {
	fuzzer, err := initializeFuzzer()
	if err != nil {
		t.Fatal(err)
	}
	router := initializeRouter(fuzzer)
	defer fuzzer.Stop()

	req, err := http.NewRequest("GET", "/corpus", nil)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()

	if fuzzer.Corpus() == nil {
		router.ServeHTTP(rr, req)
		if status := rr.Code; status != http.StatusOK {
			t.Fatalf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
		}

		// Check that we got the expected 'corpus not initialized' message
		respBody := strings.TrimSpace(rr.Body.String())
		expected := `{"error":"Corpus not initialized"}`
		if respBody != expected {
			t.Fatalf("handler returned unexpected body: got %v want %v", respBody, expected)
		}
	}

	for fuzzer.Corpus() == nil {
		time.Sleep(3 * time.Second)
	}

	rr = httptest.NewRecorder()

	router.ServeHTTP(rr, req)
	if status := rr.Code; status != http.StatusOK {
		t.Fatalf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}

	// Check that the body is a map containing only a "unexecutedCallSequences" field
	var body map[string]any
	err = json.Unmarshal(rr.Body.Bytes(), &body)
	if err != nil {
		t.Fatal(err)
	}

	if _, ok := body["unexecutedCallSequences"]; !ok {
		t.Fatalf("handler did not return unexecuted call sequences: got %v", body)
	}
}

func TestWebsocketHandler(t *testing.T) {
	fuzzer, err := initializeFuzzer()
	if err != nil {
		t.Fatal(err)
	}
	go Start(fuzzer)

	defer fuzzer.Stop()

	v, err := platforms.GetSystemSolcVersion()
	if err != nil {
		t.Fatal(err)
	}

	tcs := []struct {
		name    string
		message string
		reply   any
	}{
		{
			name:    "TestEnv",
			message: "env",
			reply:   map[string]any{"config": fuzzer.Config(), "system": os.Environ(), "medusaVersion": "0.1.3", "solcVersion": v.String()},
		},
		{
			name:    "TestCorpus",
			message: "corpus",
			reply:   map[string]any{"unexecutedCallSequences": fuzzer.Corpus().UnexecutedCallSequences()},
		},
	}

	for _, tt := range tcs {
		t.Run(tt.name, func(t *testing.T) {
			s, ws := newWSServer(t, handlers.WebsocketHandler(fuzzer))
			defer s.Close()
			defer ws.Close()

			sendMessage(t, ws, tt.message)

			replyType := reflect.TypeOf(tt.reply)
			switch replyType.Kind() {
			case reflect.Map:
				reply := receiveWSMessage[map[string]any](t, ws)

				// Compare every field of the reply
				for k, v := range tt.reply.(map[string]any) {
					if v != reply[k] {
						t.Errorf("Expected %v, got %v", v, reply[k])
					}
				}
			default:
				t.Errorf("Unsupported reply type: %v", replyType)
			}

		})
	}
}

func TestWebsocketHandlers(t *testing.T) {
	fuzzer, err := initializeFuzzer()
	if err != nil {
		t.Fatal(err)
	}
	go Start(fuzzer)
	defer fuzzer.Stop()

	//t.Parallel() // Allows running subtests in parallel

	tests := []struct {
		name           string
		handlerFunc    http.HandlerFunc
		expectedFields []string
	}{
		{
			name:           "WebsocketEnvHandler",
			handlerFunc:    handlers.WebsocketGetEnvHandler(fuzzer),
			expectedFields: []string{"config", "system", "medusaVersion", "solcVersion"},
		},
		{
			name:           "WebsocketFuzzingHandler",
			handlerFunc:    handlers.WebsocketGetFuzzingInfoHandler(fuzzer),
			expectedFields: []string{"testCases"},
		},
		{
			name:           "WebsocketLogsHandler",
			handlerFunc:    handlers.WebsocketGetLogsHandler(fuzzer),
			expectedFields: []string{"logs"},
		},
		{
			name:           "WebsocketCorpusHandler",
			handlerFunc:    handlers.WebsocketGetCorpusHandler(fuzzer),
			expectedFields: []string{"unexecutedCallSequences"},
		},
		{
			name:           "WebsocketCoverageHandler",
			handlerFunc:    handlers.WebsocketGetCoverageInfoHandler(fuzzer),
			expectedFields: []string{"sourceAnalysis"},
		},
	}

	for _, tc := range tests {
		tc := tc // Capture range variable for parallel subtests
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel() // Allows running this subtest in parallel
			testWebSocketHandler(t, tc.handlerFunc, tc.expectedFields, fuzzer)
		})
	}
}

func TestNotFoundHandler(t *testing.T) {
	req, err := http.NewRequest("GET", "/not-found", nil)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(handlers.NotFoundHandler)
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusNotFound {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusNotFound)
	}
}

func initializeFuzzer() (*fuzzing.Fuzzer, error) {
	// Obtain default projectConfig
	projectConfig, err := config.GetDefaultProjectConfig("crytic-compile")
	if err != nil {
		return nil, err
	}

	// Update compilation target
	err = projectConfig.Compilation.SetTarget("testdata")
	if err != nil {
		return nil, err
	}
	projectConfig.Fuzzing.TargetContracts = []string{"TestContract"}
	projectConfig.ApiConfig.Enabled = true
	projectConfig.ApiConfig.WsUpdateInterval = 1

	fuzzer, err := fuzzing.NewFuzzer(*projectConfig)
	if err != nil {
		return nil, err
	}

	// Start the fuzzer
	go fuzzer.Start()

	return fuzzer, nil
}

func initializeRouter(fuzzer *fuzzing.Fuzzer) *mux.Router {
	// Create a new router
	router := mux.NewRouter()

	// Attach middleware
	middleware.AttachMiddleware(router)

	// Attach routes
	routes.AttachRoutes(router, fuzzer)

	return router
}

func testWebSocketHandler(t *testing.T, handlerFunc http.HandlerFunc, expectedFields []string, fuzzer *fuzzing.Fuzzer) {
	s, ws := newWSServer(t, handlerFunc)
	defer s.Close()
	defer ws.Close()

	timestamps := make(chan time.Time)
	errChan := make(chan error, 1)

	// Goroutine to listen for messages and record timestamps
	go func() {
		for {
			reply := receiveWSMessage[map[string]any](t, ws)

			timestamps <- time.Now()

			// Check that we get every expected field
			for _, field := range expectedFields {
				if _, ok := reply[field]; !ok {
					errChan <- fmt.Errorf("expected field %v not found in reply", field)
				}
			}
		}
	}()

	// Wait for the first message to be received
	<-timestamps

	expectedInterval := time.Duration(fuzzer.Config().ApiConfig.WsUpdateInterval) * time.Second

	// Set a timeout for the test
	timeout := time.After(3 * expectedInterval)

	// Keep track of the previous timestamp
	var prevTimestamp time.Time

	for {
		select {
		case ts := <-timestamps:
			if !prevTimestamp.IsZero() {
				interval := ts.Sub(prevTimestamp)
				if interval < expectedInterval-150*time.Millisecond || interval > expectedInterval+150*time.Millisecond {
					t.Errorf("Interval between messages is %v, expected around %v", interval, expectedInterval)
				}
			}
			prevTimestamp = ts
		case err := <-errChan:
			t.Error(err)
		case <-timeout:
			// Test timeout reached, exit the loop
			return
		}
	}
}

func newWSServer(t *testing.T, h http.Handler) (*httptest.Server, *websocket.Conn) {
	t.Helper()

	s := httptest.NewServer(h)
	urlStr := httpToWs(t, s.URL)

	ws, _, err := websocket.DefaultDialer.Dial(urlStr, nil)
	if err != nil {
		t.Fatal(err)
	}

	return s, ws
}

func sendMessage(t *testing.T, ws *websocket.Conn, msg string) {
	t.Helper()

	if err := ws.WriteMessage(websocket.TextMessage, []byte(msg)); err != nil {
		t.Fatalf("%v", err)
	}
}

func receiveWSMessage[T any](t *testing.T, ws *websocket.Conn) T {
	t.Helper()

	var reply T
	err := ws.ReadJSON(&reply)
	if err != nil {
		t.Fatalf("%v", err)
	}

	return reply
}

func httpToWs(t *testing.T, urlString string) string {
	t.Helper()

	u, err := url.Parse(urlString)
	if err != nil {
		t.Fatal(err)
	}

	u.Scheme = "ws"
	return u.String()
}
