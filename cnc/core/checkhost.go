package core

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

const checkHostOrigin = "https://check-host.net"

type checkHostStart struct {
	OK        int    `json:"ok"`
	RequestID string `json:"request_id"`
}

func checkHostHTTPClient() *http.Client {
	return &http.Client{Timeout: 25 * time.Second}
}

func checkHostStartCheck(kind, host string) (string, error) {
	u := fmt.Sprintf("%s/check-%s?host=%s&max_nodes=3", checkHostOrigin, kind, url.QueryEscape(host))
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := checkHostHTTPClient().Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	var out checkHostStart
	if err := json.Unmarshal(body, &out); err != nil {
		return "", fmt.Errorf("invalid check-host response: %w", err)
	}
	if out.RequestID == "" {
		return "", fmt.Errorf("check-host: no request_id (%s)", strings.TrimSpace(string(body)))
	}
	return out.RequestID, nil
}

func checkHostPollResult(requestID string, maxWait time.Duration) (map[string]json.RawMessage, error) {
	deadline := time.Now().Add(maxWait)
	client := checkHostHTTPClient()
	for time.Now().Before(deadline) {
		u := fmt.Sprintf("%s/check-result/%s", checkHostOrigin, url.PathEscape(requestID))
		req, err := http.NewRequest(http.MethodGet, u, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Accept", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			time.Sleep(time.Second)
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		var raw map[string]json.RawMessage
		if err := json.Unmarshal(body, &raw); err != nil || len(raw) == 0 {
			time.Sleep(time.Second)
			continue
		}
		if checkHostResultsReady(raw) {
			return raw, nil
		}
		time.Sleep(time.Second)
	}
	return nil, fmt.Errorf("timeout waiting for check-host.net results")
}

func checkHostResultsReady(raw map[string]json.RawMessage) bool {
	for k, v := range raw {
		if k == "ok" || k == "request_id" || k == "permanent_link" {
			continue
		}
		if len(v) == 0 || string(v) == "null" {
			continue
		}
		return true
	}
	return false
}

// checkHostResultRows turns poll JSON into Field/Value rows (same style as ongoing tables).
func checkHostResultRows(raw map[string]json.RawMessage) [][]string {
	var keys []string
	for k, v := range raw {
		if k == "ok" || k == "request_id" || k == "permanent_link" {
			continue
		}
		if len(v) == 0 || string(v) == "null" {
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var rows [][]string
	for _, k := range keys {
		payload := raw[k]
		val := strings.TrimSpace(string(payload))
		var pretty interface{}
		if err := json.Unmarshal(payload, &pretty); err == nil {
			if enc, err := json.Marshal(pretty); err == nil {
				val = string(enc)
			}
		}
		rows = append(rows, []string{k, val})
	}
	return rows
}
