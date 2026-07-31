package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/tobiasGuta/AI-Security-Lab-Runner/runner/internal/scratchfs"
)

var (
	methodRegex = regexp.MustCompile(`^[A-Za-z0-9!#$%&'*+\-.^_` + "`" + `|~]+$`)
)

type RequestSpec struct {
	Method             string            `json:"method"`
	URL                string            `json:"url"`
	Headers            map[string]string `json:"headers"`
	Body               string            `json:"body"`
	FollowRedirects    bool              `json:"follow_redirects"`
	InsecureTLS        bool              `json:"insecure_tls"`
	TimeoutSeconds     int               `json:"timeout_seconds"`
	SaveCookiesPath    string            `json:"save_cookies_path"`
	LoadCookiesPath    string            `json:"load_cookies_path"`
	HostGatewayName    string            `json:"host_gateway_name"`
	HostGatewayEnabled bool              `json:"host_gateway_enabled"`
	MaxResponseBytes   int64             `json:"max_response_bytes"`
}

type ResponseDoc struct {
	RequestedURL           string              `json:"requested_url"`
	EffectiveURL           string              `json:"effective_url"`
	StatusCode             int                 `json:"status_code"`
	Headers                map[string][]string `json:"headers"`
	Body                   string              `json:"body"`
	BodyBase64             bool                `json:"body_base64"`
	DurationMS             int64               `json:"duration_ms"`
	RedirectChain          []string            `json:"redirect_chain"`
	ExitCode               int                 `json:"curl_exit_code"` // Kept JSON tag for backward compatibility
	ErrorCategory          string              `json:"error_category,omitempty"`
	HostGatewayTranslation bool                `json:"host_gateway_translation"`
	ConnectionHost         string              `json:"connection_host"`
	Truncated              bool                `json:"truncated"`
}

func main() {
	inputData, err := io.ReadAll(os.Stdin)
	if err != nil {
		outputError("INVALID_INPUT", fmt.Sprintf("Failed to read JSON specification from stdin: %v", err))
		return
	}

	var spec RequestSpec
	if err := json.Unmarshal(inputData, &spec); err != nil {
		outputError("INVALID_INPUT", fmt.Sprintf("Failed to parse JSON specification: %v", err))
		return
	}

	doc, err := executeHTTPRequest(spec)
	if err != nil {
		outputError("INTERNAL_ERROR", err.Error())
		return
	}

	outputJSON(doc)
}

func executeHTTPRequest(spec RequestSpec) (*ResponseDoc, error) {
	if spec.URL == "" {
		return nil, fmt.Errorf("URL cannot be empty")
	}

	parsedURL, err := url.Parse(spec.URL)
	if err != nil || (parsedURL.Scheme != "http" && parsedURL.Scheme != "https") {
		return nil, fmt.Errorf("invalid URL scheme (must be http or https): %s", spec.URL)
	}

	method := strings.ToUpper(strings.TrimSpace(spec.Method))
	if method == "" {
		method = "GET"
	}
	if !methodRegex.MatchString(method) {
		return nil, fmt.Errorf("invalid HTTP method token: %s", method)
	}

	if len(spec.Headers) > 100 {
		return nil, fmt.Errorf("exceeded maximum header count limit (100)")
	}

	for k, v := range spec.Headers {
		if strings.ContainsAny(k, "\r\n:") {
			return nil, fmt.Errorf("CRLF or invalid char in header name: %s", k)
		}
		if strings.ContainsAny(v, "\r\n") {
			return nil, fmt.Errorf("CRLF in header value for key %s", k)
		}
		if len(k) > 1024 || len(v) > 8192 {
			return nil, fmt.Errorf("header %s exceeds size limit", k)
		}
	}

	if len(spec.Body) > 1048576 {
		return nil, fmt.Errorf("request body size %d exceeds limit 1MB", len(spec.Body))
	}

	// Jar setup via descriptor-relative scratchfs
	jar, _ := cookiejar.New(nil)
	if spec.LoadCookiesPath != "" {
		cookieData, err := scratchfs.LoadCookieFileSecure(spec.LoadCookiesPath)
		if err != nil {
			return &ResponseDoc{
				RequestedURL:  spec.URL,
				ErrorCategory: "COOKIE_READ_FAILURE",
				ExitCode:      1,
				Body:          fmt.Sprintf("Failed to load cookies from '%s': %v", spec.LoadCookiesPath, err),
			}, nil
		}
		if len(cookieData) > 0 {
			var cookies []*http.Cookie
			if err := json.Unmarshal(cookieData, &cookies); err == nil {
				jar.SetCookies(parsedURL, cookies)
			}
		}
	}

	timeoutSec := spec.TimeoutSeconds
	if timeoutSec <= 0 {
		timeoutSec = 30
	}

	var redirectChain []string
	gatewayTranslation := false
	connectionHost := parsedURL.Hostname()

	dialer := &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: spec.InsecureTLS,
			// ServerName is deliberately left UNSET so Go's standard client dynamically derives TLS SNI from each request URL during redirects!
		},
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, splitErr := net.SplitHostPort(addr)
			if splitErr == nil && (host == "localhost" || host == "127.0.0.1" || host == "::1") {
				if !spec.HostGatewayEnabled {
					return nil, fmt.Errorf("POLICY_DENIED: host gateway translation is disabled for this session")
				}
				dialHost := spec.HostGatewayName
				if dialHost == "" {
					dialHost = "host.docker.internal"
				}
				addr = net.JoinHostPort(dialHost, port)
				gatewayTranslation = true
				connectionHost = dialHost
			}
			return dialer.DialContext(ctx, network, addr)
		},
	}

	client := &http.Client{
		Timeout:   time.Duration(timeoutSec) * time.Second,
		Transport: transport,
		Jar:       jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if !spec.FollowRedirects {
				return http.ErrUseLastResponse
			}
			if len(via) >= 10 {
				return fmt.Errorf("stopped after 10 redirects")
			}
			redirectChain = append(redirectChain, req.URL.String())
			return nil
		},
	}

	req, err := http.NewRequest(method, spec.URL, bytes.NewReader([]byte(spec.Body)))
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	for k, v := range spec.Headers {
		req.Header.Set(k, v)
	}

	start := time.Now()
	resp, err := client.Do(req)
	duration := time.Since(start).Milliseconds()

	doc := &ResponseDoc{
		RequestedURL:           spec.URL,
		DurationMS:             duration,
		HostGatewayTranslation: gatewayTranslation,
		ConnectionHost:         connectionHost,
		Headers:                make(map[string][]string),
		RedirectChain:          redirectChain,
	}

	if err != nil {
		doc.ErrorCategory = classifyError(err)
		doc.ExitCode = 1
		doc.Body = fmt.Sprintf("HTTP Request Failed: %v", err)
		return doc, nil
	}
	defer resp.Body.Close()

	doc.EffectiveURL = resp.Request.URL.String()
	doc.StatusCode = resp.StatusCode

	for k, v := range resp.Header {
		doc.Headers[k] = v
	}

	maxRead := spec.MaxResponseBytes
	if maxRead <= 0 {
		maxRead = 2097152
	}

	bodyReader := io.LimitReader(resp.Body, maxRead+1)
	bodyBytes, err := io.ReadAll(bodyReader)
	if err != nil && err != io.EOF {
		doc.ErrorCategory = "READ_ERROR"
		return doc, nil
	}

	if int64(len(bodyBytes)) > maxRead {
		doc.Truncated = true
		bodyBytes = bodyBytes[:maxRead]
	}

	if utf8.Valid(bodyBytes) {
		doc.Body = string(bodyBytes)
		doc.BodyBase64 = false
	} else {
		doc.Body = base64.StdEncoding.EncodeToString(bodyBytes)
		doc.BodyBase64 = true
	}

	if spec.SaveCookiesPath != "" {
		cookies := jar.Cookies(parsedURL)
		data, err := json.Marshal(cookies)
		if err != nil {
			return &ResponseDoc{
				RequestedURL:  spec.URL,
				ErrorCategory: "COOKIE_WRITE_FAILURE",
				ExitCode:      1,
				Body:          fmt.Sprintf("Failed to marshal cookies: %v", err),
			}, nil
		}

		if err := scratchfs.SaveCookieFileAtomic(spec.SaveCookiesPath, data); err != nil {
			return &ResponseDoc{
				RequestedURL:  spec.URL,
				ErrorCategory: "COOKIE_WRITE_FAILURE",
				ExitCode:      1,
				Body:          fmt.Sprintf("Failed to save cookies to '%s': %v", spec.SaveCookiesPath, err),
			}, nil
		}
	}

	return doc, nil
}

func classifyError(err error) string {
	if err == nil {
		return ""
	}
	str := err.Error()
	if strings.Contains(str, "POLICY_DENIED") {
		return "POLICY_DENIED"
	}
	if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		return "TIMEOUT"
	}
	if strings.Contains(str, "certificate") || strings.Contains(str, "tls") {
		return "TLS_FAILURE"
	}
	if strings.Contains(str, "no such host") || strings.Contains(str, "dns") {
		return "DNS_FAILURE"
	}
	if strings.Contains(str, "connection refused") || strings.Contains(str, "connect") {
		return "CONNECTION_FAILURE"
	}
	return "HTTP_ERROR"
}

func outputJSON(v interface{}) {
	data, _ := json.Marshal(v)
	fmt.Println(string(data))
}

func outputError(category, message string) {
	doc := ResponseDoc{
		ErrorCategory: category,
		StatusCode:    0,
		Body:          message,
		ExitCode:      1,
	}
	outputJSON(doc)
}
