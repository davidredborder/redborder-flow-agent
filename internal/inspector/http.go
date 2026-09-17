package inspector

import (
	"bytes"
	"strconv"
	"strings"
)

// HTTPDetails contains dissected HTTP request and response attributes.
type HTTPDetails struct {
	Method     string
	URI        string
	Host       string
	UserAgent  string
	StatusCode int
}

// ExtractHTTPInfo parses HTTP Request Host header and URI without heavy allocations.
func ExtractHTTPInfo(data []byte) (host string, uri string) {
	d := ExtractFullHTTP(data)
	return d.Host, d.URI
}

// ExtractFullHTTP extracts method, URI, host, user-agent, and status codes.
func ExtractFullHTTP(data []byte) HTTPDetails {
	var details HTTPDetails
	if len(data) < 10 {
		return details
	}

	// Check HTTP Response (HTTP/1.0 200 OK, HTTP/1.1 404 Not Found)
	if bytes.HasPrefix(data, []byte("HTTP/1.")) || bytes.HasPrefix(data, []byte("HTTP/2.")) {
		firstLineEnd := bytes.IndexByte(data, '\n')
		if firstLineEnd != -1 {
			line := strings.TrimSpace(string(data[:firstLineEnd]))
			parts := strings.SplitN(line, " ", 3)
			if len(parts) >= 2 {
				if code, err := strconv.Atoi(parts[1]); err == nil {
					details.StatusCode = code
				}
			}
		}
		return details
	}

	// Check HTTP Request verbs
	verbs := []string{"GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"}
	for _, v := range verbs {
		if bytes.HasPrefix(data, []byte(v+" ")) {
			details.Method = v
			break
		}
	}

	if details.Method == "" {
		return details
	}

	// Extract URI from request line
	firstLineEnd := bytes.IndexByte(data, '\n')
	if firstLineEnd != -1 {
		line := strings.TrimSpace(string(data[:firstLineEnd]))
		parts := strings.SplitN(line, " ", 3)
		if len(parts) >= 2 {
			details.URI = parts[1]
		}
	}

	// Scan lines for Host: and User-Agent:
	lines := bytes.Split(data, []byte("\n"))
	for _, rawLine := range lines {
		line := strings.TrimSpace(string(rawLine))
		if line == "" {
			break // End of HTTP headers
		}

		lowerLine := strings.ToLower(line)
		if strings.HasPrefix(lowerLine, "host:") {
			hostVal := strings.TrimSpace(line[5:])
			if colon := strings.Index(hostVal, ":"); colon != -1 {
				hostVal = hostVal[:colon]
			}
			details.Host = strings.ToLower(hostVal)
		} else if strings.HasPrefix(lowerLine, "user-agent:") {
			details.UserAgent = strings.TrimSpace(line[11:])
		}
	}

	return details
}
