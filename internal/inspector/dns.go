package inspector

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// DNSCache provides a fast thread-safe cache mapping IP addresses to domain names.
type DNSCache struct {
	maxEntries int
	mu         sync.RWMutex
	cache      map[string]dnsEntry
}

type dnsEntry struct {
	domain    string
	expiresAt time.Time
}

// NewDNSCache initializes the DNS resolution cache.
func NewDNSCache(maxEntries int) *DNSCache {
	if maxEntries <= 0 {
		maxEntries = 50000
	}
	return &DNSCache{
		maxEntries: maxEntries,
		cache:      make(map[string]dnsEntry, maxEntries),
	}
}

// Put records an IP -> Domain mapping with TTL.
func (c *DNSCache) Put(ip net.IP, domain string, ttl time.Duration) {
	if ip == nil || domain == "" {
		return
	}
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}

	ipStr := ip.String()
	c.mu.Lock()
	defer c.mu.Unlock()

	// Simple eviction if map gets too large
	if len(c.cache) >= c.maxEntries {
		now := time.Now()
		for k, v := range c.cache {
			if now.After(v.expiresAt) {
				delete(c.cache, k)
			}
		}
		if len(c.cache) >= c.maxEntries {
			// Evict a random subset
			cnt := 0
			for k := range c.cache {
				delete(c.cache, k)
				cnt++
				if cnt > 1000 {
					break
				}
			}
		}
	}

	c.cache[ipStr] = dnsEntry{
		domain:    domain,
		expiresAt: time.Now().Add(ttl),
	}
}

// Lookup finds the domain for a given IP.
func (c *DNSCache) Lookup(ip net.IP) string {
	if ip == nil {
		return ""
	}
	c.mu.RLock()
	defer c.mu.RUnlock()

	if entry, found := c.cache[ip.String()]; found {
		if time.Now().Before(entry.expiresAt) {
			return entry.domain
		}
	}
	return ""
}

// ParseDNSPacket extracts query and answer mappings from a UDP/TCP payload.
func ParseDNSPacket(data []byte) (queryDomain string, answers []net.IP, err error) {
	if len(data) < 12 {
		return "", nil, fmt.Errorf("payload too short for DNS (<12 bytes)")
	}

	flags := binary.BigEndian.Uint16(data[2:4])
	isResponse := (flags & 0x8000) != 0
	qdCount := int(binary.BigEndian.Uint16(data[4:6]))
	anCount := int(binary.BigEndian.Uint16(data[6:8]))

	if qdCount <= 0 {
		return "", nil, fmt.Errorf("no questions in DNS packet")
	}

	offset := 12
	domain, newOffset, err := parseDNSName(data, offset)
	if err != nil {
		return "", nil, err
	}
	offset = newOffset

	if len(data) >= offset+4 {
		offset += 4 // Skip QType & QClass
	}

	if !isResponse || anCount == 0 || offset >= len(data) {
		return domain, nil, nil
	}

	// Parse Answers
	for i := 0; i < anCount && offset < len(data); i++ {
		_, nextOffset, err := parseDNSName(data, offset)
		if err != nil {
			break
		}
		offset = nextOffset
		if offset+10 > len(data) {
			break
		}

		aType := binary.BigEndian.Uint16(data[offset : offset+2])
		rdLength := int(binary.BigEndian.Uint16(data[offset+8 : offset+10]))
		offset += 10

		if offset+rdLength > len(data) {
			break
		}

		if aType == 1 && rdLength == 4 { // A record (IPv4)
			ip := net.IPv4(data[offset], data[offset+1], data[offset+2], data[offset+3])
			answers = append(answers, ip)
		} else if aType == 28 && rdLength == 16 { // AAAA record (IPv6)
			ip := make(net.IP, 16)
			copy(ip, data[offset:offset+16])
			answers = append(answers, ip)
		}
		offset += rdLength
	}

	return domain, answers, nil
}

func parseDNSName(data []byte, offset int) (string, int, error) {
	var labels []string
	pos := offset
	jumped := false
	maxJumps := 10
	jumps := 0
	returnOffset := offset

	for pos < len(data) {
		length := int(data[pos])
		if length == 0 {
			pos++
			if !jumped {
				returnOffset = pos
			}
			break
		}

		// Compression Pointer
		if length&0xC0 == 0xC0 {
			if pos+1 >= len(data) {
				return "", 0, fmt.Errorf("truncated pointer")
			}
			if !jumped {
				returnOffset = pos + 2
				jumped = true
			}
			pointer := int(binary.BigEndian.Uint16(data[pos:pos+2])) & 0x3FFF
			if pointer >= len(data) {
				return "", 0, fmt.Errorf("invalid pointer offset %d", pointer)
			}
			pos = pointer
			jumps++
			if jumps > maxJumps {
				return "", 0, fmt.Errorf("DNS compression loop detected")
			}
			continue
		}

		pos++
		if pos+length > len(data) {
			return "", 0, fmt.Errorf("label length %d exceeds buffer", length)
		}

		labels = append(labels, string(data[pos:pos+length]))
		pos += length
	}

	if !jumped {
		returnOffset = pos
	}

	return strings.ToLower(strings.Join(labels, ".")), returnOffset, nil
}
