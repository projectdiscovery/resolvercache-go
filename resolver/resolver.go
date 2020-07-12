package resolver

import (
	"errors"
	"math/rand"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

// Client is a DNS resolver client to resolve hostnames.
// It caches hostnames according to their TTL values and
// does refresh only explicitly if another request is made to the domain.
type Client struct {
	resolvers    []string
	maxRetries   int
	currentIndex uint32
}

// Result contains the results from a DNS resolution
type Result struct {
	IPs []string
	TTL int
}

// New creates a new dns client
func New(baseResolvers []string, maxRetries int) (*Client, error) {
	// Seed the global RNG
	rand.Seed(time.Now().UnixNano())

	client := Client{maxRetries: maxRetries}
	// Append the static list of resolvers if they were given as input to the
	// resolvers array.
	client.resolvers = append(client.resolvers, baseResolvers...)

	return &client, nil
}

// Resolve is the underlying resolve function that actually resolves a host
// and gets the ip records for that host.
func (c *Client) Resolve(host string) (Result, error) {
	msg := new(dns.Msg)

	msg.Id = dns.Id()
	msg.RecursionDesired = true
	msg.Question = make([]dns.Question, 1)
	msg.Question[0] = dns.Question{
		Name:   dns.Fqdn(host),
		Qtype:  dns.TypeA,
		Qclass: dns.ClassINET,
	}

	// Round-robin the DNS servers one by one.
	index := atomic.AddUint32(&c.currentIndex, 1)
	resolver := c.resolvers[index%uint32(len(c.resolvers))]

	var err error
	var answer *dns.Msg

	result := Result{}

	for i := 0; i < c.maxRetries; i++ {
		answer, err = dns.Exchange(msg, resolver)
		if err != nil {
			continue
		}

		// In case we got some error from the server, return.
		if answer != nil && answer.Rcode != dns.RcodeSuccess {
			return result, errors.New(dns.RcodeToString[answer.Rcode])
		}

		for _, record := range answer.Answer {
			// Add the IP and the TTL to the map
			if t, ok := record.(*dns.A); ok {
				ip := t.A.String()
				if ip != "" {
					result.IPs = append(result.IPs, t.A.String())
					result.TTL = int(t.Header().Ttl)
				}
			}
		}
		return result, nil
	}
	return result, err
}
