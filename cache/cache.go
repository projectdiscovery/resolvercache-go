package cache

import (
	"net"
	"time"

	"github.com/projectdiscovery/expirablelru"
	"github.com/projectdiscovery/resolvercache-go/resolver"
)

// Cache is a strcture for caching DNS lookups
type Cache struct {
	dnsClient *resolver.Client
	cache     *expirablelru.Cache

	defaultExpirationTime int
}

// Options contains configuration options for the cache
type Options struct {
	// BaseResolvers contains additional resolvers to use for DNS lookups.
	BaseResolvers []string
	// CacheSize contains the max size of the cache in MBs
	CacheSize int
	// ExpirationTime contains the default expiration time in seconds in case of DNS
	// responses with TTL having a value of 0.
	ExpirationTime int
	// MaxRetries contains the max number of retry for DNS requests
	MaxRetries int
}

// DefaultOptions contains the default configuration options for the DNS cache
var DefaultOptions = Options{
	BaseResolvers:  DefaultResolvers,
	CacheSize:      10000,  // Default cache is 10000 mb in size
	ExpirationTime: 5 * 60, // Wait for 5 mins before item expiration by default
	MaxRetries:     5,
}

// DefaultResolvers contains the list of resolvers known to be trusted.
var DefaultResolvers = []string{
	"1.1.1.1:53",
	"1.0.0.1:53",
	"8.8.8.8:53",
	"8.8.4.4:53",
}

// New creates a new caching dns resolver
func New(options Options) (*Cache, error) {
	dnsClient, err := resolver.New(options.BaseResolvers, options.MaxRetries)
	if err != nil {
		return nil, err
	}

	cache := expirablelru.NewExpirableLRU(
		options.CacheSize,
		nil,
		time.Duration(options.ExpirationTime)*time.Second,
		5*time.Minute,
	)
	if err != nil {
		return nil, err
	}
	return &Cache{dnsClient: dnsClient, cache: cache, defaultExpirationTime: options.ExpirationTime}, nil
}

// Lookup gets records for a hostname from the cache. If the records
// don't exist, then a DNS resolution is performed for the host.
// On the next run, the records are cached with the TTL of the record.
func (c *Cache) Lookup(hostname string) ([]string, error) {
	// Check to see if the hostname is an IP address instead. If yes,
	// return the IP address as is without doing any additional effort.
	if ip := net.ParseIP(hostname); ip != nil {
		return []string{hostname}, nil
	}

	value, ok := c.cache.Get(hostname)
	if !ok {
		// Item doesn't exist yet. Resolve the hostname and add the item to the cache.
		results, err := c.dnsClient.Resolve(hostname)
		if err != nil {
			return nil, err
		}
		// If the TTL is 0, then set the expiration time to default of 5 mins.
		if results.TTL == 0 {
			results.TTL = c.defaultExpirationTime
		}
		c.cache.AddWithTTL(hostname, results.IPs, time.Duration(results.TTL)*time.Second)
		return results.IPs, nil
	}
	return value.([]string), nil
}

// LookupWithoutCache gets records for a hostname by resolving it.
func (c *Cache) LookupWithoutCache(hostname string) ([]string, error) {
	// Check to see if the hostname is an IP address instead. If yes,
	// return the IP address as is without doing any additional effort.
	if ip := net.ParseIP(hostname); ip != nil {
		return []string{hostname}, nil
	}

	// Resolve the hostname and return ips.
	results, err := c.dnsClient.Resolve(hostname)
	if err != nil {
		return nil, err
	}
	return results.IPs, nil
}
