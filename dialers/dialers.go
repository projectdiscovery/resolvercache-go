package dialers

import (
	"context"
	"net"
	"strings"
	"time"

	"github.com/projectdiscovery/resolvercache-go/cache"
)

// NoAddressFoundError occurs when no addresses are found for the host
type NoAddressFoundError struct{}

func (m *NoAddressFoundError) Error() string {
	return "no address found for host"
}

// DialerFunc is a dialer function for go net/dial
type DialerFunc func(context.Context, string, string) (net.Conn, error)

// NewWithCache gets a new Dialer instance using a resolver cache
func NewWithCache(options cache.Options) (DialerFunc, error) {
	cache, err := cache.New(options)
	if err != nil {
		return nil, err
	}

	dialer := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
		DualStack: true,
	}

	return func(ctx context.Context, network, address string) (conn net.Conn, err error) {
		// Resolve the host using the cache
		separator := strings.LastIndex(address, ":")

		ips, err := cache.Lookup(address[:separator])
		if err != nil || len(ips) == 0 {
			return nil, &NoAddressFoundError{}
		}

		// Dial to the IPs finally.
		for _, ip := range ips {
			conn, err = dialer.DialContext(ctx, network, ip+address[separator:])
			if err == nil {
				break
			}
		}
		return
	}, nil
}

// New gets a new Dialer instance without using a resolver cache
func New(options cache.Options) (DialerFunc, error) {
	cache, err := cache.New(options)
	if err != nil {
		return nil, err
	}

	dialer := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
		DualStack: true,
	}

	return func(ctx context.Context, network, address string) (conn net.Conn, err error) {
		// Resolve the host using the cache
		separator := strings.LastIndex(address, ":")

		ips, err := cache.LookupWithoutCache(address[:separator])
		if err != nil || len(ips) == 0 {
			return nil, &NoAddressFoundError{}
		}

		// Dial to the IPs finally.
		for _, ip := range ips {
			conn, err = dialer.DialContext(ctx, network, ip+address[separator:])
			if err == nil {
				break
			}
		}
		return
	}, nil
}
