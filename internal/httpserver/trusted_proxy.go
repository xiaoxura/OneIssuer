package httpserver

import (
	"context"
	"net"
	"net/http"
	"net/netip"
	"strings"
)

// ProxyInfo contains normalized forwarding data only when the direct peer was
// in an explicitly configured trusted CIDR. It is intentionally not logged.
type ProxyInfo struct {
	ClientIP netip.Addr
	Scheme   string
	Host     string
	Trusted  bool
}

type proxyInfoContextKey struct{}

// RequestProxyInfo returns the normalized connection/forwarding information.
func RequestProxyInfo(ctx context.Context) ProxyInfo {
	value, _ := ctx.Value(proxyInfoContextKey{}).(ProxyInfo)
	return value
}

func trustedProxyMiddleware(prefixes []netip.Prefix, next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		peer := remoteIP(request.RemoteAddr)
		info := ProxyInfo{ClientIP: peer}
		if peer.IsValid() && addressInPrefixes(peer, prefixes) {
			info.Trusted = true
			info.ClientIP = forwardedClientIP(request.Header.Values("X-Forwarded-For"), peer, prefixes)
			if scheme := firstHeaderValue(request.Header.Get("X-Forwarded-Proto")); scheme == "http" || scheme == "https" {
				info.Scheme = scheme
			}
			info.Host = sanitizeForwardedHost(firstHeaderValue(request.Header.Get("X-Forwarded-Host")))
		}
		ctx := context.WithValue(request.Context(), proxyInfoContextKey{}, info)
		next.ServeHTTP(writer, request.WithContext(ctx))
	})
}

func remoteIP(remoteAddr string) netip.Addr {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return netip.Addr{}
	}
	address, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}
	}
	return address.Unmap()
}

func addressInPrefixes(address netip.Addr, prefixes []netip.Prefix) bool {
	address = address.Unmap()
	for _, prefix := range prefixes {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}

func forwardedClientIP(headerValues []string, peer netip.Addr, trusted []netip.Prefix) netip.Addr {
	chain := make([]netip.Addr, 0)
	for _, header := range headerValues {
		for _, part := range strings.Split(header, ",") {
			address, err := netip.ParseAddr(strings.TrimSpace(part))
			if err != nil {
				return peer
			}
			chain = append(chain, address.Unmap())
		}
	}
	chain = append(chain, peer)
	for index := len(chain) - 1; index >= 0; index-- {
		if !addressInPrefixes(chain[index], trusted) {
			return chain[index]
		}
	}
	if len(chain) > 0 {
		return chain[0]
	}
	return peer
}

func firstHeaderValue(value string) string {
	value, _, _ = strings.Cut(value, ",")
	return strings.ToLower(strings.TrimSpace(value))
}

func sanitizeForwardedHost(host string) string {
	host = strings.TrimSpace(host)
	if host == "" || strings.ContainsAny(host, "\r\n/\\@") || len(host) > 255 {
		return ""
	}
	return host
}
