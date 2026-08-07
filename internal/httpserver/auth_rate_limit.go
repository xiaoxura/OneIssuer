package httpserver

import (
	"net/netip"
	"sync"
	"time"

	"github.com/google/uuid"
)

const (
	defaultAuthRatePerMinute = 20
	defaultAuthRateBurst     = 10
	defaultAuthGlobalRate    = 50
	defaultAuthGlobalBurst   = 100
	maxAuthRateLimitEntries  = 4096
	authRateEntryTTL         = 10 * time.Minute
	authRateSweepInterval    = time.Minute
)

// AuthenticationRateLimitConfig bounds unauthenticated browser-flow creation
// and credential submissions before either operation reaches PostgreSQL or
// Argon2. The same bounded policy is applied to an authenticated Client after
// protocol credentials have been verified.
type AuthenticationRateLimitConfig struct {
	PerMinute       int
	Burst           int
	GlobalPerSecond int
	GlobalBurst     int
}

type tokenBucket struct {
	tokens   float64
	last     time.Time
	lastSeen time.Time
}

type authenticationRateLimiter struct {
	mu sync.Mutex

	perMinute       int
	burst           int
	globalPerSecond int
	globalBurst     int
	global          tokenBucket
	clients         map[netip.Addr]tokenBucket
	authenticated   map[uuid.UUID]tokenBucket
	nextSweep       time.Time
	nextAuthSweep   time.Time
}

func newAuthenticationRateLimiter(config AuthenticationRateLimitConfig, now time.Time) *authenticationRateLimiter {
	if config.PerMinute <= 0 {
		config.PerMinute = defaultAuthRatePerMinute
	}
	if config.Burst <= 0 {
		config.Burst = defaultAuthRateBurst
	}
	if config.GlobalPerSecond <= 0 {
		config.GlobalPerSecond = defaultAuthGlobalRate
	}
	if config.GlobalBurst <= 0 {
		config.GlobalBurst = defaultAuthGlobalBurst
	}
	now = now.UTC()
	return &authenticationRateLimiter{
		perMinute: config.PerMinute, burst: config.Burst,
		globalPerSecond: config.GlobalPerSecond, globalBurst: config.GlobalBurst,
		global:        tokenBucket{tokens: float64(config.GlobalBurst), last: now, lastSeen: now},
		clients:       make(map[netip.Addr]tokenBucket),
		authenticated: make(map[uuid.UUID]tokenBucket),
		nextSweep:     now.Add(authRateSweepInterval),
		nextAuthSweep: now.Add(authRateSweepInterval),
	}
}

func (l *authenticationRateLimiter) allow(address netip.Addr, now time.Time) bool {
	if l == nil {
		return true
	}
	now = now.UTC()
	if address.IsValid() {
		address = address.Unmap()
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	l.global = refillBucket(l.global, float64(l.globalPerSecond), l.globalBurst, now)
	if l.global.tokens < 1 {
		return false
	}

	bucket, exists := l.clients[address]
	if !exists {
		l.sweepLocked(now)
		if len(l.clients) >= maxAuthRateLimitEntries {
			return false
		}
		bucket = tokenBucket{tokens: float64(l.burst), last: now, lastSeen: now}
	}
	bucket = refillBucket(bucket, float64(l.perMinute)/60, l.burst, now)
	if bucket.tokens < 1 {
		l.clients[address] = bucket
		return false
	}

	l.global.tokens--
	l.global.lastSeen = now
	bucket.tokens--
	bucket.lastSeen = now
	l.clients[address] = bucket
	return true
}

func (l *authenticationRateLimiter) sweepLocked(now time.Time) {
	// A full table must not turn every request from a new address into an O(n)
	// scan. Sweep on a fixed cadence and fail closed between sweeps instead.
	if now.Before(l.nextSweep) {
		return
	}
	cutoff := now.Add(-authRateEntryTTL)
	for address, bucket := range l.clients {
		if bucket.lastSeen.Before(cutoff) {
			delete(l.clients, address)
		}
	}
	l.nextSweep = now.Add(authRateSweepInterval)
}

// allowClient applies only the post-authentication bucket. The request's
// process-wide and per-IP budget has already been charged by allow; keeping
// this bucket separate prevents an authenticated Client from consuming the
// global budget twice while still bounding Client-specific work.
func (l *authenticationRateLimiter) allowClient(clientID uuid.UUID, now time.Time) bool {
	if l == nil || clientID == uuid.Nil {
		return true
	}
	now = now.UTC()
	l.mu.Lock()
	defer l.mu.Unlock()

	bucket, exists := l.authenticated[clientID]
	if !exists {
		l.sweepAuthenticatedLocked(now)
		if len(l.authenticated) >= maxAuthRateLimitEntries {
			return false
		}
		bucket = tokenBucket{tokens: float64(l.burst), last: now, lastSeen: now}
	}
	bucket = refillBucket(bucket, float64(l.perMinute)/60, l.burst, now)
	if bucket.tokens < 1 {
		l.authenticated[clientID] = bucket
		return false
	}
	bucket.tokens--
	bucket.lastSeen = now
	l.authenticated[clientID] = bucket
	return true
}

func (l *authenticationRateLimiter) sweepAuthenticatedLocked(now time.Time) {
	if now.Before(l.nextAuthSweep) {
		return
	}
	cutoff := now.Add(-authRateEntryTTL)
	for clientID, bucket := range l.authenticated {
		if bucket.lastSeen.Before(cutoff) {
			delete(l.authenticated, clientID)
		}
	}
	l.nextAuthSweep = now.Add(authRateSweepInterval)
}

func refillBucket(bucket tokenBucket, ratePerSecond float64, burst int, now time.Time) tokenBucket {
	if bucket.last.IsZero() {
		bucket.tokens = float64(burst)
		bucket.last = now
		bucket.lastSeen = now
		return bucket
	}
	if now.After(bucket.last) {
		bucket.tokens += now.Sub(bucket.last).Seconds() * ratePerSecond
		if bucket.tokens > float64(burst) {
			bucket.tokens = float64(burst)
		}
		bucket.last = now
	}
	return bucket
}
