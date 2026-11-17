// Copyright 2026 The Agent Substrate Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package tokenexchange

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"go.ate.dev/substrate/api/ateapi/v1"
	"go.ate.dev/substrate/internal/resources"
)

var testActor = resources.ActorRef{Atespace: "default", Name: "my-actor"}

func testSource() *ateapi.TokenExchangeSource {
	return &ateapi.TokenExchangeSource{
		TokenUrl: "https://sts.example.com/token",
		Audience: "sts.example.com",
		Scopes:   []string{"write", "read"},
	}
}

// fakeMinter's nth call returns "subject-<n>", or err when set. With hang
// set, it instead blocks until its ctx ends and returns the bare ctx error,
// as actorjwt.Minter does.
type fakeMinter struct {
	calls atomic.Int32
	last  atomic.Pointer[ateapi.ActorJwtSource]
	err   error
	hang  bool
}

func (m *fakeMinter) Token(ctx context.Context, _ resources.ActorRef, src *ateapi.ActorJwtSource) (string, error) {
	n := m.calls.Add(1)
	m.last.Store(src)
	if m.hang {
		<-ctx.Done()
		return "", ctx.Err()
	}
	if m.err != nil {
		return "", m.err
	}
	return fmt.Sprintf("subject-%d", n), nil
}

// fakeEndpoint answers the nth exchange with access token "at-<n>" and
// expiresIn, a JSON member such as `,"expires_in":900` or "" for none. A
// status other than 0 or 200 answers with an OAuth error instead. gate, when
// non-nil, blocks each exchange until it is closed or its request ends.
type fakeEndpoint struct {
	calls     atomic.Int32
	lastForm  atomic.Pointer[url.Values]
	expiresIn string
	status    int
	gate      chan struct{}
}

func (e *fakeEndpoint) RoundTrip(req *http.Request) (*http.Response, error) {
	n := e.calls.Add(1)
	body, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, err
	}
	form, err := url.ParseQuery(string(body))
	if err != nil {
		return nil, err
	}
	e.lastForm.Store(&form)
	if e.gate != nil {
		select {
		case <-e.gate:
		case <-req.Context().Done():
			return nil, req.Context().Err()
		}
	}
	code, answer := http.StatusOK, fmt.Sprintf(`{"access_token":"at-%d"%s}`, n, e.expiresIn)
	if e.status != 0 && e.status != http.StatusOK {
		code, answer = e.status, `{"error":"temporarily_unavailable"}`
	}
	return &http.Response{StatusCode: code, Body: io.NopCloser(strings.NewReader(answer)), Header: http.Header{}, Request: req}, nil
}

func newTestBroker(m *fakeMinter, e *fakeEndpoint) *Broker {
	return NewBroker(m, &Client{httpClient: &http.Client{Transport: e}})
}

func mustToken(t *testing.T, b *Broker, src *ateapi.TokenExchangeSource) string {
	t.Helper()
	token, err := b.Token(t.Context(), testActor, src)
	if err != nil {
		t.Fatalf("Token: %v", err)
	}
	return token
}

func TestTokenReuse(t *testing.T) {
	for _, tt := range []struct {
		name      string
		expiresIn string
		reuse     time.Duration
	}{
		{"until a third of the lifetime remains", `,"expires_in":900`, 600 * time.Second},
		{"until 30 seconds remain", `,"expires_in":60`, 30 * time.Second},
		{"for 60 seconds without expires_in", "", 60 * time.Second},
		{"for at most an hour", `,"expires_in":86400`, time.Hour},
		{"for at most an hour with the longest expires_in", `,"expires_in":9223372036854775807`, time.Hour},
	} {
		t.Run(tt.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				b := newTestBroker(&fakeMinter{}, &fakeEndpoint{expiresIn: tt.expiresIn})
				if got := mustToken(t, b, testSource()); got != "at-1" {
					t.Fatalf("first token = %q, want at-1", got)
				}
				time.Sleep(tt.reuse - time.Second)
				if got := mustToken(t, b, testSource()); got != "at-1" {
					t.Errorf("token %v later = %q, want the cached at-1", tt.reuse-time.Second, got)
				}
				time.Sleep(2 * time.Second)
				if got := mustToken(t, b, testSource()); got != "at-2" {
					t.Errorf("token %v later = %q, want a new at-2", tt.reuse+time.Second, got)
				}
			})
		})
	}
}

func TestDoNotCacheShortLivedTokens(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		endpoint := &fakeEndpoint{expiresIn: `,"expires_in":30`}
		b := newTestBroker(&fakeMinter{}, endpoint)
		mustToken(t, b, testSource())
		if got := mustToken(t, b, testSource()); got != "at-2" {
			t.Errorf("second token = %q, want a new at-2", got)
		}
	})
}

func TestExchangeSendsMintedSubjectToken(t *testing.T) {
	minter, endpoint := &fakeMinter{}, &fakeEndpoint{}
	mustToken(t, newTestBroker(minter, endpoint), testSource())

	want := &ateapi.ActorJwtSource{Audiences: []string{"sts.example.com"}, ExpirationSeconds: 3600}
	if got := minter.last.Load(); !proto.Equal(got, want) {
		t.Errorf("minted %v, want %v", got, want)
	}
	form := *endpoint.lastForm.Load()
	for field, want := range map[string]string{
		"subject_token": "subject-1",
		"audience":      "sts.example.com",
		"scope":         "read write",
	} {
		if got := form.Get(field); got != want {
			t.Errorf("form %s = %q, want %q", field, got, want)
		}
	}
}

func TestCollapseConcurrentExchanges(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		endpoint := &fakeEndpoint{gate: make(chan struct{})}
		b := newTestBroker(&fakeMinter{}, endpoint)
		tokens := make([]string, 10)
		var wg sync.WaitGroup
		for i := range tokens {
			wg.Go(func() { tokens[i] = mustToken(t, b, testSource()) })
		}
		synctest.Wait()
		close(endpoint.gate)
		wg.Wait()
		if n := endpoint.calls.Load(); n != 1 {
			t.Errorf("%d exchanges, want 1", n)
		}
		for i, got := range tokens {
			if got != "at-1" {
				t.Errorf("caller %d got %q, want at-1", i, got)
			}
		}
	})
}

// A caller that gives up gets DeadlineExceeded, and the exchange it started
// still fills the cache.
func TestExchangeOutlivesCaller(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		endpoint := &fakeEndpoint{gate: make(chan struct{})}
		b := newTestBroker(&fakeMinter{}, endpoint)
		ctx, cancel := context.WithTimeout(t.Context(), 4*time.Second)
		defer cancel()
		if _, err := b.Token(ctx, testActor, testSource()); status.Code(err) != codes.DeadlineExceeded {
			t.Fatalf("Token error = %v, want code DeadlineExceeded", err)
		}
		close(endpoint.gate)
		synctest.Wait()
		if got := mustToken(t, b, testSource()); got != "at-1" {
			t.Errorf("token = %q, want at-1 from the abandoned exchange", got)
		}
		if n := endpoint.calls.Load(); n != 1 {
			t.Errorf("%d exchanges, want 1", n)
		}
	})
}

// An endpoint that never answers releases its key after exchangeTimeout, so a
// later request starts a new exchange instead of joining the stuck one.
func TestHungExchangeTimesOut(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		endpoint := &fakeEndpoint{gate: make(chan struct{})}
		b := newTestBroker(&fakeMinter{}, endpoint)
		ctx, cancel := context.WithTimeout(t.Context(), 4*time.Second)
		defer cancel()
		if _, err := b.Token(ctx, testActor, testSource()); err == nil {
			t.Fatal("Token succeeded, want an error")
		}
		// Just before the deadline, a new caller joins the stuck exchange
		// rather than starting another.
		time.Sleep(exchangeTimeout - 4*time.Second - time.Second)
		ctx2, cancel2 := context.WithTimeout(t.Context(), 500*time.Millisecond)
		defer cancel2()
		if _, err := b.Token(ctx2, testActor, testSource()); status.Code(err) != codes.DeadlineExceeded {
			t.Fatalf("Token before the deadline: error = %v, want code DeadlineExceeded", err)
		}
		if n := endpoint.calls.Load(); n != 1 {
			t.Fatalf("%d exchanges before the deadline, want 1", n)
		}
		time.Sleep(2 * time.Second)
		close(endpoint.gate)
		if got := mustToken(t, b, testSource()); got != "at-2" {
			t.Errorf("token = %q, want at-2 from a new exchange", got)
		}
	})
}

func TestKeyOnActorAndEverythingSent(t *testing.T) {
	for _, tt := range []struct {
		name     string
		actor    resources.ActorRef
		mutate   func(*ateapi.TokenExchangeSource)
		wantSame bool
	}{
		{name: "another actor", actor: resources.ActorRef{Atespace: "default", Name: "other"}},
		{name: "another token URL", mutate: func(s *ateapi.TokenExchangeSource) { s.TokenUrl = "https://sts.example.com/v2/token" }},
		{name: "another audience", mutate: func(s *ateapi.TokenExchangeSource) { s.Audience = "other.example.com" }},
		{name: "other scopes", mutate: func(s *ateapi.TokenExchangeSource) { s.Scopes = []string{"read"} }},
		{name: "reordered scopes", mutate: func(s *ateapi.TokenExchangeSource) { s.Scopes = []string{"read", "write"} }, wantSame: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			endpoint := &fakeEndpoint{expiresIn: `,"expires_in":900`}
			b := newTestBroker(&fakeMinter{}, endpoint)
			mustToken(t, b, testSource())
			actor, src := testActor, testSource()
			if tt.actor != (resources.ActorRef{}) {
				actor = tt.actor
			}
			if tt.mutate != nil {
				tt.mutate(src)
			}
			if _, err := b.Token(t.Context(), actor, src); err != nil {
				t.Fatalf("Token: %v", err)
			}
			want := int32(2)
			if tt.wantSame {
				want = 1
			}
			if n := endpoint.calls.Load(); n != want {
				t.Errorf("%d exchanges, want %d", n, want)
			}
		})
	}
}

func TestMintErrorWrapsErrMint(t *testing.T) {
	endpoint := &fakeEndpoint{}
	b := newTestBroker(&fakeMinter{err: status.Error(codes.NotFound, "actor not found")}, endpoint)
	_, err := b.Token(t.Context(), testActor, testSource())
	if !errors.Is(err, ErrMint) || status.Code(err) != codes.NotFound {
		t.Errorf("Token error = %v, want ErrMint with code NotFound", err)
	}
	if n := endpoint.calls.Load(); n != 0 {
		t.Errorf("%d exchanges after a failed mint, want 0", n)
	}
}

func TestDoNotCacheErrors(t *testing.T) {
	endpoint := &fakeEndpoint{status: http.StatusServiceUnavailable}
	b := newTestBroker(&fakeMinter{}, endpoint)
	_, err := b.Token(t.Context(), testActor, testSource())
	if status.Code(err) != codes.Unavailable || errors.Is(err, ErrMint) {
		t.Fatalf("Token error = %v, want code Unavailable without ErrMint", err)
	}
	endpoint.status = http.StatusOK
	if got := mustToken(t, b, testSource()); got != "at-2" {
		t.Errorf("token after a failed exchange = %q, want at-2", got)
	}
}

// A mint that runs out the flight's time is DeadlineExceeded, which callers
// retry, not the Unknown of a bare context error.
func TestMintTimeoutIsDeadlineExceeded(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		endpoint := &fakeEndpoint{}
		b := newTestBroker(&fakeMinter{hang: true}, endpoint)
		ctx, cancel := context.WithTimeout(t.Context(), 2*exchangeTimeout)
		defer cancel()
		_, err := b.Token(ctx, testActor, testSource())
		if !errors.Is(err, ErrMint) || status.Code(err) != codes.DeadlineExceeded {
			t.Errorf("Token error = %v (code %v), want ErrMint with code DeadlineExceeded", err, status.Code(err))
		}
		if n := endpoint.calls.Load(); n != 0 {
			t.Errorf("%d exchanges after a failed mint, want 0", n)
		}
	})
}

func TestDoNotCacheMintErrors(t *testing.T) {
	minter := &fakeMinter{err: status.Error(codes.Unavailable, "ateapi unavailable")}
	endpoint := &fakeEndpoint{expiresIn: `,"expires_in":900`}
	b := newTestBroker(minter, endpoint)
	if _, err := b.Token(t.Context(), testActor, testSource()); !errors.Is(err, ErrMint) {
		t.Fatalf("Token error = %v, want ErrMint", err)
	}
	minter.err = nil
	if got := mustToken(t, b, testSource()); got != "at-1" {
		t.Errorf("token after a failed mint = %q, want at-1", got)
	}
	if n := minter.calls.Load(); n != 2 {
		t.Errorf("%d mints, want 2", n)
	}
}

func TestCallerCancelIsCanceled(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		endpoint := &fakeEndpoint{gate: make(chan struct{})}
		b := newTestBroker(&fakeMinter{}, endpoint)
		ctx, cancel := context.WithCancel(t.Context())
		go func() {
			synctest.Wait()
			cancel()
		}()
		if _, err := b.Token(ctx, testActor, testSource()); status.Code(err) != codes.Canceled {
			t.Errorf("Token error = %v, want code Canceled", err)
		}
		close(endpoint.gate)
	})
}
