package upstream

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// challenge is a parsed WWW-Authenticate challenge.
type challenge struct {
	scheme string // "bearer", "basic", or "cargo"
	params map[string]string
}

// parseChallenge picks the challenge to answer from WWW-Authenticate
// header values: Bearer if offered, else Basic, else Cargo's.
func parseChallenge(values []string) (challenge, bool) {
	var basic, cargo *challenge
	for _, v := range values {
		for _, ch := range parseChallenges(v) {
			switch ch.scheme {
			case "bearer":
				if ch.params["realm"] != "" {
					return ch, true
				}
			case "basic":
				basic = &ch
			case "cargo":
				cargo = &ch
			}
		}
	}
	switch {
	case basic != nil:
		return *basic, true
	case cargo != nil:
		return *cargo, true
	}
	return challenge{}, false
}

// parseChallenges parses one WWW-Authenticate header value, which may
// hold several challenges: a scheme followed by comma-separated
// parameters, each a token or a quoted string.
func parseChallenges(s string) []challenge {
	var out []challenge
	var cur *challenge
	for {
		s = strings.TrimLeft(s, " \t,")
		if s == "" {
			break
		}
		name, rest := cutToken(s)
		if name == "" {
			break // malformed; keep what parsed
		}
		rest = strings.TrimLeft(rest, " \t")
		if !strings.HasPrefix(rest, "=") || cur == nil {
			// A new challenge's scheme. Token68 credentials after it are
			// not used by registries and are skipped.
			out = append(out, challenge{scheme: strings.ToLower(name), params: map[string]string{}})
			cur = &out[len(out)-1]
			s = rest
			continue
		}
		rest = strings.TrimLeft(rest[1:], " \t")
		var val string
		if strings.HasPrefix(rest, `"`) {
			val, rest = cutQuoted(rest)
		} else {
			val, rest = cutToken(rest)
		}
		cur.params[strings.ToLower(name)] = val
		s = rest
	}
	return out
}

// cutToken splits a leading HTTP token off s.
func cutToken(s string) (tok, rest string) {
	i := 0
	for i < len(s) && strings.IndexByte(" \t,=\"", s[i]) < 0 {
		i++
	}
	return s[:i], s[i:]
}

// cutQuoted splits a leading quoted string off s, unescaping it.
func cutQuoted(s string) (val, rest string) {
	var b strings.Builder
	for i := 1; i < len(s); i++ {
		switch s[i] {
		case '\\':
			if i+1 < len(s) {
				i++
				b.WriteByte(s[i])
			}
		case '"':
			return b.String(), s[i+1:]
		default:
			b.WriteByte(s[i])
		}
	}
	return b.String(), ""
}

func basicAuth(user, password string) string {
	return base64.StdEncoding.EncodeToString([]byte(user + ":" + password))
}

func (c *Client) cachedToken(scope string) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	t, ok := c.tokens[scope]
	if !ok || !c.now().Before(t.expires) {
		return "", false
	}
	return t.value, true
}

func (c *Client) storeToken(scope string, t token) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.tokens) >= maxTokens {
		now := c.now()
		for k, v := range c.tokens {
			if !now.Before(v.expires) {
				delete(c.tokens, k)
			}
		}
		if len(c.tokens) >= maxTokens {
			clear(c.tokens)
		}
	}
	c.tokens[scope] = t
}

// minTokenLifetime is the lifetime assumed for a token that states none
// or a shorter one, as the registry token specification does.
const minTokenLifetime = 60 * time.Second

// maxTokenResponse bounds a token response body.
const maxTokenResponse = 1 << 20

// fetchToken obtains a bearer token for scope from the challenge's realm,
// sending the credentials if there are any, and caches it.
func (c *Client) fetchToken(ctx context.Context, ch challenge, scope string) (string, error) {
	realm, err := url.Parse(ch.params["realm"])
	op := "GET token from " + ch.params["realm"]
	if err != nil || (realm.Scheme != "https" && realm.Scheme != "http") || realm.Host == "" {
		return "", &Error{Op: op, Err: fmt.Errorf("%w: invalid token realm", ErrAuth)}
	}
	if c.base.Scheme == "https" && realm.Scheme != "https" {
		return "", &Error{Op: op, Err: fmt.Errorf("%w: the token realm is not https", ErrAuth)}
	}
	if err := c.pol.check(realm); err != nil {
		return "", &Error{Op: op, Err: fmt.Errorf("%w: %w", ErrAuth, err)}
	}
	q := realm.Query()
	if svc := ch.params["service"]; svc != "" {
		q.Set("service", svc)
	}
	reqScope := scope
	if s := ch.params["scope"]; s != "" {
		reqScope = s
	}
	if reqScope != "" {
		q.Set("scope", reqScope)
	}
	realm.RawQuery = q.Encode()
	auth := ""
	if c.username != "" {
		pw, err := c.password()
		if err != nil {
			return "", &Error{Op: op, Err: err}
		}
		auth = "Basic " + basicAuth(c.username, pw)
	}
	resp, err := c.roundTrip(ctx, http.MethodGet, realm.String(), nil, nil, auth)
	if err != nil {
		return "", transportError(op, err)
	}
	defer drain(resp)
	switch {
	case (resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden) && c.username != "":
		return "", &Error{Op: op, Status: resp.StatusCode, Err: fmt.Errorf("%w: the token service refused the credentials", ErrAuth)}
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return "", &Error{Op: op, Status: resp.StatusCode, Err: fmt.Errorf("%w: the token service refused anonymous access", ErrDenied)}
	case retryable(resp.StatusCode):
		return "", &Error{Op: op, Status: resp.StatusCode, Err: ErrUnavailable}
	case resp.StatusCode != http.StatusOK:
		return "", &Error{Op: op, Status: resp.StatusCode, Err: errors.New("the token service failed")}
	}
	var body struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxTokenResponse)).Decode(&body); err != nil {
		return "", &Error{Op: op, Err: fmt.Errorf("decoding the token response: %w", err)}
	}
	tok := body.Token
	if tok == "" {
		tok = body.AccessToken
	}
	if tok == "" {
		return "", &Error{Op: op, Err: errors.New("the token response holds no token")}
	}
	life := max(time.Duration(body.ExpiresIn)*time.Second, minTokenLifetime)
	// Stop using the token a little early, so it does not expire in flight.
	c.storeToken(scope, token{value: tok, expires: c.now().Add(life * 9 / 10)})
	return tok, nil
}
