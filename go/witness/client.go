package witness

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/action-state-group/cll-go/checkpoint"
	"github.com/action-state-group/cll-go/cll"
)

// DefaultMaxResponseBytes is the shared portable witness-response limit.
const DefaultMaxResponseBytes = cll.MaxWitnessResponseBytes

// DefaultRequestTimeout prevents one unavailable witness from hanging its runner.
const DefaultRequestTimeout = 30 * time.Second

// EntryHashSchemeCheckpointDigest is the witness protocol wire label for a
// checkpoint digest registered as raw bytes with the transparency log.
const EntryHashSchemeCheckpointDigest = "legacy"

// Receipt contains the bounded witness response needed for offline verification.
type Receipt struct {
	Bytes           []byte
	EntryHash       string
	EntryHashScheme string
	LeafIndex       int64
	TreeSize        int64
}

// HTTPError preserves the status used for retry classification.
type HTTPError struct {
	StatusCode int
	Body       string
}

func (e *HTTPError) Error() string {
	return fmt.Sprintf("witness returned HTTP %d: %s", e.StatusCode, e.Body)
}
func (e *HTTPError) Retryable() bool {
	return e.StatusCode == http.StatusRequestTimeout || e.StatusCode == http.StatusTooManyRequests || e.StatusCode >= 500
}

type transportError struct{ cause error }

func (e *transportError) Error() string { return e.cause.Error() }
func (e *transportError) Unwrap() error { return e.cause }

// Client submits signed checkpoints to a witness service.
type Client struct {
	endpoint string
	http     *http.Client
	maxBytes int64
}

// NewClient constructs a redirect-rejecting, response-bounded client.
func NewClient(baseURL string, client *http.Client, maxResponseBytes int64) (*Client, error) {
	if baseURL == "" {
		return nil, fmt.Errorf("base URL is required")
	}
	parsed, err := url.Parse(baseURL)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, fmt.Errorf("base URL must be an HTTP(S) origin or path")
	}
	if maxResponseBytes == 0 {
		maxResponseBytes = DefaultMaxResponseBytes
	}
	if maxResponseBytes < 1 {
		return nil, fmt.Errorf("max response bytes must be positive")
	}
	if client == nil {
		client = http.DefaultClient
	}
	copyClient := *client
	if copyClient.Timeout == 0 {
		copyClient.Timeout = DefaultRequestTimeout
	}
	copyClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &Client{endpoint: strings.TrimRight(baseURL, "/") + "/checkpoints", http: &copyClient, maxBytes: maxResponseBytes}, nil
}

func (c *Client) Submit(ctx context.Context, signedCheckpoint []byte) (Receipt, error) {
	record, err := checkpoint.ParseRecord(signedCheckpoint)
	if err != nil {
		return Receipt{}, err
	}
	if err := record.VerifySignature(); err != nil {
		return Receipt{}, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(signedCheckpoint))
	if err != nil {
		return Receipt{}, err
	}
	request.Header.Set("Content-Type", checkpoint.ContentType)
	request.Header.Set("Accept", "application/json")
	response, err := c.http.Do(request)
	if err != nil {
		return Receipt{}, &transportError{cause: err}
	}
	raw, readErr := io.ReadAll(io.LimitReader(response.Body, c.maxBytes+1))
	err = errors.Join(readErr, response.Body.Close())
	if err != nil {
		return Receipt{}, &transportError{cause: err}
	}
	if int64(len(raw)) > c.maxBytes {
		return Receipt{}, fmt.Errorf("witness response exceeds %d bytes", c.maxBytes)
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return Receipt{}, &HTTPError{StatusCode: response.StatusCode, Body: boundedText(strings.TrimSpace(string(raw)))}
	}
	var wire struct {
		ReceiptB64      string `json:"receipt_b64"`
		EntryHash       string `json:"entry_hash"`
		EntryHashScheme string `json:"entry_hash_scheme"`
		LeafIndex       int64  `json:"leaf_index"`
		TreeSize        int64  `json:"tree_size"`
	}
	// The witness response is versioned additively. Validate every field this
	// client consumes while allowing new, bounded fields from newer servers.
	if err := json.Unmarshal(raw, &wire); err != nil {
		return Receipt{}, fmt.Errorf("decode witness response: %w", err)
	}
	if wire.EntryHashScheme != EntryHashSchemeCheckpointDigest {
		return Receipt{}, fmt.Errorf("unsupported entry hash scheme %q", wire.EntryHashScheme)
	}
	entryHash, err := hex.DecodeString(wire.EntryHash)
	if err != nil || len(entryHash) != 32 || hex.EncodeToString(entryHash) != wire.EntryHash {
		return Receipt{}, fmt.Errorf("invalid entry hash")
	}
	if wire.TreeSize <= 0 || wire.LeafIndex < 0 || wire.LeafIndex >= wire.TreeSize ||
		uint64(wire.TreeSize) > cll.MaxPortableInteger || uint64(wire.LeafIndex) > cll.MaxPortableInteger {
		return Receipt{}, fmt.Errorf("invalid transparency position")
	}
	receiptBytes, err := base64.StdEncoding.Strict().DecodeString(wire.ReceiptB64)
	if err != nil || len(receiptBytes) == 0 {
		return Receipt{}, fmt.Errorf("invalid receipt base64")
	}
	return Receipt{Bytes: receiptBytes, EntryHash: wire.EntryHash, EntryHashScheme: wire.EntryHashScheme, LeafIndex: wire.LeafIndex, TreeSize: wire.TreeSize}, nil
}

// boundedText normalizes operational error text into a form that is stable
// across a durable JSON round-trip: always valid UTF-8 and never longer than
// cll.MaxReasonBytes. A remote witness body can contain invalid or mid-rune
// bytes; encoding/json rewrites invalid UTF-8 to U+FFFD (three bytes each), so
// a raw byte truncation could grow past the cap after persistence and then
// fail backend validation on reopen. Normalizing first, then trimming to a
// rune boundary, keeps len(boundedText(x)) <= cll.MaxReasonBytes after storage.
func boundedText(value string) string {
	value = strings.ToValidUTF8(value, "�")
	if len(value) <= cll.MaxReasonBytes {
		return value
	}
	value = value[:cll.MaxReasonBytes]
	for len(value) > 0 && !utf8.ValidString(value) {
		value = value[:len(value)-1]
	}
	return value
}

// IsRetryable reports timeout, 408, 429, and 5xx failures.
func IsRetryable(err error) bool {
	var target *HTTPError
	if errors.As(err, &target) {
		return target.Retryable()
	}
	var transport *transportError
	if errors.As(err, &transport) {
		return true
	}
	var networkError net.Error
	return errors.As(err, &networkError)
}
