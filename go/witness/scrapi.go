package witness

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/action-state-group/checkpointed-local-log/go/checkpoint"
	"github.com/action-state-group/checkpointed-local-log/go/cll"
)

// SCRAPIContentType is the media type of a SCRAPI registration request and of
// the COSE Receipt it returns (draft-ietf-scitt-scrapi).
const SCRAPIContentType = "application/cose"

// DefaultSCRAPIMaxPolls bounds how many Location responses one registration
// follows before it is reported as still pending.
const DefaultSCRAPIMaxPolls = 10

// DefaultSCRAPIPollInterval is the wait before re-reading a registration the
// service reported as accepted but not yet complete.
const DefaultSCRAPIPollInterval = time.Second

// ErrSCRAPIPending reports a registration the service accepted but had not
// completed within the poll budget. It is retryable.
var ErrSCRAPIPending = errors.New("SCRAPI registration did not complete")

// SCRAPIClient registers signed checkpoints with a SCITT Transparency Service
// through SCRAPI's POST /entries (draft-ietf-scitt-scrapi).
//
// It sends the checkpoint's COSE statement octets exactly as signed, so the
// service's leaf entry is SHA-256 of the cll-checkpoint octets: the anchor
// digest that agent-action-capsule interop profile v1 section 6.2.2 checks.
// The returned Receipt has no entry hash scheme; a caller tells it apart from
// a cll binding Receipt by the witness URL it came from. It is checked with
// that profile's anchor_witnessed verifier, not with ReceiptVerifier.
type SCRAPIClient struct {
	base         *url.URL
	entries      string
	http         *http.Client
	maxBytes     int64
	maxPolls     int
	pollInterval time.Duration
	timeout      time.Duration
}

// NewSCRAPIClient constructs a redirect-rejecting, response-bounded SCRAPI
// client for the service at baseURL, an HTTP(S) origin or path with no
// binding prefix. Location responses are followed only within baseURL's
// origin. One registration, its polls included, takes at most the client's
// request timeout (DefaultRequestTimeout when unset), the bound one cll
// binding request has.
func NewSCRAPIClient(baseURL string, client *http.Client, maxResponseBytes int64) (*SCRAPIClient, error) {
	plain, err := NewClient(baseURL, client, maxResponseBytes)
	if err != nil {
		return nil, err
	}
	base, _ := url.Parse(baseURL)
	return &SCRAPIClient{
		base:         base,
		entries:      strings.TrimRight(baseURL, "/") + "/entries",
		http:         plain.http,
		maxBytes:     plain.maxBytes,
		maxPolls:     DefaultSCRAPIMaxPolls,
		pollInterval: DefaultSCRAPIPollInterval,
		timeout:      plain.http.Timeout,
	}, nil
}

// Submit registers signedCheckpoint and returns the service's COSE Receipt.
// A 200 or 201 answer carries the Receipt. A 202, 302 or 303 answer names a
// Location to read next; 202 and 302 mean the registration is still running
// and are re-read after the poll interval. The Receipt is checked against the
// receipt profile ReceiptVerifier applies and for an inclusion proof that
// folds from SHA-256 of the statement, but not for the service's signature,
// which needs the relying party's witness key.
func (c *SCRAPIClient) Submit(ctx context.Context, signedCheckpoint []byte) (Receipt, error) {
	record, err := checkpoint.ParseRecord(signedCheckpoint)
	if err != nil {
		return Receipt{}, err
	}
	if err := record.VerifySignature(); err != nil {
		return Receipt{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.entries, bytes.NewReader(signedCheckpoint))
	if err != nil {
		return Receipt{}, err
	}
	request.Header.Set("Content-Type", SCRAPIContentType)
	status, location, raw, err := c.do(request)
	for polls := 0; err == nil && (status == http.StatusAccepted || status == http.StatusFound || status == http.StatusSeeOther); polls++ {
		if polls >= c.maxPolls {
			return Receipt{}, fmt.Errorf("%w after %d polls (HTTP %d)", ErrSCRAPIPending, polls, status)
		}
		next, locErr := c.resolve(request.URL, location)
		if locErr != nil {
			return Receipt{}, locErr
		}
		if status != http.StatusSeeOther {
			if waitErr := sleep(ctx, c.pollInterval); waitErr != nil {
				return Receipt{}, waitErr
			}
		}
		request, err = http.NewRequestWithContext(ctx, http.MethodGet, next.String(), nil)
		if err != nil {
			return Receipt{}, err
		}
		status, location, raw, err = c.do(request)
	}
	if err != nil {
		return Receipt{}, err
	}
	if status != http.StatusOK && status != http.StatusCreated {
		return Receipt{}, &HTTPError{StatusCode: status, Body: boundedText(strings.TrimSpace(string(raw)))}
	}
	entry := sha256.Sum256(signedCheckpoint)
	leafIndex, treeSize, err := scrapiReceiptPosition(raw)
	if err != nil {
		return Receipt{}, err
	}
	return Receipt{Bytes: raw, EntryHash: hex.EncodeToString(entry[:]), LeafIndex: leafIndex, TreeSize: treeSize}, nil
}

// do sends one request and reads its bounded response.
func (c *SCRAPIClient) do(request *http.Request) (int, string, []byte, error) {
	request.Header.Set("Accept", SCRAPIContentType)
	response, err := c.http.Do(request)
	if err != nil {
		return 0, "", nil, &transportError{cause: err}
	}
	raw, readErr := io.ReadAll(io.LimitReader(response.Body, c.maxBytes+1))
	if err := errors.Join(readErr, response.Body.Close()); err != nil {
		return 0, "", nil, &transportError{cause: err}
	}
	if int64(len(raw)) > c.maxBytes {
		return 0, "", nil, fmt.Errorf("witness response exceeds %d bytes", c.maxBytes)
	}
	return response.StatusCode, response.Header.Get("Location"), raw, nil
}

// resolve reads a Location against the request that returned it and refuses
// one that leaves the service's origin or carries credentials.
func (c *SCRAPIClient) resolve(from *url.URL, location string) (*url.URL, error) {
	if location == "" {
		return nil, fmt.Errorf("SCRAPI response has no Location")
	}
	ref, err := url.Parse(location)
	if err != nil {
		return nil, fmt.Errorf("SCRAPI Location is invalid")
	}
	next := from.ResolveReference(ref)
	if next.Scheme != c.base.Scheme || next.Host != c.base.Host || next.User != nil {
		return nil, fmt.Errorf("SCRAPI Location leaves the witness origin")
	}
	next.Fragment = ""
	return next, nil
}

func sleep(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// scrapiReceiptPosition checks raw with decodeReceipt, the receipt profile
// ReceiptVerifier and agent-action-capsule's VerifyReceipts apply, and returns
// its first inclusion proof's position. decodeReceipt refuses a proof that
// cannot fit its tree, so every proof folds to a root; which root the service
// signed needs the relying party's witness key, which this client lacks.
func scrapiReceiptPosition(raw []byte) (int64, int64, error) {
	if len(raw) == 0 {
		return 0, 0, fmt.Errorf("SCRAPI response has no receipt")
	}
	decoded, err := decodeReceipt(raw)
	if err != nil {
		return 0, 0, fmt.Errorf("decode SCRAPI receipt: %w", err)
	}
	proof := decoded.proofs[0]
	// The store refuses a position beyond the portable integer range, as the
	// cll binding's Client does; refuse it here so delivery records a failure
	// instead of erroring on every pass.
	if uint64(proof.size) > cll.MaxPortableInteger {
		return 0, 0, fmt.Errorf("SCRAPI receipt tree size exceeds the portable integer range")
	}
	return proof.index, proof.size, nil
}
