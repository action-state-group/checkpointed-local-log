package witness

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/action-state-group/checkpointed-local-log/go/checkpoint"
	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"
	"github.com/veraison/go-cose"
)

// scrapiService is a test SCITT Transparency Service. It appends the SHA-256
// of each registered statement to an RFC 9162 tree after two earlier entries,
// and answers per mode: "created" returns the Receipt with 201, "accepted"
// returns 202 then the Receipt from the Location, "found" does the same with
// 302 while the registration runs, "see-other" returns 303.
type scrapiService struct {
	t        *testing.T
	key      ed25519.PrivateKey
	mode     string
	received [][]byte
	polls    atomic.Int32
	server   *httptest.Server
}

func newSCRAPIService(t *testing.T, mode string) *scrapiService {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	s := &scrapiService{t: t, key: key, mode: mode}
	var receipt []byte
	s.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/entries":
			require.Equal(t, SCRAPIContentType, r.Header.Get("Content-Type"))
			require.Equal(t, SCRAPIContentType, r.Header.Get("Accept"))
			body, err := io.ReadAll(r.Body)
			require.NoError(t, err)
			s.received = append(s.received, body)
			entry := sha256.Sum256(body)
			receipt = s.receipt(entry[:])
			switch s.mode {
			case "created":
				w.Header().Set("Content-Type", SCRAPIContentType)
				w.WriteHeader(http.StatusCreated)
				_, _ = w.Write(receipt)
			case "accepted", "found", "pending":
				w.Header().Set("Location", "/operations/1")
				w.WriteHeader(http.StatusAccepted)
			case "see-other":
				w.Header().Set("Location", "/entries/1")
				w.WriteHeader(http.StatusSeeOther)
			case "elsewhere":
				w.Header().Set("Location", "https://other.example/entries/1")
				w.WriteHeader(http.StatusSeeOther)
			case "malformed":
				w.WriteHeader(http.StatusCreated)
				_, _ = w.Write([]byte("not a receipt"))
			case "unavailable":
				w.WriteHeader(http.StatusServiceUnavailable)
			case "refused":
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte("bad statement"))
			}
		case r.Method == http.MethodGet && r.URL.Path == "/operations/1":
			if s.mode == "pending" || s.polls.Add(1) < 2 {
				w.Header().Set("Location", "/operations/1")
				if s.mode == "found" {
					w.WriteHeader(http.StatusFound)
				} else {
					w.WriteHeader(http.StatusAccepted)
				}
				return
			}
			w.Header().Set("Location", "/entries/1")
			w.WriteHeader(http.StatusSeeOther)
		case r.Method == http.MethodGet && r.URL.Path == "/entries/1":
			require.Equal(t, SCRAPIContentType, r.Header.Get("Accept"))
			w.Header().Set("Content-Type", SCRAPIContentType)
			_, _ = w.Write(receipt)
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(s.server.Close)
	return s
}

// receipt signs an RFC 9162 Receipt for entry at index 2 of a three-entry tree.
func (s *scrapiService) receipt(entry []byte) []byte {
	s.t.Helper()
	entries := [][]byte{bytes.Repeat([]byte{0xa0}, 32), bytes.Repeat([]byte{0xa1}, 32), entry}
	proof, err := cbor.Marshal([]any{int64(len(entries)), int64(2), auditPath(2, entries)})
	require.NoError(s.t, err)
	message := cose.NewSign1Message()
	message.Headers.Protected.SetAlgorithm(cose.AlgorithmEdDSA)
	message.Headers.Protected[headerVDS] = vdsRFC9162
	message.Headers.Unprotected[headerVDP] = map[any]any{vdpInclusion: []any{proof}}
	message.Payload = treeHash(entries)
	signer, err := cose.NewSigner(cose.AlgorithmEdDSA, s.key)
	require.NoError(s.t, err)
	require.NoError(s.t, message.Sign(rand.Reader, nil, signer))
	message.Payload = nil
	raw, err := message.MarshalCBOR()
	require.NoError(s.t, err)
	return raw
}

func (s *scrapiService) client(t *testing.T) *SCRAPIClient {
	t.Helper()
	client, err := NewSCRAPIClient(s.server.URL, s.server.Client(), 0)
	require.NoError(t, err)
	client.pollInterval = time.Millisecond
	return client
}

// treeHash is the RFC 9162 MTH over entries.
func treeHash(entries [][]byte) []byte {
	if len(entries) == 1 {
		sum := sha256.Sum256(append([]byte{0}, entries[0]...))
		return sum[:]
	}
	k := largestPowerBelow(int64(len(entries)))
	return nodeHash(treeHash(entries[:k]), treeHash(entries[k:]))
}

// auditPath is the RFC 9162 PATH(m, entries), leaf first.
func auditPath(m int64, entries [][]byte) [][]byte {
	if len(entries) == 1 {
		return [][]byte{}
	}
	k := largestPowerBelow(int64(len(entries)))
	if m < k {
		return append(auditPath(m, entries[:k]), treeHash(entries[k:]))
	}
	return append(auditPath(m-k, entries[k:]), treeHash(entries[:k]))
}

// scrapiReceiptVerifies checks receipt's signature under the service key over
// the root its proof folds to from entry: the anchor_witnessed check of
// interop profile v1 section 6.2.2, with entry as the anchor digest.
func scrapiReceiptVerifies(t *testing.T, s *scrapiService, entry []byte, receipt Receipt) bool {
	t.Helper()
	var message cose.Sign1Message
	require.NoError(t, message.UnmarshalCBOR(receipt.Bytes))
	vdp, _ := lookup(message.Headers.Unprotected, headerVDP)
	proofs, _ := lookup(vdp.(map[any]any), vdpInclusion)
	size, index, path, err := decodeProof(proofs.([]any)[0].([]byte))
	require.NoError(t, err)
	root, ok := rootFromProof(entry, index, size, path)
	require.True(t, ok)
	message.Payload = root
	verifier, err := cose.NewVerifier(cose.AlgorithmEdDSA, s.key.Public())
	require.NoError(t, err)
	return message.Verify(nil, verifier) == nil
}

// The Receipt covers SHA-256 of the statement octets, the anchor digest, and
// not the cll binding's entry, SHA-256 of the payload digest.
func TestSCRAPIClientReceiptCoversTheAnchorDigest(t *testing.T) {
	for _, mode := range []string{"created", "accepted", "found", "see-other"} {
		t.Run(mode, func(t *testing.T) {
			service := newSCRAPIService(t, mode)
			statement := checkpointStatement(t)
			receipt, err := service.client(t).Submit(t.Context(), statement)
			require.NoError(t, err)

			require.Equal(t, [][]byte{statement}, service.received, "the statement octets are sent exactly as signed")
			anchor := sha256.Sum256(statement)
			require.Equal(t, hex.EncodeToString(anchor[:]), receipt.EntryHash)
			require.Empty(t, receipt.EntryHashScheme, "no new entry hash scheme")
			require.Equal(t, int64(2), receipt.LeafIndex)
			require.Equal(t, int64(3), receipt.TreeSize)
			require.True(t, scrapiReceiptVerifies(t, service, anchor[:], receipt))

			record, err := checkpoint.ParseRecord(statement)
			require.NoError(t, err)
			legacy, err := record.EntryHash()
			require.NoError(t, err)
			require.False(t, scrapiReceiptVerifies(t, service, legacy, receipt), "the cll binding's entry is a different leaf")
		})
	}
}

func TestSCRAPIClientRefusesBeforeSendingAnUnsignedOrAlteredStatement(t *testing.T) {
	service := newSCRAPIService(t, "created")
	client := service.client(t)
	statement := checkpointStatement(t)
	tampered := append([]byte(nil), statement...)
	tampered[len(tampered)-1] ^= 1
	_, err := client.Submit(t.Context(), tampered)
	require.Error(t, err)
	_, err = client.Submit(t.Context(), []byte("checkpoint"))
	require.Error(t, err)
	require.Empty(t, service.received)
}

func TestSCRAPIClientClassifiesFailures(t *testing.T) {
	statement := checkpointStatement(t)

	_, err := newSCRAPIService(t, "pending").client(t).Submit(t.Context(), statement)
	require.ErrorIs(t, err, ErrSCRAPIPending)
	require.True(t, IsRetryable(err))

	// The whole registration, polls included, stays within one request
	// timeout, and running out of it is retryable.
	slow := newSCRAPIService(t, "pending").client(t)
	slow.pollInterval = time.Second
	slow.timeout = 50 * time.Millisecond
	started := time.Now()
	_, err = slow.Submit(t.Context(), statement)
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.Less(t, time.Since(started), time.Second)
	require.True(t, IsRetryable(err))

	_, err = newSCRAPIService(t, "unavailable").client(t).Submit(t.Context(), statement)
	require.True(t, IsRetryable(err))

	_, err = newSCRAPIService(t, "refused").client(t).Submit(t.Context(), statement)
	var answered *HTTPError
	require.ErrorAs(t, err, &answered)
	require.Equal(t, http.StatusBadRequest, answered.StatusCode)
	require.Equal(t, "bad statement", answered.Body)
	require.False(t, IsRetryable(err))

	_, err = newSCRAPIService(t, "elsewhere").client(t).Submit(t.Context(), statement)
	require.ErrorContains(t, err, "leaves the witness origin")
	require.False(t, IsRetryable(err))

	_, err = newSCRAPIService(t, "malformed").client(t).Submit(t.Context(), statement)
	require.ErrorContains(t, err, "decode SCRAPI receipt")
	require.False(t, IsRetryable(err))
}

func TestSCRAPIClientBoundsResponsesAndRedirects(t *testing.T) {
	statement := checkpointStatement(t)
	var gets atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/entries":
			w.Header().Set("Location", "/redirected")
			w.WriteHeader(http.StatusTemporaryRedirect)
		case "/big/entries":
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(strings.Repeat("x", 65)))
		default:
			gets.Add(1)
		}
	}))
	t.Cleanup(server.Close)

	client, err := NewSCRAPIClient(server.URL, server.Client(), 0)
	require.NoError(t, err)
	_, err = client.Submit(t.Context(), statement)
	var answered *HTTPError
	require.ErrorAs(t, err, &answered, "a redirect outside the SCRAPI flow is not followed")
	require.Equal(t, http.StatusTemporaryRedirect, answered.StatusCode)
	require.Zero(t, gets.Load())

	client, err = NewSCRAPIClient(server.URL+"/big", server.Client(), 64)
	require.NoError(t, err)
	_, err = client.Submit(t.Context(), statement)
	require.ErrorContains(t, err, "exceeds 64 bytes")

	_, err = NewSCRAPIClient("scrapi+https://witness.example", nil, 0)
	require.Error(t, err, "the binding prefix is the caller's to remove")
}

func TestSCRAPIReceiptPositionRefusesMalformedReceipts(t *testing.T) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	entry := bytes.Repeat([]byte{1}, 32)
	sign := func(edit func(*cose.Sign1Message)) []byte {
		proof, err := cbor.Marshal([]any{int64(1), int64(0), [][]byte{}})
		require.NoError(t, err)
		message := cose.NewSign1Message()
		message.Headers.Protected.SetAlgorithm(cose.AlgorithmEdDSA)
		message.Headers.Protected[headerVDS] = vdsRFC9162
		message.Headers.Unprotected[headerVDP] = map[any]any{vdpInclusion: []any{proof}}
		message.Payload = treeHash([][]byte{entry})
		signer, err := cose.NewSigner(cose.AlgorithmEdDSA, key)
		require.NoError(t, err)
		require.NoError(t, message.Sign(rand.Reader, nil, signer))
		message.Payload = nil
		edit(message)
		raw, err := message.MarshalCBOR()
		require.NoError(t, err)
		return raw
	}
	_, _, err = scrapiReceiptPosition(sign(func(*cose.Sign1Message) {}), entry)
	require.NoError(t, err)

	for name, edit := range map[string]func(*cose.Sign1Message){
		"attached payload": func(m *cose.Sign1Message) { m.Payload = []byte("root") },
		"no VDS":           func(m *cose.Sign1Message) { delete(m.Headers.Protected, headerVDS) },
		"no VDP":           func(m *cose.Sign1Message) { delete(m.Headers.Unprotected, headerVDP) },
		"no proof":         func(m *cose.Sign1Message) { m.Headers.Unprotected[headerVDP] = map[any]any{vdpInclusion: []any{}} },
		"proof not bytes": func(m *cose.Sign1Message) {
			m.Headers.Unprotected[headerVDP] = map[any]any{vdpInclusion: []any{int64(1)}}
		},
		"tree size beyond portable integer": func(m *cose.Sign1Message) {
			// Leaf 0 of a 2^53 tree has a 53-hash path, so only the cap refuses it.
			path := make([][]byte, 53)
			for i := range path {
				path[i] = bytes.Repeat([]byte{2}, 32)
			}
			proof, err := cbor.Marshal([]any{int64(1) << 53, int64(0), path})
			require.NoError(t, err)
			m.Headers.Unprotected[headerVDP] = map[any]any{vdpInclusion: []any{proof}}
		},
		"wrong path length": func(m *cose.Sign1Message) {
			proof, err := cbor.Marshal([]any{int64(2), int64(0), [][]byte{}})
			require.NoError(t, err)
			m.Headers.Unprotected[headerVDP] = map[any]any{vdpInclusion: []any{proof}}
		},
	} {
		_, _, err := scrapiReceiptPosition(sign(edit), entry)
		require.Error(t, err, name)
	}
	_, _, err = scrapiReceiptPosition(nil, entry)
	require.Error(t, err)
}
