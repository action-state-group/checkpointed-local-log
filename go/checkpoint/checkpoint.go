package checkpoint

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/action-state-group/cll-go/cll"
	"github.com/action-state-group/cll-go/mmr"
	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/go-cose"
)

// MaxEncodedBytes bounds canonical checkpoint signing bodies and signed records.
const MaxEncodedBytes = 64 << 10

// Payload is the canonical checkpoint signing body.
type Payload struct {
	LogID     string
	KeyID     string
	MMRSize   uint64
	Root      string
	PrevSize  uint64
	PrevRoot  string
	Timestamp time.Time
}

// recordWire is the exact JSON developer projection authenticated by the COSE
// checkpoint claims.
type recordWire struct {
	Version   uint64 `json:"v"`
	Kind      string `json:"kind"`
	LogID     string `json:"log_id"`
	MMRSize   uint64 `json:"mmr_size"`
	Root      string `json:"root"`
	PrevSize  uint64 `json:"prev_size"`
	PrevRoot  string `json:"prev_root"`
	KeyID     string `json:"key_id"`
	Timestamp string `json:"timestamp"`
}

// ParsePayload accepts only this profile's exact canonical JSON projection.
func ParsePayload(data []byte) (Payload, error) {
	if len(data) == 0 || len(data) > MaxEncodedBytes {
		return Payload{}, fmt.Errorf("checkpoint payload size is invalid")
	}
	var wire recordWire
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&wire); err != nil {
		return Payload{}, fmt.Errorf("decode checkpoint payload: %w", err)
	}
	if wire.Kind != "mmr_checkpoint" || wire.Version != 1 {
		return Payload{}, fmt.Errorf("checkpoint profile fields are invalid")
	}
	timestamp, err := time.Parse(time.RFC3339Nano, wire.Timestamp)
	if err != nil {
		return Payload{}, fmt.Errorf("checkpoint timestamp is invalid: %w", err)
	}
	payload := Payload{LogID: wire.LogID, KeyID: wire.KeyID, MMRSize: wire.MMRSize, Root: wire.Root, PrevSize: wire.PrevSize, PrevRoot: wire.PrevRoot, Timestamp: timestamp}
	canonical, err := payload.CanonicalJSON()
	if err != nil || !bytes.Equal(canonical, data) {
		return Payload{}, fmt.Errorf("checkpoint payload is not canonical")
	}
	return payload, nil
}

func (p Payload) CanonicalJSON() ([]byte, error) {
	fields, err := p.canonicalFields()
	if err != nil {
		return nil, err
	}
	return json.Marshal(fields)
}

type canonicalProjection struct {
	KeyID     string `json:"key_id"`
	Kind      string `json:"kind"`
	LogID     string `json:"log_id"`
	MMRSize   uint64 `json:"mmr_size"`
	PrevRoot  string `json:"prev_root"`
	PrevSize  uint64 `json:"prev_size"`
	Root      string `json:"root"`
	Timestamp string `json:"timestamp"`
	Version   uint64 `json:"v"`
}

func (p Payload) canonicalFields() (canonicalProjection, error) {
	key, keyErr := hex.DecodeString(p.KeyID)
	if cll.ValidateIdentifier(p.LogID) != nil || keyErr != nil || len(key) != ed25519.PublicKeySize || hex.EncodeToString(key) != p.KeyID || p.MMRSize == 0 || p.MMRSize > cll.MaxPortableInteger || p.PrevSize > cll.MaxPortableInteger || len(p.Root) != 64 {
		return canonicalProjection{}, fmt.Errorf("invalid checkpoint payload")
	}
	if p.PrevSize >= p.MMRSize || (p.PrevSize == 0) != (p.PrevRoot == "") {
		return canonicalProjection{}, fmt.Errorf("invalid checkpoint predecessor")
	}
	if _, err := hex.DecodeString(p.Root); err != nil || p.Root != string(bytes.ToLower([]byte(p.Root))) {
		return canonicalProjection{}, fmt.Errorf("invalid checkpoint root")
	}
	if p.PrevRoot != "" {
		if decoded, err := hex.DecodeString(p.PrevRoot); err != nil || len(decoded) != 32 || p.PrevRoot != string(bytes.ToLower([]byte(p.PrevRoot))) {
			return canonicalProjection{}, fmt.Errorf("invalid previous checkpoint root")
		}
	}
	timestamp, err := formatTimestamp(p.Timestamp)
	if err != nil {
		return canonicalProjection{}, err
	}
	return canonicalProjection{KeyID: p.KeyID, Kind: "mmr_checkpoint", LogID: p.LogID, MMRSize: p.MMRSize, PrevRoot: p.PrevRoot, PrevSize: p.PrevSize, Root: p.Root, Timestamp: timestamp, Version: 1}, nil
}

// formatTimestamp matches the checkpoint wire profile shared with TypeScript.
// Unlike persisted backend times, checkpoint timestamps retain sub-millisecond
// precision and omit an all-zero fraction.
func formatTimestamp(value time.Time) (string, error) {
	value = value.UTC()
	if value.Year() < 0 || value.Year() > 9999 {
		return "", fmt.Errorf("invalid checkpoint timestamp")
	}
	return value.Format(time.RFC3339Nano), nil
}

// Digest returns the SHA-256 digest of the canonical signing body.
func (p Payload) Digest() ([sha256.Size]byte, error) {
	body, err := p.CanonicalJSON()
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	return sha256.Sum256(body), nil
}

// DigestHex returns Digest as lowercase hexadecimal text.
func (p Payload) DigestHex() (string, error) {
	digest, err := p.Digest()
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(digest[:]), nil
}

// ContentType is the canonical media type for CLL checkpoint COSE statements.
const ContentType = "application/cll-checkpoint+cbor"

const wireKind = "cll-checkpoint"

// Record is a verified-shape CLL checkpoint decoded from its COSE_Sign1 wire
// statement. Cadence is the optional positive maximum checkpoint interval in
// seconds. NewPeaks and PrevPeaks are the ordered commitment accumulators.
type Record struct {
	Version          uint64
	Kind             string
	LogID            string
	MMRSize          uint64
	Root             string
	PrevSize         uint64
	PrevRoot         string
	KeyID            string
	Timestamp        time.Time
	Cadence          *uint64
	NewPeaks         [][]byte
	PrevPeaks        [][]byte
	ConsistencyProof *mmr.ConsistencyProof
	statement        []byte
}

// Payload returns the JSON developer projection authenticated by the COSE
// statement's corresponding CLL claims.
func (r Record) Payload() Payload {
	return Payload{LogID: r.LogID, KeyID: r.KeyID, MMRSize: r.MMRSize, Root: r.Root, PrevSize: r.PrevSize, PrevRoot: r.PrevRoot, Timestamp: r.Timestamp}
}

// ParseRecord accepts only the canonical raw COSE_Sign1 checkpoint profile
// consumed by POST /checkpoints.
func ParseRecord(data []byte) (Record, error) {
	if len(data) == 0 || len(data) > MaxEncodedBytes {
		return Record{}, fmt.Errorf("signed checkpoint size is invalid")
	}
	var message cose.Sign1Message
	if err := message.UnmarshalCBOR(data); err != nil {
		return Record{}, fmt.Errorf("decode signed checkpoint COSE: %w", err)
	}
	reencoded, err := message.MarshalCBOR()
	if err != nil || !bytes.Equal(reencoded, data) {
		return Record{}, fmt.Errorf("signed checkpoint COSE is not canonical")
	}
	if len(message.Headers.Unprotected) != 0 || len(message.Headers.Protected) != 4 {
		return Record{}, fmt.Errorf("checkpoint COSE headers are invalid")
	}
	algorithm, err := message.Headers.Protected.Algorithm()
	if err != nil || algorithm != cose.AlgorithmEdDSA {
		return Record{}, fmt.Errorf("checkpoint COSE algorithm is invalid")
	}
	contentType, ok := message.Headers.Protected[cose.HeaderLabelContentType].(string)
	if !ok || contentType != ContentType {
		return Record{}, fmt.Errorf("checkpoint COSE content type is invalid")
	}
	kid, ok := message.Headers.Protected[cose.HeaderLabelKeyID].([]byte)
	if !ok || len(kid) != ed25519.PublicKeySize {
		return Record{}, fmt.Errorf("checkpoint COSE key id is invalid")
	}
	claims, err := protectedCWTClaims(message.Headers.Protected[cose.HeaderLabelCWTClaims])
	if err != nil || len(claims) != 2 {
		return Record{}, fmt.Errorf("checkpoint CWT claims are invalid")
	}
	issuer, issuerOK := claims[cose.CWTClaimIssuer].(string)
	subject, subjectOK := claims[cose.CWTClaimSubject].(string)
	if !issuerOK || !subjectOK {
		return Record{}, fmt.Errorf("checkpoint CWT identity is invalid")
	}
	wire, err := decodeWireClaims(message.Payload)
	if err != nil {
		return Record{}, err
	}
	if subject != fmt.Sprintf("%s#%d", issuer, wire.LogSize) {
		return Record{}, fmt.Errorf("checkpoint CWT subject is invalid")
	}
	newPeaks, err := decodeCommitment(wire.Commitment, "commitment")
	if err != nil {
		return Record{}, err
	}
	prevPeaks := [][]byte{}
	if len(wire.PrevCommitment) > 0 {
		prevPeaks, err = decodeCommitment(wire.PrevCommitment, "previous commitment")
		if err != nil {
			return Record{}, err
		}
	}
	timestamp, err := time.Parse(time.RFC3339Nano, wire.IssuedAt)
	if err != nil {
		return Record{}, fmt.Errorf("checkpoint timestamp is invalid: %w", err)
	}
	record := Record{
		Version: 1, Kind: "mmr_checkpoint", LogID: issuer, MMRSize: wire.LogSize,
		Root: hex.EncodeToString(rootFromPeaks(newPeaks)), PrevSize: wire.PrevSize,
		PrevRoot: hex.EncodeToString(rootFromPeaks(prevPeaks)), KeyID: hex.EncodeToString(kid),
		Timestamp: timestamp, NewPeaks: clonePeaks(newPeaks), PrevPeaks: clonePeaks(prevPeaks),
		statement: append([]byte(nil), data...),
	}
	if wire.Cadence != nil {
		cadence := *wire.Cadence
		record.Cadence = &cadence
	}
	if wire.ConsistencyProof != nil {
		record.ConsistencyProof = &mmr.ConsistencyProof{
			V:       1,
			Kind:    "consistency",
			OldSize: wire.ConsistencyProof.SizeA, NewSize: wire.ConsistencyProof.SizeB,
			OldPeaks: clonePeaks(wire.ConsistencyProof.OldPeaks),
			Witness:  cloneWitness(wire.ConsistencyProof.Witness),
			NewPeaks: clonePeaks(wire.ConsistencyProof.NewPeaks),
		}
	}
	if record.PrevSize == 0 {
		if len(record.PrevPeaks) != 0 {
			return Record{}, fmt.Errorf("first checkpoint has a previous commitment")
		}
		record.PrevRoot = ""
	} else if len(record.PrevPeaks) == 0 {
		return Record{}, fmt.Errorf("checkpoint previous commitment is required")
	}
	if record.PrevSize == 0 {
		if record.ConsistencyProof != nil {
			return Record{}, fmt.Errorf("first checkpoint cannot carry a consistency proof")
		}
	} else if record.ConsistencyProof == nil || !mmr.VerifyConsistency(
		rootFromPeaks(record.PrevPeaks), rootFromPeaks(record.NewPeaks), *record.ConsistencyProof,
	) {
		return Record{}, fmt.Errorf("checkpoint consistency proof is invalid")
	}
	if _, err := record.Payload().canonicalFields(); err != nil {
		return Record{}, err
	}
	return record, nil
}

// EntryHash returns the CT-log entry hash used by the checkpoint-only witness.
func (r Record) EntryHash() ([]byte, error) {
	digest, err := r.Payload().Digest()
	if err != nil {
		return nil, err
	}
	entry := sha256.Sum256(digest[:])
	return entry[:], nil
}

// VerifySignature checks the self-contained Ed25519 checkpoint signature.
func (r Record) VerifySignature() error {
	public, err := hex.DecodeString(r.KeyID)
	if err != nil || len(public) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid checkpoint public key")
	}
	var message cose.Sign1Message
	if err := message.UnmarshalCBOR(r.statement); err != nil {
		return fmt.Errorf("decode checkpoint signature: %w", err)
	}
	verifier, err := cose.NewVerifier(cose.AlgorithmEdDSA, ed25519.PublicKey(public))
	if err != nil {
		return err
	}
	if err := message.Verify(nil, verifier); err != nil {
		return fmt.Errorf("verify checkpoint signature: %w", err)
	}
	return nil
}

// Ed25519Signer emits checkpoint records whose key_id is the raw public key.
type Ed25519Signer struct {
	private ed25519.PrivateKey
	public  ed25519.PublicKey
}

func NewEd25519Signer(private ed25519.PrivateKey) (*Ed25519Signer, error) {
	if len(private) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("Ed25519 private key is required")
	}
	public, ok := private.Public().(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("derive Ed25519 public key")
	}
	return &Ed25519Signer{private: append(ed25519.PrivateKey(nil), private...), public: append(ed25519.PublicKey(nil), public...)}, nil
}

func (s *Ed25519Signer) KeyID() string { return hex.EncodeToString(s.public) }

func (s *Ed25519Signer) SignCheckpoint(ctx context.Context, payload []byte, newPeaks, prevPeaks [][]byte, proof *mmr.ConsistencyProof) ([]byte, error) {
	return s.signCheckpoint(ctx, payload, newPeaks, prevPeaks, proof, nil)
}

// SignCheckpointWithCadence signs a checkpoint carrying the producer's
// positive, portable maximum checkpoint interval in seconds.
func (s *Ed25519Signer) SignCheckpointWithCadence(ctx context.Context, payload []byte, newPeaks, prevPeaks [][]byte, proof *mmr.ConsistencyProof, cadence uint64) ([]byte, error) {
	return s.signCheckpoint(ctx, payload, newPeaks, prevPeaks, proof, &cadence)
}

func (s *Ed25519Signer) signCheckpoint(ctx context.Context, payload []byte, newPeaks, prevPeaks [][]byte, proof *mmr.ConsistencyProof, cadence *uint64) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	parsed, err := ParsePayload(payload)
	if err != nil || parsed.KeyID != s.KeyID() {
		return nil, fmt.Errorf("checkpoint payload key does not match signer")
	}
	claims, err := encodeWireClaims(parsed, newPeaks, prevPeaks, proof, cadence)
	if err != nil {
		return nil, err
	}
	message := cose.NewSign1Message()
	message.Headers.Protected.SetAlgorithm(cose.AlgorithmEdDSA)
	message.Headers.Protected[cose.HeaderLabelContentType] = ContentType
	message.Headers.Protected[cose.HeaderLabelKeyID] = append([]byte(nil), s.public...)
	if _, err := message.Headers.Protected.SetCWTClaims(cose.CWTClaims{
		cose.CWTClaimIssuer: parsed.LogID, cose.CWTClaimSubject: fmt.Sprintf("%s#%d", parsed.LogID, parsed.MMRSize),
	}); err != nil {
		return nil, fmt.Errorf("set checkpoint CWT claims: %w", err)
	}
	message.Payload = claims
	signer, err := cose.NewSigner(cose.AlgorithmEdDSA, s.private)
	if err != nil {
		return nil, err
	}
	if err := message.Sign(rand.Reader, nil, signer); err != nil {
		return nil, fmt.Errorf("sign checkpoint COSE: %w", err)
	}
	encoded, err := message.MarshalCBOR()
	if err != nil {
		return nil, fmt.Errorf("encode checkpoint COSE: %w", err)
	}
	if err := s.VerifyCheckpoint(payload, encoded); err != nil {
		return nil, fmt.Errorf("verify newly signed checkpoint: %w", err)
	}
	return encoded, nil
}

func (s *Ed25519Signer) VerifyCheckpoint(payload, statement []byte) error {
	parsedPayload, err := ParsePayload(payload)
	if err != nil {
		return err
	}
	record, err := ParseRecord(statement)
	if err != nil {
		return err
	}
	if record.Payload() != parsedPayload || record.KeyID != s.KeyID() {
		return fmt.Errorf("checkpoint payload mismatch")
	}
	return record.VerifySignature()
}

type wireClaims struct {
	Kind             string                `cbor:"kind"`
	LogSize          uint64                `cbor:"log_size"`
	Commitment       []byte                `cbor:"commitment"`
	PrevSize         uint64                `cbor:"prev_size"`
	PrevCommitment   []byte                `cbor:"prev_commitment"`
	IssuedAt         string                `cbor:"issued_at"`
	Cadence          *uint64               `cbor:"cadence,omitempty"`
	ConsistencyProof *wireConsistencyProof `cbor:"consistency_proof,omitempty"`
}

type wireConsistencyProof struct {
	SizeA    uint64     `cbor:"size_a"`
	SizeB    uint64     `cbor:"size_b"`
	OldPeaks [][]byte   `cbor:"old_peaks"`
	Witness  [][][]byte `cbor:"witness"`
	NewPeaks [][]byte   `cbor:"new_peaks"`
}

var canonicalCBOR = func() cbor.EncMode {
	mode, err := cbor.CanonicalEncOptions().EncMode()
	if err != nil {
		panic(err)
	}
	return mode
}()

func encodeWireClaims(payload Payload, newPeaks, prevPeaks [][]byte, proof *mmr.ConsistencyProof, cadence *uint64) ([]byte, error) {
	if err := validatePeakCommitments(payload, newPeaks, prevPeaks); err != nil {
		return nil, err
	}
	if cadence != nil && (*cadence == 0 || *cadence > cll.MaxPortableInteger) {
		return nil, fmt.Errorf("checkpoint cadence must be a positive portable integer")
	}
	if payload.PrevSize == 0 && proof != nil {
		return nil, fmt.Errorf("first checkpoint cannot carry a consistency proof")
	}
	if payload.PrevSize > 0 {
		if proof == nil || proof.OldSize != payload.PrevSize || proof.NewSize != payload.MMRSize || !mmr.VerifyConsistency(
			rootFromPeaks(prevPeaks), rootFromPeaks(newPeaks), *proof,
		) {
			return nil, fmt.Errorf("checkpoint consistency proof is required and must bridge the declared checkpoints")
		}
	}
	newCommitment, err := mmr.CommitmentObject(newPeaks)
	if err != nil {
		return nil, err
	}
	previousCommitment := []byte{}
	if payload.PrevSize > 0 {
		previousCommitment, err = mmr.CommitmentObject(prevPeaks)
		if err != nil {
			return nil, err
		}
	}
	timestamp, err := formatTimestamp(payload.Timestamp)
	if err != nil {
		return nil, err
	}
	claims := wireClaims{
		Kind: wireKind, LogSize: payload.MMRSize, Commitment: newCommitment,
		PrevSize: payload.PrevSize, PrevCommitment: previousCommitment,
		IssuedAt: timestamp, Cadence: cadence,
	}
	if proof != nil {
		claims.ConsistencyProof = &wireConsistencyProof{
			SizeA: proof.OldSize, SizeB: proof.NewSize, OldPeaks: clonePeaks(proof.OldPeaks),
			Witness: cloneWitness(proof.Witness), NewPeaks: clonePeaks(proof.NewPeaks),
		}
	}
	return canonicalCBOR.Marshal(claims)
}

func decodeWireClaims(data []byte) (wireClaims, error) {
	var claims wireClaims
	options := cbor.DecOptions{DupMapKey: cbor.DupMapKeyEnforcedAPF, IndefLength: cbor.IndefLengthForbidden}
	mode, err := options.DecMode()
	if err != nil {
		return wireClaims{}, err
	}
	if err := mode.Unmarshal(data, &claims); err != nil {
		return wireClaims{}, fmt.Errorf("decode checkpoint claims: %w", err)
	}
	encoded, err := canonicalCBOR.Marshal(claims)
	if err != nil || !bytes.Equal(encoded, data) {
		return wireClaims{}, fmt.Errorf("checkpoint claims are not canonical")
	}
	if claims.Kind != wireKind || claims.LogSize == 0 || len(claims.Commitment) == 0 || claims.IssuedAt == "" {
		return wireClaims{}, fmt.Errorf("checkpoint claims are invalid")
	}
	if claims.Cadence != nil && (*claims.Cadence == 0 || *claims.Cadence > cll.MaxPortableInteger) {
		return wireClaims{}, fmt.Errorf("checkpoint cadence must be a positive portable integer")
	}
	return claims, nil
}

func decodeCommitment(data []byte, name string) ([][]byte, error) {
	var peaks [][]byte
	options := cbor.DecOptions{DupMapKey: cbor.DupMapKeyEnforcedAPF, IndefLength: cbor.IndefLengthForbidden}
	mode, err := options.DecMode()
	if err != nil {
		return nil, err
	}
	if err := mode.Unmarshal(data, &peaks); err != nil {
		return nil, fmt.Errorf("decode checkpoint %s: %w", name, err)
	}
	encoded, err := mmr.CommitmentObject(peaks)
	if err != nil || !bytes.Equal(encoded, data) {
		return nil, fmt.Errorf("checkpoint %s is not canonical", name)
	}
	return peaks, nil
}

func validatePeakCommitments(payload Payload, newPeaks, prevPeaks [][]byte) error {
	if len(newPeaks) == 0 || hex.EncodeToString(rootFromPeaks(newPeaks)) != payload.Root {
		return fmt.Errorf("checkpoint peaks do not match root")
	}
	if payload.PrevSize == 0 {
		if len(prevPeaks) != 0 {
			return fmt.Errorf("first checkpoint cannot carry previous peaks")
		}
		return nil
	}
	if len(prevPeaks) == 0 || hex.EncodeToString(rootFromPeaks(prevPeaks)) != payload.PrevRoot {
		return fmt.Errorf("checkpoint previous peaks do not match root")
	}
	return nil
}

func rootFromPeaks(peaks [][]byte) []byte {
	return mmr.RootFromPeaks(peaks)
}

func clonePeaks(peaks [][]byte) [][]byte {
	cloned := make([][]byte, len(peaks))
	for index := range peaks {
		cloned[index] = append([]byte(nil), peaks[index]...)
	}
	return cloned
}

func cloneWitness(witness [][][]byte) [][][]byte {
	cloned := make([][][]byte, len(witness))
	for index := range witness {
		cloned[index] = clonePeaks(witness[index])
	}
	return cloned
}

func protectedCWTClaims(value any) (cose.CWTClaims, error) {
	switch claims := value.(type) {
	case cose.CWTClaims:
		return claims, nil
	case map[any]any:
		return cose.CWTClaims(claims), nil
	default:
		return nil, fmt.Errorf("invalid CWT claims")
	}
}

// Config defines the entry-count and age checkpoint cadence thresholds.
type Config struct {
	CadenceEntries uint64
	CadenceAge     time.Duration
}

// DefaultConfig returns 100 entries and 15 minutes.
func DefaultConfig() Config {
	return Config{CadenceEntries: 100, CadenceAge: 15 * time.Minute}
}

func (c Config) Validate() error {
	if c.CadenceEntries == 0 || c.CadenceAge <= 0 {
		return fmt.Errorf("invalid checkpoint cadence")
	}
	return nil
}

func (c Config) Due(entries uint64, firstUncheckpointed, now time.Time) bool {
	if entries == 0 {
		return false
	}
	return entries >= c.CadenceEntries || !firstUncheckpointed.IsZero() && now.Sub(firstUncheckpointed) >= c.CadenceAge
}
