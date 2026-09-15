package sqlite

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"sync"
	"time"

	"github.com/action-state-group/cll-go/cll"
	"github.com/action-state-group/cll-go/internal/backend"
	"github.com/action-state-group/cll-go/internal/portable"
	modernsqlite "modernc.org/sqlite"
)

const schema = `
CREATE TABLE IF NOT EXISTS cll_meta (
  log_id TEXT PRIMARY KEY,
  state BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS cll_entries (
  log_id TEXT NOT NULL,
  seq INTEGER NOT NULL,
  value BLOB NOT NULL,
  appended_at TEXT NOT NULL,
  PRIMARY KEY(log_id, seq),
  UNIQUE(log_id, value)
);
CREATE TABLE IF NOT EXISTS cll_nodes (
  log_id TEXT NOT NULL,
  position INTEGER NOT NULL,
  node BLOB NOT NULL,
  PRIMARY KEY(log_id, position)
);
CREATE TABLE IF NOT EXISTS cll_witnesses (
  log_id TEXT NOT NULL,
  witness_id TEXT NOT NULL,
  checkpoint_size TEXT NOT NULL,
  attempts INTEGER NOT NULL,
  witness BLOB NOT NULL,
  PRIMARY KEY(log_id, witness_id, checkpoint_size)
);`

type sharedLock struct {
	mu   sync.Mutex
	refs int
}

var sharedLocks = struct {
	sync.Mutex
	items map[string]*sharedLock
}{items: make(map[string]*sharedLock)}

// Store is a transactional SQLite implementation of cll.Backend.
type Store struct {
	lifecycle sync.RWMutex
	db        *sql.DB
	logID     string
	lockKey   string
	shared    *sharedLock
	closed    bool
}

// Open validates an existing logical log without schema or metadata writes.
// Provision the database and log explicitly with Init before runtime use.
func Open(path, logID string) (*Store, error) {
	return open(path, logID, false)
}

// Init provisions the SQLite schema and logical log explicitly. It preserves
// existing entries and may be retried after a partial initialization failure.
func Init(path, logID string) error {
	store, err := open(path, logID, true)
	if err != nil {
		return err
	}
	return store.Close()
}

func open(path, logID string, initialize bool) (*Store, error) {
	if path == "" || cll.ValidateIdentifier(logID) != nil {
		return nil, fmt.Errorf("%w: database path and log ID are required", cll.ErrInvalid)
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve SQLite path: %w", err)
	}
	key := filepath.Clean(absolute) + "\x00" + logID
	lock := acquireShared(key)
	lock.mu.Lock()
	defer lock.mu.Unlock()
	mode := "rw"
	if initialize {
		mode = "rwc"
	}
	uri := url.URL{Scheme: "file", Path: absolute, RawQuery: "mode=" + mode}
	db, err := sql.Open("sqlite", uri.String())
	if err != nil {
		releaseShared(key)
		return nil, err
	}
	db.SetMaxOpenConns(1)
	store := &Store{db: db, logID: logID, lockKey: key, shared: lock}
	for _, pragma := range []string{"PRAGMA foreign_keys=ON", "PRAGMA busy_timeout=5000"} {
		if _, err := db.Exec(pragma); err != nil {
			return nil, closeOpenFailure(db, key, classify(err))
		}
	}
	if initialize {
		if _, err := db.Exec("PRAGMA journal_mode=WAL"); err != nil {
			return nil, closeOpenFailure(db, key, classify(err))
		}
		if _, err := db.Exec(schema); err != nil {
			return nil, closeOpenFailure(db, key, classify(err))
		}
		empty, err := backend.MarshalMetadata(cll.State{})
		if err != nil {
			return nil, closeOpenFailure(db, key, err)
		}
		if _, err := db.Exec("INSERT OR IGNORE INTO cll_meta(log_id,state) VALUES(?,?)", logID, empty); err != nil {
			return nil, closeOpenFailure(db, key, classify(err))
		}
	}
	if err := validateOpenState(context.Background(), db, logID); err != nil {
		return nil, closeOpenFailure(db, key, err)
	}
	return store, nil
}

func validateOpenState(ctx context.Context, db *sql.DB, logID string) error {
	return runTransaction(ctx, db, "BEGIN", func(conn *sql.Conn) error {
		if err := validateEntries(ctx, conn, logID); err != nil {
			return err
		}
		_, err := loadState(ctx, conn, logID)
		return err
	})
}

func closeOpenFailure(db *sql.DB, key string, cause error) error {
	closeErr := db.Close()
	releaseShared(key)
	return errors.Join(cause, closeErr)
}

func acquireShared(key string) *sharedLock {
	sharedLocks.Lock()
	defer sharedLocks.Unlock()
	lock := sharedLocks.items[key]
	if lock == nil {
		lock = &sharedLock{}
		sharedLocks.items[key] = lock
	}
	lock.refs++
	return lock
}

func releaseShared(key string) {
	sharedLocks.Lock()
	defer sharedLocks.Unlock()
	lock := sharedLocks.items[key]
	if lock == nil {
		return
	}
	lock.refs--
	if lock.refs == 0 {
		delete(sharedLocks.items, key)
	}
}

type queryer interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func (s *Store) withRead(ctx context.Context, operation func(queryer) error) error {
	return s.withTransaction(ctx, "BEGIN", func(conn *sql.Conn) error {
		return operation(conn)
	})
}

func (s *Store) withWrite(ctx context.Context, operation func(*sql.Conn) error) error {
	return s.withTransaction(ctx, "BEGIN IMMEDIATE", operation)
}

func (s *Store) withTransaction(ctx context.Context, begin string, operation func(*sql.Conn) error) error {
	s.lifecycle.RLock()
	defer s.lifecycle.RUnlock()
	if s.closed {
		return cll.ErrClosed
	}
	s.shared.mu.Lock()
	defer s.shared.mu.Unlock()
	return runTransaction(ctx, s.db, begin, operation)
}

func runTransaction(ctx context.Context, db *sql.DB, begin string, operation func(*sql.Conn) error) (err error) {
	conn, err := db.Conn(ctx)
	if err != nil {
		return classify(err)
	}
	defer func() { err = errors.Join(err, conn.Close()) }()
	if _, err := conn.ExecContext(ctx, begin); err != nil {
		return classify(err)
	}
	committed := false
	defer func() {
		if !committed {
			_, rollbackErr := conn.ExecContext(context.Background(), "ROLLBACK")
			err = errors.Join(err, rollbackErr)
		}
	}()
	if err := operation(conn); err != nil {
		return classify(err)
	}
	if _, err := conn.ExecContext(ctx, "COMMIT"); err != nil {
		return classify(err)
	}
	committed = true
	return nil
}

func validateEntries(ctx context.Context, q queryer, logID string) (resultErr error) {
	rows, err := q.QueryContext(ctx, "SELECT seq,length(value),appended_at FROM cll_entries WHERE log_id=? ORDER BY seq", logID)
	if err != nil {
		return classify(err)
	}
	defer func() { resultErr = errors.Join(resultErr, rows.Close()) }()
	expected := uint64(1)
	for rows.Next() {
		var seq uint64
		var width int
		var timestamp string
		if err := rows.Scan(&seq, &width, &timestamp); err != nil {
			return err
		}
		if seq != expected || seq > cll.MaxPortableInteger || width != cll.EntryBytes {
			return fmt.Errorf("%w: stored entries are not dense and valid", cll.ErrCorrupt)
		}
		if _, err := portable.ParseTime(timestamp); err != nil {
			return fmt.Errorf("%w: stored entry time is invalid", cll.ErrCorrupt)
		}
		expected++
	}
	return rows.Err()
}

func loadState(ctx context.Context, q queryer, logID string) (cll.State, error) {
	var raw []byte
	if err := q.QueryRowContext(ctx, "SELECT state FROM cll_meta WHERE log_id=?", logID).Scan(&raw); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return cll.State{}, fmt.Errorf("%w: missing CLL metadata", cll.ErrCorrupt)
		}
		return cll.State{}, err
	}
	var wire backend.WireState
	if err := json.Unmarshal(raw, &wire); err != nil {
		return cll.State{}, fmt.Errorf("%w: decode CLL metadata: %v", cll.ErrCorrupt, err)
	}
	wire.Nodes = []string{}
	rows, err := q.QueryContext(ctx, "SELECT position,node FROM cll_nodes WHERE log_id=? ORDER BY position", logID)
	if err != nil {
		return cll.State{}, err
	}
	position := uint64(0)
	for rows.Next() {
		var storedPosition uint64
		var node []byte
		if err := rows.Scan(&storedPosition, &node); err != nil {
			return cll.State{}, closeRows(rows, err)
		}
		if storedPosition != position {
			return cll.State{}, closeRows(rows, fmt.Errorf("%w: stored node positions are not dense", cll.ErrCorrupt))
		}
		wire.Nodes = append(wire.Nodes, base64.StdEncoding.EncodeToString(node))
		position++
	}
	if err := rows.Err(); err != nil {
		return cll.State{}, closeRows(rows, err)
	}
	if err := rows.Close(); err != nil {
		return cll.State{}, err
	}
	wire.Witnesses, err = loadWireWitnesses(ctx, q, logID)
	if err != nil {
		return cll.State{}, err
	}
	return backend.StateFromWire(wire)
}

func loadWireWitnesses(ctx context.Context, q queryer, logID string) ([]backend.WireWitness, error) {
	rows, err := q.QueryContext(ctx, "SELECT witness_id,checkpoint_size,attempts,witness FROM cll_witnesses WHERE log_id=? ORDER BY checkpoint_size,witness_id", logID)
	if err != nil {
		return nil, err
	}
	witnesses := []backend.WireWitness{}
	for rows.Next() {
		var id, size string
		var attempts uint32
		var encoded []byte
		if err := rows.Scan(&id, &size, &attempts, &encoded); err != nil {
			return nil, closeRows(rows, err)
		}
		var witness backend.WireWitness
		if err := json.Unmarshal(encoded, &witness); err != nil {
			return nil, closeRows(rows, fmt.Errorf("%w: decode witness row: %v", cll.ErrCorrupt, err))
		}
		if witness.WitnessID != id || witness.CheckpointSize != size || witness.Attempts != attempts {
			return nil, closeRows(rows, fmt.Errorf("%w: witness index disagrees with JSON", cll.ErrCorrupt))
		}
		witnesses = append(witnesses, witness)
	}
	if err := rows.Err(); err != nil {
		return nil, closeRows(rows, err)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	return witnesses, nil
}

func closeRows(rows *sql.Rows, cause error) error {
	return errors.Join(cause, rows.Close())
}

func (s *Store) Append(ctx context.Context, input cll.AppendInput) (result cll.AppendResult, err error) {
	err = s.withWrite(ctx, func(conn *sql.Conn) error {
		if len(input.Value) != cll.EntryBytes || portable.ValidateTime(input.AppendedAt) != nil {
			return fmt.Errorf("%w: invalid append input", cll.ErrInvalid)
		}
		var seq uint64
		var value []byte
		var timestamp string
		err := conn.QueryRowContext(ctx, "SELECT seq,value,appended_at FROM cll_entries WHERE log_id=? AND value=?", s.logID, input.Value).Scan(&seq, &value, &timestamp)
		if err == nil {
			entry, err := entryFromRow(seq, value, timestamp)
			if err != nil {
				return err
			}
			result = cll.AppendResult{Entry: entry, Outcome: cll.AppendIdempotent}
			return nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		var maximum sql.NullInt64
		if err := conn.QueryRowContext(ctx, "SELECT MAX(seq) FROM cll_entries WHERE log_id=?", s.logID).Scan(&maximum); err != nil {
			return err
		}
		seq = 1
		if maximum.Valid {
			seq = uint64(maximum.Int64) + 1
		}
		if seq > cll.MaxPortableInteger {
			return fmt.Errorf("%w: entry sequence exceeds portable range", cll.ErrInvalid)
		}
		timestamp, err = portable.FormatTime(input.AppendedAt)
		if err != nil {
			return fmt.Errorf("%w: invalid append time", cll.ErrInvalid)
		}
		if _, err := conn.ExecContext(ctx, "INSERT INTO cll_entries(log_id,seq,value,appended_at) VALUES(?,?,?,?)", s.logID, seq, input.Value, timestamp); err != nil {
			return err
		}
		result = cll.AppendResult{Entry: cll.Entry{Seq: seq, Value: append([]byte(nil), input.Value...), AppendedAt: portable.NormalizeTime(input.AppendedAt)}, Outcome: cll.AppendInserted}
		return nil
	})
	return result, err
}

func entryFromRow(seq uint64, value []byte, timestamp string) (cll.Entry, error) {
	if seq == 0 || seq > cll.MaxPortableInteger || len(value) != cll.EntryBytes {
		return cll.Entry{}, fmt.Errorf("%w: stored entry is invalid", cll.ErrCorrupt)
	}
	appendedAt, err := portable.ParseTime(timestamp)
	if err != nil {
		return cll.Entry{}, fmt.Errorf("%w: stored entry time is invalid", cll.ErrCorrupt)
	}
	return cll.Entry{Seq: seq, Value: append([]byte(nil), value...), AppendedAt: appendedAt}, nil
}

func (s *Store) GetEntry(ctx context.Context, identity []byte) (result cll.Entry, err error) {
	err = s.withRead(ctx, func(q queryer) error {
		if len(identity) != cll.EntryBytes {
			return fmt.Errorf("%w: entry value has wrong width", cll.ErrInvalid)
		}
		var seq uint64
		var value []byte
		var timestamp string
		err := q.QueryRowContext(ctx, "SELECT seq,value,appended_at FROM cll_entries WHERE log_id=? AND value=?", s.logID, identity).Scan(&seq, &value, &timestamp)
		if errors.Is(err, sql.ErrNoRows) {
			return cll.ErrNotFound
		}
		if err != nil {
			return err
		}
		result, err = entryFromRow(seq, value, timestamp)
		return err
	})
	return result, err
}

func (s *Store) ScanEntries(ctx context.Context, afterSeq uint64, limit int) (result []cll.Entry, err error) {
	err = s.withRead(ctx, func(q queryer) (scanErr error) {
		if afterSeq > cll.MaxPortableInteger || limit < 1 || limit > cll.MaxScanLimit {
			return fmt.Errorf("%w: invalid entry scan", cll.ErrInvalid)
		}
		rows, err := q.QueryContext(ctx, "SELECT seq,value,appended_at FROM cll_entries WHERE log_id=? AND seq>? ORDER BY seq LIMIT ?", s.logID, afterSeq, limit)
		if err != nil {
			return err
		}
		defer func() { scanErr = errors.Join(scanErr, rows.Close()) }()
		for rows.Next() {
			var seq uint64
			var value []byte
			var timestamp string
			if err := rows.Scan(&seq, &value, &timestamp); err != nil {
				return err
			}
			entry, err := entryFromRow(seq, value, timestamp)
			if err != nil {
				return err
			}
			result = append(result, entry)
		}
		return rows.Err()
	})
	return result, err
}

func (s *Store) LoadCLL(ctx context.Context) (result cll.State, err error) {
	err = s.withRead(ctx, func(q queryer) error {
		result, err = loadState(ctx, q, s.logID)
		return err
	})
	return result, err
}

func (s *Store) CommitCLL(ctx context.Context, expectedSize uint64, expectedCheckpoint []byte, next cll.State) error {
	return s.withWrite(ctx, func(conn *sql.Conn) error {
		current, err := loadState(ctx, conn, s.logID)
		if err != nil {
			return err
		}
		updated, err := backend.ApplyCLL(current, expectedSize, expectedCheckpoint, next)
		if err != nil {
			return err
		}
		metadata, err := backend.MarshalMetadata(updated)
		if err != nil {
			return err
		}
		if _, err := conn.ExecContext(ctx, "UPDATE cll_meta SET state=? WHERE log_id=?", metadata, s.logID); err != nil {
			return err
		}
		for position := len(current.Nodes); position < len(updated.Nodes); position++ {
			if _, err := conn.ExecContext(ctx, "INSERT INTO cll_nodes(log_id,position,node) VALUES(?,?,?)", s.logID, position, updated.Nodes[position]); err != nil {
				return err
			}
		}
		existing := make(map[string]struct{}, len(current.Witnesses))
		for _, witness := range current.Witnesses {
			existing[backend.WitnessKey(witness.WitnessID, witness.CheckpointSize)] = struct{}{}
		}
		for _, witness := range updated.Witnesses {
			if _, found := existing[backend.WitnessKey(witness.WitnessID, witness.CheckpointSize)]; found {
				continue
			}
			encoded, err := backend.MarshalWitness(witness)
			if err != nil {
				return err
			}
			if _, err := conn.ExecContext(ctx, "INSERT INTO cll_witnesses(log_id,witness_id,checkpoint_size,attempts,witness) VALUES(?,?,?,?,?)", s.logID, witness.WitnessID, fmt.Sprintf("%d", witness.CheckpointSize), witness.Attempts, encoded); err != nil {
				return err
			}
		}
		return nil
	})
}

func (s *Store) PendingWitnesses(ctx context.Context, now time.Time, limit int) (result []cll.WitnessState, err error) {
	err = s.withRead(ctx, func(q queryer) error {
		witnesses, err := loadWireWitnesses(ctx, q, s.logID)
		if err != nil {
			return err
		}
		state, err := backend.StateFromWire(backend.WireState{Size: "0", IndexedSeq: "0", Nodes: []string{}, Witnesses: witnesses})
		if err != nil {
			return err
		}
		engine := backend.New()
		if err := engine.Replace(nil, state); err != nil {
			return err
		}
		result, err = engine.PendingWitnesses(now, limit)
		return err
	})
	return result, err
}

func (s *Store) GetWitness(ctx context.Context, witnessID string, checkpointSize uint64) (result cll.WitnessState, err error) {
	err = s.withRead(ctx, func(q queryer) error {
		if cll.ValidateIdentifier(witnessID) != nil || checkpointSize == 0 {
			return fmt.Errorf("%w: invalid witness key", cll.ErrInvalid)
		}
		var attempts uint32
		var encoded []byte
		err := q.QueryRowContext(ctx, "SELECT attempts,witness FROM cll_witnesses WHERE log_id=? AND witness_id=? AND checkpoint_size=?", s.logID, witnessID, fmt.Sprintf("%d", checkpointSize)).Scan(&attempts, &encoded)
		if errors.Is(err, sql.ErrNoRows) {
			return cll.ErrNotFound
		}
		if err != nil {
			return err
		}
		result, err = backend.UnmarshalWitness(encoded)
		if err == nil && (result.Attempts != attempts || result.WitnessID != witnessID || result.CheckpointSize != checkpointSize) {
			return fmt.Errorf("%w: witness index disagrees with JSON", cll.ErrCorrupt)
		}
		return err
	})
	return result, err
}

func (s *Store) CommitWitness(ctx context.Context, expectedAttempts uint32, next cll.WitnessState) error {
	return s.withWrite(ctx, func(conn *sql.Conn) error {
		var encodedCurrent []byte
		err := conn.QueryRowContext(ctx, "SELECT witness FROM cll_witnesses WHERE log_id=? AND witness_id=? AND checkpoint_size=?", s.logID, next.WitnessID, fmt.Sprintf("%d", next.CheckpointSize)).Scan(&encodedCurrent)
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("%w: witness state changed", cll.ErrContention)
		}
		if err != nil {
			return err
		}
		current, err := backend.UnmarshalWitness(encodedCurrent)
		if err != nil {
			return err
		}
		updated, err := backend.ApplyWitness(cll.State{Witnesses: []cll.WitnessState{current}}, expectedAttempts, next)
		if err != nil {
			return err
		}
		encoded, err := backend.MarshalWitness(updated.Witnesses[0])
		if err != nil {
			return err
		}
		result, err := conn.ExecContext(ctx, "UPDATE cll_witnesses SET attempts=?,witness=? WHERE log_id=? AND witness_id=? AND checkpoint_size=? AND attempts=?", next.Attempts, encoded, s.logID, next.WitnessID, fmt.Sprintf("%d", next.CheckpointSize), expectedAttempts)
		if err != nil {
			return err
		}
		changed, err := result.RowsAffected()
		if err != nil {
			return err
		}
		if changed != 1 {
			return fmt.Errorf("%w: witness CAS failed", cll.ErrContention)
		}
		return nil
	})
}

// Close is idempotent and waits for in-process operations on this handle.
func (s *Store) Close() error {
	s.lifecycle.Lock()
	defer s.lifecycle.Unlock()
	if s.closed {
		return nil
	}
	s.shared.mu.Lock()
	err := s.db.Close()
	s.shared.mu.Unlock()
	s.closed = true
	releaseShared(s.lockKey)
	return err
}

func classify(err error) error {
	if err == nil {
		return nil
	}
	var sqliteErr *modernsqlite.Error
	if errors.As(err, &sqliteErr) {
		code := sqliteErr.Code() & 0xff
		if code == 5 || code == 6 {
			return fmt.Errorf("%w: %v", cll.ErrContention, err)
		}
	}
	return err
}

var _ cll.Backend = (*Store)(nil)
