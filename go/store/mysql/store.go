package mysql

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/action-state-group/cll-go/cll"
	"github.com/action-state-group/cll-go/internal/backend"
	"github.com/action-state-group/cll-go/internal/portable"
	mysqldriver "github.com/go-sql-driver/mysql"
)

var schemaStatements = []string{
	`CREATE TABLE IF NOT EXISTS cll_meta (
  log_id VARCHAR(191) PRIMARY KEY,
  state LONGBLOB NOT NULL
) ENGINE=InnoDB`,
	`CREATE TABLE IF NOT EXISTS cll_entries (
  log_id VARCHAR(191) NOT NULL,
  seq BIGINT UNSIGNED NOT NULL,
  value BINARY(32) NOT NULL,
  appended_at VARCHAR(32) NOT NULL,
  PRIMARY KEY(log_id, seq),
  UNIQUE KEY uq_cll_entry(log_id, value)
) ENGINE=InnoDB`,
	`CREATE TABLE IF NOT EXISTS cll_nodes (
  log_id VARCHAR(191) NOT NULL,
  position BIGINT UNSIGNED NOT NULL,
  node BINARY(32) NOT NULL,
  PRIMARY KEY(log_id, position)
) ENGINE=InnoDB`,
	`CREATE TABLE IF NOT EXISTS cll_witnesses (
  log_id VARCHAR(191) NOT NULL,
  witness_id VARCHAR(191) NOT NULL,
  checkpoint_size VARCHAR(32) NOT NULL,
  attempts INT UNSIGNED NOT NULL,
  witness LONGBLOB NOT NULL,
  PRIMARY KEY(log_id, witness_id, checkpoint_size)
) ENGINE=InnoDB`,
}

// Store is a MySQL 8 implementation of cll.Backend.
type Store struct {
	lifecycle sync.RWMutex
	db        *sql.DB
	logID     string
	closed    bool
}

// Init explicitly provisions the shared MySQL schema and an empty logical log.
// Existing records are preserved. MySQL DDL is not transactional, so retrying
// Init after a partial failure is supported. Runtime readers should use Open.
func Init(ctx context.Context, dsn, logID string) (err error) {
	db, err := openDatabase(ctx, dsn, logID)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, db.Close()) }()
	for _, statement := range schemaStatements {
		if _, err := db.ExecContext(ctx, statement); err != nil {
			return classify(err)
		}
	}
	empty, err := backend.MarshalMetadata(cll.State{})
	if err != nil {
		return err
	}
	if _, err := db.ExecContext(ctx, "INSERT IGNORE INTO cll_meta(log_id,state) VALUES(?,?)", logID, empty); err != nil {
		return classify(err)
	}
	if err := validateEntries(ctx, db, logID); err != nil {
		return err
	}
	store := &Store{db: db, logID: logID}
	return store.readState(ctx, func(cll.State) error { return nil })
}

// Open opens and validates an existing logical log without DDL or data writes.
// An absent schema or log is an error; provision it with Init first. SELECT-only
// credentials suffice for reads. Mutating methods need separate SQL grants.
func Open(ctx context.Context, dsn, logID string) (*Store, error) {
	db, err := openDatabase(ctx, dsn, logID)
	if err != nil {
		return nil, err
	}
	store := &Store{db: db, logID: logID}
	if err := validateEntries(ctx, db, logID); err != nil {
		return nil, errors.Join(err, db.Close())
	}
	if err := store.readState(ctx, func(cll.State) error { return nil }); err != nil {
		return nil, errors.Join(err, db.Close())
	}
	return store, nil
}

// openDatabase owns connection validation but never initializes stored state.
func openDatabase(ctx context.Context, dsn, logID string) (*sql.DB, error) {
	if dsn == "" || cll.ValidateIdentifier(logID) != nil {
		return nil, fmt.Errorf("%w: DSN and log ID are required", cll.ErrInvalid)
	}
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, err
	}
	if err := db.PingContext(ctx); err != nil {
		return nil, errors.Join(err, db.Close())
	}
	return db, nil
}

type queryer interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func validateEntries(ctx context.Context, q queryer, logID string) (resultErr error) {
	rows, err := q.QueryContext(ctx, "SELECT seq,OCTET_LENGTH(value),appended_at FROM cll_entries WHERE log_id=? ORDER BY seq", logID)
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

func loadState(ctx context.Context, q queryer, logID string, forUpdate bool) (cll.State, error) {
	query := "SELECT state FROM cll_meta WHERE log_id=?"
	if forUpdate {
		query += " FOR UPDATE"
	}
	var raw []byte
	if err := q.QueryRowContext(ctx, query, logID).Scan(&raw); err != nil {
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
		var stored uint64
		var node []byte
		if err := rows.Scan(&stored, &node); err != nil {
			return cll.State{}, closeRows(rows, err)
		}
		if stored != position {
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

func (s *Store) write(ctx context.Context, operation func(*sql.Tx) error) (err error) {
	s.lifecycle.RLock()
	defer s.lifecycle.RUnlock()
	if s.closed {
		return cll.ErrClosed
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return classify(err)
	}
	committed := false
	defer func() {
		if !committed {
			err = errors.Join(err, tx.Rollback())
		}
	}()
	if err := operation(tx); err != nil {
		return classify(err)
	}
	if err := tx.Commit(); err != nil {
		return classify(err)
	}
	committed = true
	return nil
}

func (s *Store) readState(ctx context.Context, operation func(cll.State) error) (err error) {
	s.lifecycle.RLock()
	defer s.lifecycle.RUnlock()
	if s.closed {
		return cll.ErrClosed
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return classify(err)
	}
	committed := false
	defer func() {
		if !committed {
			err = errors.Join(err, tx.Rollback())
		}
	}()
	state, err := loadState(ctx, tx, s.logID, false)
	if err != nil {
		return classify(err)
	}
	if err := operation(state); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return classify(err)
	}
	committed = true
	return nil
}

func (s *Store) read(ctx context.Context, operation func(queryer) error) error {
	s.lifecycle.RLock()
	defer s.lifecycle.RUnlock()
	if s.closed {
		return cll.ErrClosed
	}
	return classify(operation(s.db))
}

func lockMetadata(ctx context.Context, tx *sql.Tx, logID string) error {
	var ignored []byte
	return tx.QueryRowContext(ctx, "SELECT state FROM cll_meta WHERE log_id=? FOR UPDATE", logID).Scan(&ignored)
}

func (s *Store) Append(ctx context.Context, input cll.AppendInput) (result cll.AppendResult, err error) {
	err = s.write(ctx, func(tx *sql.Tx) error {
		if len(input.Value) != cll.EntryBytes || portable.ValidateTime(input.AppendedAt) != nil {
			return fmt.Errorf("%w: invalid append input", cll.ErrInvalid)
		}
		if err := lockMetadata(ctx, tx, s.logID); err != nil {
			return err
		}
		var seq uint64
		var value []byte
		var timestamp string
		err := tx.QueryRowContext(ctx, "SELECT seq,value,appended_at FROM cll_entries WHERE log_id=? AND value=?", s.logID, input.Value).Scan(&seq, &value, &timestamp)
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
		if err := tx.QueryRowContext(ctx, "SELECT MAX(seq) FROM cll_entries WHERE log_id=?", s.logID).Scan(&maximum); err != nil {
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
		if _, err := tx.ExecContext(ctx, "INSERT INTO cll_entries(log_id,seq,value,appended_at) VALUES(?,?,?,?)", s.logID, seq, input.Value, timestamp); err != nil {
			return err
		}
		result = cll.AppendResult{Entry: cll.Entry{Seq: seq, Value: append([]byte(nil), input.Value...), AppendedAt: portable.NormalizeTime(input.AppendedAt)}, Outcome: cll.AppendInserted}
		return nil
	})
	return result, err
}

func (s *Store) GetEntry(ctx context.Context, identity []byte) (result cll.Entry, err error) {
	err = s.read(ctx, func(q queryer) error {
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
	err = s.read(ctx, func(q queryer) (scanErr error) {
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
	err = s.readState(ctx, func(state cll.State) error { result = state; return nil })
	return result, err
}

func (s *Store) CommitCLL(ctx context.Context, expectedSize uint64, expectedCheckpoint []byte, next cll.State) error {
	return s.write(ctx, func(tx *sql.Tx) error {
		current, err := loadState(ctx, tx, s.logID, true)
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
		if _, err := tx.ExecContext(ctx, "UPDATE cll_meta SET state=? WHERE log_id=?", metadata, s.logID); err != nil {
			return err
		}
		for position := len(current.Nodes); position < len(updated.Nodes); position++ {
			if _, err := tx.ExecContext(ctx, "INSERT INTO cll_nodes(log_id,position,node) VALUES(?,?,?)", s.logID, position, updated.Nodes[position]); err != nil {
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
			if _, err := tx.ExecContext(ctx, "INSERT INTO cll_witnesses(log_id,witness_id,checkpoint_size,attempts,witness) VALUES(?,?,?,?,?)", s.logID, witness.WitnessID, fmt.Sprintf("%d", witness.CheckpointSize), witness.Attempts, encoded); err != nil {
				return err
			}
		}
		return nil
	})
}

func (s *Store) PendingWitnesses(ctx context.Context, now time.Time, limit int) (result []cll.WitnessState, err error) {
	err = s.read(ctx, func(q queryer) error {
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
	err = s.read(ctx, func(q queryer) error {
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
	return s.write(ctx, func(tx *sql.Tx) error {
		var encodedCurrent []byte
		err := tx.QueryRowContext(ctx, "SELECT witness FROM cll_witnesses WHERE log_id=? AND witness_id=? AND checkpoint_size=?", s.logID, next.WitnessID, fmt.Sprintf("%d", next.CheckpointSize)).Scan(&encodedCurrent)
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
		result, err := tx.ExecContext(ctx, "UPDATE cll_witnesses SET attempts=?,witness=? WHERE log_id=? AND witness_id=? AND checkpoint_size=? AND attempts=?", next.Attempts, encoded, s.logID, next.WitnessID, fmt.Sprintf("%d", next.CheckpointSize), expectedAttempts)
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

// Close is idempotent and waits for operations on this handle.
func (s *Store) Close() error {
	s.lifecycle.Lock()
	defer s.lifecycle.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	return s.db.Close()
}

func classify(err error) error {
	if err == nil {
		return nil
	}
	var mysqlErr *mysqldriver.MySQLError
	if errors.As(err, &mysqlErr) && (mysqlErr.Number == 1062 || mysqlErr.Number == 1205 || mysqlErr.Number == 1213) {
		return fmt.Errorf("%w: %v", cll.ErrContention, err)
	}
	return err
}

var _ cll.Backend = (*Store)(nil)
