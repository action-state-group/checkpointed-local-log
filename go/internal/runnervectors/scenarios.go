package runnervectors

import (
	"bytes"
	"encoding/base64"
	"strings"
	"time"
)

var t0 = time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)

func at(offset time.Duration) string {
	return t0.Add(offset).Format("2006-01-02T15:04:05.000Z")
}

func appendStep(value byte, offset time.Duration) Step {
	return Step{Op: "append", Value: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{value}, 32)), AppendedAt: at(offset)}
}

func appendSteps(first, last byte, offset time.Duration) []Step {
	var steps []Step
	for value := first; value <= last; value++ {
		steps = append(steps, appendStep(value, offset+time.Duration(value-first)*time.Second))
	}
	return steps
}

func checkpointStep(offset time.Duration) Step { return Step{Op: "runCheckpoint", Now: at(offset)} }

func load() Step { return Step{Op: "loadCll"} }

func deliver(offset time.Duration, submit map[string][]Outcome, verify map[string][]bool) Step {
	return Step{Op: "deliverWitnesses", Now: at(offset), Limit: 32, Submit: submit, Verify: verify}
}

func receipt(label string, leaf int64) Outcome {
	return Outcome{Receipt: &Receipt{
		Bytes:           base64.StdEncoding.EncodeToString([]byte("receipt " + label)),
		EntryHash:       strings.Repeat("ab", 32),
		EntryHashScheme: "legacy",
		LeafIndex:       leaf,
		TreeSize:        leaf + 1,
	}}
}

var (
	retryable = Outcome{Error: "retryable"}
	permanent = Outcome{Error: "permanent"}
)

func steps(groups ...[]Step) []Step {
	var out []Step
	for _, group := range groups {
		out = append(out, group...)
	}
	return out
}

func one(items ...Step) []Step { return items }

func scenarios() []Case {
	second := time.Second
	return []Case{
		{
			Name:        "checkpoint/empty-log",
			Description: "A pass over an empty log commits nothing.",
			Config:      Config{CadenceEntries: 1, CadenceAgeMs: 60_000, ScanLimit: 10, WitnessIDs: []string{"w-a"}, BaseBackoffMs: 1000, MaxBackoffMs: 8000},
			Steps:       one(checkpointStep(0), load()),
		},
		{
			Name: "checkpoint/entry-cadence",
			Description: "Entries are indexed as they arrive; a checkpoint is signed once cadenceEntries are uncheckpointed, " +
				"queues one row per witness, and the next checkpoint carries a consistency proof from the previous one.",
			Config: Config{CadenceEntries: 3, CadenceAgeMs: 3_600_000, ScanLimit: 10, WitnessIDs: []string{"w-a", "w-b"}, BaseBackoffMs: 1000, MaxBackoffMs: 8000},
			Steps: steps(
				appendSteps(1, 2, 0),
				one(checkpointStep(2*second), load(), appendStep(3, 3*second), checkpointStep(4*second), load(),
					checkpointStep(5*second), load()),
				appendSteps(4, 6, 6*second),
				one(checkpointStep(9500*time.Millisecond), load()),
			),
		},
		{
			Name: "checkpoint/age-cadence",
			Description: "A checkpoint is signed once the oldest uncheckpointed entry has waited cadenceAgeMs, " +
				"also by a pass that scans no new entry.",
			Config: Config{CadenceEntries: 100, CadenceAgeMs: 60_000, ScanLimit: 10, BaseBackoffMs: 1000, MaxBackoffMs: 8000},
			Steps: steps(
				one(appendStep(1, 0), checkpointStep(30*second), load(), checkpointStep(60*second), load(),
					appendStep(2, 61*second), checkpointStep(62*second), load(), checkpointStep(121*second), load()),
			),
		},
		{
			Name:        "checkpoint/bounded-batches",
			Description: "Each pass scans at most scanLimit entries and checkpoints that batch when it is due.",
			Requires:    []string{"bounded-run"},
			Config:      Config{CadenceEntries: 2, CadenceAgeMs: 3_600_000, ScanLimit: 2, BaseBackoffMs: 1000, MaxBackoffMs: 8000},
			Steps: steps(
				appendSteps(1, 5, 0),
				one(checkpointStep(10*second), load(), checkpointStep(11*second), load(), checkpointStep(12*second), load()),
			),
		},
		{
			Name: "witness/delivery",
			Description: "Witnesses are delivered independently: a verified receipt completes a row, a retryable failure " +
				"backs off from baseBackoffMs, and a permanent failure stops the row.",
			Config: Config{CadenceEntries: 2, CadenceAgeMs: 3_600_000, ScanLimit: 10, WitnessIDs: []string{"w-b", "w-a"}, BaseBackoffMs: 1000, MaxBackoffMs: 4000},
			Steps: steps(
				appendSteps(1, 2, 0),
				one(
					checkpointStep(10*second),
					deliver(10*second, map[string][]Outcome{"w-a": {receipt("w-a", 0)}, "w-b": {retryable}}, map[string][]bool{"w-a": {true}}),
					load(),
					deliver(10500*time.Millisecond, nil, nil),
					deliver(11*second, map[string][]Outcome{"w-b": {permanent}}, nil),
					load(),
					deliver(60*second, nil, nil),
				),
			),
		},
		{
			Name:        "witness/rejected-receipt",
			Description: "A receipt that fails verification makes the row permanent.",
			Config:      Config{CadenceEntries: 2, CadenceAgeMs: 3_600_000, ScanLimit: 10, WitnessIDs: []string{"w-a"}, BaseBackoffMs: 1000, MaxBackoffMs: 4000},
			Steps: steps(
				appendSteps(1, 2, 0),
				one(checkpointStep(10*second), deliver(10*second, map[string][]Outcome{"w-a": {receipt("w-a", 3)}}, map[string][]bool{"w-a": {false}}), load()),
			),
		},
		{
			Name:        "witness/backoff",
			Description: "The retry delay doubles per earlier attempt and stops at maxBackoffMs.",
			Config:      Config{CadenceEntries: 1, CadenceAgeMs: 3_600_000, ScanLimit: 10, WitnessIDs: []string{"w-a"}, BaseBackoffMs: 1000, MaxBackoffMs: 2500},
			Steps: steps(
				one(appendStep(1, 0), checkpointStep(10*second)),
				one(deliver(10*second, map[string][]Outcome{"w-a": {retryable}}, nil), load()),
				one(deliver(11*second, map[string][]Outcome{"w-a": {retryable}}, nil), load()),
				one(deliver(13*second, map[string][]Outcome{"w-a": {retryable}}, nil), load()),
				one(deliver(15500*time.Millisecond, map[string][]Outcome{"w-a": {retryable}}, nil), load()),
			),
		},
		{
			Name: "witness/stop-after-retryable",
			Description: "Rows of one witness are delivered in checkpoint order, and a retryable failure ends that " +
				"witness's pass.",
			Requires: []string{"stop-after-retryable"},
			Config:   Config{CadenceEntries: 1, CadenceAgeMs: 3_600_000, ScanLimit: 10, WitnessIDs: []string{"w-a"}, BaseBackoffMs: 1000, MaxBackoffMs: 4000},
			Steps: steps(
				one(appendStep(1, 0), checkpointStep(10*second), appendStep(2, 11*second), checkpointStep(12*second)),
				one(deliver(12*second, map[string][]Outcome{"w-a": {retryable}}, nil), load()),
				one(deliver(20*second, map[string][]Outcome{"w-a": {receipt("w-a 1", 0), receipt("w-a 2", 1)}}, map[string][]bool{"w-a": {true, true}}), load()),
			),
		},
	}
}
