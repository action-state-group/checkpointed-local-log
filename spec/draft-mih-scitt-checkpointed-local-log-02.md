---
title: "The Checkpointed Local Log (CLL)"
abbrev: "CLL"
docname: draft-mih-scitt-checkpointed-local-log-02
date: 2026-10-13
category: std
ipr: trust200902
area: Security
workgroup: SCITT
keyword:
  - transparency
  - merkle mountain range
  - receipts
  - audit log
stand_alone: yes
pi: [toc, sortrefs, symrefs]

author:
 - ins: S. Mih
   name: Steven Mih
   organization: Action State Group
   email: steven@actionstate.ai

normative:
  RFC2119:
  RFC3339:
  RFC8174:
  RFC8392:
  RFC8949:
  RFC9052:
  RFC9597:
  RFC9942:
  I-D.bryce-cose-receipts-mmr-profile:
  RFC9943:

informative:
  RFC9162:
  RFC9864:
  I-D.mih-sokolov-scitt-payload-binding:
  MMR-PROFILE-MAIN:
    title: "COSE Receipts for MMRs, editors' copy"
    target: https://github.com/robinbryce/draft-bryce-cose-receipts-mmr-profile/blob/f1320c0/draft-bryce-cose-receipts-mmr-profile.md
    author:
      - name: Robin Bryce
      - name: Jon Geater
    date: 2026-10
  CLL-VECTORS:
    title: "draft-mih-scitt-checkpointed-local-log-02 test vectors"
    target: https://github.com/action-state-group/checkpointed-local-log/tree/main/cll-02-vectors
    date: 2026-10

--- abstract

Many systems emit individually signed records — receipts, attestations,
statements — and store them locally. Each record verifies on its own, but the
collection proves nothing: records can be deleted, reordered, or created after
the fact without detection. This document specifies the Checkpointed Local Log
(CLL): a producer-operated append-only log that is a Merkle Mountain Range as
defined by the COSE Receipts profile for Merkle Mountain Ranges, together with
a small signed checkpoint that commits to the log's entire history. A
checkpoint carries the content of that profile's Receipt of consistency — the
accumulator and the consistency proof — inside a SCITT Signed Statement, so it
can be registered with one or more independent Transparency Services without
any change to them. A CLL upgrades a set of point receipts into a stream with
provable order, contemporaneity, and completeness, and states precisely what
it does not establish. It defines no new proof format, no change to SCITT
Registration or Receipts, and no payload semantics.

--- middle

# Introduction

A signed record proves that its issuer produced those bytes. It does not prove
when the record was produced relative to its neighbors, that no record between
two others was deleted, or that the set presented to a verifier is the set
that existed. In current practice, producers of agent receipts, decision
records, build attestations, SBOM and other supply-chain artifact revisions,
and similar records sign each record and store the results in ordinary
storage — a "log" whose integrity rests entirely on the operator's word. A
relying party examining such a collection cannot distinguish an honest
archive from a curated one. The problem is payload-neutral: a stream of SBOM
revisions and a stream of agent action receipts fail in exactly the same way,
and this document treats them identically.

Transparency logs in the style of {{RFC9162}} address this by publishing
entries to a small number of large, centrally operated logs, where anyone can
audit the whole. That model asks two things the local case cannot give: that
the entries themselves be published to a log the producer does not control,
which is unacceptable when the content is private; and that each record be
registered with a central service as it is produced, which a producer emitting
thousands of records a day will not sustain in cost or latency. The need is a
construction that keeps entries local and private and still lets a relying
party check order and completeness.

The Checkpointed Local Log occupies the middle position: the log is local and
private; only a small **checkpoint** — a signed commitment to the log's entire
history — ever leaves the producer. The local log makes the record set
tamper-evident to anyone who trusts the producer; the checkpoint collapses
that history, however many entries, into one commitment cheap enough to
publish on every emission; and a Transparency Service whose published
Registration Policy admits a checkpoint only when it is consistent with the
one before is what removes "trust the producer" from existence and ordering
claims.

{{I-D.bryce-cose-receipts-mmr-profile}} (the "MMR profile") defines the
Merkle Mountain Range (MMR) structure, its accumulator, and the COSE Receipts
{{RFC9942}} that prove inclusion and consistency over it. An MMR suits a local
log: appends are streaming and never restructure earlier entries, and proofs
are logarithmic. This document is a companion to the MMR profile. It takes the
structure, the accumulator encoding, and the consistency proof unchanged, and
adds what a producer-operated log needs on top: how entries become leaves, a
checkpoint that carries the profile's accumulator and consistency proof as a
SCITT Signed Statement {{RFC9943}}, the discipline that makes a sequence of
checkpoints meaningful, and the claims a relying party can and cannot draw
from them. {{relationship}} states the relationship in full, including the
path from a checkpointed local log to full Registration at a Transparency
Service.

## Conventions and Definitions

{::boilerplate bcp14-tagged}

The terms tree size, accumulator, node value, consistency proof, Receipt of
consistency, `add_leaf_hash`, `leaf_count`, `peaks` and `consistent_roots` are
used as defined in {{I-D.bryce-cose-receipts-mmr-profile}}.

**Entry:** a 32-byte value appended to the log, typically the SHA-256 digest
of a signed record produced by the operator or received from another party.
Entries are otherwise opaque to this specification. The binding between an
entry and the record it commits to MAY be expressed using a declared digest
context (e.g., {{I-D.mih-sokolov-scitt-payload-binding}}), including contexts
that commit to already-signed bytes exactly as transmitted.

**Log:** an append-only sequence of entries held as an MMR per
{{log-structure}}.

**Log size:** the tree size of the log's MMR: its number of nodes, not its
number of entries. A log of 21 entries has log size 39.

**Checkpoint:** a Signed Statement committing to the log's state at a given
log size, structured per {{checkpoint}}.

**Consistency Registration Policy:** a Registration Policy
({{Section 5.1.1 of RFC9943}}), published by a Transparency Service operated
by a party other than the log operator, that admits a checkpoint only if it is
consistent ({{registration}}) with the last checkpoint that service registered
for the same log identity.

**Producer / operator:** the party that appends entries and signs checkpoints.
This specification assumes they are the same party ({{claims}}).

**Log identity:** the pair (`iss`, `sub`) carried in the checkpoint's
CWT_Claims ({{registration}}). All continuity requirements in this document
are per log identity.

## Relation to SCITT Terms {#scitt-terms}

This document uses the terms of {{RFC9943}}. The party that signs a record is
an Issuer, and a signed record is a Signed Statement (COSE_Sign1). A
checkpoint is a Signed Statement whose Issuer is the producer and whose
Artifact is the log. A service that registers Signed Statements and returns
Receipts {{RFC9942}} is a Transparency Service; a Receipt proves inclusion in
that service's log, not agreement with the statement. The check a
Transparency Service makes before registering is its published Registration
Policy. Independence comes from registering the same Signed Statement with
more than one Transparency Service. A party that independently recomputes
checks over records it is given works in the manner of an Auditor. SCITT
defines no "witness" role and this document defines none; earlier revisions
of this document used that word for what is now a Transparency Service
applying a Consistency Registration Policy. One party signing another
operator's log head is a separate layer outside SCITT and outside this
document.

# The Log Discipline {#discipline}

1. **Append at production time.** An entry SHOULD be appended when the record
   it commits to is produced or received, not batched for later assembly. The
   evidentiary difference is the point of this document: an entry appended at
   time t is committed by every subsequent checkpoint, so contemporaneity
   becomes checkable; end-of-period assembly permits curation that no later
   verification can detect.
2. **Append-only.** Entries MUST NOT be modified or removed. Erasure of the
   *content* an entry commits to is a separate act on separate storage and
   does not touch the log; the entry (a digest) remains.
3. **One log, one signing identity.** A log's checkpoints are signed under one
   key at a time. Key rotation is announced by an entry declaring the
   rotation — produced under the outgoing key and naming the incoming key
   identifier — appended before the first checkpoint signed under the new
   key. The log identity ({{registration}}) is unchanged by rotation.

**Segmentation and archival (non-normative).** A conforming implementation MAY
store the log as a sequence of segments rather than one unbounded file. This
specification imposes no segment format; the only checkpoint-relevant
discipline is that any segment boundary a producer defines SHOULD coincide
with a checkpoint boundary, never a calendar boundary: closing a segment at
the log's state at a checkpoint's declared size means the segment plus that
checkpoint is independently verifiable without the rest of the log, using
inclusion proofs against the checkpoint's accumulator. A store's own manifest
of which segments exist, and whether each is presently retrievable
("mounted") or has been archived elsewhere, is local bookkeeping, not itself
evidence a verifier trusts — only a checkpoint (and what it commits to)
carries that property. A verifier presented with a reference to an entry
whose segment is not presently retrievable receives a distinct, honest
refusal (e.g., "retention expired") rather than being told the entry never
existed, since the checkpoint chain already proves it did.

# The Log Structure {#log-structure}

A CLL is an MMR as specified by {{I-D.bryce-cose-receipts-mmr-profile}}, with
verifiable data structure algorithm MMR_SHA256: SHA-256 node values,
interior nodes formed by `hash_pospair64`, and nodes added by
`add_leaf_hash`. This document changes none of that. It fixes only what the
profile leaves to the application, the leaf value:

    leaf value = SHA-256(0x00 || entry)

where `entry` is exactly 32 bytes. The leaf value is the input `f` to
`add_leaf_hash`. The leaf pre-image is therefore 33 bytes beginning with
0x00, which no interior pre-image (72 bytes, beginning with a position) can
equal. This is the leaf commitment the MMR profile's Security Considerations
recommend for applications that need leaves distinguishable from interior
nodes.

The log size is always a complete MMR size: `add_leaf_hash` returns one after
every append, and a checkpoint is only ever taken between appends. The
number of entries at log size `s` is `leaf_count(s - 1)` (0 when `s` is 0).

# The Checkpoint {#checkpoint}

A checkpoint is a COSE_Sign1 {{RFC9052}} with an attached payload. The
payload is a CBOR map {{RFC8949}} with text-string keys, encoded
deterministically ({{Section 4.2.1 of RFC8949}}), with the following claims:

| Claim | Type | Description |
|---|---|---|
| `kind` | tstr | MUST be `"cll-checkpoint"` |
| `log_size` | uint | the log size: the MMR tree size (node count) the checkpoint commits to |
| `leaf_count` | uint | OPTIONAL: the number of entries, `leaf_count(log_size - 1)` |
| `commitment` | bstr | the accumulator at `log_size`, encoded per {{commitment}} |
| `prev_size` | uint | `log_size` of this log's previous checkpoint; 0 for the first |
| `prev_commitment` | bstr | the previous checkpoint's `commitment`; zero-length for the first |
| `consistency_proof` | bstr | the MMR profile consistency proof from `prev_size` to `log_size` ({{consistency}}); present if and only if 0 < `prev_size` < `log_size` |
| `issued_at` | tstr | issuance time per {{RFC3339}} |
| `cadence` | uint | OPTIONAL: declared maximum seconds between checkpoints ({{constraints}}) |
{: #claims-table title="Checkpoint claims"}

The protected header carries the signature algorithm, the key identifier of
the log's signing identity, and the CWT_Claims of {{registration}}.
Additional claims MAY be present; verifiers MUST ignore claims they do not
understand.

`log_size` and `prev_size` are tree sizes in the sense of the MMR profile.
They count nodes, not entries. A producer that wants to state the entry count
carries it in `leaf_count`, never in `log_size`.

## Commitment Encoding {#commitment}

`commitment` and `prev_commitment` carry the MMR profile accumulator for
their size: the node values of the peaks, concatenated in descending height
order (tallest first), with no length prefix, separator, or further
combination. For MMR_SHA256 each node value is 32 bytes, so the encoding is
32 times the number of peaks long, and the empty log (size 0) has a
zero-length commitment.

These are exactly the bytes {{MMR-PROFILE-MAIN}} specifies as the detached
payload of a Receipt of consistency for that size. A verifier recovers the
accumulator by splitting the value into 32-byte node values; the number of
node values is fixed by the size and MUST match it.

An implementation MAY additionally fold the accumulator into a single "bagged
root" for its own fast comparisons between local log states. No such fold is
specified by this document or by the MMR profile, and a bagged root MUST NOT
be carried in `commitment` or `prev_commitment`.

## Consistency Proof {#consistency}

When 0 < `prev_size` < `log_size`, the checkpoint MUST carry
`consistency_proof`, whose value is the MMR profile's `consistency-proof`:

    consistency-proof = bstr .cbor consistency-proof-content
    consistency-proof-content = [
      tree-size-1: uint,            ; = prev_size
      tree-size-2: uint,            ; = log_size
      consistency-paths: [ * consistency-path ],
      right-peaks: [ * hash ]
    ]

as defined in {{I-D.bryce-cose-receipts-mmr-profile}}. It is the same proof
a Receipt of consistency carries in its unprotected header, here carried
inside the signed payload. When `prev_size` is 0, or when `prev_size` equals
`log_size` (the log did not grow between checkpoints), `consistency_proof`
MUST be absent.

Carrying the proof in the checkpoint makes every checkpoint independently
checkable from its predecessor with no further exchange with the producer,
and gives a Transparency Service everything its Consistency Registration
Policy needs in the Signed Statement it registers.

## Checking a Checkpoint {#checkpoint-checks}

A verifier holding a checkpoint and the public key of the log's signing
identity MUST reject the checkpoint unless all of the following hold:

1. The COSE_Sign1 signature verifies, and the protected header carries
   CWT_Claims with text-string `iss` and `sub` ({{registration}}).
2. `kind` is `"cll-checkpoint"`, and `log_size`, `prev_size`, `commitment`,
   `prev_commitment` and `issued_at` are present with the types of
   {{claims-table}}.
3. `log_size` and `prev_size` are complete MMR sizes, and `prev_size` is not
   greater than `log_size`.
4. The length of `commitment` is 32 times the number of peaks of `log_size`,
   and the length of `prev_commitment` is 32 times the number of peaks of
   `prev_size`.
5. If `leaf_count` is present, it equals `leaf_count(log_size - 1)` (0 when
   `log_size` is 0).
6. If `prev_size` is 0, `consistency_proof` is absent.
7. If `prev_size` equals `log_size`, `consistency_proof` is absent and
   `commitment` equals `prev_commitment`.
8. Otherwise `consistency_proof` is present and is a `consistency-proof`;
   its tree-size-1 equals `prev_size` and its tree-size-2 equals
   `log_size`; and applying the verification steps of the MMR profile for a
   Receipt of consistency — `consistent_roots` from `prev_size` and the
   accumulator in `prev_commitment`, followed by the right-peaks — yields an
   accumulator whose encoding ({{commitment}}) equals `commitment`.

Step 8 is the step a Receipt of consistency verifier performs before checking
its signature, with `prev_commitment` as the trusted accumulator. It
establishes that the log at `log_size` extends the log at `prev_size` without
modification. It does not establish that `prev_commitment` is the commitment
of a checkpoint anyone else has seen; that is the role of Registration
({{registration}}).

## Required Constraints — Elected Once, Then Binding {#constraints}

Publishing checkpoints is OPTIONAL. **Once a producer elects to publish, the
following are REQUIREMENTS**, because a checkpoint regime with discretionary
gaps supports none of the claims in {{claims}}:

1. **Declared cadence.** The producer MUST declare a maximum interval between
   checkpoints (and MAY declare a maximum entry lag). The declaration SHOULD
   be carried in the checkpoint's `cadence` claim; however conveyed, it MUST
   be available to every Transparency Service the checkpoints are registered
   with. A missing checkpoint at any of them is thereby a detectable event,
   not an ambiguity. A producer with no new entries meets the cadence with a
   checkpoint whose `log_size` equals its `prev_size`.
2. **Continuity.** Each checkpoint MUST pass {{checkpoint-checks}} with its
   `prev_size` and `prev_commitment` equal to the `log_size` and
   `commitment` of the producer's previous checkpoint for the same log
   identity. This *internal* relation is checkable offline by any verifier
   holding the two checkpoints; it establishes that the presented history was
   not rewritten between them. It does **not**, by itself, establish that no
   divergent history exists: a forking producer can satisfy the internal
   relation on each fork separately. Detecting that requires state across
   time, which a single offline verifier does not have, and is what a
   Consistency Registration Policy adds ({{registration}}).
3. **Named, independent Transparency Services.** A producer representing a
   log's checkpoints as independently registered MUST name the Transparency
   Services it relies on and the Registration Policy each publishes. A
   Transparency Service operated by the producer confers no independence; it
   is a replica.
4. **No claims beyond the last registered checkpoint.** Entries appended
   after the most recent registered checkpoint are, to a relying party,
   exactly as strong as a log with no registered checkpoint. Producers MUST
   NOT represent them otherwise.

## Checkpoint Registration {#registration}

The checkpoint's protected header MUST carry the CWT_Claims header parameter
{{RFC9597}} with the claims {{RFC9943}} requires of a Signed Statement:
`iss` (the CWT Issuer claim {{RFC8392}}) identifies the producer, and `sub`
(the CWT Subject claim) identifies the log. `sub` MUST be
the same value in every checkpoint of a log, and MUST NOT vary per
checkpoint: a checkpoint is a new Signed Statement about the same Artifact,
which {{Section 6.3 of RFC9943}} asks an Issuer to register under the same
`iss` and `sub`. The pair (`iss`, `sub`) is the **log identity** every
continuity check keys on. A `sub` that changes with every checkpoint (for
example, one that embeds the log size) gives each checkpoint a new log
identity, so a Transparency Service never finds a predecessor to check it
against, and continuity is silently never enforced.

The checkpoint is registered as a Signed Statement per {{RFC9943}}, by any
transport the Transparency Service accepts. A Transparency Service unaware of
this document can register it as an ordinary Signed Statement.

A Transparency Service applying a Consistency Registration Policy performs
the checks of {{checkpoint-checks}} and, in addition, keeps for each log
identity the `log_size` and `commitment` of the last checkpoint *it itself
registered*. For a checkpoint whose log identity it holds state for, it MUST
verify that `prev_size` and `prev_commitment` equal that state, and on
failure MUST refuse registration and MUST treat the failure as evidence of
log mutation, never as an error to be retried. For a log identity it holds no
state for, it MAY register the checkpoint as the start of that log's history
at the service; continuity at that service is then established from that
checkpoint forward and says nothing about the history before it. This is the
MMR profile's "empty tree as trusted state" case, applied per log identity.

The {{RFC9942}} Receipt the Transparency Service returns proves that the
checkpoint is included in the Transparency Service's log, and the time of
registration if and only if the Receipt carries a signed time claim. A
Receipt is an inclusion proof; it is not the service's agreement with the
checkpoint. Continuity follows from the published Registration Policy: where
that policy is a Consistency Registration Policy, inclusion under it shows
the check passed. A Transparency Service that registers a checkpoint without
the check returns a Receipt that proves inclusion and nothing about
continuity. A verifier SHOULD know which Registration Policy the
Transparency Service applied, and relies on continuity only when it does.

**Scope of the Consistency Registration Policy.** {{RFC9943}} defines a
Registration Policy over the non-opaque header and metadata of the COSE
Envelope, permits the service to validate the payload of a Signed Statement
({{Section 6.3 of RFC9943}}), and leaves the scope of checks beyond the
mandatory ones to the implementation ({{Section 5.1.1 of RFC9943}}). A
Consistency Registration Policy reads the log identity from the protected
header's CWT_Claims and the claims of {{checkpoint}} from the payload. This
document does not copy those claims into the protected header. Because the
consistency proof is carried in the checkpoint, the Signed Statement itself
is the material {{Section 5.1.1.2 of RFC9943}} requires the service to make
available for Auditors to reproduce its check.

Registering the same checkpoint with more than one Transparency Service
({{Section 6.3 of RFC9943}}) strengthens the log against equivocation
(presenting different histories to different parties): an equivocating
producer must present a consistent history to every one of them
({{security}}).

# Relationship to the MMR Profile {#relationship}

This section is non-normative. It states how a CLL relates to
{{I-D.bryce-cose-receipts-mmr-profile}}, what a checkpoint gives a relying
party and what it does not, and how a CLL's entries can later receive full
Registration at a Transparency Service.

## What Each Document Defines

| | MMR profile | This document |
|---|---|---|
| Tree, node values, `add_leaf_hash` | defines | uses unchanged |
| Leaf pre-image | leaves to the application | `0x00 || entry` ({{log-structure}}) |
| Tree size | defines (node count) | `log_size`, `prev_size` |
| Accumulator and its encoding | defines | `commitment`, `prev_commitment` |
| Consistency proof format and verification | defines | `consistency_proof`, step 8 of {{checkpoint-checks}} |
| Inclusion proof format and verification | defines | used for entries ({{verification}}) |
| Who signs the accumulator | the log, in a Receipt | the producer, in a Signed Statement |
| Continuity across signers and time | out of scope | Registration under a Consistency Registration Policy |
| Append discipline, cadence, claims | out of scope | {{discipline}}, {{constraints}}, {{claims}} |
{: title="Division of labor"}

## A Checkpoint and a Receipt of Consistency

A Receipt of consistency for an MMR_SHA256 log is a COSE_Sign1 whose detached
payload is the accumulator at tree-size-2, whose protected header carries
tree-size-2, and whose unprotected header carries one or more consistency
proofs. A checkpoint carries the same three things — `commitment` is the
payload bytes, `log_size` is tree-size-2, `consistency_proof` is the proof —
with three differences:

* **Signer.** A Receipt is signed by the operator of the verifiable data
  structure in its role as a Transparency Service, over that service's own
  log. A checkpoint is signed by the producer as an Issuer, over the
  producer's local log. It is a Signed Statement, not a Receipt in the sense
  of {{RFC9943}}, and it becomes transparent only by being registered.
* **Placement.** The Receipt detaches its payload and carries the proof in
  the unprotected header. The checkpoint attaches the accumulator and puts
  the proof, `log_size` and the previous state inside the signed payload, so
  a Transparency Service registering it receives everything its Registration
  Policy evaluates in one Signed Statement, and the proof is covered by the
  producer's signature.
* **Previous state.** A Receipt of consistency leaves the trusted
  accumulator to the verifier. A checkpoint names its predecessor
  (`prev_size`, `prev_commitment`), which is what lets a Transparency
  Service detect a fork or a skipped checkpoint by comparing it with the
  state it holds.

Because the bytes coincide, a producer that also operates its log as a
Receipt-issuing service can issue a Receipt of consistency over the same
sizes, and a verifier that has checked one has checked the other's
accumulator. Nothing in this document requires that.

## What a Checkpoint Establishes

Given one checkpoint, any verifier can check entries against it: an entry is
in the log at a position (an MMR profile inclusion proof against the
accumulator in `commitment`), and a presented range of entries is complete.
Given two checkpoints of one log, any verifier can check that the later log
extends the earlier one without modification ({{checkpoint-checks}}, step 8).
All of this holds to the extent the verifier trusts the producer, because the
producer signed every checkpoint and chose what to present.

Registered under a Consistency Registration Policy at one or more
Transparency Services the verifier regards as independent of the producer,
the same checkpoints additionally establish, against a producer the verifier
does not trust: that each committed entry existed no later than the
registration of the first checkpoint covering it; that no registered
checkpoint was followed by a rewritten, reordered, or truncated history; and,
across services, that the producer did not show divergent histories to them
({{claims}}).

## What a Checkpoint Does Not Establish

A checkpoint does not make any entry transparent. A Transparency Service that
registers checkpoints never receives the entries; it cannot be queried for a
record, and verifying a particular entry still requires the producer (or
another holder) to present the entry and its inclusion proof. A checkpoint
says nothing about the truth of an entry's content, about whether the
producer has other logs, or about records the producer never appended
({{claims}}). And a checkpoint is not a Receipt: a relying party that needs a
Transparency Service's own signed proof about a specific record needs that
record registered.

## The Path to Full Registration

A CLL is designed so that its records can later receive full Registration
without losing what the local log already proved:

1. **Checkpoints only (this document).** The producer registers checkpoints;
   records stay local and private. Relying parties get order, completeness,
   and an upper bound on creation time for every entry, at the cost of one
   small Signed Statement per cadence interval.
2. **Selected records registered.** When a record needs independent,
   per-record transparency — it is disclosed to a counterparty, or contested
   — the producer registers that record itself, as a Signed Statement, with a
   Transparency Service ({{Section 6.3 of RFC9943}}). The record gains its own
   Receipt and becomes a Transparent Statement. Its CLL inclusion proof
   against an earlier registered checkpoint is retained as evidence that the
   record existed, in that position, before the later Registration; the
   later Receipt does not by itself establish that.
3. **The log operated as a Transparency Service.** A producer that wants
   every record registered as it is produced can operate (or delegate) its
   log as a Transparency Service whose verifiable data structure is
   MMR_SHA256. Its Receipts of inclusion and of consistency then come
   directly from the MMR profile, and checkpoints become unnecessary for
   that log; the continuity a Consistency Registration Policy gave is then
   given by Receipts of consistency verified from trusted state. The log's
   existing nodes need no conversion, since they were built with the
   profile's algorithms from the start.

Each step keeps the leaf values, node values, and accumulators of the step
before it, so a relying party's earlier verification remains valid.

## Profile Revisions

This document cites {{I-D.bryce-cose-receipts-mmr-profile}} at its current
revision, -03. The editors' copy of the profile {{MMR-PROFILE-MAIN}} differs
from -03 in ways this document depends on: it specifies the detached payload
of a Receipt of consistency as the accumulator's node values concatenated in
descending height order (the encoding {{commitment}} uses), it adds a
protected tree-size-2 header to the Receipt of consistency, and it states
`consistent_roots` with the exact proof shape checks step 8 of
{{checkpoint-checks}} relies on. This document follows the editors' copy and
will track the next published revision of the profile. The checkpoint
carries its tree size in the signed payload, so it does not depend on the
protected tree-size-2 header.

# Verification {#verification}

Given a checkpoint that passes {{checkpoint-checks}}, a verifier can check,
using only the proof formats of {{I-D.bryce-cose-receipts-mmr-profile}}:

- **Inclusion:** a given entry is committed at a given position under
  `commitment`: the leaf value of {{log-structure}} and an MMR profile
  inclusion proof reach one of the accumulator's node values.
- **Consistency:** a later checkpoint's log extends an earlier
  checkpoint's log without modification: step 8 of {{checkpoint-checks}},
  applied across one or more consecutive checkpoints.
- **Range completeness:** the entries between positions i and j under a
  checkpoint are exactly the presented set — nothing between them was
  omitted: an inclusion proof for every position in the range against the
  same accumulator. Implementations MAY use a more compact multi-leaf proof;
  this document does not define one.

Given a checkpoint registered under a Consistency Registration Policy, each
of these claims additionally holds against a party who does not trust the
producer, to the extent the verifier trusts that the Transparency Services
are independent of the producer and apply their published policy.

# What a CLL Does and Does Not Establish {#claims}

A CLL whose checkpoints are registered under a Consistency Registration
Policy establishes: that each committed entry existed no later than the first
registered checkpoint covering it (**contemporaneity**); that the committed
sequence has not been reordered, had entries removed, or been rewritten
(**order and integrity**); and that a presented range is complete
(**completeness**).

These claims come from what the Transparency Service registers, which is
**only checkpoints, not entries**. A Transparency Service registering
checkpoints receives commitments; it does not receive, index, or retain the
entries themselves. Its log therefore records the *shape* of the committed
history — existence, order, completeness of the committed sequence — and
nothing about any individual entry beyond its membership. Two consequences a
reader familiar with per-record transparency logs must not overlook: it
cannot be queried as an independent index or lookup for a particular record,
because it never held one; and verifying any individual entry still requires
the producer, or another holder, to present that entry and its inclusion
proof — the registered checkpoint is the commitment they resolve against, not
the entry. A deployment that needs per-record lookup registers those records
directly with a Transparency Service ({{relationship}}, step 2 of the path to
full Registration); that is a different trade — publication and per-record
registration cost in exchange for independent per-record lookup.

A CLL establishes **nothing about the truth of any entry's content**. A log
of false records with every checkpoint registered is still a set of false
records. Whether a record's content is accurate, whether its signer was
authorized, and whether any claimed real-world effect occurred are separate
claims requiring separate evidence (counterparty confirmation, external
corroboration), outside this document's scope. Producers and tools MUST NOT
present registration of checkpoints as evidence of content accuracy.

A CLL likewise does not establish that the log is the producer's *only* log,
nor that all records the producer created were appended. It bounds omission
*within* the committed history; it cannot prove a parallel uncommitted
history does not exist. Deployments for which that distinction matters bind
the log identity to an accountable party by mechanisms outside this document.

# Implementation Status
{:removeinrfc="true"}

This section records the status of known implementations at the time of
writing. It is not a conformance statement.

Four implementations (Python, Go, TypeScript, and Rust) maintained in one
repository build the log of {{log-structure}} and agree, node for node, with
the test vectors published with this revision {{CLL-VECTORS}}, which are
generated from the editors' copy of the MMR profile without using any of
them. Each implementation's consistency proof maps onto the MMR profile's
`consistency-proof` without loss. As of this revision, all four still emit
the checkpoint wire form of the previous revision: the commitment as a CBOR
array of node values, a consistency proof in an implementation-specific
form, and a `sub` that varies per checkpoint. The vectors include tests that
detect when each implementation adopts the form specified here.

# Security Considerations {#security}

The security considerations of {{I-D.bryce-cose-receipts-mmr-profile}} apply.

**Equivocation.** A producer maintaining two divergent logs under one log
identity must present each Transparency Service a consistent view. With k
independent Transparency Services and a verifier that checks Receipts from
any subset of them, sustained equivocation requires controlling or
partitioning every Transparency Service that verifier relies on. The
cheapness of checking a checkpoint (a logarithmic proof from the previous
commitment, holding no entry data) is what makes registration with a
meaningful number of independent Transparency Services economically
plausible. Verifiers SHOULD require Receipts from more than one Transparency
Service where the threat model includes collusion between the producer and a
service operator.

**Log identity.** Continuity is enforced per (`iss`, `sub`). A producer that
changes `sub` between checkpoints, or registers a checkpoint under a new log
identity, starts a new history at every Transparency Service. A verifier
SHOULD treat a log identity that first appears at a service with
`prev_size` greater than 0 as a log whose earlier history that service did
not check.

**Declared sizes.** The MMR profile notes that a consistency proof does not
by itself fix tree-size-2. A checkpoint signs `log_size` in its payload and
step 8 of {{checkpoint-checks}} requires the proof's tree-size-2 to equal it,
so a presenter cannot choose the size a verifier records.

**Backdating.** An entry can be created with any internal timestamp, but its
position in the log bounds its creation time from above by the first
registered checkpoint covering it. The backdating window is therefore the
declared cadence plus registration latency. Producers wanting a smaller window
declare a shorter cadence.

**Key compromise.** A stolen signing key permits forged future checkpoints
but cannot rewrite history already registered: a forged checkpoint
inconsistent with a registered predecessor fails the Consistency Registration
Policy. Each Transparency Service's append-only log retains every registered
checkpoint, which is part of the security function.

**Signature algorithm.** This document defines no signature algorithm. New
deployments using Ed25519 should identify it with the fully specified
algorithm identifier of {{RFC9864}}.

**Cryptographic agility.** This revision defines checkpoints for logs using
MMR_SHA256 only. The node value size, and therefore the commitment length
rule of {{checkpoint-checks}}, follows from that identifier. A log using
another verifiable data structure algorithm registered for the MMR profile in
the future would need a claim naming it; this document does not define one.

# Privacy Considerations

A checkpoint reveals the log's size and cadence and nothing else; entries
are digests, and content never leaves the producer. Deployments for which
entry *count* is sensitive MAY pad with reserved entries; this document does
not define a padding scheme. The privacy considerations of
{{I-D.bryce-cose-receipts-mmr-profile}} on low-entropy leaf pre-images apply
to entries: an entry that is the digest of a guessable record can be
confirmed by anyone who obtains an inclusion proof for it.

# IANA Considerations

This document makes no IANA requests.

## Artifact Type Declaration for Payload Binding

This section declares, for use with
{{I-D.mih-sokolov-scitt-payload-binding}}, the digest context of the
`cll-checkpoint` artifact type. It is a declaration by the owning
specification, not an IANA registration.

Artifact type:
: `cll-checkpoint`

Digest context:
: the log state a checkpoint commits to.

Canonicalization algorithm:
: `as-transmitted`.

Byte-boundary selector:
: the value of the `commitment` claim of a checkpoint ({{commitment}} of this
  document): the accumulator at `log_size`, which
  {{I-D.bryce-cose-receipts-mmr-profile}} names the detached payload of a
  Receipt of consistency.

Hash function and representation:
: SHA-256; 64-character lowercase hexadecimal, as the `as-transmitted`
  registration fixes.

Composite:
: no. The commitment embeds no other artifact type's payload bytes;
  `prev_commitment` refers to the previous log state by value, not by
  digest reference.

The test vectors {{CLL-VECTORS}} give this digest for every log size of the
example log (`commitment_sha256`).

--- back

# Changes since -01
{:removeinrfc="true"}

Wire changes (each is a break from -01 for producers and verifiers):

* `commitment` and `prev_commitment` are the accumulator's node values
  concatenated in descending height order, the encoding the MMR profile's
  editors' copy specifies for the payload of a Receipt of consistency. -01
  said "canonical-CBOR-encoded exactly as the commitment object" of the
  profile, which no published revision of the profile defines. A
  verifier reading -01 checkpoints sees a CBOR array of byte strings.
* `log_size` and `prev_size` are stated to be MMR tree sizes (node counts),
  matching the profile's tree size and what every known implementation
  already writes. -01 described `log_size` as the number of entries. Added
  the OPTIONAL `leaf_count` claim for the entry count.
* Added the `consistency_proof` claim, carrying the MMR profile's
  `consistency-proof`, REQUIRED when the log grew since a previous
  checkpoint. -01 required the proof to be "made available" without saying
  how.
* `sub` is the log and MUST be the same in every checkpoint of a log, per
  {{Section 6.3 of RFC9943}}. A `sub` that varies per checkpoint defeats
  continuity.

Other changes:

* New {{log-structure}}: a CLL is an MMR_SHA256 MMR; the leaf value is
  `SHA-256(0x00 || entry)` with a 32-byte entry.
* New {{checkpoint-checks}}: the complete list of checks on one checkpoint,
  including a checkpoint where the log did not grow.
* {{registration}} states what a Consistency Registration Policy checks, and
  what a service does with a log identity it has not seen.
* New {{relationship}}: the division of labor with the MMR profile, a
  checkpoint compared with a Receipt of consistency, what a checkpoint does
  and does not establish, and the path to full Registration.
* Aligned terminology with {{RFC9943}}. Removed the "Witness" definition.
  The role is now a Transparency Service that registers checkpoints under a
  Consistency Registration Policy; added {{scitt-terms}}. Stated that a
  Receipt proves inclusion (and the time of registration only if it carries
  a signed time claim), not agreement, and carries no continuity meaning of
  its own. Replaced the multiple-witness text with registering the same
  checkpoint with more than one Transparency Service
  ({{Section 6.3 of RFC9943}}).
* Removed the direct checkpoint countersignature form (RFC 9338), the "Stub
  Countersignatures — Future Work" section, and the IANA sentence
  forecasting a COSE header parameter for stub countersignatures.
* Removed the SHOULD that each checkpoint holder retain every checkpoint: a
  Transparency Service's append-only log already retains every registered
  checkpoint.
* Added the `cll-checkpoint` artifact type declaration for payload binding,
  moved here from the payload-binding provisional registry.
* Added Implementation Status, Privacy Considerations, and security
  considerations on log identity, declared sizes, and the signature
  algorithm.
* New test vectors {{CLL-VECTORS}}.

# Changes since -00
{:removeinrfc="true"}

* Clarified the commitment representation: named the bagged-root fold as an
  explicit, non-wire, implementation-internal alternative to the peak-list
  commitment, and stated the peak-list encoding as the required wire form.
* Downgraded the stub countersignature section (removed in -02) from a
  normatively-specified mechanism to a Future Work note, and removed the
  corresponding IANA registration request.
* No checkpoint claim names were renamed.

# Acknowledgments
{:numbered="false"}

The Merkle Mountain Range structure and its COSE proof formats are the work
of the authors of {{I-D.bryce-cose-receipts-mmr-profile}}; this document
exists because that structure makes streaming local commitment practical.
