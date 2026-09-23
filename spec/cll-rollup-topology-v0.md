# CLL Multi-Level Roll-up Topology — v0

**Status.** Design specification, pre-Internet-Draft, **HELD FOR LINE REVIEW**. This document
proposes an appendix or companion to the CLL base draft
(`draft-mih-scitt-checkpointed-local-log-01.md`, this repository's `spec/`, referred to below as
"the base draft") covering the proof-construction section (§3 below) — no part of this document
is to be merged into the base draft, cut as a new draft revision, or represented as ratified
until that review lands (`[a17-fleet-log-topology-and-capture-policy-v0]`, spec lane). Everything
else in this document (topology framing, worked example, security notes) is auto-gated per the
lane card; §3 alone carries the line-review hold.

**One-sentence claim.** A roll-up is composition, not new cryptography: every level of the
topology below is an ordinary CLL as the base draft already defines it, and every proof a
verifier checks is an ordinary base-draft inclusion or consistency proof. This document defines
no new MMR algorithm, no new checkpoint claim, and no new wire form. Where that bears repeating,
it is repeated rather than left implicit.

## Dependency boundary

**Owns:** the recursive roll-up composition rule (§1), the topology names L0/L1/L2 as a
deployment convention rather than a protocol layer (§2), the entry-construction rule that
preserves both the logging identity and the emitting identity across a roll-up hop (§3), the
depth-collapsing rule for small estates (§4), the witness-economics consequence of composition
(§5), and the `provenance_mode` recommendation for backfilled entries (§6).

**Depends on:** the CLL base draft for every cryptographic primitive — the MMR structure, the
checkpoint claims table, the consistency and inclusion proof formats, the witnessing modes, and
the "What a CLL Does and Does Not Establish" rigor this document extends rather than restates.
This document also assumes the base draft's **Entry** definition: "a byte string appended to the
log... opaque to this specification" — a roll-up is one particular, disciplined choice of what
that byte string is at a non-leaf level, and nothing this document says requires the base draft
to know that choice was made.

**Explicitly out of scope:**

- Any change to the MMR accumulator, the peak-list/bagged-root distinction, or the checkpoint
  claims table — all unchanged, at every level, per the CLL base draft §"The Checkpoint".
- Any new proof format. Every inclusion or consistency check named below is the CLL base draft's own,
  applied once per hop.
- Retention, legal hold, or how long any level's log or its committed content survives —
  operator/customer policy, not a proof-construction concern (see the companion
  `capture-policy-v0.md`/`payload-store-v0.md` in `agent-action-capsule/spec/` for the capture
  and storage side of that boundary).
- Transport of checkpoints between levels — any transport the CLL base draft §"Witnessing" already permits
  for conveying a checkpoint to a witness works identically for conveying one to the log one
  level up; this document adds no transport requirement.

## 1. The recursive definition

A roll-up level is an ordinary CLL whose **entries are the checkpoints of the level below**,
recursively:

```
level N   : an ordinary CLL, per the CLL base draft, whose Entry (§2's definition) at position i
            is entry_digest(checkpoint_(N-1)_i) — a digest over the full COSE_Sign1
            checkpoint object emitted by some log at level N-1 (§3: the FULL object,
            not its numeric fields alone).
level 0   : an ordinary CLL, per the CLL base draft, whose entries are whatever the deployment's
            leaf producers append (a Capsule digest, a receipt digest, any record class
            the CLL base draft already treats as opaque).
```

Nothing distinguishes a "roll-up log" from any other CLL at the wire level: its checkpoint has
the same claims table, its proofs use the same inclusion/consistency algorithms, and a verifier
who has never heard the word "roll-up" can still verify it as an ordinary CLL — it will simply
see a log whose entries happen to be checkpoint digests. The roll-up is a fact about *what a
deployment chose to put in the log*, not a fact the CLL base draft needs a new claim to express.

## 2. Topology names are a deployment convention, not a protocol layer {#topology}

This document uses **L0 (cluster) → L1 (domain) → L2 (root)** as names for a fleet deployment
with three levels, because three is the shape a fleet operator commonly needs (a cluster-local
collector, a domain aggregator spanning several clusters, one root spanning several domains).
Nothing in §1's recursive definition fixes the count at three, names the levels, or requires
every branch of a fleet to have the same depth. A deployment MAY have two levels, four, or a
non-uniform tree (one domain collapses straight to root while another has an intermediate hop —
§4). "L0/L1/L2" is this document's naming for one common case, used for concreteness in the
worked example (§5.1); it is not a vocabulary this document asks the CLL base draft or any registry to fix.

**The verifier is indifferent to depth.** Verifying an entry against a witnessed top-level
checkpoint is: walk the chain of inclusion proofs from the entry's home log up through however
many intermediate levels exist, terminating at the level whose checkpoint was actually witnessed
(the CLL base draft §"Witnessing"). The verification algorithm does not change shape between a two-hop and
a four-hop chain — it is the same loop, run a different number of times. §4 makes this the basis
for depth-collapsing.

## 3. Entry construction across a hop — both identities survive {#construction}

**[HELD FOR STEVEN'S LINE REVIEW — proof construction.]**

At level N-1, the party that appends entries and signs level N-1's checkpoints is that level's
**producer** per the CLL base draft's definition (e.g., at L0, the cluster's collector). The entries that
producer appended may themselves have been signed by other parties — an individual agent, a
service instance, any **emitter** whose signature is on the underlying record the L0 entry
digests, per the CLL base draft's own Entry definition ("typically the digest of a signed record produced
by the operator or received from another party"). These are already two distinct identities at
level 0 alone, and the CLL base draft already keeps them distinct: the checkpoint's `iss` names the
producer; the emitter, if different, is recoverable only by resolving the entry's digest back to
the record it commits to — the checkpoint itself says nothing about who emitted any individual
entry.

**The roll-up rule:** when level N's entry is constructed from level N-1's checkpoint, it MUST be
the digest of the **complete COSE_Sign1 checkpoint object** — protected header (carrying
level N-1's `iss`/`sub` per the CLL base draft §"Witnessing"), payload, and signature — not a digest of the
checkpoint's numeric claims alone (`log_size`/`commitment`/etc. in isolation). The base draft
imposes no constraint here (entries are opaque to it); this document imposes one, because dropping the
protected header from the pre-image would sever the recoverable link to level N-1's producer
identity at exactly the hop where it is needed.

**Consequence.** A verifier holding a level-N-2 record, the level-N-1 checkpoint that committed
it, and the level-N checkpoint that committed *that* checkpoint can recover, without trusting any
intermediate party's say-so: (a) the original emitter's signature on the record itself
(unchanged by any roll-up — the record's bytes are never touched); (b) level N-1's producer
identity, from the `iss` inside the checkpoint object that level N's entry digests; and (c) level
N's own producer identity, from level N's own checkpoint. Climbing a level never launders or
drops an identity — it only adds one more producer identity to the chain, each recoverable at
the hop it was introduced. This is the sense in which "signing is per-emitter, logging is
per-producer, and both identities are in the proof": the roll-up composes producer identities one
per level, without ever needing to touch, re-sign, or re-attest the original emitter's signature
at the leaf.

This construction rule is the only normative addition this document makes beyond the CLL base draft's
existing text, and it constrains an application-layer choice ("what bytes does a roll-up
collector digest when it appends the level-below checkpoint as its own entry"), not the CLL wire
format itself — the CLL base draft's checkpoint claims table, MMR accumulator, and proof formats are
unchanged at every level, per the one-sentence claim above.

## 4. Small estates collapse levels {#collapse}

A deployment with few enough logs to make an intermediate level pointless MAY skip it: L0
checkpoints become direct entries of L2, with no L1 in between. This is not a different
composition rule — it is §1's recursive definition applied with fewer levels, because the
definition never referenced L1 by name; "level N's entries are level N-1's checkpoints" holds
whether N-1 is one hop below or the label a deployment happens to call "L1" for its larger
branches. A verifier presented with a two-hop chain (L0 → L2) and one presented with a three-hop
chain (L0 → L1 → L2) run the identical per-hop check (§2) the corresponding number of times; the
chain length is a property of the proof presented, not a protocol constant either verifier needs
to have been told in advance.

A single deployment's tree MAY be non-uniform — one cluster's L0 checkpoints entering L2 directly
while another cluster's enter an intervening L1 domain log — with no coordination requirement
between branches, because each branch's proof chain is independently walked and independently
terminates at whichever level was actually witnessed.

## 5. One witness receipt per period covers every log in the tree {#witness-economics}

Only the **top level actually reached by a verifier's proof chain** needs external witnessing
(the CLL base draft §"Witnessing" — SCITT registration or direct countersignature). Every level below is
covered *transitively*: an entry's inclusion at level 0 is bound, by the level-1 inclusion proof,
to a specific level-0 checkpoint digest that cannot change without breaking level 1's own
consistency (the CLL base draft §"Required constraints", constraint 2) — and level 1's consistency is in
turn bound the same way to level 2, and so on up to whichever level is witnessed. A fleet that
witnesses only its L2 root gets one registration, or one countersignature, per checkpoint period
— covering every entry in every L0 and L1 log in the tree that period, however many there are.

**This is not a new guarantee beyond what the CLL base draft already states — it is what the CLL base draft's own
consistency and inclusion proofs compose to, applied recursively.** §5.1 works the arithmetic.

**What this does *not* buy.** An unwitnessed intermediate level carries exactly the assurance
the CLL base draft §"What a CLL Does and Does Not Establish" already assigns an unwitnessed log: what its
own producer vouches for, nothing a party who does not trust that producer can independently
check, until a proof chain reaches a level that *is* witnessed. Rolling up does not retroactively
witness anything; it changes how few witness registrations are needed to make an entire tree's
proof chains terminate at a witnessed checkpoint. A verifier who does not trust the L1 domain
aggregator not to *omit* a cluster's checkpoint entirely (rather than tamper with one it
included) is relying on the same completeness claim the CLL base draft §"What a CLL Does and Does Not
Establish" already scopes narrowly: a CLL bounds omission *within* the committed history and
does not prove a parallel, never-submitted history does not exist. A roll-up composes this
exact, already-narrow claim once per level; it does not widen it. A deployment for which an
aggregator's silent omission is a live threat names that aggregator as a party the verifier must
additionally trust not to omit — the same trade the CLL base draft already requires a verifier to reason
about for any single producer, one level up.

### 5.1 Worked example — 500 logs

A fleet runs **500 L0 collector logs** (cluster level), grouped into **25 L1 domain logs** of 20
collectors each, aggregated by **one L2 root**. Each level checkpoints once per period (a day,
for concreteness).

**Without roll-up** — every L0 log witnessed individually: **500 witness registrations per
period.**

**With this topology:**

- Each L1 domain log takes that period's 20 L0 checkpoints as its own entries and emits one
  checkpoint: **25 L1 checkpoints per period**, none of them individually witnessed.
- The L2 root takes that period's 25 L1 checkpoints as its own entries and emits one checkpoint:
  **1 L2 checkpoint per period** — the only one registered with a witness.

**Witness registrations per period: 500 → 1** (a 500× reduction), independent of how long the
period is, because the reduction comes from tree fan-in, not from checkpointing less often.

**Proof-size cost of the reduction**, for one entry in one L0 log that checkpointed at 4096
entries that period (⌈log₂ 4096⌉ = 12 sibling hashes for its L0 inclusion proof, unchanged from a
non-rolled-up deployment):

- L0 inclusion proof (entry → its L0 checkpoint): 12 hashes, as above — this hop is identical
  whether or not the deployment rolls up at all.
- L1 inclusion proof (that L0 checkpoint → its L1 domain checkpoint, one of 20 entries that
  period): ⌈log₂ 20⌉ = 5 additional hashes.
- L2 inclusion proof (that L1 checkpoint → the L2 root checkpoint, one of 25 entries that
  period): ⌈log₂ 25⌉ = 5 additional hashes.

**Total: 12 + 5 + 5 = 22 hashes** to carry one entry's proof all the way to the single witnessed
checkpoint, versus 12 hashes plus one dedicated witness registration for that entry's log alone
in the non-rolled-up case. Ten additional hashes (roughly 320–640 bytes at 32–64 bytes/hash,
depending on the MMR profile's hash algorithm) buys the 500×-fewer-registrations reduction above
— both quantities logarithmic in the fan-in at each level, per §"the cheapness of MMR checkpoint
verification" already noted in the CLL base draft §"Security Considerations".

**If the same 500 collectors instead skip the domain level (§4)** and enter L2 directly: 500
entries at L2 that period, ⌈log₂ 500⌉ = 9 additional hashes for the L0→L2 hop — fewer levels,
slightly more hashes per proof at the (now single) aggregation hop, same 500→1 witness-
registration reduction, no coordination requirement changed. This is §4's claim made concrete:
the verifier's per-hop check and the economics of witnessing are the same shape at two hops or
three; only the hash count at the collapsed hop differs, and it differs by a few hashes, not by
a different proof format.

## 6. Backfilled entries and `provenance_mode` {#backfill}

The base draft's §"The Log Discipline" already states the append-at-production-time rule and, in
§"Security Considerations" ("Backdating"), already bounds what a log entry's position can and
cannot prove: an entry's creation time is bounded *from above* by the first witnessed checkpoint
covering it, never proven to equal whatever internal timestamp the entry itself carries. A
**backfilled** entry — one appended for a record produced or received before the append, e.g.
recovered after a collector outage, or imported from a legacy store not previously logged — is
exactly the case that bound exists for, and this document adds nothing cryptographic to it: a
backfilled entry's position still only proves it existed no later than the checkpoint that first
covers it, which is the time of the *backfill*, not the record's original claimed time.

**Recommendation, non-normative to the CLL base draft's wire format:** a backfilled entry SHOULD carry a
`provenance_mode` value (e.g. `live` | `backfilled`) as part of the record it digests — an
application/digest-context concern, not a CLL checkpoint claim, per the CLL base draft's own entry-opacity
principle (§1). Carrying it lets a relying party distinguish, when reading the underlying record
after resolving an entry's digest, an entry whose logged position is contemporaneous with the
event it describes from one whose logged position only bounds when the *backfill itself*
happened — a distinction the CLL base draft's Backdating paragraph already implies but does not surface as a
labeled field, because the CLL base draft does not define record content at all.

**Placement in the topology.** A backfilled entry enters the **L0 log of the collector that
performed the backfill** — never inserted into, or represented as originating from, any other
collector's L0 log, and never inserted at any level above L0. The log commits it at the position
corresponding to *when the backfill was appended*, not the record's original occurrence time;
the CLL base draft's append-only and one-log-one-signing-identity rules (§"The Log Discipline") apply to a
backfilling collector exactly as they apply to a live-appending one — a backfill is a normal
append, distinguished from an ordinary one only by the `provenance_mode` value carried in the
record it digests, not by any different logging discipline.

## Vocabulary discipline

This document MUST NOT use, in any form: `Authority`, `Relay`, `score`/`scoring`, `reputation`,
or any retention/legal-hold policy language beyond noting that such policy is out of this
document's scope (§"Dependency boundary"). This document specifies topology and proof
composition only; capture and retention policy are the companion `capture-policy-v0.md` and
`payload-store-v0.md` in `agent-action-capsule/spec/`.

