# Implementation import provenance

The Go and TypeScript imports retain their original commits as merge parents.
The one-time imports contain every tracked file, including their licenses,
design guidance, pinned fixtures and original workflow snapshots. Nested
workflow snapshots are provenance; active workflows live in the root `.github/`.

| Source | Frozen revision | Destination |
| --- | --- | --- |
| checkpointed-local-log | c56aae1b575cc47698a41ee1ab8288d3aa79ca7b | Python source/metadata/tests to `python/`; CLL crate to `rust/`; EvidenceBook to `evidencebook/` |
| cll-go | ed7a1b74aab12cda39030cac048d844901475fa0 | `go/` |
| cll-ts | 725d1eb3056546fe9872c505475fde9040b7fea6 | `ts/` |

No source tags are transferred or rewritten. Historical versions retain their
original package paths. The Go module now uses the destination `/go` identity;
consumers must migrate a whole dependency graph to avoid mixing named types.

The incoming Go MMR/commitment and TS MMR fixture copies differ from the frozen
root corpora. They remain byte-for-byte preserved; their original root-corpus
revision is not established by the source comments. The Go checkpoint copy
matches the root checkpoint corpus. Root corpora remain authoritative, while
incoming fixtures remain pinned regression inputs. This move does not refresh
them or claim that the external MMR-profile research corpus is CLL conformance.

Retain both root license texts, imported subtree licenses, crate notices and
the BSD/IETF exception in `mmr-profile-vectors/draft03.py`. Unheaded data retains
source provenance; co-location does not grant a new file-specific license.

Path adjustments affect installers, vector traversal, local crate dependencies,
module imports, package repository metadata and active CI. The storage interop
helper additionally awaits the existing asynchronous TS MMR append operation.
No runtime persistence or wire semantics change is intended.
