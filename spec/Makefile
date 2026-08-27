# SPDX-License-Identifier: BSD-3-Clause
# Build the Internet-Draft from the kramdown-rfc source.
#
# kramdown-rfc emits RFCXML v2, so the build converts v2 -> v3 with
# `xml2rfc --v2v3` before rendering text.
#
# Toolchain (one-time):
#   gem install kramdown-rfc
#   python3 -m venv ~/.venvs/x2r && ~/.venvs/x2r/bin/pip install xml2rfc

DRAFT    = draft-mih-scitt-checkpointed-local-log-00
XML2RFC  ?= ~/.venvs/x2r/bin/xml2rfc
KDRFC    ?= kramdown-rfc

.PHONY: all clean idnits rebuild refresh-refs

all: $(DRAFT).xml $(DRAFT).txt

# Force a rebuild from the Markdown source.
#
# `make` decides by modification time, and several routine git operations give a
# generated file a *fresh* mtime without changing its contents -- a fresh clone,
# a checkout, or resolving a conflict with `git checkout --ours`.  When that
# happens make judges the .xml newer than the .md, skips kramdown entirely, and
# regenerates only the .txt from the stale .xml.  The output says "Created file"
# and looks like a successful build while shipping the previous revision's text.
# Use this target after any merge or checkout; never restore a generated file
# from a branch and trust a plain `make`.
rebuild:
	rm -f $(DRAFT).xml $(DRAFT).txt
	$(MAKE) all

# Re-fetch the bibliographic reference cache.
#
# .refcache/ is COMMITTED so that building the draft never depends on
# bib.ietf.org being reachable.  Every uncached build fetches one file per
# external reference, so an outage at the IETF reds the spec gate on every open
# pull request simultaneously, for reasons unrelated to any of them.
#
# RFC references are immutable and need no refreshing.  References to
# Internet-Drafts are not -- and this draft cites several of them WITHOUT a
# version pin, so they resolve to whatever revision is current at fetch time.
# Run this before submitting a revision so a superseded I-D reference cannot be
# carried forward silently, and rebuild afterwards so the artifacts agree with
# the cache.
refresh-refs:
	rm -rf .refcache
	$(KDRFC) $(DRAFT).md > /dev/null
	@echo "refreshed: $$(ls .refcache | wc -l) references -- review 'git diff' before committing"

# md -> v2 xml -> v3 xml
$(DRAFT).xml: $(DRAFT).md
	$(KDRFC) $(DRAFT).md > .$(DRAFT).v2.xml
	$(XML2RFC) --v2v3 .$(DRAFT).v2.xml -o $(DRAFT).xml
	@rm -f .$(DRAFT).v2.xml

# v3 xml -> text
$(DRAFT).txt: $(DRAFT).xml
	$(XML2RFC) --text --v3 $(DRAFT).xml -o $(DRAFT).txt

idnits: $(DRAFT).txt
	npx --yes @ietf-tools/idnits $(DRAFT).txt

clean:
	rm -f .$(DRAFT).v2.xml
