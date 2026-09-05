# SPDX-License-Identifier: Apache-2.0
"""``cll`` command-line entry point.

Currently just ``cll segments list|mount|unmount|verify`` -- inspect and
archive a store's closed segments (see ``cll.ledger.segments``). Operates on
a store root directory already using ``rotate_at_checkpoint=True``; every
subcommand opens the store read-mostly (no checkpointer attached, so nothing
here can trigger a rotation).
"""
from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence

from .ledger.store import LedgerStore


def _cmd_segments_list(args: argparse.Namespace) -> int:
    store = LedgerStore(args.store, rotate_at_checkpoint=True)
    try:
        for entry in store.list_segments():
            state = "mounted" if entry.mounted else "unmounted"
            closing = (
                f"mmr_size={entry.mmr_size} root={entry.checkpoint_root}"
                if entry.manifest is not None
                else "open"
            )
            print(f"{entry.name}\t{state}\t{closing}")
        return 0
    finally:
        store.close()


def _cmd_segments_mount(args: argparse.Namespace) -> int:
    store = LedgerStore(args.store, rotate_at_checkpoint=True)
    try:
        store.mount_segment(args.segment)
        return 0
    finally:
        store.close()


def _cmd_segments_unmount(args: argparse.Namespace) -> int:
    store = LedgerStore(args.store, rotate_at_checkpoint=True)
    try:
        store.unmount_segment(args.segment)
        return 0
    finally:
        store.close()


def _cmd_segments_verify(args: argparse.Namespace) -> int:
    store = LedgerStore(args.store, rotate_at_checkpoint=True)
    try:
        ok, errors = store.verify_segment_standalone(args.segment)
        for err in errors:
            print(err, file=sys.stderr)
        print("OK" if ok else "FAILED")
        return 0 if ok else 1
    finally:
        store.close()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="cll")
    sub = parser.add_subparsers(dest="command", required=True)

    segments = sub.add_parser("segments", help="segment rotation/archival")
    segments_sub = segments.add_subparsers(dest="segments_command", required=True)

    p_list = segments_sub.add_parser("list", help="list this store's segments")
    p_list.add_argument("store", help="store root directory")
    p_list.set_defaults(func=_cmd_segments_list)

    p_mount = segments_sub.add_parser("mount", help="mount an archived segment")
    p_mount.add_argument("store", help="store root directory")
    p_mount.add_argument("segment", help="segment file name, e.g. seg-000001.jsonl")
    p_mount.set_defaults(func=_cmd_segments_mount)

    p_unmount = segments_sub.add_parser("unmount", help="archive a closed segment")
    p_unmount.add_argument("store", help="store root directory")
    p_unmount.add_argument("segment", help="segment file name, e.g. seg-000001.jsonl")
    p_unmount.set_defaults(func=_cmd_segments_unmount)

    p_verify = segments_sub.add_parser(
        "verify", help="re-check a closed segment against its own closing checkpoint"
    )
    p_verify.add_argument("store", help="store root directory")
    p_verify.add_argument("segment", help="segment file name, e.g. seg-000001.jsonl")
    p_verify.set_defaults(func=_cmd_segments_verify)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
