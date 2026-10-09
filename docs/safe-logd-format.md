# Safe diagnostic bundles, version 1

`safe-logd-v1` replaces the bundled opaque Encryptly executable in the build
path. It is a new, documented format. It is **not Encryptly-compatible** and
cannot be decoded with the old executable. Old artifacts remain historical
records; the build never executes their associated bundled tool.

## Inputs and limits

`tools/safe_logd.py` accepts exactly three in-memory UTF-8 strings:
`build.log`, `build-summary.txt`, and `system-info.txt`. It has no directory-pack
API, default include paths, HOME scan, recursive discovery, network operation,
or shell execution. The caller supplies the destination archive path. File and
directory parents must be controlled by the caller; existing final output files,
symlinks, and extraction directories are rejected rather than overwritten.

Each text is limited to 8 MiB, their total UTF-8 size to 16 MiB, and the encoded
JSON payload to 16 MiB. JSON escaping can make the encoded limit stricter than
the raw text limit. Oversize input fails explicitly; it is never silently
omitted or shortened in the encrypted log. Archive input is limited to the
payload bound plus the 9-byte magic/version, 12-byte nonce, and 16-byte tag.
Metadata supplied to the unpack CLI is limited to 1 MiB.

## Binary representation and encryption

In order, a bundle contains:

1. Nine bytes `SAFELOGD\x01` (eight ASCII magic bytes and version byte `0x01`).
2. A fresh, random 12-byte nonce.
3. AES-256-GCM ciphertext with its full 16-byte authentication tag appended.

A fresh random 32-byte key is generated for each bundle. AES-GCM is provided by
`cryptography`, pinned in `requirements-diagnostics.txt`; no custom cipher is
implemented. The complete magic/version is authenticated as associated data.
The encrypted plaintext is a UTF-8 JSON object with exactly `format` and `files`:

```json
{"format":"safe-logd-v1","files":{"build.log":"...","build-summary.txt":"...","system-info.txt":"..."}}
```

Duplicate JSON keys, unknown schema fields, other filenames, non-text content,
oversize documents, unsupported versions, wrong keys, and altered ciphertext
are rejected. Authentication completes before the contents are parsed or
written. Extraction creates a new output directory and only the three fixed
filenames; archive-provided paths are never joined into output paths.

The legacy JSON field `password` contains the canonical padded base64url
encoding of the 32-byte AES key, **not a human password**. There is no password
KDF. Publishing this key with the archive makes the content publicly readable
and allows anyone to create another valid ciphertext. AES-GCM is **not an author
signature** and does not prove a build happened. The public Git source revision,
reviewed producer, and verified plaintext logs provide the build evidence.

## Building and provenance

Install the pinned Python dependency in a virtual environment, commit the
reviewed source, then run the normal build entry point. For example:

```sh
python -m pip install -r requirements-diagnostics.txt
python build.py -m backend,v2-market-stream
```

This selects two modules; it is not evidence that all ten modules passed. A
failed module still has its actual failure output packed. Overall build exit
status remains unsuccessful if any selected module fails or diagnostics fail.
The source HEAD and tree are recorded before building and checked again before
packing; tracked changes or untracked, unignored files cause a refusal. Build
outputs covered by the repository's ignore rules are allowed. A synthetic or
unknown source ID is never substituted.

`diagnostic/build-<first-eight-source-hex>.json` contains the full `source_commit`
and `source_tree`. The same complete source IDs are inside the encrypted build
summary. `source_commit` denotes the source used for the build, **not** the later
automatically-created diagnostics commit. Per-text byte lengths and SHA-256
hashes and per-artifact hashes aid the explicit verification step; metadata
itself is not cryptographically signed.

The diagnostic directory must be directly under the repository root and may
not be a symlink. Existing artifacts for the same source prefix are preserved;
the generator refuses to overwrite or reuse them. A deliberate retry requires
reviewing the prior evidence and choosing a fresh committed source revision.
Do not silently delete or rename existing evidence to make a check pass.

On success, the build retains the existing `git add`/`git commit` behavior for
only the generated diagnostic paths; it never pushes. A failure after source
validation can leave and commit a JSON error report with no `.logd` reference.
That error report is not a successful encrypted bundle. Git hooks, if configured
in the caller's checkout, can still run during that Git commit; review checkout
configuration before running a build. The diagnostic CI gate is unchanged.

## Privacy and JSON previews

Only Python version, OS name, machine architecture, and CPU count are explicitly
collected for `system-info.txt`. There is no `df`, `uname`, environment dump, or
out-of-repository file collection. Known repository/home/temp paths, machine
and user identities, and common labelled credentials are redacted from the full
log, summary, and JSON output. This is not a guarantee against arbitrary secrets
printed by a compiler or dependency script. Inspect decrypted contents before
publishing, especially because the decryption key is public.

Each module's JSON `output` is a UTF-8 preview of at most 16 KiB.
`output_truncated` states whether it is shortened, `output_byte_count` is the
full redacted output length, and `full_output` is `build.log` only when an
actual encrypted artifact exists. Full output remains in the encrypted log;
these metadata previews do not relax the archive size limits.

## Decrypting and verifying

Use a new output directory; do not use or execute the old Encryptly binary:

```sh
python tools/safe_logd.py unpack diagnostic/build-12345678.logd /path/to/new-output \
  --metadata diagnostic/build-12345678.json
```

Archives larger than `DIAGNOSTIC_CHUNK_SIZE` retain the existing ordered
`-part001.logd`, `-part002.logd`, ... convention. The default chunk size is 40 MiB
and the v1 payload cap is lower, so default builds currently produce one file.
If a deployment deliberately lowers the chunk size, concatenate exactly the
JSON-listed parts in order to a new file before running the unpack command.
Do not include unrelated diagnostic files with a broad glob.

Verify that the decrypted set is exactly the three required files, compare the
full source IDs and module results, and compare UTF-8 lengths and SHA-256 hashes
against the metadata. The generator also performs a real encrypt/decrypt
round-trip before splitting and committing its output.
