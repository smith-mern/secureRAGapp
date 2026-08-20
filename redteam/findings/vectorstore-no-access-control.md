# No access control at the vector store (and no protection at rest)

**Severity:** High — full confidentiality bypass; every tier's content stored
unencrypted and readable from disk with no authentication.
**Attack:** [`redteam/attacks/vectorstore_no_access_control.py`](../attacks/vectorstore_no_access_control.py)
**Component:** `app/vectorstore.py` (`_collection`, the persistent Chroma store);
`data/chroma_db/`.

## Vulnerability

Authorization in this app lives entirely in the application layer.
`rag_chain.answer` computes a tier set and hands it to `vectorstore.query`,
which searches exactly the tiers it is given. The store underneath enforces
nothing:

- **Chroma has no auth.** `_collection(tier)` (vectorstore.py:42) is a plain
  function — `_get_client().get_or_create_collection(name=f"docs_{tier}")`. It
  takes no `User`, checks no clearance, and returns the `restricted` collection
  to any caller that names it. The tier scoping in `query()` is advisory: it
  binds only callers who go through it.
- **No protection at rest — every tier in the clear.** Chroma persists each
  chunk's text and metadata as plaintext in `data/chroma_db/chroma.sqlite3`,
  with no encryption at rest. It is not just the restricted tier: `public`,
  `internal`, and `restricted` collections all sit unencrypted in the same file,
  each row self-labelled with its `tier`. A raw `strings` of the file recovers
  readable content and JSON — which it could not do if the store were encrypted —
  so a filesystem read bypasses all tiering, not merely one tier's. This is a
  documented property of the design (see the `vectorstore` module docstring),
  surfaced here as a phase-2 finding.

The threat model is a **local / filesystem attacker**: anyone who can read the
`data/chroma_db/` directory (a stolen laptop, a backup, a shared host, a
container layer, an over-broad file permission), not a web client. The API's
login, tokens, roles, and clearances are all above the layer being read and do
not apply.

## Exploit

No account, no token, no running server. A single read of the SQLite file:

```
$ strings data/chroma_db/chroma.sqlite3 | grep -i -A1 northwind
...
{"tier":"restricted","source":"restricted/acquisition.md",
 "chroma:document":"Project Redwood: we intend to acquire Northwind Systems for 240 million."}
...
```

Or via the repeatable script:

```
$ python3 redteam/attacks/vectorstore_no_access_control.py
[*] reading data/chroma_db/chroma.sqlite3 directly — no auth, no app, no clearance
[*] recovered: Project Redwood: we intend to acquire Northwind Systems for 240 million dollars...
[!] BYPASS — restricted content read straight off disk (recovered: tier label,
    restricted source path, restricted body). App-side tier scoping never applied.
```

The recovered rows include the restricted document body, its `source`
(`restricted/acquisition.md`), and a self-describing `"tier":"restricted"` label —
so the attacker does not even have to guess which content is sensitive; the store
labels it. Equivalent access is available in-process without touching the file:
`vectorstore._collection("restricted").get()` returns the same chunks with no
`User` anywhere in the call.

The exposure is not confined to one tier. Enumerating the tier labels stored in
plaintext shows the whole corpus is unencrypted at rest:

```
$ strings data/chroma_db/chroma.sqlite3 | grep -o '"tier":"[a-z]*"' | sort | uniq -c
   ...  "tier":"internal"
   ...  "tier":"public"
   ...  "tier":"restricted"
$ strings data/chroma_db/chroma.sqlite3 | grep -iE 'refund window|hardware margin|Northwind'
The refund window for standard orders is 30 days from delivery. ...   # public
Gross margin on hardware was 42 percent this quarter ...              # internal
Project Redwood: we intend to acquire Northwind Systems for 240 million ...  # restricted
```

One line from each tier, all readable — the filesystem read bypasses tiering
wholesale, not just the restricted collection.

Note this is the floor under the other findings. The cross-tier retrieval leak,
source-name disclosure, and output-filter bypass are all *app-layer* leaks that a
config flag can close. This one is beneath the app entirely: no flag reaches it.

## Detection

The app cannot see this. `audit.log` records API events; a filesystem read of
`chroma.sqlite3` generates none, so a leak via this path leaves no trace in the
application's own telemetry — which is itself part of the finding. Detection has
to come from the layer the read actually happens at:

- OS-level file access auditing / EDR on `data/chroma_db/`.
- Access to the file by any principal other than the app's service user.
- Backup, snapshot, or image exfiltration containing `data/chroma_db/`.

Any alert here is out of band from the application logs the other findings rely
on.

## Mitigation

**Partial. The finding stays open.** The exposure is below the app's
authorization layer, so no code change in `vectorstore.py` can close it — the
attacker never calls the app. What code *can* do is set the perimeter the
operating system enforces, and the deployment was not even doing that.

`_get_client()` now chmods `CHROMA_DIR` to `0700` on every client build, not
only when it creates the directory, so an already-permissive store is tightened
rather than inherited:

```
before:  drwxr-xr-x  data/chroma_db          # 022 umask, world-readable
after:   drwx------  data/chroma_db
```

`chroma.sqlite3` stays `0644` and that is fine — a non-traversable parent makes
per-file modes moot for a different-user attacker, and narrowing the directory
is the whole of what the mode can buy.

**Second: document bodies and free-text metadata are encrypted at rest**
(`app/crypto.py`, wired into `vectorstore.add_chunks`/`query`). Embeddings are
computed from plaintext and passed to Chroma explicitly, so the stored body can
be ciphertext without breaking similarity search. Metadata is split by an
allowlist: the keys retrieval filters on (`source`, `tier`, `origin`,
`reviewed`, `content_hash`, …) stay readable because Chroma cannot match what it
cannot read; everything else — a connector `title` is a sentence out of the
document — is sealed.

Measured on this repo's own store, before and after, with the attack script that
defines this finding:

```
before:  [!] BYPASS — recovered: tier label, restricted source path, restricted body
         $ strings chroma.sqlite3 | grep -ci northwind   ->  69

after:   [!] BYPASS — recovered: tier label, restricted source path
         $ strings chroma.sqlite3 | grep -ci northwind   ->  0
```

The script still exits 0, and should: source paths and tier labels are still
recoverable, and they are still a disclosure. What it no longer recovers is the
text of the documents.

Construction is HMAC-SHA256 as a PRF in counter mode with encrypt-then-MAC under
a separately derived key — stdlib only, because adding `cryptography` means
regenerating `requirements.lock`, which is phase-3 supply-chain evidence.
`STORE_ENCRYPTION_KEY` is required at boot like the signing key; there is no
default, because a store that looks encrypted and is not is worse than one that
plainly is not. Both keys must clear `secrets.MIN_KEY_CHARS` (32): the store is
full of *authenticated* ciphertext, so a short key is testable offline against
the tag at whatever rate the attacker likes, with no rate limit and no log line.

### The first version of this shipped a retrieval DoS

Worth recording, because it is the failure this whole finding is about repeating
one layer up. Sealing originally skipped any value that already "looked
encrypted" — `value.startswith("v1:")` — so that `mark_reviewed` could rewrite
metadata without double-sealing it.

That made attacker input the input to a security decision. Anyone can file a
ticket upstream; a ticket titled `v1:AAAA` was read as already-encrypted, stored
in the clear, and then failed authentication on the way *out* — raising inside
`vectorstore.query`, before the unreviewed-content suppression that record should
have hit. One unauthenticated ticket broke every search that retrieved it, and
the document never had to be approved to do it.

The fix is not a better prefix check. Records now carry an explicit `enc` marker
alongside the other cleartext control keys, and that marker — how the record was
*written* — is the only thing that decides whether a value is decrypted on the
way out. `crypto.decrypt_if_needed` is gone and `is_ciphertext` is now private
`_has_prefix`, documented as a format check that must never be branched on.
Separately, a chunk that fails to decrypt is now dropped from the results and
logged (`store.decrypt` / `deny`) rather than raised on, so a single tampered or
half-migrated record withholds itself instead of failing the search.

Covered by `test_attacker_chosen_v1_prefix_does_not_escape_encryption` and
`test_a_corrupt_record_is_dropped_not_raised_on`.

### What this does not fix

- **The same user — and this is the whole finding.** The key lives in `.env`,
  which the app must read, so anything running as the app's account reads the
  key and decrypts everything. Encryption raises the bar for a *copy* of the
  store; it does nothing for the principal that owns it. There is no in-app fix,
  because the attacker never calls the app: adding a `User` argument to
  `_collection()` would be theatre, sidestepped by one
  `chromadb.PersistentClient(path=...)`. The controls are OS-level — run the app
  as its own service account, and keep the key out of the store's backup set.
- **Embeddings.** Vectors stay in the clear, because similarity search needs
  them, and they are partially invertible back toward their source text. Exact
  strings (an SSN, a card number, a dollar figure) no longer sit in the file; an
  approximate paraphrase is still derivable by an attacker who does the work.
- **Filterable metadata.** `source`, `tier`, and `origin` are readable by
  design, so the store still discloses that `restricted/acquisition.md` exists
  and which tier it is in. An attacker-chosen upload filename
  (`upload/public/redwood-refund-memo.md`) leaks whatever the uploader put in it.
- **Copies.** Backups, snapshots, and images carry their own permissions; `0700`
  says nothing about where the directory gets copied to. Encryption is what
  covers this case — provided the key is not copied alongside it.
- **Remanence.** VACUUM drops free pages but writes a *new* file rather than
  scrubbing the old one, and Chroma's `embeddings_queue` write-ahead log retains
  a full payload per operation with nothing pruning it. A store *migrated* onto
  encryption therefore still holds its pre-encryption plaintext in that log.
  Deleting `data/chroma_db/` and re-ingesting is how to lose that history —
  every chunk is reproducible from `data/documents/`, `data/uploads/`, and the
  connector, which is exactly how this store was rebuilt. Do not prune the queue
  by hand; the warning in `vectorstore.compact` records how that silently
  destroys the vector index.
- **Model and pipeline compromise.** Unchanged by any of this.

Net: a local account that is not the app's user loses `cat` access, and a stolen
copy of the store yields filenames and tiers instead of documents. The finding
stays open, which is why the README still lists it as having no in-app fix.
