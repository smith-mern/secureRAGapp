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

Deferred — to be written up in phase 3. Noted for now: there is **no in-app fix**,
because the exposure is below the app's authorization layer. The controls are
operational (filesystem permissions, encryption at rest, keeping the store off
shared/backed-up locations), not code changes to `vectorstore.py`. Full
treatment, and what still fails after those controls, goes in the phase-3 pass.
