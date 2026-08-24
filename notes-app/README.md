# Synthetic notes target

This is a deliberately vulnerable Flask application used as the runtime target for
`aisec`. It is a test fixture, not a production service. Every user, note, attachment,
and secret-like value is synthetic.

The target binds to loopback only. Its intentionally unsafe file behavior is confined
to this directory's `data/` tree, and its URL-fetching behavior is confined to loopback
HTTP services. Do not change those containment boundaries or expose this app on a
network.

## Run it

From the repository root:

```bash
python3 -m venv .venv
.venv/bin/pip install -r notes-app/requirements.txt
./notes-app/run.py
```

The API listens on `http://127.0.0.1:5000`. Set `NOTES_APP_PORT` to use another local
port. Each launch rebuilds `notes-app/instance/notes.sqlite3` from fixed seed data, so
scans always begin with the same state.

Check that it is ready:

```bash
curl http://127.0.0.1:5000/health
```

## Test identities

Authenticated routes expect an `X-User` header. The two seeded identities are `alice`
and `bob`; there are no passwords or real credentials.

```bash
curl -H 'X-User: alice' http://127.0.0.1:5000/api/notes

curl -X POST \
  -H 'Content-Type: application/json' \
  -H 'X-User: alice' \
  -d '{"title":"Demo note","body":"Synthetic content only"}' \
  http://127.0.0.1:5000/api/notes
```

The API provides note listing, creation, lookup, search, metadata, attachment download,
and link-preview operations. Some behavior is deliberately insecure and some merely
looks insecure. The exact map is kept out of this directory so a source-scanning agent
must investigate and demonstrate its conclusions rather than reading an answer key.

## Test the fixture

```bash
.venv/bin/pytest tests/notes_app
```

These tests intentionally assert both the vulnerable behavior and the safe controls.
If a vulnerability is accidentally fixed, broadened beyond its containment boundary,
or duplicated in a control route, the fixture tests should fail.
