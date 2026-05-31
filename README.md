# TaskForge API Backend

This is a small working backend and browser app for the TaskForge items API.

It implements:

- `GET /v1/health`
- `POST /v1/auth/login`
- `GET /v1/me`
- `GET /v1/items`
- `POST /v1/items`
- `GET /v1/items/{id}`
- `PUT /v1/items/{id}`
- `PATCH /v1/items/{id}`
- `DELETE /v1/items/{id}`

## Run

```bash
python server.py
```

The server starts at:

```text
http://127.0.0.1:8000
```

You can open these directly in a browser:

```text
http://127.0.0.1:8000
http://127.0.0.1:8000/v1/health
http://127.0.0.1:8000/app
```

Demo login:

```text
Email: demo@taskforge.local
Password: demo123
```

API requests use bearer tokens returned by `/v1/auth/login`. For local development, this fallback token also works:

```text
Authorization: Bearer dev-token
```

## Login

```bash
curl -X POST http://127.0.0.1:8000/v1/auth/login \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"demo@taskforge.local\",\"password\":\"demo123\"}"
```

## Create An Item

```bash
curl -X POST http://127.0.0.1:8000/v1/items \
  -H "Authorization: Bearer dev-token" \
  -H "Content-Type: application/json" \
  -d "{\"name\":\"New Laptop\",\"description\":\"Top-spec developer laptop\",\"price\":2500.5,\"currency\":\"USD\",\"status\":\"active\",\"tags\":[\"hardware\",\"electronics\"]}"
```

## List Items

```bash
curl http://127.0.0.1:8000/v1/items \
  -H "Authorization: Bearer dev-token"
```

## Test

```bash
python -m unittest test_server.py
```

Data is saved locally in `%LOCALAPPDATA%\TaskForge\taskforge.db` using SQLite. If an old `items.json` file exists, its items are imported into SQLite once for the demo user.
