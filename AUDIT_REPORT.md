# Secure Coding Audit Report: `samples/vulnerable_app.py`

- **Generated:** 2026-11-16
- **Tool:** `secure_code_auditor.py` (Aegis Code Audit Standalone CLI — Python `ast.parse` + Regex Rules)
- **Total Findings:** 5

## Summary Table

| Severity | Count |
| --- | ---: |
| Critical | 4 |
| High | 1 |
| Medium | 0 |
| Low | 0 |
| **Total** | **5** |

## Detailed Findings

### 1. [CRITICAL] Hardcoded Secret or Credential

- **File & Line:** `vulnerable_app.py:5`
- **Engine:** AST
- **CWE:** CWE-798
- **OWASP Category:** A07:2021 Identification and Authentication Failures
- **Recommendation:** Load credentials dynamically at runtime from environment variables or a managed secret store.

**Vulnerable Code:**
```python
DB_PASSWORD = "insecure-dev-password-123"
```

**Secure Fix Code:**
```python
DB_PASSWORD = os.environ["DB_PASSWORD"]
```

### 2. [CRITICAL] SQL Injection via Dynamic Query Construction

- **File & Line:** `vulnerable_app.py:12`
- **Engine:** AST
- **CWE:** CWE-89
- **OWASP Category:** A03:2021 Injection
- **Recommendation:** Use parameterized queries with bound placeholders (%s or ?) so the database driver separates SQL code from data.

**Vulnerable Code:**
```python
cursor.execute(query)
```

**Secure Fix Code:**
```python
cursor.execute("SELECT * FROM users WHERE name = %s", (username,))
```

### 3. [CRITICAL] OS Command Injection via Shell Execution

- **File & Line:** `vulnerable_app.py:17`
- **Engine:** AST
- **CWE:** CWE-78
- **OWASP Category:** A03:2021 Injection
- **Recommendation:** Replace shell execution with subprocess.run([...], shell=False) using an explicit argument list and allowlist validation.

**Vulnerable Code:**
```python
os.system("ping -c 1 " + host)
```

**Secure Fix Code:**
```python
subprocess.run(["ping", "-c", "1", validated_host], shell=False, check=True)
```

### 4. [CRITICAL] Python Dynamic Code Execution (eval / exec)

- **File & Line:** `vulnerable_app.py:25`
- **Engine:** AST
- **CWE:** CWE-95
- **OWASP Category:** A03:2021 Injection
- **Recommendation:** Replace eval() with ast.literal_eval() for safe literals, json.loads() for structured data, or an explicit operation map.

**Vulnerable Code:**
```python
return eval(input())
```

**Secure Fix Code:**
```python
result = ast.literal_eval(user_expr)
```

### 5. [HIGH] Weak Cryptographic Hash (MD5 / SHA-1)

- **File & Line:** `vulnerable_app.py:21`
- **Engine:** AST
- **CWE:** CWE-328
- **OWASP Category:** A02:2021 Cryptographic Failures
- **Recommendation:** Use Argon2id or bcrypt for passwords, and SHA-256 or HMAC-SHA256 for integrity digests.

**Vulnerable Code:**
```python
return hashlib.md5(raw_password.encode()).hexdigest()
```

**Secure Fix Code:**
```python
digest = hashlib.sha256(data.encode()).hexdigest()  # Use bcrypt/argon2 for passwords
```

## Secure coding recommendations

1. **Eliminate hardcoded secrets:** Load database credentials, API keys, and signing tokens from environment variables or Google Cloud Secret Manager (`os.environ`).
2. **Use parameterized database queries:** Always pass bound parameter tuples/arrays (`%s`, `?`, `$1`) instead of string concatenation or f-strings.
3. **Avoid shell execution and dynamic code evaluation:** Replace `os.system()` / `shell=True` with `subprocess.run([...], shell=False)`, and replace `eval()` with `ast.literal_eval()` or `json.loads()`.
4. **Upgrade legacy cryptography:** Replace MD5/SHA-1 with Argon2id or `bcrypt` for password hashing, and SHA-256/HMAC-SHA256 for data integrity.
