# Aegis Code Audit — Secure Coding Review Workbench

A full-stack **Secure Coding Review & Static Application Security Testing (SAST)** platform designed for auditing Python, TypeScript/JavaScript, Go, and SQL applications against OWASP Top 10 and CWE security standards.

## Capabilities

- **Deterministic Multi-Language SAST Engine**: Scans source files line-by-line with intra-file variable taint tracking for SQL Injection (`CWE-89`), OS Command Injection (`CWE-78`), Hardcoded Secrets (`CWE-798`), Insecure Deserialization (`CWE-502`), XSS (`CWE-79`), Weak Cryptography (`CWE-328`, `CWE-338`), SSRF (`CWE-918`), Path Traversal (`CWE-22`), Prototype Pollution (`CWE-1321`), and Unverified JWTs (`CWE-347`).
- **Custom SAST Rule Authoring & Regex Test Bench**: Enable/disable built-in rules or author custom organization security rules with live regex validation.
- **Interactive Remediation & Diff Patching**: Inspect side-by-side vulnerable vs. secure patterns, generate context-aware patches via server-side Gemini API with automated model fallback, and apply patches directly to source files.
- **Deep Semantic Architecture Review**: Server-side LLM-assisted code review wrapped in strict prompt-injection isolation delimiters (`<untrusted_source_code>`).
- **Compliance Exports**: Download audit deliverables in **Markdown** (`.md`) and **SARIF 2.1.0** (`.sarif.json`) formats.

---

## Local Development

### 1. Prerequisites
- Node.js `v22+`
- Google Cloud SDK (`gcloud` CLI) and Firebase CLI (for cloud deployment)

### 2. Environment Setup
Copy `.env.example` to `.env` and configure your runtime secret:
```bash
cp .env.example .env
```

Install dependencies and run unit tests:
```bash
npm install
npx --yes tsx --test src/utils/sastEngine.test.ts
```

Start the unified full-stack development server on port `3000`:
```bash
npm run dev
```

Build and run production server:
```bash
npm run build
npm start
```

---

## Security & Cloud Deployment Guide (Google Cloud Run)

### 1. Enable Required Google Cloud APIs
```bash
gcloud services enable \
  run.googleapis.com \
  secretmanager.googleapis.com \
  firestore.googleapis.com
```

### 2. Secret Manager Setup & IAM Bindings
Never hardcode API keys or credentials in source code. Store `GEMINI_API_KEY` in Google Cloud Secret Manager and grant the Cloud Run runtime service account access:

```bash
# Create and populate the secret
gcloud secrets create GEMINI_API_KEY --replication-policy="automatic"
echo -n "YOUR_API_KEY" | gcloud secrets versions add GEMINI_API_KEY --data-file=-

# Grant the default Cloud Run service account access to read the secret
gcloud secrets add-iam-policy-binding GEMINI_API_KEY \
  --member="serviceAccount:YOUR_PROJECT_NUMBER-compute@developer.gserviceaccount.com" \
  --role="roles/secretmanager.secretAccessor"
```

### 3. Firestore Security Configuration (Optional Multi-User Cloud Persistence)
If deploying with Firebase Auth and Cloud Firestore, enforce strict owner-bound document isolation in `firestore.rules`:

```javascript
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /users/{userId}/interactions/{interactionId} {
      allow read, write: if request.auth != null && request.auth.uid == userId;
    }
  }
}
```

Deploy rules via Firebase CLI:
```bash
firebase deploy --only firestore:rules
```

### 4. Deploy to Google Cloud Run
```bash
gcloud run deploy aegis-code-audit \
  --source . \
  --region us-central1 \
  --allow-unauthenticated \
  --set-secrets="GEMINI_API_KEY=GEMINI_API_KEY:latest"
```

### 5. Required Campaign Verification Labeling
Apply the mandatory resource label to register the Cloud Run service:
```bash
gcloud run services update aegis-code-audit \
  --update-labels=dev-tutorial=cloud-run-ai-challenge \
  --region=us-central1
```
