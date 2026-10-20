# Veil — Smart PII Masking (Flask + Supabase)

A responsive HTML/CSS/JavaScript frontend with a Flask API. Supports TXT, MD, JSON, CSV, XLSX, DOCX and text-based PDFs. It masks common pattern-based identifiers and can upload masked outputs plus job metadata to a private Supabase project.

## Important limitations (read before production)
- **No PII detector is perfect.** This baseline detects patterns such as email, phone, Aadhaar-like 12-digit values, PAN, Luhn-valid payment-card numbers, IPv4, labeled DOB and US SSN. It does not reliably identify names, addresses, free-form sensitive details, or every locale-specific ID.
- **Scanned/image-only PDFs are not OCR'd.** Text-based PDF redaction is approximate; PDF text search can miss split text, ligatures, unusual fonts, and overlapping matches. Inspect output before sharing.
- XLSX cell text is masked, but formulas, comments, hidden sheets, metadata, embedded images and linked objects are not comprehensively scrubbed. DOCX run formatting may change in paragraphs containing matches; headers/footers and embedded objects are not comprehensively scrubbed.
- The current interface reports aggregate counts, not a detailed review/redaction audit UI. Use human review before sharing sensitive documents.
- The download endpoint is intended for a single-process demo. For multi-worker/production deployments, replace the ephemeral output lookup with a database-backed job/output mapping or direct authenticated object retrieval. Most hosts have ephemeral local disk.
- Do not store or log original files. This app deletes temporary source files after processing, but masked outputs remain in the local outputs folder until cleaned up; configure a scheduled cleanup or use private object storage for production.

## 1. Run locally
Python 3.11+ recommended.

```bash
python -m venv .venv
# Windows PowerShell:
.venv\Scripts\Activate.ps1
# macOS/Linux:
source .venv/bin/activate
pip install -r requirements.txt
copy .env.example .env   # Windows
# cp .env.example .env   # macOS/Linux
python app.py
```
Open http://127.0.0.1:5000

## 2. Configure Supabase
Project URL configured by environment variable `SUPABASE_URL`. The public publishable key is not a secret, but **it cannot safely authorize privileged server-side writes**. Configure `SUPABASE_SERVICE_ROLE_KEY` as a secret environment variable in your host. Never put it in HTML, JS, a public repository, or a client-side bundle. If it was ever exposed, rotate it in Supabase.

1. Open Supabase SQL Editor.
2. Run `supabase_schema.sql`.
3. In your deployment environment set:
   - `SUPABASE_URL=https://onpgahywhveksleripxc.supabase.co`
   - `SUPABASE_PUBLISHABLE_KEY=sb_publishable_OYGdRC1anbWtZ6IZJ9pLOA_mdv1_0qN` (optional for this server-rendered UI)
   - `SUPABASE_SERVICE_ROLE_KEY=...` (required for privileged DB and private Storage writes)
   - `SUPABASE_BUCKET=masked-files`
   - `PII_HMAC_KEY=` a long random secret (reserved for future deterministic tokenization; current masking does not use it).
4. Keep the Storage bucket private.

If no service role key is configured, masking and downloading still work, but Supabase persistence is disabled and the UI explains that.

## 3. Deploy
### Render (Docker)
- Push this folder to a private GitHub repository.
- Create a Render Blueprint from `render.yaml` or create a Docker web service using this Dockerfile.
- Add the environment variables above in the Render dashboard. Do not commit `.env`.
- Run `supabase_schema.sql` once in Supabase.
- Verify `/api/health`, upload a synthetic test file, download the result and verify the Supabase table and private bucket.

### Other Docker host
```bash
docker build -t veil-pii-masking .
docker run --rm -p 5000:5000 --env-file .env veil-pii-masking
```

## Security checklist before real personal data
- Set an upload size limit and HTTPS.
- Add authentication, per-user authorization, rate limiting, CSRF protection if using cookie sessions, malware scanning and retention cleanup.
- Avoid public links to masked outputs; use authenticated downloads and private object storage.
- Review outputs manually; test with representative data and false-positive/false-negative cases.
- Keep secrets in host secret manager and rotate if exposed.
- Consider a dedicated DLP/NER/OCR pipeline for names, addresses, scanned PDFs and context-dependent PII.

## Supported files
| Type | Processing |
|---|---|
| TXT / MD / JSON | Text replacement |
| CSV | Cell-by-cell replacement |
| XLSX | String cell values; not a full workbook sanitization |
| DOCX | Paragraph/table text replacement |
| PDF | Redaction annotations for searchable text; scanned PDFs not supported without OCR |
| XLS | Rejected; convert to XLSX |

## API
- `GET /api/health`
- `POST /api/mask` multipart form fields: `file`, one or more `types`, and `mode` (`placeholder` or `partial`)
- `GET /api/download/<job_id>` (see production note above)
"# pii-masking" 
"# pii-masking" 
