import os, re, io, csv, json, uuid, hashlib, hmac, secrets, mimetypes
from datetime import datetime, timezone
from pathlib import Path
from flask import Flask, render_template, request, jsonify, send_file
from werkzeug.utils import secure_filename
from dotenv import load_dotenv

load_dotenv()
app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = int(os.getenv("MAX_UPLOAD_MB", "25")) * 1024 * 1024
ROOT = Path(__file__).resolve().parent
UPLOAD_DIR, OUTPUT_DIR = ROOT / "uploads", ROOT / "outputs"
UPLOAD_DIR.mkdir(exist_ok=True); OUTPUT_DIR.mkdir(exist_ok=True)
ALLOWED = {".txt", ".csv", ".xlsx", ".xls", ".pdf", ".docx", ".json", ".md"}
SUPABASE_URL = os.getenv("SUPABASE_URL", "").rstrip("/")
SUPABASE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY", "").strip()
SUPABASE_BUCKET = os.getenv("SUPABASE_BUCKET", "masked-files")
PII_HMAC_KEY = os.getenv("PII_HMAC_KEY", "").encode()

# Detection is deliberately conservative. This is a useful baseline, not a guarantee of perfect PII discovery.
PATTERNS = [
    ("EMAIL", re.compile(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b")),
    ("AADHAAR", re.compile(r"(?<!\d)(?:\d{4}[\s-]?\d{4}[\s-]?\d{4})(?!\d)")),
    ("PAN", re.compile(r"(?i)\b[A-Z]{5}\d{4}[A-Z]\b")),
    ("PHONE", re.compile(r"(?<!\w)(?:\+?91[\s-]?)?[6-9]\d{9}(?!\w)|(?<!\d)\+?\d[\d\s().-]{8,}\d(?!\d)")),
    ("CREDIT_CARD", re.compile(r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)")),
    ("IP_ADDRESS", re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")),
    ("DATE_OF_BIRTH", re.compile(r"(?i)\b(?:DOB|date of birth|birth date)\s*[:=-]?\s*(?:\d{1,2}[/-]\d{1,2}[/-]\d{2,4}|\d{4}[/-]\d{1,2}[/-]\d{1,2})\b")),
    ("SSN", re.compile(r"(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)")),
]
def is_luhn(s):
    digits = re.sub(r"\D", "", s)
    if not 13 <= len(digits) <= 19: return False
    total, parity = 0, len(digits) % 2
    for i, ch in enumerate(digits):
        n = int(ch)
        if i % 2 == parity:
            n *= 2
            if n > 9: n -= 9
        total += n
    return total % 10 == 0

def detect(text, selected=None):
    selected = set(selected or [x[0] for x in PATTERNS])
    found = []
    for kind, pattern in PATTERNS:
        if kind not in selected: continue
        for m in pattern.finditer(text or ""):
            value = m.group(0)
            if kind == "CREDIT_CARD" and not is_luhn(value): continue
            if kind == "AADHAAR" and len(re.sub(r"\D", "", value)) != 12: continue
            found.append({"start": m.start(), "end": m.end(), "type": kind, "value": value})
    # Longest-first conflict resolution; then restore reading order.
    found.sort(key=lambda x: (x["start"], -(x["end"]-x["start"])))
    out, end = [], -1
    for item in found:
        if item["start"] >= end:
            out.append(item); end = item["end"]
    return out

def mask_text(text, selected=None, mode="placeholder"):
    hits = detect(text, selected)
    for h in reversed(hits):
        replacement = f"[{h['type']}_MASKED]" if mode == "placeholder" else ("*" * max(4, len(h["value"])-4) + h["value"][-4:])
        text = text[:h["start"]] + replacement + text[h["end"]:]
    return text, hits

def supabase_request(method, path, **kwargs):
    if not SUPABASE_URL or not SUPABASE_KEY: return None, "Supabase credentials are not configured."
    import requests
    headers = kwargs.pop("headers", {})
    headers.update({"apikey": SUPABASE_KEY, "Authorization": f"Bearer {SUPABASE_KEY}", "Content-Type": "application/json"})
    try:
        r = requests.request(method, SUPABASE_URL + path, headers=headers, timeout=20, **kwargs)
        if r.status_code >= 400: return None, f"Supabase returned HTTP {r.status_code}: {r.text[:300]}"
        return (r.json() if r.text else {}), None
    except Exception as e: return None, f"Supabase connection failed: {str(e)[:200]}"

def save_record(record):
    # Metadata only; never store the original uploaded file.
    result, err = supabase_request("POST", "/rest/v1/masking_jobs", json=record, headers={"Prefer":"return=minimal"})
    return not bool(err), err

def process_file(src_path, original_name, selected, mode):
    ext = Path(original_name).suffix.lower()
    hits = []
    output_path = OUTPUT_DIR / (uuid.uuid4().hex + "_masked" + ext)
    if ext in {".txt", ".md", ".json"}:
        raw = src_path.read_text(encoding="utf-8", errors="replace")
        masked, hits = mask_text(raw, selected, mode)
        output_path.write_text(masked, encoding="utf-8")
    elif ext == ".csv":
        with src_path.open("r", encoding="utf-8-sig", errors="replace", newline="") as f:
            sample = f.read(4096); f.seek(0)
            try: dialect = csv.Sniffer().sniff(sample, delimiters=",;\t|")
            except csv.Error: dialect = csv.excel
            rows = list(csv.reader(f, dialect))
        for row in rows:
            for i, cell in enumerate(row):
                masked, found = mask_text(cell, selected, mode); row[i] = masked; hits.extend(found)
        with output_path.open("w", encoding="utf-8", newline="") as f: csv.writer(f).writerows(rows)
    elif ext in {".xlsx", ".xls"}:
        if ext == ".xls": raise ValueError("Legacy .xls files are not supported. Save as .xlsx and upload again.")
        from openpyxl import load_workbook
        wb = load_workbook(src_path)
        for ws in wb.worksheets:
            for row in ws.iter_rows():
                for cell in row:
                    if isinstance(cell.value, str):
                        masked, found = mask_text(cell.value, selected, mode)
                        cell.value = masked; hits.extend(found)
        wb.save(output_path)
    elif ext == ".docx":
        from docx import Document
        doc = Document(src_path)
        def mask_paragraph(p):
            nonlocal hits
            # Replacing paragraph text preserves paragraph formatting less precisely than run-level replacement.
            original = p.text
            masked, found = mask_text(original, selected, mode)
            if found:
                hits.extend(found)
                if p.runs:
                    p.runs[0].text = masked
                    for run in p.runs[1:]: run.text = ""
                else: p.add_run(masked)
        for p in doc.paragraphs: mask_paragraph(p)
        for table in doc.tables:
            for row in table.rows:
                for cell in row:
                    for p in cell.paragraphs: mask_paragraph(p)
        doc.save(output_path)
    elif ext == ".pdf":
        import fitz
        doc = fitz.open(src_path)
        for page in doc:
            text = page.get_text()
            page_hits = detect(text, selected)
            # Match each detected string to page text positions; redaction is irreversible.
            for h in page_hits:
                value = h["value"]
                for rect in page.search_for(value):
                    page.add_redact_annot(rect, fill=(0, 0, 0))
                    hits.append(h)
            page.apply_redactions()
        doc.save(output_path, garbage=4, deflate=True)
        doc.close()
    else:
        raise ValueError("Unsupported file type.")
    return output_path, hits

@app.get("/")
def index():
    return render_template("index.html", supabase_url=SUPABASE_URL, publishable_key=os.getenv("SUPABASE_PUBLISHABLE_KEY", ""))

@app.get("/api/health")
def health():
    return jsonify({"status":"ok", "supabase_configured":bool(SUPABASE_URL and SUPABASE_KEY), "max_upload_mb":int(os.getenv("MAX_UPLOAD_MB","25"))})

@app.post("/api/mask")
def mask():
    if "file" not in request.files: return jsonify(error="Choose a file first."), 400
    f = request.files["file"]
    if not f.filename: return jsonify(error="Choose a file first."), 400
    original_name = secure_filename(f.filename)
    ext = Path(original_name).suffix.lower()
    if ext not in ALLOWED: return jsonify(error="Unsupported file. Use CSV, XLSX, PDF, DOCX, TXT, MD or JSON."), 400
    job_id = uuid.uuid4().hex
    source = UPLOAD_DIR / f"{job_id}{ext}"
    f.save(source)
    selected = request.form.getlist("types") or [x[0] for x in PATTERNS]
    mode = request.form.get("mode", "placeholder")
    try:
        output_path, hits = process_file(source, original_name, selected, mode)
        stable_output = OUTPUT_DIR / f"{job_id}_masked{ext}"
        output_path.replace(stable_output)
        output_path = stable_output
        # Save only metadata and masked-output file in Supabase Storage (never the source).
        storage_path = None
        storage_error = None
        if SUPABASE_URL and SUPABASE_KEY:
            try:
                import requests
                object_name = f"{job_id}/{secure_filename(Path(original_name).stem)}_masked{ext}"
                data = output_path.read_bytes()
                headers = {"apikey":SUPABASE_KEY, "Authorization":f"Bearer {SUPABASE_KEY}", "Content-Type":mimetypes.guess_type(output_path.name)[0] or "application/octet-stream", "x-upsert":"false"}
                r = requests.post(f"{SUPABASE_URL}/storage/v1/object/{SUPABASE_BUCKET}/{object_name}", headers=headers, data=data, timeout=45)
                if r.status_code < 400: storage_path = object_name
                else: storage_error = f"Storage HTTP {r.status_code}: {r.text[:200]}"
            except Exception as e: storage_error = str(e)[:200]
        record = {
            "job_id":job_id, "original_filename":original_name, "output_filename":f"{Path(original_name).stem}_masked{ext}",
            "file_type":ext.lstrip("."), "detected_count":len(hits),
            "detected_types":sorted(set(h["type"] for h in hits)), "mask_mode":mode,
            "storage_path":storage_path, "created_at":datetime.now(timezone.utc).isoformat()
        }
        db_ok, db_error = save_record(record) if SUPABASE_URL and SUPABASE_KEY else (False, "Supabase service role key not configured.")
        return jsonify({
            "job_id":job_id, "filename":record["output_filename"], "download_url":f"/api/download/{job_id}",
            "detected_count":len(hits), "detected_types":record["detected_types"],
            "saved_to_supabase":bool(storage_path and db_ok), "storage_saved":bool(storage_path),
            "metadata_saved":db_ok, "storage_error":storage_error, "database_error":db_error,
            "note":"Detection is pattern-based. Review the output before sharing; scanned PDFs and image-only documents require OCR and may contain undetected PII."
        })
    except Exception as e:
        return jsonify(error=f"Could not process file: {str(e)[:300]}"), 400
    finally:
        try: source.unlink(missing_ok=True)
        except Exception: pass

@app.get("/api/download/<job_id>")
def download(job_id):
    # Job ID is random; output file path is selected from known generated files only.
    matches = list(OUTPUT_DIR.glob(f"{job_id}_masked*"))
    if not matches:
        # The output filename includes a random prefix, and job IDs are distinct; find by stored map is not persistent.
        return jsonify(error="This download has expired or the file is unavailable. Re-process the file."), 404
    return send_file(matches[0], as_attachment=True, download_name=matches[0].name)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "5000")), debug=False)
