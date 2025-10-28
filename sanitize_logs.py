import csv, hashlib, os
from pathlib import Path
from datetime import datetime

SRC_DIR = Path("typing_logs")         # change if your logs are elsewhere
DST_DIR = Path("sanitized_samples")
DST_DIR.mkdir(exist_ok=True)

def hash_val(s):
    return hashlib.sha256(s.encode("utf-8")).hexdigest()[:12]

for csvfile in SRC_DIR.glob("*.csv"):
    out = DST_DIR / f"sanitized_{csvfile.name}"
    with csvfile.open(newline='', encoding='utf-8') as inf, out.open("w", newline='', encoding='utf-8') as outf:
        reader = csv.DictReader(inf)
        fieldnames = ["session_hash", "timestamp_rounded", "key_sym", "char_redacted"]
        writer = csv.DictWriter(outf, fieldnames=fieldnames)
        writer.writeheader()
        for r in reader:
            sid = r.get("session_id","")
            ts = r.get("timestamp_iso","")
            # parse/round timestamp to minute
            ts_parsed = None
            try:
                ts_parsed = datetime.fromisoformat(ts.replace("Z","+00:00"))
                ts_round = ts_parsed.replace(second=0, microsecond=0).isoformat()
            except Exception:
                ts_round = ""
            key_sym = r.get("key_sym","")
            char = r.get("char","")
            # redact actual characters (replace letters with '*', keep nothing or indicate type)
            if char and char.strip():
                char_redacted = "<CHAR>"
            else:
                char_redacted = ""
            writer.writerow({
                "session_hash": hash_val(sid) if sid else "",
                "timestamp_rounded": ts_round,
                "key_sym": key_sym,
                "char_redacted": char_redacted
            })
    print("Wrote:", out)
print("Sanitization complete. Inspect files in sanitized_samples/ before pushing.")
