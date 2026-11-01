"""
AuthenticLayer - خادم التحقّق
واجهة بسيطة تُصدر الأختام وتتحقّق منها عبر الإنترنت.

تشغيل:
    pip install -r requirements.txt
    uvicorn api.server:app --reload --host 127.0.0.1 --port 8000
    ثم افتح  http://127.0.0.1:8000/verify
"""

import html
import os
import sys

from fastapi import FastAPI, Form
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

sys.path.append(os.path.join(os.path.dirname(__file__), "..", "core"))
from authentic_core import (  # noqa: E402
    human_attestation, issue_identity, sign_content, verify_content, fingerprint,
)

app = FastAPI(title="AuthenticLayer Verify API", version="0.1.0")

HERE = os.path.dirname(__file__)
VERIFY_HTML = os.path.join(HERE, "..", "verify", "index.html")

# متجر تجريبي في الذاكرة (للعرض فقط). في الإنتاج: قاعدة بيانات + إدارة مفاتيح آمنة.


class SignRequest(BaseModel):
    handle: str
    content: str


class VerifyRequest(BaseModel):
    content: str
    stamp: dict
    public_key_pem: str


@app.get("/", response_class=HTMLResponse)
def index():
    return "<h3>AuthenticLayer API</h3><p>اذهب إلى <a href='/verify'>/verify</a></p>"


@app.post("/sign")
def sign(req: SignRequest):
    att = human_attestation(req.handle)
    priv, pub = issue_identity()
    stamp = sign_content(req.content.encode(), priv, att)
    return {
        "stamp": stamp,
        "public_key_pem": pub.decode(),
        "fingerprint": fingerprint(pub),
        "note": "المفتاح السرّي لم يُخزَّن ولم يُرسَل — هذا مبدأ التصميم.",
    }


@app.post("/verify")
def verify(req: VerifyRequest):
    return verify_content(req.content.encode(), req.stamp, req.public_key_pem.encode())


@app.get("/verify", response_class=HTMLResponse)
def verify_page():
    with open(VERIFY_HTML, encoding="utf-8") as f:
        return f.read()


@app.post("/sign-and-verify", response_class=HTMLResponse)
def sign_and_verify(content: str = Form(...), handle: str = Form("demo@user")):
    att = human_attestation(handle)
    priv, pub = issue_identity()
    stamp = sign_content(content.encode(), priv, att)
    result = verify_content(content.encode(), stamp, pub)

    ok = result["valid"]
    color = "#2ea043" if ok else "#f85149"
    status = "✅ حقيقي" if ok else "❌ غير موثّق"

    # ملاحظة أمنية: كل النصوص المدخلة تُمرَّر عبر html.escape — لا HTML/سكربت قابل للتنفيذ.
    return f"""<!doctype html><html lang='ar' dir='rtl'><head><meta charset='utf-8'>
    <title>نتيجة التحقّق</title>
    <style>body{{font-family:system-ui;background:#0d1117;color:#e6edf3;max-width:680px;margin:56px auto;padding:0 20px}}
    .card{{padding:20px;border-radius:10px;background:#161b22;border:1px solid #30363d}}
    .badge{{font-size:20px;font-weight:700;color:{color}}}
    a{{color:#58a6ff}}</style></head><body>
    <h1>🛡️ نتيجة التحقّق</h1>
    <div class='card'>
      <div class='badge'>{html.escape(status)}</div>
      <p><b>السبب:</b> {html.escape(result['reason'])}</p>
      <p><b>معرّف مجهول:</b> {html.escape(att['attestation_id'])}</p>
      <p><b>بصمة المفتاح العام:</b> {html.escape(fingerprint(pub))}</p>
      <p><b>هل يوجد إنسان موثّق؟</b> {html.escape(str(result['is_human']))}</p>
    </div>
    <p><a href='/verify'>← العودة وتجربة أخرى</a></p>
    </body></html>"""
