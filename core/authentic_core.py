#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AuthenticLayer - النواة
توليد المفاتيح + توقيع المحتوى + التحقّق (بلا كشف بيانات شخصية).

يبني فوق معايير عالمية: Ed25519 (توقيع رقمي) + SHA-256 (بصمة).
لا نخترع تشفيرًا من الصفر.
"""

import base64
import hashlib
import json
from datetime import datetime, timezone

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey,
)
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature

STANDARD = "AuthenticLayer/0.1"


def b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# --- 1) بوابة الإنسانية (محاكاة). الواقع: برهان صفري المعرفة أو فحص حيوية. ---
def human_attestation(handle: str) -> dict:
    anon_id = hashlib.sha256((handle + "salt-demo").encode()).hexdigest()[:24]
    return {
        "attestation_id": anon_id,
        "is_human": True,
        "verified_at": now_iso(),
        "personal_data_stored": False,
    }


# --- 2) وحدة الإصدار ---
def issue_identity():
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return priv_pem, pub_pem


def fingerprint(pub_pem: bytes) -> str:
    return hashlib.sha256(pub_pem).hexdigest()[:16]


# --- 3) وحدة التوقيع ---
def sign_content(content: bytes, priv_pem: bytes, attestation: dict) -> dict:
    private_key = serialization.load_pem_private_key(priv_pem, password=None)
    manifest = {
        "standard": STANDARD,
        "content_sha256": hashlib.sha256(content).hexdigest(),
        "attestation": attestation,
        "issued_at": now_iso(),
        "generated_by_ai": False,
    }
    payload = json.dumps(manifest, sort_keys=True, ensure_ascii=False).encode()
    return {"manifest": manifest, "signature": b64(private_key.sign(payload))}


# --- 4) وحدة التحقّق ---
def verify_content(content: bytes, stamp: dict, pub_pem: bytes) -> dict:
    result = {"valid": False, "is_human": False, "generated_by_ai": None, "reason": ""}
    manifest = stamp.get("manifest", {})

    if hashlib.sha256(content).hexdigest() != manifest.get("content_sha256"):
        result["reason"] = "المحتوى عُدّل بعد الختم (تحطّم التوقيع)"
        return result

    payload = json.dumps(manifest, sort_keys=True, ensure_ascii=False).encode()
    public_key: Ed25519PublicKey = serialization.load_pem_public_key(pub_pem)
    try:
        public_key.verify(base64.urlsafe_b64decode(stamp["signature"] + "=="), payload)
    except InvalidSignature:
        result["reason"] = "التوقيع غير صالح"
        return result
    except Exception as e:
        result["reason"] = f"خطأ في التحقّق: {e}"
        return result

    result["valid"] = True
    result["is_human"] = bool(manifest.get("attestation", {}).get("is_human"))
    result["generated_by_ai"] = bool(manifest.get("generated_by_ai"))
    result["reason"] = "✅ أصلي وموثّق من إنسان"
    return result


def demo():
    print("=" * 62)
    print("  AuthenticLayer — عرض توضيحي")
    print("=" * 62)
    att = human_attestation("user@example")
    priv, pub = issue_identity()
    print(f"\n[1] معرّف مجهول        : {att['attestation_id']}")
    print(f"[2] بصمة المفتاح العام : {fingerprint(pub)}")
    content = "هذه صورة صحفية حقيقية التُقطت في الميدان.".encode()
    stamp = sign_content(content, priv, att)
    print(f"[3] ختم المحتوى: {stamp['manifest']['content_sha256'][:24]}...")
    print(f"[4] تحقّق الأصلي : {verify_content(content, stamp, pub)['reason']}")
    tampered = "هذه صورة مزيفة تم توليدها بالذكاء الاصطناعي.".encode()
    print(f"[5] تحقّق المعدّل: {verify_content(tampered, stamp, pub)['reason']}")


if __name__ == "__main__":
    demo()
