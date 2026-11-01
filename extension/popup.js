// AuthenticLayer — إضافة المتصفّح (نموذج أوّلي)
// تتّصل بخادم التحقّق المحلي لختم المحتوى والتحقّق منه.

const API = "http://127.0.0.1:8000";

document.getElementById("go").addEventListener("click", async () => {
  const content = document.getElementById("c").value;
  const out = document.getElementById("out");
  out.textContent = "جارٍ الختم…";
  try {
    const signRes = await fetch(`${API}/sign`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ handle: "extension-user", content }),
    });
    const signed = await signRes.json();

    const vRes = await fetch(`${API}/verify`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        content,
        stamp: signed.stamp,
        public_key_pem: signed.public_key_pem,
      }),
    });
    const v = await vRes.json();

    // نصّ آمن: نستخدم textContent في الأسفل — لا HTML قابل للتنفيذ.
    out.textContent = `بصمة المفتاح: ${signed.fingerprint}\n${v.reason}`;
  } catch (e) {
    out.textContent = "تعذّر الاتصال بالخادم. شغّل الخادم أولًا.";
  }
});
