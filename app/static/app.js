document.addEventListener("submit", (ev) => {
  const msg = ev.target.dataset && ev.target.dataset.confirm;
  if (msg && !window.confirm(msg)) ev.preventDefault();
});
document.addEventListener("click", async (ev) => {
  const btn = ev.target.closest("[data-copy]");
  if (!btn) return;
  const el = document.getElementById(btn.dataset.copy);
  try {
    await navigator.clipboard.writeText(el.textContent.trim());
    const old = btn.textContent; btn.textContent = "Đã chép ✓";
    setTimeout(() => (btn.textContent = old), 1500);
  } catch (e) {
    const r = document.createRange(); r.selectNodeContents(el);
    const s = window.getSelection(); s.removeAllRanges(); s.addRange(r);
  }
});
