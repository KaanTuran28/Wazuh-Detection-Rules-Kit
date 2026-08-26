# Durum Günlüğü

> En üstteki kayıt en güncelidir. Her çalışma sonrası buraya kısa bir not düşülür.

---

## 2026-08-20 — Paketleme, JSON çıktı ve lint eklendi

- Konu: `pyproject.toml` ile pip kurulabilir hale getirildi (`pip install -e .` → `validate-wazuh-rules` komutu), `--format json` eklendi (hem validate hem simulate modunda), ruff lint + CI'a ayrı lint job'u eklendi.
- Durum: ✅ 8/8 test geçiyor (2 yeni JSON-shape testi dahil), `ruff check .` temiz, `pip install -e .` + CLI komutu + `pip uninstall` gerçekten denendi ve başarılı.

**Sıradaki iş:** GitHub'da `Wazuh-Detection-Rules-Kit` adıyla repo aç, git init + push.

---

## 2026-08-20 — İlk sürüm oluşturuldu

- Konu: 3 custom Wazuh rule XML dosyası (SSH brute-force korelasyonu, web saldırı tespiti, host anomali tespiti), `validate_rules.py` (linter + simülatör), 8 threat-hunting sorgusu ve örnek loglar hazırlandı.
- Durum: ✅ Çalışıyor, test edildi. `validate --mode validate` 8 kuralı hatasız geçiyor, `--mode simulate` her iki örnek logda da beklenen kuralları doğru tetikliyor. 6/6 pytest testi geçiyor.

**Sıradaki iş:** GitHub'da `Wazuh-Detection-Rules-Kit` adıyla repo aç, git init + push.
