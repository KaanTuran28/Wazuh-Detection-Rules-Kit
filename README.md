# Wazuh Detection Rules Kit

![CI](https://github.com/KaanTuran28/Wazuh-Detection-Rules-Kit/actions/workflows/ci.yml/badge.svg)
![Python](https://img.shields.io/badge/python-3.9%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

<p align="center"><b><a href="#english">English</a></b> · <b><a href="#türkçe">Türkçe</a></b></p>

---

## English

A collection of custom [Wazuh](https://wazuh.com/) detection rules, a rule validator/simulator, and documented threat-hunting queries — built around real SOC use cases (SSH brute-force, common web attacks, host anomalies).

## Overview

Wazuh ships with a large built-in ruleset, but every environment needs custom rules tuned to its own logs and risk model. This kit provides:

- **Custom rules** (`rules/`) covering SSH brute-force correlation, common web attacks (SQLi/XSS/path traversal), and host anomalies (obfuscated PowerShell, unauthorized admin account creation).
- **`validate_rules.py`** — a standalone linter/simulator that checks rule hygiene (unique IDs, valid ranges, required fields) and can test standalone regex/match rules against a sample log without needing a running Wazuh manager.
- **Threat-hunting queries** (`queries/threat-hunting-queries.md`) — ready-to-run OpenSearch Query DSL snippets for hunting inside `wazuh-alerts-*`.

## Rule ID Convention

Wazuh reserves IDs `0-99999` for its built-in ruleset. All custom rules in this kit use IDs in the `100000-119999` range, as recommended by Wazuh documentation, to avoid collisions with built-in or third-party rulesets.

## Installation

Install the CLI locally (adds a `validate-wazuh-rules` command, no dependencies):

```bash
pip install -e .
```

To deploy the rules themselves on a Wazuh manager:

```bash
cp rules/*.xml /var/ossec/etc/rules/
/var/ossec/bin/wazuh-control restart
```

Then verify the new rules loaded correctly:

```bash
/var/ossec/bin/wazuh-logtest
```

## `validate_rules.py` Usage

**Validate mode** — structural linting of every file in `rules/` (well-formed XML, unique IDs, IDs in the `100000-119999` range, valid `level`, non-empty `description`). Exits non-zero if any error is found — safe to wire into CI before deploying rules to a manager.

```bash
python validate_rules.py --mode validate --rules-dir rules
# or, after `pip install -e .`:
validate-wazuh-rules --mode validate --rules-dir rules
```

**Simulate mode** — tests *standalone* rules (no `if_sid`/`if_matched_sid`/`frequency` correlation) against a sample log file, line by line, and reports which rule IDs would fire.

```bash
python validate_rules.py --mode simulate --rules-dir rules --log sample_logs/web_access_sample.log --output sample_report.md
```

Both modes accept `--format json` for machine-readable output (default is `markdown`):

```bash
python validate_rules.py --mode simulate --log sample_logs/web_access_sample.log --format json --output report.json
```

**Limitation:** correlated rules (e.g. the SSH brute-force chain in `ssh_bruteforce_rules.xml`, which relies on `if_sid`/`if_matched_sid`/`frequency`) cannot be simulated statically — they require Wazuh's real event-correlation engine (`wazuh-logtest` or a live manager) because their behavior depends on state accumulated across multiple events over time.

## Threat-Hunting Queries

See [`queries/threat-hunting-queries.md`](./queries/threat-hunting-queries.md) for 8 documented OpenSearch Query DSL queries: alert-level spikes per agent, password-spraying detection, off-hours admin logins, rare process command lines, new-geography logins, rare parent-child process pairs, and more.

## Project Structure

```
Wazuh-Detection-Rules-Kit/
├── rules/
│   ├── ssh_bruteforce_rules.xml     # correlated (if_sid/frequency) — simulation N/A
│   ├── web_attack_rules.xml         # standalone regex — simulatable
│   └── host_anomaly_rules.xml       # standalone regex — simulatable
├── queries/
│   └── threat-hunting-queries.md
├── sample_logs/
│   ├── web_access_sample.log
│   └── host_events_sample.log
├── validate_rules.py
├── pyproject.toml                   # pip install -e . -> `validate-wazuh-rules` command
├── sample_report.md                 # real output of --mode simulate against both sample logs
└── tests/
    └── test_validate_rules.py
```

## Testing

```bash
pip install -r requirements-dev.txt
ruff check .
pytest -v
```

## License

MIT — see [LICENSE](./LICENSE).

---

## Türkçe

[Wazuh](https://wazuh.com/) için özel tespit (detection) kurallarından, bir kural doğrulayıcı/simülatöründen ve belgelenmiş threat-hunting sorgularından oluşan bir koleksiyon — gerçek SOC kullanım senaryoları (SSH brute-force, yaygın web saldırıları, host anomalileri) etrafında inşa edilmiştir.

## Genel Bakış

Wazuh, büyük bir yerleşik (built-in) kural kümesiyle gelir, ancak her ortamın kendi loglarına ve risk modeline göre ayarlanmış özel kurallara ihtiyacı vardır. Bu kit şunları sağlar:

- **Özel kurallar** (`rules/`) — SSH brute-force korelasyonu, yaygın web saldırıları (SQLi/XSS/path traversal) ve host anomalilerini (gizlenmiş PowerShell, yetkisiz yönetici hesabı oluşturma) kapsar.
- **`validate_rules.py`** — kural hijyenini (benzersiz ID'ler, geçerli aralıklar, zorunlu alanlar) kontrol eden ve çalışan bir Wazuh manager'a ihtiyaç duymadan bağımsız (standalone) regex/eşleşme kurallarını bir örnek loga karşı test edebilen bağımsız bir linter/simülatör.
- **Threat-hunting sorguları** (`queries/threat-hunting-queries.md`) — `wazuh-alerts-*` içinde arama yapmak için hazır, çalıştırılabilir OpenSearch Query DSL parçacıkları.

## Kural ID Kuralı (Convention)

Wazuh, yerleşik kural kümesi için `0-99999` aralığındaki ID'leri ayırır. Bu kitteki tüm özel kurallar, Wazuh belgelerinin önerdiği şekilde, yerleşik veya üçüncü taraf kural kümeleriyle çakışmayı önlemek için `100000-119999` aralığındaki ID'leri kullanır.

## Kurulum

CLI'yi yerel olarak kurun (bağımlılık gerektirmeyen bir `validate-wazuh-rules` komutu ekler):

```bash
pip install -e .
```

Kuralların kendisini bir Wazuh manager üzerine dağıtmak için:

```bash
cp rules/*.xml /var/ossec/etc/rules/
/var/ossec/bin/wazuh-control restart
```

Ardından yeni kuralların doğru şekilde yüklendiğini doğrulayın:

```bash
/var/ossec/bin/wazuh-logtest
```

## `validate_rules.py` Kullanımı

**Validate modu** — `rules/` içindeki her dosyanın yapısal lint kontrolü (iyi biçimlendirilmiş XML, benzersiz ID'ler, `100000-119999` aralığında ID'ler, geçerli `level`, boş olmayan `description`). Herhangi bir hata bulunursa sıfır olmayan bir kodla çıkış yapar — kuralları bir manager'a dağıtmadan önce CI'ye bağlamak için güvenlidir.

```bash
python validate_rules.py --mode validate --rules-dir rules
# or, after `pip install -e .`:
validate-wazuh-rules --mode validate --rules-dir rules
```

**Simulate modu** — *bağımsız* kuralları (`if_sid`/`if_matched_sid`/`frequency` korelasyonu olmayan) bir örnek log dosyasına karşı satır satır test eder ve hangi kural ID'lerinin tetikleneceğini bildirir.

```bash
python validate_rules.py --mode simulate --rules-dir rules --log sample_logs/web_access_sample.log --output sample_report.md
```

Her iki mod da makine tarafından okunabilir çıktı için `--format json` kabul eder (varsayılan `markdown`'dır):

```bash
python validate_rules.py --mode simulate --log sample_logs/web_access_sample.log --format json --output report.json
```

**Sınırlama:** korelasyonlu kurallar (örn. `if_sid`/`if_matched_sid`/`frequency`'ye dayanan `ssh_bruteforce_rules.xml` içindeki SSH brute-force zinciri) statik olarak simüle edilemez — davranışları zaman içinde birden fazla olay üzerinde biriken duruma bağlı olduğundan Wazuh'un gerçek olay-korelasyon motorunu (`wazuh-logtest` veya canlı bir manager) gerektirirler.

## Threat-Hunting Sorguları

Ajan (agent) başına uyarı seviyesi sıçramaları, şifre spreyleme (password-spraying) tespiti, mesai dışı yönetici girişleri, nadir görülen process komut satırları, yeni coğrafyadan girişler, nadir görülen parent-child process çiftleri ve daha fazlasını kapsayan 8 belgelenmiş OpenSearch Query DSL sorgusu için [`queries/threat-hunting-queries.md`](./queries/threat-hunting-queries.md) dosyasına bakın.

## Proje Yapısı

```
Wazuh-Detection-Rules-Kit/
├── rules/
│   ├── ssh_bruteforce_rules.xml     # correlated (if_sid/frequency) — simulation N/A
│   ├── web_attack_rules.xml         # standalone regex — simulatable
│   └── host_anomaly_rules.xml       # standalone regex — simulatable
├── queries/
│   └── threat-hunting-queries.md
├── sample_logs/
│   ├── web_access_sample.log
│   └── host_events_sample.log
├── validate_rules.py
├── pyproject.toml                   # pip install -e . -> `validate-wazuh-rules` command
├── sample_report.md                 # real output of --mode simulate against both sample logs
└── tests/
    └── test_validate_rules.py
```

## Test

```bash
pip install -r requirements-dev.txt
ruff check .
pytest -v
```

## Lisans

MIT — bkz. [LICENSE](./LICENSE).

---
