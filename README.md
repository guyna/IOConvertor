# IOConvertor

Desktop tool that converts **TITAN** IOC files (the indicator exports distributed by the Israel National Cyber Directorate) into bulk-import files for:

| Target | Output file | How it is used |
|---|---|---|
| **CrowdStrike Falcon** | `CS_IOCs_YYYY-MM-DD.csv` | IOC Management → import CSV |
| **SentinelOne** | `S1_IOCs_YYYY-MM-DD.csv` | Blocklist → import CSV |
| **Rapid7 InsightIDR** | `R7_IOCs_YYYY-MM-DD.csv` | Values only — paste into the *All* tab |

Pick any combination of CS / S1 / R7 — only the selected files are generated.

## Usage

**With Python (3.10+)**

```
pip install -r requirements.txt
python app.py
```

or double-click `run.bat`.

**As a standalone EXE (Windows 64-bit)**

1. Run `build_exe.bat` once on a machine with Python.
2. Share `dist\TitanIOCConverter_Generic.exe` — no Python needed on other machines.
3. Windows SmartScreen may warn because the EXE is unsigned: *More info → Run anyway*.

**In the app**

1. **Output formats** — click the CS / S1 / R7 cards to turn each on or off. When S1 is on, set the **S1 Scope Path** for your site (default `Global`).
2. **TITAN files** — add CSV / XLSX / XLSB files or a whole folder.
3. **Generate** — files are written next to the app / EXE.

> Upload the generated CSVs as-is. Re-saving them in Excel can change values (e.g. `TRUE`, date formats).

## Conversion rules

**CrowdStrike**
- `sha256` → `prevent`; domain / hostname → `detect`; IPv4 / IPv6 → `detect`
- From a URL only an IP host is taken (no domain extraction)
- severity `HIGH`, platforms `windows,mac,linux`, applied_globally `TRUE`
- expiration = today + 3 months
- description = `Alert {event_id} - {event_info}`
- The same IOC across several alerts stays one row; the description lists every alert

**SentinelOne**
- Each SHA256 and each SHA1 → 3 rows (`windows`, `linux`, `osx`); SHA256 rows first
- `Scope=site`, `Scope Path=<from the app>`, `Source=user`
- MD5 / domains / IPs / URLs are not written to S1
- Duplicate hashes are kept once; the description lists every alert

**Rapid7**
- One column, no header row
- Domains, MD5, IPs, URLs (protocol fixed, brackets removed)
- SHA1 / SHA256 are not written to R7

**Defang cleanup**
- `[.]` `[:]` `[://]` `[@]` `[ ]` are restored / removed
- `hxxp` / `hxxps` → `http` / `https`
- URLs without a protocol get `https://`

## Input format

TITAN files are expected to have the columns `event_id`, `event_info`, `type`, `value` (header names are case-insensitive).
