# Entra ID Password & Account Risk Assessment

A single PowerShell tool that finds the accounts in a Microsoft 365 / Entra ID tenant that are genuinely at risk — **leaked credentials, no MFA, stale or never-expiring passwords, and inactive-but-enabled accounts** — scores them, shows a console dashboard, and exports a clean Excel report. Optionally, it can email the flagged users to update their password.

> It does **not** read, guess, or test passwords. That's impossible in Entra ID, and password-spraying is an attack, not an assessment. This tool uses Microsoft's own risk signals instead — safer and far more effective.

---

## What you get

A console risk dashboard, plus an Excel workbook (`PasswordRiskAssessment.xlsx`):

| Sheet | What's in it |
|-------|--------------|
| **Summary** | Totals — accounts assessed, Critical / High / Medium, leaked credentials, no MFA, never-expiring |
| **All Accounts** | Every enabled account with its risk score, category and the reasons it was flagged |
| **High Risk** | Just the Critical and High accounts, ready for action |

---

## Prerequisites

- **PowerShell 7** (run `pwsh`). The script uses Microsoft Graph, which works best on 7.
- A sign-in account with at least **Security Reader** or **Global Reader** (read-only is enough for the assessment).
- **Internet access** the first time, to install the modules.

> The modules (`Microsoft.Graph`, `ImportExcel`) install automatically on first run — you don't set anything up.

### Licensing note
- **Leaked credentials** and **risky user** signals need **Microsoft Entra ID P2**.
- If you don't have P2, those two columns are simply left blank — the **No MFA**, **password age**, **never-expires** and **inactive** checks still run on any tenant. The script skips gracefully, it doesn't crash.

---

## How to run it (read-only — safe)

1. Open **PowerShell 7** (`pwsh`).
2. Go to the folder with the script and run it:

```powershell
cd C:\Tools
.\Get-PasswordRiskAssessment.ps1
```

3. Sign in when the browser opens, and consent to the permissions on the first run.

When it finishes you'll find **`PasswordRiskAssessment.xlsx`** in the same folder, and a risk dashboard printed in the console.

---

## Options

### Email the flagged users (optional)
Off by default. When you add this, it emails High/Critical users asking them to update their password and enable MFA — and it asks you to type `YES` to confirm before sending anything.

```powershell
.\Get-PasswordRiskAssessment.ps1 -SendNotifications -NotifyFrom security@yourtenant.onmicrosoft.com
```
- `-NotifyFrom` — the mailbox the notifications are sent from
- This requires the `Mail.Send` permission

### Adjust the thresholds
```powershell
.\Get-PasswordRiskAssessment.ps1 -StalePasswordDays 180 -InactiveDays 60
```
- `-StalePasswordDays` — password older than this is flagged (default 365)
- `-InactiveDays` — no sign-in for this long is flagged (default 90)

---

## How the score works

Each enabled account earns points; the total sets its category.

| Signal | Points |
|--------|--------|
| Leaked credential detected | +50 |
| Risk level high / medium | +30 |
| No MFA registered | +25 |
| Password older than threshold | +15 |
| Password never expires | +10 |
| Inactive beyond threshold | +10 |

**Critical ≥ 70 · High ≥ 40 · Medium ≥ 20 · Low < 20**

---

## The real fix for weak passwords

Detection is half the job. To stop weak and common passwords from being set in the first place, turn on **Microsoft Entra Password Protection**:

> Entra admin center → **Protection → Authentication methods → Password protection** → enable enforcement and add a custom banned-password list.

It blocks weak passwords at the moment a user tries to set one — no cracking, no chasing.

---

## Things to keep in mind

- **Read-only by default.** Without `-SendNotifications`, the tool only reads — it changes nothing.
- **Pilot first.** Run it once and review the report before acting on a large tenant.
- **Disabled accounts are skipped** — only enabled accounts are scored.
- **Large tenants take longer** — it reads all users and their sign-in activity.

---

*Built for IT admins and migration consultants. Use it, share it, improve it.*
