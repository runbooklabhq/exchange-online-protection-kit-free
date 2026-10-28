# Exchange Online Protection Kit: Top 5 (free)

Most Microsoft 365 tenants need the same five email protection controls first: the Standard preset security policy for everyone (Strict for priority accounts), automatic forwarding to outside addresses blocked, SPF and DKIM for every domain that sends mail, DMARC on its way to p=reject, and the anti-malware attachment filter with zero-hour auto purge. This kit checks those five and turns them into a project.

| File | What it is |
|---|---|
| `exchange-online-protection-kit-top-5-guide.md` | Why, steps, impact, rollback, check, verify, licence, effort and the Microsoft Learn source for each control |
| `exchange-online-protection-kit-top-5-jira-import.csv` | Jira Cloud import: epics + stories with parent links, priority, sprint and labels |
| `exchange-online-protection-kit-top-5-tracker.csv` | Same backlog for Planner, Azure DevOps, Excel or Linear |
| `exchange-online-protection-kit-top-5-project-plan.xlsx` | Excel project plan for teams without Jira: owner, dates, status drop-down, % complete and a progress dashboard |
| `exchange-online-protection-kit-top-5-readonly-checks.ps1` | Get-* cmdlets and DNS lookups only. Changes nothing. Writes `hardening-check-results.csv` |

| # | Control |
|---|---|
| EX01 | Turn on the Standard preset security policy for all users (Strict for priority accounts) |
| EX02 | Block automatic forwarding to external addresses and review the forwards that already exist |
| EX03 | Publish SPF and turn on DKIM signing for every domain that sends mail |
| EX04 | Publish DMARC for every domain and move it from p=none to p=reject |
| EX05 | Anti-malware: common attachments filter on with Reject, zero-hour auto purge on, admin-only quarantine |

## Run the checks
```powershell
Connect-ExchangeOnline
./exchange-online-protection-kit-top-5-readonly-checks.ps1
```
Global Reader, Security Reader or View-Only Organization Management is enough. Needs the ExchangeOnlineManagement module. The SPF and DMARC checks use Resolve-DnsName, so run them on Windows.

## Scope and limits
- Built from Microsoft Learn pages re-read on 28 October 2026 (links in the guide). Validated before release: every control has why, steps, impact, rollback, verify, licence and a Learn source; the script contains read commands only and passes our syntax check (brackets, quotes, sub-expressions); the Excel plan recalculates with no errors. If a check misreads your setup, open an issue.
- EOP settings work with any Exchange Online plan. Safe Links, Safe Attachments and impersonation protection in the presets need Defender for Office 365 (Business Premium, E5 or the add-on).
- The Complete kit adds 15 controls: inbound and outbound anti-spam values, spoof and DMARC handling, impersonation protection, Safe Attachments and Safe Links, quarantine policies, user-reported messages, allow list hygiene, the External tag, mail flow rules that bypass filtering, SMTP AUTH Basic auth (off by default from end of December 2026, MC786329), priority accounts and a monthly Configuration analyzer review.

## Complete kit
All 20 controls (anti-spam and outbound limits, spoof and DMARC handling, impersonation, Safe Links, Safe Attachments, quarantine, user-reported messages, SMTP AUTH, priority accounts, monthly review) plus a policy map and an 8-week DMARC plan: https://runbooklab.gumroad.com/l/exchange-online-protection-kit?utm_source=github&utm_campaign=exo-free-repo

MIT licence. Not affiliated with or endorsed by Microsoft. Use alongside Microsoft's Configuration analyzer and Secure Score, not instead of them.
