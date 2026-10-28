# Exchange Online Protection Kit: Top 5

_Version 1.0 (2026-10-28; facts re-read on Microsoft Learn 2026-10-28; validated: quality gate, read-only guard, syntax check, Excel recalc)_

Five Exchange Online protection controls to put in place first: the Standard preset security policy (Strict for priority accounts), automatic external forwarding blocked, SPF and DKIM for every sending domain, DMARC on its way to p=reject, and the anti-malware attachment filter with zero-hour auto purge. Free. Each control has why, steps, impact, rollback, a read-only PowerShell check, how to verify, licence, effort and the Microsoft Learn page it is based on.

Read-only checks: run `exchange-online-protection-kit-top-5-readonly-checks.ps1` (read-only, changes nothing).

| # | Control | Area | Sprint | Priority | Effort |
|---|---|---|---|---|---|
| EX01 | Turn on the Standard preset security policy for all users (Strict for priority accounts) | Preset policies and baseline | Sprint 1 - Baseline | Highest | 2 h |
| EX02 | Block automatic forwarding to external addresses and review the forwards that already exist | Outbound mail and forwarding | Sprint 1 - Baseline | Highest | 2 h |
| EX03 | Publish SPF and turn on DKIM signing for every domain that sends mail | Email authentication (SPF, DKIM, DMARC) | Sprint 2 - Authenticate your domains | Highest | 3 h |
| EX04 | Publish DMARC for every domain and move it from p=none to p=reject | Email authentication (SPF, DKIM, DMARC) | Sprint 2 - Authenticate your domains | High | 1 h set-up + 4 to 8 weeks monitoring |
| EX05 | Anti-malware: common attachments filter on with Reject, zero-hour auto purge on, admin-only quarantine | Preset policies and baseline | Sprint 1 - Baseline | High | 30 min |

## EX01. Turn on the Standard preset security policy for all users (Strict for priority accounts)

**Why:** Preset security policies apply Microsoft's recommended anti-spam, anti-malware and anti-phishing settings (and, with Defender for Office 365, Safe Links, Safe Attachments and impersonation protection) without hand-tuning dozens of settings. Standard and Strict are assigned to nobody until you turn them on, and they take precedence over custom policies for the same recipients.

**Steps:**
1. Defender portal > Email & collaboration > Policies & rules > Threat policies > Preset security policies. Turn on Standard protection and assign it to all recipients (for example all accepted domains).
2. Turn on Strict protection for a group of priority accounts (executives, finance, admins). Strict wins over Standard for users in both.
3. In the Defender for Office 365 step, add up to 350 users and 50 custom domains to impersonation protection and list trusted senders that must never be flagged.
4. Write down any custom anti-spam or anti-phishing policies that target the same users: presets override them, so either retire them or exclude those users from the preset on purpose.

**Impact:** Spam goes to Junk under Standard and to quarantine under Strict; high confidence phishing and malware go to quarantine that only admins can release. Expect a few legitimate bulk senders to move to Junk in the first week.

**Rollback:** Turn the preset off (the recipient conditions are kept) or add the affected users as exceptions. The default policies still protect everyone in the meantime.

**Check (read-only PowerShell):**

```powershell
foreach ($n in 'Standard Preset Security Policy','Strict Preset Security Policy') { foreach ($r in @(Get-EOPProtectionPolicyRule -Identity $n -ErrorAction SilentlyContinue)) { "EOP | $n | State: $($r.State) | domains: $(@($r.RecipientDomainIs) -join ',') | groups: $(@($r.SentToMemberOf) -join ',')" }; foreach ($r in @(Get-ATPProtectionPolicyRule -Identity $n -ErrorAction SilentlyContinue)) { "MDO | $n | State: $($r.State)" } }; "Rules only exist after a preset was turned on once in the portal. No output above = presets never enabled."
```

**Verify:** Standard preset rule State is Enabled and covers all accepted domains; Strict covers the priority group; Configuration analyzer shows no policy weaker than Standard for those users.

**Licence:** EOP parts: any Exchange Online plan. Safe Links, Safe Attachments and impersonation in the presets: Defender for Office 365 Plan 1 or 2 (Business Premium, E5 or add-on). · **Effort:** 2 h · **Priority:** Highest · **Sprint 1 - Baseline**

**Microsoft Learn:** https://learn.microsoft.com/en-us/defender-office-365/preset-security-policies · https://learn.microsoft.com/en-us/defender-office-365/recommended-settings-for-eop-and-office365

## EX02. Block automatic forwarding to external addresses and review the forwards that already exist

**Why:** Attackers who take over a mailbox add an inbox rule or mailbox forward to an outside address and read the mail quietly for months. Microsoft recommends AutoForwardingMode Off in the outbound spam policy for both Standard and Strict. The default Automatic value behaves differently from tenant to tenant, so Microsoft advises setting On or Off explicitly.

**Steps:**
1. List mailboxes that forward today (ForwardingSmtpAddress or ForwardingAddress set) and inbox rules that forward or redirect. Ask each owner whether the forward is still needed.
2. Defender portal > Threat policies > Anti-spam > Anti-spam outbound policy (Default) > Forwarding rules: set Automatic forwarding rules to Off - Forwarding is disabled.
3. For approved business forwards, create a custom outbound spam policy with forwarding On, scoped to those senders only, and limit the destination with a remote domain.
4. Tell the helpdesk about the NDR users will see: 5.7.520 Access denied, Your organization does not allow external forwarding.

**Impact:** Users who forward mail to personal or partner mailboxes get an NDR. Internal forwarding is not affected.

**Rollback:** Set the default outbound policy back to the previous value, or add the user to a custom outbound policy with forwarding On.

**Check (read-only PowerShell):**

```powershell
Get-HostedOutboundSpamFilterPolicy | ForEach-Object { "$($_.Name) | AutoForwardingMode: $($_.AutoForwardingMode)" }; $f = Get-Mailbox -ResultSize Unlimited | Where-Object { $_.ForwardingSmtpAddress -or $_.ForwardingAddress }; "Mailboxes with a forward: $(@($f).Count)"; $f | Select-Object -First 50 | ForEach-Object { "$($_.UserPrincipalName) -> $($_.ForwardingSmtpAddress)$($_.ForwardingAddress)" }
```

**Verify:** The Default outbound policy shows AutoForwardingMode Off; every remaining forward is in a named custom policy with an owner; a test inbox rule forwarding outside the tenant returns 5.7.520.

**Licence:** Any Exchange Online plan (EOP). · **Effort:** 2 h · **Priority:** Highest · **Sprint 1 - Baseline**

**Microsoft Learn:** https://learn.microsoft.com/en-us/defender-office-365/outbound-spam-policies-external-email-forwarding · https://learn.microsoft.com/en-us/defender-office-365/recommended-settings-for-eop-and-office365

## EX03. Publish SPF and turn on DKIM signing for every domain that sends mail

**Why:** Receiving servers, Microsoft 365 included, use SPF and DKIM to decide whether mail that claims to be from your domain is real. DMARC (EX04) needs at least one of them to pass and align. Microsoft recommends -all in the SPF record and DKIM signing with your own domain so the signing domain matches the From address.

**Steps:**
1. List every accepted domain and every service that sends as it (Microsoft 365, CRM, marketing, ticketing, scanners). Move bulk senders to a subdomain where you can.
2. Publish one SPF TXT record per sending domain, for example v=spf1 include:spf.protection.outlook.com -all plus the other senders. Stay under 10 DNS lookups. Domains that never send mail get v=spf1 -all.
3. For each custom domain: copy Selector1CNAME and Selector2CNAME from Get-DkimSigningConfig, publish both CNAME records (selector1._domainkey, selector2._domainkey), then turn on signing in the Defender portal (Email authentication settings > DKIM).
4. Rotate 1024-bit keys to 2048 with Rotate-DkimSigningConfig -KeySize 2048 (takes effect after 96 hours; rotate a second time to move the other selector).

**Impact:** None for users if every sending service is listed. A service missing from SPF and not DKIM-signing will start failing once DMARC moves past p=none.

**Rollback:** DKIM: turn signing off for the domain (Microsoft then signs with the onmicrosoft domain). SPF: restore the previous TXT record (keep a copy before you change it).

**Check (read-only PowerShell):**

```powershell
Get-DkimSigningConfig | ForEach-Object { "$($_.Name) | Enabled: $($_.Enabled) | Status: $($_.Status) | key bits: $($_.Selector1KeySize)/$($_.Selector2KeySize)" }; foreach ($d in (Get-AcceptedDomain).DomainName) { $t = (Resolve-DnsName -Type TXT -Name $d -ErrorAction SilentlyContinue | Where-Object { $_.Strings -match '^v=spf1' }).Strings -join ' '; "SPF $d : $(if ($t) { $t } else { 'NO SPF RECORD' })" }
```

**Verify:** Every custom sending domain has exactly one SPF record ending in -all and DKIM Enabled True with Status Valid; a test message shows spf=pass and dkim=pass with header.d=<your domain> in Authentication-Results.

**Licence:** Any Exchange Online plan. DNS changes at your registrar or DNS host. · **Effort:** 3 h · **Priority:** Highest · **Sprint 2 - Authenticate your domains**

**Microsoft Learn:** https://learn.microsoft.com/en-us/defender-office-365/email-authentication-spf-configure · https://learn.microsoft.com/en-us/defender-office-365/email-authentication-dkim-configure

## EX04. Publish DMARC for every domain and move it from p=none to p=reject

**Why:** SPF and DKIM alone do not stop someone sending mail with your domain in the From address. DMARC tells receivers what to do when both fail. Microsoft's goal for every custom domain and subdomain is p=reject, reached step by step with aggregate reports so good mail is not rejected along the way.

**Steps:**
1. Create a dedicated mailbox or Microsoft 365 group (or a DMARC reporting service) for aggregate reports. Publish _dmarc TXT v=DMARC1; p=none; pct=100; rua=mailto:<that address> on each sending domain.
2. Read the reports for 2 to 4 weeks. Fix every legitimate source that fails both SPF and DKIM alignment (EX03).
3. Move to p=quarantine (optionally with pct=10, 25, 50, 75, 100), then to p=reject. Do subdomains first and the parent domain last.
4. Domains that never send mail, and the onmicrosoft.com domain if you do not send from it, get v=DMARC1; p=reject; straight away (the onmicrosoft record is added in the Microsoft 365 admin center > Domains > DNS records).

**Impact:** At p=quarantine and p=reject, mail from services that fail both SPF and DKIM alignment lands in Junk or is rejected by receivers. Nothing changes for inbound mail to your users.

**Rollback:** Lower the policy (p=reject to p=quarantine or p=none) in DNS. Receivers pick it up within the record TTL.

**Check (read-only PowerShell):**

```powershell
foreach ($d in (Get-AcceptedDomain).DomainName) { $t = (Resolve-DnsName -Type TXT -Name "_dmarc.$d" -ErrorAction SilentlyContinue | Where-Object { $_.Strings -match '^v=DMARC1' }).Strings -join ' '; "DMARC $d : $(if ($t) { $t } else { 'NO DMARC RECORD' })" }
```

**Verify:** Every accepted domain returns a DMARC record; sending domains are at p=reject (or on a dated plan to get there); parked domains and onmicrosoft.com are at p=reject; aggregate reports arrive daily.

**Licence:** Any plan. DNS changes only. · **Effort:** 1 h set-up + 4 to 8 weeks monitoring · **Priority:** High · **Sprint 2 - Authenticate your domains**

**Microsoft Learn:** https://learn.microsoft.com/en-us/defender-office-365/email-authentication-dmarc-configure

## EX05. Anti-malware: common attachments filter on with Reject, zero-hour auto purge on, admin-only quarantine

**Why:** Most malware still arrives as an attachment type no business sends by mail (.exe, .iso, .js and similar). Microsoft's Standard and Strict values turn on the common attachments filter with Reject with NDR, zero-hour auto purge (ZAP) to pull malware out of mailboxes after delivery, and the AdminOnlyAccessPolicy quarantine policy so users cannot release malware themselves.

**Steps:**
1. Defender portal > Threat policies > Anti-malware > Default (Default) > Edit protection settings: tick Enable the common attachments filter, choose Reject the message with a non-delivery receipt, keep the default file types and add any others you never accept.
2. Tick Enable zero-hour auto purge for malware and set Quarantine policy to AdminOnlyAccessPolicy.
3. If a business process really needs a blocked file type (for example .iso from one vendor), use a shared upload location instead of an exception in the policy.

**Impact:** Senders of blocked attachment types get an NDR. Users cannot release quarantined malware; requests go to the admin.

**Rollback:** Untick the filter or remove a single file type from the list. ZAP can be turned off per policy.

**Check (read-only PowerShell):**

```powershell
Get-MalwareFilterPolicy | ForEach-Object { "$($_.Name) | EnableFileFilter: $($_.EnableFileFilter) | FileTypeAction: $($_.FileTypeAction) | ZapEnabled: $($_.ZapEnabled) | QuarantineTag: $($_.QuarantineTag) | file types: $(@($_.FileTypes).Count)" }
```

**Verify:** Every anti-malware policy shows EnableFileFilter True, FileTypeAction Reject, ZapEnabled True and QuarantineTag AdminOnlyAccessPolicy.

**Licence:** Any Exchange Online plan (EOP). · **Effort:** 30 min · **Priority:** High · **Sprint 1 - Baseline**

**Microsoft Learn:** https://learn.microsoft.com/en-us/defender-office-365/recommended-settings-for-eop-and-office365

---
Not affiliated with or endorsed by Microsoft. Test every change in Report-only or on a pilot group first. Licence names and portal paths change; check Microsoft Learn if a menu has moved.
