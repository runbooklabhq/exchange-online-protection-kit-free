<#
 Exchange Online Protection Kit: Top 5 - read-only checks (Runbook Lab)
 Read-only: Get-* cmdlets and DNS lookups only. Changes nothing in your tenant.
 Requires: ExchangeOnlineManagement module (3.x). DNS checks use Resolve-DnsName (Windows PowerShell 5.1 or PowerShell 7 on Windows).
 Connect first:
   Connect-ExchangeOnline
   Connect-IPPSSession   # only for the alert policy check (EX20)
 Role: Global Reader, Security Reader or View-Only Organization Management is enough for these reads.
 Output: .\hardening-check-results.csv (ID, Control, Status, Output).
#>
$ErrorActionPreference = 'Stop'
$results = @()
function Invoke-Check($Id, $Title, [scriptblock]$Block) {
  try { $o = & $Block | Out-String -Width 400; $s = 'OK' } catch { $o = $_.Exception.Message; $s = 'ERROR' }
  Write-Host "[$Id] $Title -> $s"
  $script:results += [pscustomobject]@{ ID = $Id; Control = $Title; Status = $s; Output = $o.Trim() }
}

Invoke-Check 'EX01' 'Turn on the Standard preset security policy for all users (Strict for priority accounts)' { foreach ($n in 'Standard Preset Security Policy','Strict Preset Security Policy') { foreach ($r in @(Get-EOPProtectionPolicyRule -Identity $n -ErrorAction SilentlyContinue)) { "EOP | $n | State: $($r.State) | domains: $(@($r.RecipientDomainIs) -join ',') | groups: $(@($r.SentToMemberOf) -join ',')" }; foreach ($r in @(Get-ATPProtectionPolicyRule -Identity $n -ErrorAction SilentlyContinue)) { "MDO | $n | State: $($r.State)" } }; "Rules only exist after a preset was turned on once in the portal. No output above = presets never enabled." }
Invoke-Check 'EX02' 'Block automatic forwarding to external addresses and review the forwards that already exist' { Get-HostedOutboundSpamFilterPolicy | ForEach-Object { "$($_.Name) | AutoForwardingMode: $($_.AutoForwardingMode)" }; $f = Get-Mailbox -ResultSize Unlimited | Where-Object { $_.ForwardingSmtpAddress -or $_.ForwardingAddress }; "Mailboxes with a forward: $(@($f).Count)"; $f | Select-Object -First 50 | ForEach-Object { "$($_.UserPrincipalName) -> $($_.ForwardingSmtpAddress)$($_.ForwardingAddress)" } }
Invoke-Check 'EX03' 'Publish SPF and turn on DKIM signing for every domain that sends mail' { Get-DkimSigningConfig | ForEach-Object { "$($_.Name) | Enabled: $($_.Enabled) | Status: $($_.Status) | key bits: $($_.Selector1KeySize)/$($_.Selector2KeySize)" }; foreach ($d in (Get-AcceptedDomain).DomainName) { $t = (Resolve-DnsName -Type TXT -Name $d -ErrorAction SilentlyContinue | Where-Object { $_.Strings -match '^v=spf1' }).Strings -join ' '; "SPF $d : $(if ($t) { $t } else { 'NO SPF RECORD' })" } }
Invoke-Check 'EX04' 'Publish DMARC for every domain and move it from p=none to p=reject' { foreach ($d in (Get-AcceptedDomain).DomainName) { $t = (Resolve-DnsName -Type TXT -Name "_dmarc.$d" -ErrorAction SilentlyContinue | Where-Object { $_.Strings -match '^v=DMARC1' }).Strings -join ' '; "DMARC $d : $(if ($t) { $t } else { 'NO DMARC RECORD' })" } }
Invoke-Check 'EX05' 'Anti-malware: common attachments filter on with Reject, zero-hour auto purge on, admin-only quarantine' { Get-MalwareFilterPolicy | ForEach-Object { "$($_.Name) | EnableFileFilter: $($_.EnableFileFilter) | FileTypeAction: $($_.FileTypeAction) | ZapEnabled: $($_.ZapEnabled) | QuarantineTag: $($_.QuarantineTag) | file types: $(@($_.FileTypes).Count)" } }

$results | Export-Csv -NoTypeInformation -Encoding UTF8 .\hardening-check-results.csv
Write-Host "Done: $($results.Count) checks -> hardening-check-results.csv"
