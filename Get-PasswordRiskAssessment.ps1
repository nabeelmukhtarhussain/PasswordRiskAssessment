<#
.SYNOPSIS
    Entra ID Password & Account Risk Assessment.
    Finds accounts that are genuinely at risk - leaked credentials, no MFA,
    stale/never-expiring passwords, inactive-but-enabled - scores them, and
    (optionally) emails the flagged users to change & strengthen their password.

    NOTE: This tool does NOT read, guess, or test passwords. That is impossible
    in Entra ID (passwords are hashed) and password-spraying is an attack, not an
    assessment. Instead it uses Microsoft's own risk signals, which is safer and
    far more effective.

.USAGE
    # Read-only assessment (default):
    .\Get-PasswordRiskAssessment.ps1

    # Also email flagged users (asks for confirmation first):
    .\Get-PasswordRiskAssessment.ps1 -SendNotifications -NotifyFrom security@contoso.com

.WHAT IT CHECKS
    - Leaked credential detection (Entra ID Protection)   [needs Entra ID P2]
    - Risky user level/state                              [needs Entra ID P2]
    - MFA registration                                    [any tenant]
    - Password age / "password never expires"            [any tenant]
    - Inactive but enabled accounts                       [needs AuditLog read]

.REMEDIATION TIP
    The real fix for "common passwords" is PREVENTION: enable Microsoft Entra
    Password Protection (Entra admin > Protection > Authentication methods >
    Password protection) and add a custom banned-password list. That blocks weak
    passwords at the moment users set them - no cracking required.

.NOTES
    Requires: Microsoft.Graph, ImportExcel modules (auto-installed).
    Sign in as a Security Reader / Global Reader (read-only) or higher.
    Notifications require Mail.Send and an explicit -SendNotifications switch.
    Pilot on a small scope before tenant-wide use.
#>

param(
    [int]$StalePasswordDays = 365,     # password older than this = flagged
    [int]$InactiveDays      = 90,      # no sign-in for this long = flagged
    [switch]$SendNotifications,        # OFF by default (read-only)
    [string]$NotifyFrom                # mailbox to send notifications from
)

$ErrorActionPreference = "Stop"
foreach ($m in "Microsoft.Graph.Authentication","Microsoft.Graph.Users","Microsoft.Graph.Identity.SignIns","Microsoft.Graph.Reports","ImportExcel") {
    if (-not (Get-Module -ListAvailable $m)) {
        Write-Host "Installing $m..." -ForegroundColor Cyan
        Install-Module $m -Scope CurrentUser -Force -AllowClobber
    }
}
Import-Module Microsoft.Graph.Authentication, ImportExcel

# ---- Connect ----
$scopes = @("User.Read.All","AuditLog.Read.All","IdentityRiskyUser.Read.All","IdentityRiskEvent.Read.All")
if ($SendNotifications) { $scopes += "Mail.Send" }
Write-Host "Sign in (Security Reader / Global Reader is enough for assessment)..." -ForegroundColor Yellow
Connect-MgGraph -Scopes $scopes -NoWelcome

# ---- 1) Users ----
Write-Host "Reading users..." -ForegroundColor Cyan
$props = "id,displayName,userPrincipalName,accountEnabled,passwordPolicies,lastPasswordChangeDateTime,createdDateTime,signInActivity"
$users = Get-MgUser -All -Property $props -ConsistencyLevel eventual -CountVariable c |
         Select-Object Id,DisplayName,UserPrincipalName,AccountEnabled,PasswordPolicies,LastPasswordChangeDateTime,CreatedDateTime,
            @{n="LastSignIn";e={$_.SignInActivity.LastSignInDateTime}}
Write-Host "  $($users.Count) users." -ForegroundColor Green

# ---- 2) MFA registration (one report call) ----
Write-Host "Reading MFA registration state..." -ForegroundColor Cyan
$mfa = @{}
try {
    $reg = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/reports/authenticationMethods/userRegistrationDetails?`$top=999"
    foreach ($r in $reg.value) { $mfa[$r.id] = [bool]$r.isMfaRegistered }
    # page if needed
    while ($reg.'@odata.nextLink') {
        $reg = Invoke-MgGraphRequest -Method GET -Uri $reg.'@odata.nextLink'
        foreach ($r in $reg.value) { $mfa[$r.id] = [bool]$r.isMfaRegistered }
    }
} catch { Write-Host "  (MFA report unavailable: $($_.Exception.Message))" -ForegroundColor DarkYellow }

# ---- 3) Leaked credentials / risky users (P2) ----
Write-Host "Reading risk signals (Identity Protection)..." -ForegroundColor Cyan
$risk = @{}; $leaked = @{}
try {
    $ru = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/identityProtection/riskyUsers?`$top=500"
    foreach ($u in $ru.value) { $risk[$u.id] = $u.riskLevel }
    while ($ru.'@odata.nextLink') { $ru = Invoke-MgGraphRequest -Method GET -Uri $ru.'@odata.nextLink'; foreach ($u in $ru.value) { $risk[$u.id] = $u.riskLevel } }
} catch { Write-Host "  (Risky users unavailable - needs Entra ID P2)" -ForegroundColor DarkYellow }
try {
    $rd = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/identityProtection/riskDetections?`$filter=riskEventType eq 'leakedCredentials'&`$top=500"
    foreach ($d in $rd.value) { if ($d.userId) { $leaked[$d.userId] = $true } }
} catch { Write-Host "  (Leaked-credential detections unavailable - needs Entra ID P2)" -ForegroundColor DarkYellow }

# ---- 4) Score every account ----
$now = Get-Date
$rows = New-Object System.Collections.Generic.List[object]
foreach ($u in $users) {
    if (-not $u.AccountEnabled) { continue }   # skip disabled accounts

    $neverExpires = ($u.PasswordPolicies -match "DisablePasswordExpiration") -ne $null -and ("$($u.PasswordPolicies)" -like "*DisablePasswordExpiration*")
    $pwdAge = if ($u.LastPasswordChangeDateTime) { [int]($now - [datetime]$u.LastPasswordChangeDateTime).TotalDays } else { $null }
    $signInAge = if ($u.LastSignIn) { [int]($now - [datetime]$u.LastSignIn).TotalDays } else { $null }
    $hasMfa = if ($mfa.ContainsKey($u.Id)) { $mfa[$u.Id] } else { $false }
    $isLeaked = $leaked.ContainsKey($u.Id)
    $riskLevel = if ($risk.ContainsKey($u.Id)) { $risk[$u.Id] } else { "none" }

    $score = 0; $reasons = @()
    if ($isLeaked)                                   { $score += 50; $reasons += "Leaked credential" }
    if ($riskLevel -in @("high","medium"))           { $score += 30; $reasons += "Risk: $riskLevel" }
    if (-not $hasMfa)                                { $score += 25; $reasons += "No MFA" }
    if ($pwdAge -ne $null -and $pwdAge -gt $StalePasswordDays) { $score += 15; $reasons += "Password $pwdAge d old" }
    if ($neverExpires)                               { $score += 10; $reasons += "Never expires" }
    if ($signInAge -ne $null -and $signInAge -gt $InactiveDays) { $score += 10; $reasons += "Inactive $signInAge d" }

    $cat = if ($score -ge 70) { "Critical" } elseif ($score -ge 40) { "High" } elseif ($score -ge 20) { "Medium" } else { "Low" }

    $rows.Add([PSCustomObject]@{
        DisplayName=$u.DisplayName; UPN=$u.UserPrincipalName
        RiskScore=$score; Category=$cat
        LeakedCredential=$isLeaked; RiskLevel=$riskLevel; MFA=$hasMfa
        PasswordAgeDays=$pwdAge; NeverExpires=$neverExpires; InactiveDays=$signInAge
        Reasons=($reasons -join "; ")
    })
}

$sorted = $rows | Sort-Object RiskScore -Descending

# ---- 5) Excel ----
$xlsx = ".\PasswordRiskAssessment.xlsx"
try { if (Test-Path $xlsx) { Remove-Item $xlsx -Force -ErrorAction Stop } }
catch { $xlsx = ".\PasswordRiskAssessment_{0}.xlsx" -f (Get-Date -Format "yyyyMMdd_HHmmss") }
$xp = @{ AutoSize=$true; FreezeTopRow=$true; BoldTopRow=$true }
$sorted | Export-Excel -Path $xlsx -WorksheetName "All Accounts" -TableName "All" -TableStyle Medium2 @xp
$sorted | Where-Object { $_.Category -in "Critical","High" } |
    Export-Excel -Path $xlsx -WorksheetName "High Risk" -TableName "HighRisk" -TableStyle Medium3 @xp
$summary = [PSCustomObject]@{
    "Accounts assessed"=$rows.Count
    "Critical"=(@($rows|?{$_.Category -eq "Critical"}).Count)
    "High"=(@($rows|?{$_.Category -eq "High"}).Count)
    "Medium"=(@($rows|?{$_.Category -eq "Medium"}).Count)
    "Leaked credentials"=(@($rows|?{$_.LeakedCredential}).Count)
    "No MFA"=(@($rows|?{-not $_.MFA}).Count)
    "Password never expires"=(@($rows|?{$_.NeverExpires}).Count)
}
$summary | Export-Excel -Path $xlsx -WorksheetName "Summary" -Title "Password Risk Assessment" -TitleBold @xp

# ---- 6) Interactive console dashboard ----
function Bar($n,$max){ $w=[int](($n/[math]::Max($max,1))*24); "█"*$w }
$crit=@($rows|?{$_.Category -eq "Critical"}).Count
$high=@($rows|?{$_.Category -eq "High"}).Count
$med =@($rows|?{$_.Category -eq "Medium"}).Count
$mx=[math]::Max($crit,[math]::Max($high,$med))
Write-Host "`n  ╔══════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host   "  ║        PASSWORD RISK DASHBOARD                ║" -ForegroundColor Cyan
Write-Host   "  ╚══════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ("   Critical {0,4}  {1}" -f $crit,(Bar $crit $mx)) -ForegroundColor Red
Write-Host ("   High     {0,4}  {1}" -f $high,(Bar $high $mx)) -ForegroundColor Yellow
Write-Host ("   Medium   {0,4}  {1}" -f $med,(Bar $med $mx))  -ForegroundColor DarkYellow
Write-Host ("   Leaked creds: {0}   No MFA: {1}   Never-expire pwd: {2}" -f `
    (@($rows|?{$_.LeakedCredential}).Count),(@($rows|?{-not $_.MFA}).Count),(@($rows|?{$_.NeverExpires}).Count)) -ForegroundColor Gray
Write-Host "`n   Top 10 riskiest accounts:" -ForegroundColor Cyan
$sorted | Select-Object -First 10 | Format-Table @{n="Score";e={$_.RiskScore}},Category,UPN,Reasons -AutoSize | Out-String | Write-Host
Write-Host "   Full report: $xlsx`n" -ForegroundColor Cyan

# ---- 7) Optional notifications ----
if ($SendNotifications) {
    $targets = $sorted | Where-Object { $_.Category -in "Critical","High" }
    if (-not $NotifyFrom) { $NotifyFrom = Read-Host "From which mailbox should notifications be sent? (e.g. security@contoso.com)" }
    Write-Host "`nAbout to email $($targets.Count) high/critical users from $NotifyFrom." -ForegroundColor Yellow
    $confirm = Read-Host "Type YES to send"
    if ($confirm -eq "YES") {
        foreach ($t in $targets) {
            $bodyHtml = @"
<p>Hi $($t.DisplayName),</p>
<p>As part of a routine security review, your account has been flagged to <b>update your password</b>.</p>
<p>Please change it to a strong, unique passphrase (12+ characters, not reused anywhere) and make sure
multi-factor authentication is set up. You can update it here:
<a href="https://aka.ms/sspr">https://aka.ms/sspr</a>.</p>
<p>Thanks for helping keep our environment secure.<br>IT Security</p>
"@
            $msg = @{ message = @{
                subject = "Action needed: please update your password"
                body = @{ contentType = "HTML"; content = $bodyHtml }
                toRecipients = @(@{ emailAddress = @{ address = $t.UPN } })
            }; saveToSentItems = $true }
            try {
                Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/v1.0/users/$NotifyFrom/sendMail" -Body $msg
                Write-Host "  sent -> $($t.UPN)" -ForegroundColor Green
            } catch { Write-Host "  failed -> $($t.UPN): $($_.Exception.Message)" -ForegroundColor Red }
        }
    } else { Write-Host "Cancelled - no emails sent." -ForegroundColor DarkYellow }
}

Disconnect-MgGraph | Out-Null
