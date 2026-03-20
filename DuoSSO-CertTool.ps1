#Requires -RunAsAdministrator

# ================================================================
# DuoSSO LDAPS Certificate Tool
# Modes: Single DC | Multi-DC Primary | Multi-DC Secondary | Multi-DC Agent
# Full chain recreated on every run
# Backs up all certs before deletion with restore instructions
# ================================================================

# ----------------------------------------------------------------
# PREFLIGHT CHECKS
# ----------------------------------------------------------------
function Test-PreflightRequirements {
    param([string]$Mode = "Single")
    
    $errors = [System.Collections.Generic.List[string]]::new()
    
    # Check elevation
    $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object System.Security.Principal.WindowsPrincipal($currentUser)
    if (!$principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
        $errors.Add("Script requires Administrator elevation. Please run PowerShell as Administrator.")
    }
    
    # Check if system is a domain controller
    $isDC = (Get-WmiObject -Class Win32_ComputerSystem -ErrorAction SilentlyContinue).DomainRole -in @(4, 5)
    if (!$isDC -and $Mode -ne "Validation") {
        $errors.Add("This system does not appear to be a Domain Controller. NTDS, LDAPS binding, and DC-specific registry paths are not available.")
    }
    
    # Check for certutil
    if (!(Test-Path "C:\Windows\System32\certutil.exe")) {
        $errors.Add("certutil.exe not found. Certificate tools may not be available.")
    }
    
    # Check NTDS registry path exists on DC
    if ($isDC -and !(Test-Path "HKLM:\SOFTWARE\Microsoft\Cryptography\Services\NTDS")) {
        $errors.Add("NTDS registry path does not exist. This DC may not support certificate-based LDAPS binding.")
    }
    
    if ($errors.Count -gt 0) {
        Write-Host ""
        Write-Host "Preflight Check Failed:" -ForegroundColor Red
        $errors | ForEach-Object { Write-Host "  ✗ $_" -ForegroundColor Red }
        Write-Host ""
        exit 1
    }
}

# ----------------------------------------------------------------
# LOGGING + PATHS
# ----------------------------------------------------------------
$ScriptDir  = Split-Path -Path $PSCommandPath -Parent
$WorkingDir = (Get-Location).Path
$BackupDir  = Join-Path $WorkingDir "Backup"
$LogFile    = Join-Path $WorkingDir "DuoSSO-CertTool.log"
$RestoreLog = Join-Path $BackupDir "RESTORE-INSTRUCTIONS.log"

# Log file deletion happens conditionally after mode selection (see below)

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $line = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message"
    Write-Host $Message
    Add-Content -Path $LogFile -Value $line
}

function Write-Restore {
    param([string]$Message)

    if ($RunContext) {
        $RunContext.RestoreInstructions.Add($Message)
    }

    if (!$RunContext -or $RunContext.RunMode -eq "Execution") {
        Add-Content -Path $RestoreLog -Value $Message
    }
}

# ----------------------------------------------------------------
# GLOBAL VARIABLES
# ----------------------------------------------------------------
$CertFolder   = Join-Path $WorkingDir "Certificates"
$ReportsDir   = Join-Path $WorkingDir "Reports"

# PFX password: generated at runtime, NEVER logged or displayed unless explicitly needed for operator handoff
# For cross-DC scenarios, password is shown ONLY in final summary section and user must acknowledge
$PlainPfxPass = $null
$PfxPassword  = $null

function Initialize-PfxPassword {
    if ($PlainPfxPass) { return }  # Already initialized
    
    # Generate secure random password: 16 characters, mix of upper/lower/digits/symbols
    $chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*-_=+"
    $random = New-Object System.Random
    $PlainPfxPass = -join (1..16 | ForEach-Object { $chars[$random.Next($chars.Length)] })
    $PfxPassword = $PlainPfxPass | ConvertTo-SecureString -AsPlainText -Force
}

$Certutil     = "C:\Windows\System32\certutil.exe"
$NtdsRegPath  = "HKLM:\SOFTWARE\Microsoft\Cryptography\Services\NTDS\SystemCertificates\My\Certificates"

# ================================================================
# EXECUTION CONTEXT: Mode-aware state tracking
# ================================================================
$RunContext   = $null  # Initialized before interactive menu

function Initialize-RunContext {
    param([string]$RunMode)
    
    return @{
        RunMode              = $RunMode                    # "Execution" or "ReportOnly"
        SessionId            = "{0:yyyyMMdd-HHmmss-fff}" -f (Get-Date)
        Interactive          = $true
        PlannedActions       = [System.Collections.Generic.List[hashtable]]::new()
        ExecutedActions      = [System.Collections.Generic.List[hashtable]]::new()
        SkippedActions       = [System.Collections.Generic.List[hashtable]]::new()
        RestoreInstructions  = [System.Collections.Generic.List[string]]::new()
        Findings             = [System.Collections.Generic.List[string]]::new()
        Warnings             = [System.Collections.Generic.List[string]]::new()
        Errors               = [System.Collections.Generic.List[string]]::new()
    }
}

function Get-PromptPrefix {
    if (!$RunContext -or $RunContext.RunMode -eq "Execution") { return "" }
    return "[REPORT-ONLY] "
}

function Invoke-InteractivePrompt {
    param(
        [string]$Prompt,
        [string[]]$ValidAnswers = @(),
        [bool]$AllowFreeform = $false
    )
    
    $prefix = Get-PromptPrefix
    $fullPrompt = if ($prefix) { "$prefix $Prompt" } else { $Prompt }
    
    if ($ValidAnswers.Count -gt 0 -and !$AllowFreeform) {
        do {
            $response = Read-Host $fullPrompt
            if ($response -notin $ValidAnswers) {
                Write-Host "  Invalid selection. Please enter one of: $($ValidAnswers -join ', ')" -ForegroundColor Yellow
            } else {
                return $response
            }
        } while ($true)
    } else {
        return Read-Host $fullPrompt
    }
}

function Log-PlannedAction {
    param([string]$ActionType, [hashtable]$Details)
    if (!$RunContext) { return }
    $RunContext.PlannedActions.Add(@{
        Timestamp  = Get-Date
        Type       = $ActionType
        Details    = $Details
    })
    Write-Log "  [PLANNED] $ActionType : $(ConvertTo-Json $Details -Compress)" "INFO"
}

function Log-ExecutedAction {
    param([string]$ActionType, [hashtable]$Details)
    if (!$RunContext) { return }
    $RunContext.ExecutedActions.Add(@{
        Timestamp  = Get-Date
        Type       = $ActionType
        Details    = $Details
    })
}

$rootCer  = Join-Path $CertFolder "DuoSSO-RootCert.cer"
$rootPem  = Join-Path $CertFolder "DuoSSO-RootCert.pem"
$rootPfx  = Join-Path $CertFolder "DuoSSO-RootCert.pfx"
$ldapsCer = Join-Path $CertFolder "DuoSSO-LDAPS.cer"
$ldapsPfx = Join-Path $CertFolder "DuoSSO-LDAPS.pfx"


# ================================================================
# OPERATION WRAPPERS: Mode-aware mutating actions
# All state-changing operations go through these wrappers so both
# Execution and Report-Only modes use identical code paths.
# ================================================================

function Invoke-FileWrite {
    param([string]$FilePath, [object]$Content, [string]$Encoding = "UTF8", [string]$Description = "")
    
    $details = @{
        Path        = $FilePath
        Size        = if ($Content -is [byte[]]) { $Content.Length } else { ([System.Text.Encoding]::UTF8.GetByteCount($Content)) }
        Description = $Description
    }
    
    Log-PlannedAction -ActionType "FileWrite" -Details $details
    
    if ($RunContext.RunMode -eq "Execution") {
        try {
            if ($Content -is [byte[]]) {
                [System.IO.File]::WriteAllBytes($FilePath, $Content)
            } else {
                Add-Content -Path $FilePath -Value $Content -NoNewline -Encoding $Encoding
            }
            Log-ExecutedAction -ActionType "FileWrite" -Details $details
            return
        } catch {
            Write-Log "ERROR: FileWrite failed: $($_.Exception.Message)" "ERROR"
            $RunContext.Errors.Add("FileWrite '$FilePath': $($_.Exception.Message)")
            return
        }
    } else {
        Write-Log "  [DRY-RUN] Would write file: $FilePath" "INFO"
        return
    }
}

function Invoke-FileDelete {
    param([string]$FilePath, [string]$Description = "")
    
    if (!(Test-Path $FilePath)) { return }  # Already gone
    
    $details = @{
        Path        = $FilePath
        Description = $Description
    }
    
    Log-PlannedAction -ActionType "FileDelete" -Details $details
    
    if ($RunContext.RunMode -eq "Execution") {
        try {
            Remove-Item -Path $FilePath -Force -ErrorAction Stop
            Log-ExecutedAction -ActionType "FileDelete" -Details $details
            return
        } catch {
            Write-Log "WARNING: FileDelete failed: $($_.Exception.Message)" "WARN"
            return
        }
    } else {
        Write-Log "  [DRY-RUN] Would delete file: $FilePath" "INFO"
        return
    }
}

function Invoke-FileCopy {
    param([string]$SourcePath, [string]$DestinationPath, [string]$Description = "")

    $details = @{
        SourcePath  = $SourcePath
        Destination = $DestinationPath
        Description = $Description
    }

    Log-PlannedAction -ActionType "FileCopy" -Details $details

    if ($RunContext.RunMode -eq "Execution") {
        try {
            Copy-Item -Path $SourcePath -Destination $DestinationPath -Force -ErrorAction Stop
            Log-ExecutedAction -ActionType "FileCopy" -Details $details
            Write-Log "  - Copied file: $SourcePath -> $DestinationPath"
            return
        } catch {
            Write-Log "WARNING: FileCopy failed: $($_.Exception.Message)" "WARN"
            return
        }
    } else {
        Write-Log "  [DRY-RUN] Would copy file: $SourcePath -> $DestinationPath" "INFO"
        return
    }
}

function Invoke-DirectoryCreate {
    param([string]$Path, [string]$Description = "")
    
    if (Test-Path $Path) { return }  # Already exists
    
    $details = @{
        Path        = $Path
        Description = $Description
    }
    
    Log-PlannedAction -ActionType "DirectoryCreate" -Details $details
    
    if ($RunContext.RunMode -eq "Execution") {
        try {
            New-Item -ItemType Directory -Path $Path -Force | Out-Null
            Log-ExecutedAction -ActionType "DirectoryCreate" -Details $details
            Write-Log "  - Created folder: $Path"
            return
        } catch {
            Write-Log "ERROR: DirectoryCreate failed: $($_.Exception.Message)" "ERROR"
            return
        }
    } else {
        Write-Log "  [DRY-RUN] Would create directory: $Path" "INFO"
        return
    }
}

function Invoke-CertificateCreate {
    param(
        [string]$Type,
        [string]$Subject,
        [string[]]$DnsName,
        [int]$KeyLength,
        [object]$Signer,
        [hashtable]$Extensions,
        [string]$Description = ""
    )
    
    $details = @{
        Type        = $Type
        Subject     = $Subject
        DnsNames    = $DnsName -join ", "
        KeyLength   = $KeyLength
        HasSigner   = $null -ne $Signer
        Description = $Description
    }
    
    Log-PlannedAction -ActionType "CertCreate" -Details $details
    
    if ($RunContext.RunMode -eq "ReportOnly") {
        Write-Log "  [DRY-RUN] Would create certificate: $Subject" "INFO"
        $dummyCert = @{ Thumbprint = "REPORTONLY-DUMMY"; Subject = $Subject }
        return $dummyCert
    }
    
    # Execution mode - actually create cert (rest of function continues below)
    # This return value will be replaced with actual cert
    return $null  # Will be filled by caller with actual New-SelfSignedCertificate output
}

function Invoke-CertificateImport {
    param([string]$FilePath, [string]$Store, [object]$Password = $null, [string]$Description = "")
    
    $details = @{
        FilePath    = $FilePath
        Store       = $Store
        Description = $Description
    }
    
    Log-PlannedAction -ActionType "CertImport" -Details $details
    
    if ($RunContext.RunMode -eq "ReportOnly") {
        Write-Log "  [DRY-RUN] Would import certificate: $FilePath → $Store" "INFO"
        $dummyCert = @{ Thumbprint = "REPORTONLY-IMPORTED"; FilePath = $FilePath }
        return $dummyCert
    }
    
    if ($RunContext.RunMode -eq "Execution") {
        try {
            $imported = $null
            if ($Password) {
                $imported = Import-PfxCertificate -FilePath $FilePath -CertStoreLocation $Store -Password $Password -ErrorAction Stop
            } else {
                $imported = Import-Certificate -FilePath $FilePath -CertStoreLocation $Store -ErrorAction Stop
            }
            Log-ExecutedAction -ActionType "CertImport" -Details $details
            Write-Log "  - Imported certificate: $FilePath -> $Store"
            return $imported
        } catch {
            Write-Log "ERROR: CertImport failed: $($_.Exception.Message)" "ERROR"
            $RunContext.Errors.Add("CertImport '$FilePath': $($_.Exception.Message)")
            return $null
        }
    }

    return $null
}

function Invoke-CertificateExport {
    param([object]$Certificate, [string]$FilePath, [string]$Format = "CER", [object]$Password = $null, [string]$Description = "")
    
    if (!$Certificate) { return }
    
    $details = @{
        CertSubject = $Certificate.Subject
        FilePath    = $FilePath
        Format      = $Format
        Description = $Description
    }
    
    Log-PlannedAction -ActionType "CertExport" -Details $details
    
    if ($RunContext.RunMode -eq "Execution") {
        try {
            switch ($Format.ToUpper()) {
                "CER" { Export-Certificate -Cert $Certificate -FilePath $FilePath -Force | Out-Null }
                "PFX" { Export-PfxCertificate -Cert $Certificate -FilePath $FilePath -Password $Password -Force | Out-Null }
            }
            Log-ExecutedAction -ActionType "CertExport" -Details $details
                Write-Log "  - Exported ${Format}: $FilePath"
            return
        } catch {
            Write-Log "WARNING: CertExport failed: $($_.Exception.Message)" "WARN"
            return
        }
    } else {
        Write-Log "  [DRY-RUN] Would export certificate to: $FilePath" "INFO"
        return
    }
}

function Invoke-CertificateDelete {
    param([string]$Thumbprint, [string]$Store = "Cert:\LocalMachine\My", [string]$Description = "")
    
    $details = @{
        Thumbprint  = $Thumbprint
        Store       = $Store
        Description = $Description
    }
    
    Log-PlannedAction -ActionType "CertDelete" -Details $details
    
    if ($RunContext.RunMode -eq "Execution") {
        try {
            Remove-Item "$Store\$Thumbprint" -Force -ErrorAction Stop
            Log-ExecutedAction -ActionType "CertDelete" -Details $details
            Write-Log "  - Deleted cert: $Thumbprint from $Store"
            return
        } catch {
            Write-Log "WARNING: CertDelete failed: $($_.Exception.Message)" "WARN"
            return
        }
    } else {
        Write-Log "  [DRY-RUN] Would delete certificate: $Thumbprint from $Store" "INFO"
        return
    }
}

function Invoke-RegistryWrite {
    param([string]$Path, [string]$Name, [object]$Value, [string]$Type = "String", [string]$Description = "")
    
    $details = @{
        Path        = $Path
        Name        = $Name
        ValueType   = $Type
        Description = $Description
    }
    
    Log-PlannedAction -ActionType "RegistryWrite" -Details $details
    
    if ($RunContext.RunMode -eq "Execution") {
        try {
            Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type -Force -ErrorAction Stop
            Log-ExecutedAction -ActionType "RegistryWrite" -Details $details
            Write-Log "  - Registry write: $Path\$Name"
            return
        } catch {
            Write-Log "ERROR: Registry write failed: $($_.Exception.Message)" "ERROR"
            return
        }
    } else {
        Write-Log "  [DRY-RUN] Would write registry: $Path\$Name" "INFO"
        return
    }
}

function Invoke-RegistryDelete {
    param([string]$Path, [string]$Description = "")
    
    if (!(Test-Path $Path)) { return }
    
    $details = @{
        Path        = $Path
        Description = $Description
    }
    
    Log-PlannedAction -ActionType "RegistryDelete" -Details $details
    
    if ($RunContext.RunMode -eq "Execution") {
        try {
            Remove-Item -Path $Path -Force -ErrorAction Stop
            Log-ExecutedAction -ActionType "RegistryDelete" -Details $details
            Write-Log "  - Deleted registry: $Path"
            return
        } catch {
            Write-Log "WARNING: RegistryDelete failed: $($_.Exception.Message)" "WARN"
            return
        }
    } else {
        Write-Log "  [DRY-RUN] Would delete registry: $Path" "INFO"
        return
    }
}

function Invoke-RegistryKeyCreate {
    param([string]$Path, [string]$Description = "")

    if (Test-Path $Path) { return }

    $details = @{
        Path        = $Path
        Description = $Description
    }

    Log-PlannedAction -ActionType "RegistryKeyCreate" -Details $details

    if ($RunContext.RunMode -eq "Execution") {
        try {
            New-Item -Path $Path -Force | Out-Null
            Log-ExecutedAction -ActionType "RegistryKeyCreate" -Details $details
            Write-Log "  - Created registry key: $Path"
            return
        } catch {
            Write-Log "ERROR: RegistryKeyCreate failed: $($_.Exception.Message)" "ERROR"
            return
        }
    } else {
        Write-Log "  [DRY-RUN] Would create registry key: $Path" "INFO"
        return
    }
}

function Invoke-ServiceAction {
    param([string]$Action, [string]$ServiceName, [string]$Description = "")
    
    $details = @{
        Action       = $Action
        ServiceName  = $ServiceName
        Description  = $Description
    }
    
    Log-PlannedAction -ActionType "ServiceAction" -Details $details
    
    if ($RunContext.RunMode -eq "Execution") {
        try {
            switch ($Action.ToLower()) {
                "restart" { Restart-Service $ServiceName -Force -ErrorAction Stop }
                "stop"    { Stop-Service $ServiceName -Force -ErrorAction Stop }
                "start"   { Start-Service $ServiceName -ErrorAction Stop }
            }
            Log-ExecutedAction -ActionType "ServiceAction" -Details $details
            Write-Log "  - Service $Action`: $ServiceName"
            return
        } catch {
            Write-Log "WARNING: ServiceAction failed: $($_.Exception.Message)" "WARN"
            return
        }
    } else {
        Write-Log "  [DRY-RUN] Would $Action service: $ServiceName" "INFO"
        return
    }
}

function Invoke-RemoteCommand {
    param([string]$ComputerName, [scriptblock]$ScriptBlock, [object[]]$ArgumentList, [string]$Description = "")
    
    $details = @{
        ComputerName = $ComputerName
        Description  = $Description
    }
    
    Log-PlannedAction -ActionType "RemoteCommand" -Details $details
    
    if ($RunContext.RunMode -eq "Execution") {
        try {
            $result = Invoke-Command -ComputerName $ComputerName -ScriptBlock $ScriptBlock -ArgumentList $ArgumentList -ErrorAction Stop
            Log-ExecutedAction -ActionType "RemoteCommand" -Details $details
            return $result
        } catch {
            Write-Log "ERROR: RemoteCommand failed: $($_.Exception.Message)" "ERROR"
            return $null
        }
    } else {
        Write-Log "  [DRY-RUN] Would invoke remote command on: $ComputerName" "INFO"
        return $null
    }
}

function Invoke-RemoteCopy {
    param([string]$SourcePath, [string]$TargetPath, [string]$ComputerName, [string]$Description = "")
    
    $details = @{
        SourcePath  = $SourcePath
        TargetPath  = $TargetPath
        ComputerName = $ComputerName
        Description = $Description
    }
    
    Log-PlannedAction -ActionType "RemoteCopy" -Details $details
    
    if ($RunContext.RunMode -eq "Execution") {
        try {
            Copy-Item -Path $SourcePath -Destination $TargetPath -Force -ErrorAction Stop
            Log-ExecutedAction -ActionType "RemoteCopy" -Details $details
            Write-Log "  - Remote copy: $SourcePath → $TargetPath on $ComputerName"
            return
        } catch {
            Write-Log "WARNING: RemoteCopy failed: $($_.Exception.Message)" "WARN"
            return
        }
    } else {
        Write-Log "  [DRY-RUN] Would copy to remote: $SourcePath → $ComputerName\$TargetPath" "INFO"
        return
    }
}


# ================================================================
# SHARED FUNCTIONS
# ================================================================

function Ensure-Folders {
    foreach ($path in @($CertFolder, $BackupDir, $ReportsDir)) {
        Invoke-DirectoryCreate -Path $path -Description "Required working folder"
    }
}

# ----------------------------------------------------------------
# CERT COMPLIANCE CHECK
# Validates a single certificate against all Duo SSO LDAPS
# requirements. Returns a hashtable:
#   Passes  - [bool] true if all required values are present
#   Issues  - [string[]] list of human-readable compliance failures
#
# Requirements checked:
#   - Key Algorithm:    RSA
#   - Key Size:         >= 2048 bits
#   - Signature Hash:   SHA-256 or better (not SHA-1 or MD5)
#   - Key Usage:        DigitalSignature + KeyEncipherment present
#   - EKU:              Server Authentication (1.3.6.1.5.5.7.3.1)
#   - EKU:              Client Authentication (1.3.6.1.5.5.7.3.2)
#   - Not Expired:      NotAfter > now
#   - Has Private Key:  required for LDAPS binding
# ----------------------------------------------------------------
function Test-CertCompliance {
    param($Cert)

    $issues = [System.Collections.Generic.List[string]]::new()

    # Key algorithm must be RSA
    $keyAlg = $Cert.PublicKey.Oid.FriendlyName
    if ($keyAlg -ne "RSA") {
        $issues.Add("Key algorithm is '$keyAlg' - RSA is required")
    }

    # Key size must be >= 2048
    try {
        $keySize = $Cert.PublicKey.Key.KeySize
        if ($keySize -lt 2048) {
            $issues.Add("Key size is $keySize bits - minimum 2048 required")
        }
    } catch {
        $issues.Add("Could not determine key size")
    }

    # Signature hash must be SHA-256 or better
    $sigAlg = $Cert.SignatureAlgorithm.FriendlyName
    if ($sigAlg -match "sha1|md5|md2" -or $sigAlg -notmatch "sha2|sha256|sha384|sha512") {
        $issues.Add("Signature algorithm is '$sigAlg' - SHA-256 or stronger required (Duo Error 68)")
    }

    # Key Usage: must include DigitalSignature and KeyEncipherment
    $kuExt = $Cert.Extensions | Where-Object { $_.Oid.FriendlyName -eq "Key Usage" }
    if ($kuExt) {
        $kuText = $kuExt.Format(1)
        if ($kuText -notmatch "Digital Signature") {
            $issues.Add("Key Usage missing: Digital Signature")
        }
        if ($kuText -notmatch "Key Encipherment") {
            $issues.Add("Key Usage missing: Key Encipherment")
        }
    } else {
        $issues.Add("Key Usage extension is absent entirely")
    }

    # EKU: Server Authentication
    $eku = $Cert.EnhancedKeyUsageList.FriendlyName
    if ($eku -notcontains "Server Authentication") {
        $issues.Add("EKU missing: Server Authentication (1.3.6.1.5.5.7.3.1)")
    }

    # EKU: Client Authentication
    if ($eku -notcontains "Client Authentication") {
        $issues.Add("EKU missing: Client Authentication (1.3.6.1.5.5.7.3.2)")
    }

    # Not expired
    if ($Cert.NotAfter -le (Get-Date)) {
        $issues.Add("Certificate is EXPIRED (NotAfter: $($Cert.NotAfter))")
    }

    # Private key present
    if (!$Cert.HasPrivateKey) {
        $issues.Add("Private key not present on this machine - cannot be used for LDAPS")
    }

    return @{
        Passes = ($issues.Count -eq 0)
        Issues = $issues
    }
}

# ----------------------------------------------------------------
# CHAIN SCANNER + COMPLIANCE REPORTER
#
# Scans LocalMachine\My for ALL non-self-signed, non-DuoSSO leaf
# certificates that have Server Authentication EKU, regardless of
# whether they fully comply with Duo requirements. Builds and walks
# the full chain (leaf → intermediates → root) for each candidate.
#
# Each discovered chain is:
#   - Compliance-checked at every level (leaf, each intermediate, root)
#   - Categorised as FULLY COMPLIANT, PARTIAL (chain issues), or
#     NON-COMPLIANT (missing required values)
#   - Exported to Certificates\ folder
#   - Presented to the user with a numbered selection menu
#
# Returns:
#   "use-existing"  - user selected a chain and it was deployed
#   "create-new"    - no chains found, or user chose to create new
# ----------------------------------------------------------------
function Find-ExistingValidChain {
    param([string]$FQDN)

    Write-Log "`n--- Scanning for existing LDAPS certificate chains ---"

    # Collect all leaf candidates: has private key, Server Authentication EKU,
    # not self-signed, not expired, not our own DuoSSO-issued cert
    $candidates = Get-ChildItem Cert:\LocalMachine\My -ErrorAction SilentlyContinue |
        Where-Object {
            $_.HasPrivateKey -and
            ($_.EnhancedKeyUsageList.FriendlyName -contains "Server Authentication" -or
             $_.EnhancedKeyUsageList.Count -eq 0) -and   # also catch certs with no EKU (will fail compliance)
            $_.Subject -ne $_.Issuer -and                 # exclude self-signed
            $_.Subject -notmatch "DuoSSO-RootCA" -and     # exclude our own CA cert
            $_.Issuer  -notmatch "DuoSSO-RootCA"          # exclude our own leaf cert
        }

    if (!$candidates -or $candidates.Count -eq 0) {
        Write-Log "  - No existing non-self-signed certificate candidates found."
        Write-Log "  - Proceeding with self-signed chain creation."
        return "create-new"
    }

    Write-Log "  - Found $(@($candidates).Count) candidate leaf cert(s). Analysing chains..."

    # Build a chain result object for every candidate
    $chainResults = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($leaf in @($candidates)) {

        # Build the X509 chain
        $chainObj = New-Object System.Security.Cryptography.X509Certificates.X509Chain
        $chainObj.ChainPolicy.RevocationMode = `
            [System.Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
        $chainObj.ChainPolicy.VerificationFlags = `
            [System.Security.Cryptography.X509Certificates.X509VerificationFlags]::AllowUnknownCertificateAuthority
        $chainBuilt = $chainObj.Build($leaf)

        # Extract elements: index 0 = leaf, last = root, middle = intermediates
        $elements      = $chainObj.ChainElements | Select-Object -ExpandProperty Certificate
        $chainRoot     = $elements | Select-Object -Last 1
        $intermediates = if ($elements.Count -gt 2) { $elements[1..($elements.Count - 2)] } else { @() }

        # Determine chain type
        $isCAIssued = ($chainRoot.Subject -ne $chainRoot.Issuer) -eq $false -and
                      ($leaf.Issuer -ne $leaf.Subject)
        $chainType  = if ($intermediates.Count -gt 0) { "PKI (Root + $($intermediates.Count) Intermediate(s) + Leaf)" }
                      else { "PKI (Root + Leaf)" }

        # Chain build errors (untrusted root is expected/normal for internal CAs)
        $chainErrors = $chainObj.ChainStatus |
            Where-Object { $_.Status -ne "NoError" -and $_.Status -ne "UntrustedRoot" } |
            ForEach-Object { $_.StatusInformation.Trim() }

        # Compliance check each element in the chain
        $leafCompliance  = Test-CertCompliance -Cert $leaf
        $rootCompliance  = Test-CertCompliance -Cert $chainRoot

        $intCompliances = @()
        foreach ($inter in $intermediates) {
            $intCompliances += [PSCustomObject]@{
                Cert       = $inter
                Compliance = Test-CertCompliance -Cert $inter
            }
        }

        # Overall compliance: leaf must fully pass; intermediates/root must
        # have valid key sizes and hash algorithms (chain integrity)
        $allIssues = [System.Collections.Generic.List[string]]::new()

        # Leaf issues are primary — these directly affect whether Duo accepts the cert
        foreach ($issue in $leafCompliance.Issues) { $allIssues.Add("[Leaf] $issue") }

        # Intermediate issues affect chain trust
        foreach ($ic in $intCompliances) {
            foreach ($issue in $ic.Compliance.Issues) {
                $allIssues.Add("[Intermediate: $($ic.Cert.Subject)] $issue")
            }
        }

        # Root hash/key issues affect Duo's chain validation
        $rootCriticalIssues = $rootCompliance.Issues | Where-Object {
            $_ -match "Signature algorithm|Key size|Key algorithm"
        }
        foreach ($issue in $rootCriticalIssues) { $allIssues.Add("[Root] $issue") }

        # Classify overall status
        $status = if ($allIssues.Count -eq 0 -and $chainBuilt) {
            "COMPLIANT"
        } elseif ($leafCompliance.Passes -and $allIssues.Count -eq 0) {
            "COMPLIANT"
        } elseif ($leafCompliance.Issues | Where-Object { $_ -match "EKU|Key Usage|Signature|Key size" }) {
            "NON-COMPLIANT"   # leaf is missing values Duo requires
        } else {
            "PARTIAL"         # chain has issues but leaf may still work
        }

        $chainResults.Add([PSCustomObject]@{
            Leaf           = $leaf
            Root           = $chainRoot
            Intermediates  = $intermediates
            ChainType      = $chainType
            ChainBuilt     = $chainBuilt
            ChainErrors    = $chainErrors
            Status         = $status
            AllIssues      = $allIssues
            LeafCompliance = $leafCompliance
        })

        Write-Log "    Chain: $($leaf.Subject) [$($leaf.Thumbprint)]"
        Write-Log "      Type:   $chainType"
        Write-Log "      Root:   $($chainRoot.Subject)"
        Write-Log "      Status: $status"
        if ($allIssues.Count -gt 0) {
            $allIssues | ForEach-Object { Write-Log "      Issue:  $_" "WARN" }
        }
    }

    # Split into compliant vs non-compliant for display ordering
    $compliantChains    = @($chainResults | Where-Object { $_.Status -eq "COMPLIANT" })
    $partialChains      = @($chainResults | Where-Object { $_.Status -eq "PARTIAL" })
    $nonCompliantChains = @($chainResults | Where-Object { $_.Status -eq "NON-COMPLIANT" })

    $totalFound = $chainResults.Count

    Write-Log ""
    Write-Log "  Scan complete: $totalFound chain(s) found."
    Write-Log "    Fully compliant:  $($compliantChains.Count)"
    Write-Log "    Partial issues:   $($partialChains.Count)"
    Write-Log "    Non-compliant:    $($nonCompliantChains.Count)"

    # -----------------------------------------------------------------
    # DISPLAY: print all chains to the user grouped by status,
    # assign a selection number to each compliant/partial chain
    # -----------------------------------------------------------------
    Ensure-Folders

    Write-Host ""
    Write-Host "  ========================================================"
    Write-Host "  EXISTING CERTIFICATE CHAIN SCAN RESULTS"
    Write-Host "  ========================================================"

    $menuOptions = [System.Collections.Generic.List[PSCustomObject]]::new()
    $menuIndex   = 1

    # Helper: print a single chain block
    function Print-ChainBlock {
        param($result, [int]$index, [bool]$selectable)

        $statusColor = switch ($result.Status) {
            "COMPLIANT"     { "Green"  }
            "PARTIAL"       { "Yellow" }
            "NON-COMPLIANT" { "Red"    }
        }

        $prefix = if ($selectable) { "  [$index]" } else { "   [-]" }

        Write-Host ""
        Write-Host "$prefix $($result.Leaf.Subject)" -ForegroundColor $statusColor
        Write-Host "       Status:    $($result.Status)" -ForegroundColor $statusColor
        Write-Host "       Type:      $($result.ChainType)"
        Write-Host "       Thumbprint: $($result.Leaf.Thumbprint)"
        Write-Host "       Expires:    $($result.Leaf.NotAfter)"
        Write-Host "       Issuer:     $($result.Leaf.Issuer)"
        Write-Host "       Algorithm:  $($result.Leaf.SignatureAlgorithm.FriendlyName)  |  Key: $($result.Leaf.PublicKey.Oid.FriendlyName) $(try{$result.Leaf.PublicKey.Key.KeySize}catch{'?'}) bit"
        Write-Host "       EKU:        $($result.Leaf.EnhancedKeyUsageList.FriendlyName -join ', ')"

        if ($result.Intermediates.Count -gt 0) {
            Write-Host "       Intermediates:"
            foreach ($inter in $result.Intermediates) {
                Write-Host "         - $($inter.Subject)  [$($inter.Thumbprint)]"
                Write-Host "           Expires: $($inter.NotAfter)  |  $($inter.SignatureAlgorithm.FriendlyName)"
            }
        }

        Write-Host "       Root:       $($result.Root.Subject)"
        Write-Host "                   [$($result.Root.Thumbprint)]"
        Write-Host "                   Expires: $($result.Root.NotAfter)"

        if ($result.AllIssues.Count -gt 0) {
            Write-Host ""
            Write-Host "       Compliance Issues:" -ForegroundColor Yellow
            foreach ($issue in $result.AllIssues) {
                Write-Host "         ! $issue" -ForegroundColor Yellow
            }
        }

        if ($result.ChainErrors.Count -gt 0) {
            Write-Host ""
            Write-Host "       Chain Errors:" -ForegroundColor Red
            foreach ($err in $result.ChainErrors) {
                Write-Host "         ! $err" -ForegroundColor Red
            }
        }
    }

    # Compliant chains — selectable
    if ($compliantChains.Count -gt 0) {
        Write-Host ""
        Write-Host "  --- FULLY COMPLIANT  (meet all Duo requirements) ---" -ForegroundColor Green
        foreach ($r in $compliantChains) {
            Print-ChainBlock -result $r -index $menuIndex -selectable $true
            $menuOptions.Add([PSCustomObject]@{ Index = $menuIndex; Result = $r })
            $menuIndex++
        }
    }

    # Partial chains — selectable with warning
    if ($partialChains.Count -gt 0) {
        Write-Host ""
        Write-Host "  --- PARTIAL  (chain issues present, leaf may still work) ---" -ForegroundColor Yellow
        foreach ($r in $partialChains) {
            Print-ChainBlock -result $r -index $menuIndex -selectable $true
            $menuOptions.Add([PSCustomObject]@{ Index = $menuIndex; Result = $r })
            $menuIndex++
        }
    }

    # Non-compliant chains — display only, not selectable
    if ($nonCompliantChains.Count -gt 0) {
        Write-Host ""
        Write-Host "  --- NON-COMPLIANT  (missing required values, cannot be used with Duo) ---" -ForegroundColor Red
        foreach ($r in $nonCompliantChains) {
            Print-ChainBlock -result $r -index 0 -selectable $false
        }
        Write-Host ""
        Write-Host "  Non-compliant chains are shown for information only and cannot be selected." -ForegroundColor Red
        Write-Host "  The certificates exist but are missing values Duo requires." -ForegroundColor Red
        Write-Host "  You would need to re-issue them from your CA with the correct values," -ForegroundColor Red
        Write-Host "  or proceed with a new self-signed chain below." -ForegroundColor Red
    }

    # -----------------------------------------------------------------
    # MENU: selection prompt
    # -----------------------------------------------------------------
    Write-Host ""
    Write-Host "  ========================================================"
    Write-Host ""

    if ($menuOptions.Count -gt 0) {
        Write-Host "  Select an option:"
        Write-Host ""
        foreach ($opt in $menuOptions) {
            $label = if ($opt.Result.Status -eq "COMPLIANT") {
                "[$($opt.Index)] Use chain: $($opt.Result.Leaf.Subject)  [COMPLIANT]"
            } else {
                "[$($opt.Index)] Use chain: $($opt.Result.Leaf.Subject)  [PARTIAL - review issues above]"
            }
            Write-Host "  $label"
        }
        Write-Host "  [$menuIndex] Create a new self-signed certificate chain"
        Write-Host ""

        $validIndices = (1..$menuIndex) -join "|"
        do {
            $choice = (Read-Host "  Enter selection (1-$menuIndex)").Trim()
        } while ($choice -notmatch "^\d+$" -or [int]$choice -lt 1 -or [int]$choice -gt $menuIndex)

        $choiceInt = [int]$choice

    } else {
        # Only non-compliant chains found — no selectable options
        Write-Host "  No usable chains found. Only non-compliant chains were detected."
        Write-Host "  [$menuIndex] Create a new self-signed certificate chain"
        Write-Host ""
        $choiceInt = $menuIndex  # force create-new
    }

    # User chose create-new
    if ($choiceInt -eq $menuIndex) {
        Write-Log "  - User chose to create a new self-signed certificate chain."
        return "create-new"
    }

    # User selected an existing chain
    $selected    = ($menuOptions | Where-Object { $_.Index -eq $choiceInt }).Result
    $selectedLeaf = $selected.Leaf
    $selectedRoot = $selected.Root

    Write-Log "  - User selected chain: $($selectedLeaf.Subject) [$($selectedLeaf.Thumbprint)]"
    Write-Log "    Status: $($selected.Status)"

    # If partial, confirm the user understands the issues before proceeding
    if ($selected.Status -eq "PARTIAL") {
        Write-Host ""
        Write-Host "  WARNING: This chain has compliance issues that may cause problems with Duo." -ForegroundColor Yellow
        Write-Host "  The certificate will be deployed but Duo may reject it." -ForegroundColor Yellow
        Write-Host ""
        do {
            $confirm = (Read-Host "  Type YES to proceed or NO to go back to the menu").Trim().ToUpper()
        } while ($confirm -ne "YES" -and $confirm -ne "NO")

        if ($confirm -eq "NO") {
            # Recurse back to show the menu again
            return Find-ExistingValidChain -FQDN $FQDN
        }
        Write-Log "  - User confirmed proceeding with PARTIAL chain." "WARN"
    }

    # Export selected chain to Certificates\ folder
    $existingLeafCer = Join-Path $CertFolder "Existing-LDAPS.cer"
    $existingLeafPfx = Join-Path $CertFolder "Existing-LDAPS.pfx"
    $existingRootCer = Join-Path $CertFolder "Existing-RootCert.cer"
    $existingRootPem = Join-Path $CertFolder "Existing-RootCert.pem"

    try {
        Invoke-CertificateExport -Certificate $selectedLeaf -FilePath $existingLeafCer -Format "CER" -Description "Existing leaf CER export"
        Write-Log "  - Leaf cert exported: $existingLeafCer"
    } catch {
        Write-Log "  WARNING: Could not export leaf cert: $($_.Exception.Message)" "WARN"
    }

    try {
        Invoke-CertificateExport -Certificate $selectedLeaf -FilePath $existingLeafPfx -Format "PFX" -Password $PfxPassword -Description "Existing leaf PFX export"
        Write-Log "  - Leaf PFX exported: $existingLeafPfx"
    } catch {
        Write-Log "  WARNING: Could not export leaf PFX (private key may not be exportable): $($_.Exception.Message)" "WARN"
    }

    try {
        Invoke-CertificateExport -Certificate $selectedRoot -FilePath $existingRootCer -Format "CER" -Description "Existing root CER export"
        Invoke-FileDelete -FilePath $existingRootPem -Description "Existing root PEM cleanup"
        if ($RunContext.RunMode -eq "Execution") {
            & $Certutil -encode $existingRootCer $existingRootPem | Out-Null
        } else {
            Log-PlannedAction -ActionType "ExternalCommand" -Details @{ Command = "certutil -encode"; Input = $existingRootCer; Output = $existingRootPem }
            Write-Log "  [DRY-RUN] Would encode Root CA CER to PEM" "INFO"
        }
        Write-Log "  - Root CA CER: $existingRootCer"
        Write-Log "  - Root CA PEM: $existingRootPem"
    } catch {
        Write-Log "  WARNING: Could not export root cert: $($_.Exception.Message)" "WARN"
    }

    # Export any intermediates for reference
    $interIndex = 1
    foreach ($inter in $selected.Intermediates) {
        try {
            $interFile = Join-Path $CertFolder "Existing-Intermediate$interIndex.cer"
            Invoke-CertificateExport -Certificate $inter -FilePath $interFile -Format "CER" -Description "Existing intermediate export"
            Write-Log "  - Intermediate $interIndex exported: $interFile"
            $interIndex++
        } catch {
            Write-Log "  WARNING: Could not export intermediate cert: $($_.Exception.Message)" "WARN"
        }
    }

    Write-Host ""
    Write-Host "  Exported to Certificates\ folder:"
    Write-Host "    Leaf CER: $existingLeafCer"
    Write-Host "    Leaf PFX: $existingLeafPfx"
    Write-Host "    Root CER: $existingRootCer"
    Write-Host "    Root PEM: $existingRootPem  <-- upload this to Duo"
    if ($selected.Intermediates.Count -gt 0) {
        Write-Host "    Intermediates: $($selected.Intermediates.Count) file(s) exported to Certificates\ folder"
    }
    Write-Host ""

    # Inject and verify
    Write-Log "`n--- Injecting existing cert into NTDS ---"
    Inject-IntoNTDS -Cert $selectedLeaf

    Write-Log "`n--- Restarting NTDS + verifying ---"
    Restart-NTDSAndVerify -Thumbprint $selectedLeaf.Thumbprint -FQDN $FQDN

    Write-Log ""
    Write-Log "========================================================"
    Write-Log "  EXISTING CHAIN DEPLOYED"
    Write-Log "  Status:          $($selected.Status)"
    Write-Log "  Leaf Thumbprint: $($selectedLeaf.Thumbprint)"
    Write-Log "  Root Thumbprint: $($selectedRoot.Thumbprint)"
    Write-Log ""
    Write-Log "  *** Upload this PEM to Duo ***"
    Write-Log "      $existingRootPem"
    Write-Log "========================================================"

    return "use-existing"
}

function Resolve-DCNames {
    $fqdn  = $null
    $short = $env:COMPUTERNAME

    try {
        $fqdn = (Get-ADDomainController -Identity $short -ErrorAction Stop).HostName
        Write-Log "  - FQDN via Get-ADDomainController: $fqdn"
    } catch {
        Write-Log "  WARNING: Get-ADDomainController failed: $($_.Exception.Message)" "WARN"
    }

    if (!$fqdn) {
        try {
            $fqdn = [System.Net.Dns]::GetHostEntry($short).HostName
            Write-Log "  - FQDN via DNS: $fqdn"
        } catch {
            Write-Log "  WARNING: DNS lookup failed: $($_.Exception.Message)" "WARN"
        }
    }

    if (!$fqdn) {
        try {
            $cs   = Get-WmiObject Win32_ComputerSystem -ErrorAction Stop
            $fqdn = "$($cs.DNSHostName).$($cs.Domain)"
            Write-Log "  - FQDN via WMI: $fqdn"
        } catch {
            Write-Log "  WARNING: WMI failed: $($_.Exception.Message)" "WARN"
        }
    }

    $domain = $null
    try {
        $domain = (Get-ADDomain -ErrorAction Stop).DNSRoot
    } catch {
        Write-Log "  WARNING: Get-ADDomain failed: $($_.Exception.Message)" "WARN"
        $domain = if ($fqdn -like "*.*") { $fqdn.Substring($fqdn.IndexOf('.') + 1) }
                  else                   { $env:USERDNSDOMAIN }
    }

    if (!$fqdn)   { Write-Log "ERROR: Could not resolve FQDN."   "ERROR"; exit 1 }
    if (!$domain) { Write-Log "ERROR: Could not resolve Domain." "ERROR"; exit 1 }

    return @{ FQDN = $fqdn.ToLower(); Short = $short; Domain = $domain.ToLower() }
}

function Get-CertificateBackupFileName {
    param(
        $Certificate,
        [string]$Prefix
    )

    $subjectName = $Certificate.Subject
    if ($subjectName -match 'CN=([^,]+)') {
        $subjectName = $matches[1]
    }

    $safeName = $subjectName -replace '[\\/:*?"<>|]', '_'
    $safeName = $safeName -replace '\s+', '_'
    $safeName = $safeName.Trim('_')

    if ([string]::IsNullOrWhiteSpace($safeName)) {
        $safeName = $Certificate.Thumbprint
    }

    return "{0}_{1}_{2}.cer" -f $Prefix, $safeName, $Certificate.Thumbprint
}

# ----------------------------------------------------------------
# BACKUP: exports every cert we are about to delete into a
# timestamped subfolder under .\Backup and writes per-cert
# restore commands into RESTORE-INSTRUCTIONS.log.
#
# Returns a hashtable:
#   BackupFolder         - path to the timestamped backup folder
#   TotalCount           - total certs backed up
#   IrrecoverableItems   - list of PSCustomObjects describing items
#                          whose private keys cannot be recovered:
#                          { Label, Subject, Thumbprint, BackupFile, Reason }
# ----------------------------------------------------------------
function Backup-CertsBeforeWipe {
    param([string]$RunLabel)

    $stamp     = Get-Date -Format "yyyyMMdd-HHmmss-fff"      # milliseconds added for uniqueness
    $runBackup = Join-Path $BackupDir "$stamp-$RunLabel"
    Invoke-DirectoryCreate -Path $runBackup -Description "Run-specific backup folder"

    Write-Log "  - Backing up to: $runBackup"

    Write-Restore ""
    Write-Restore "================================================================"
    Write-Restore "  BACKUP: $stamp  [$RunLabel]"
    Write-Restore "  Folder: $runBackup"
    Write-Restore "================================================================"
    Write-Restore "  To restore, run each command below in an elevated PowerShell"
    Write-Restore "  prompt on this DC, then restart the NTDS service."
    Write-Restore ""

    $count            = 0
    $irrecoverable    = [System.Collections.Generic.List[PSCustomObject]]::new()

    # ---- LocalMachine\My - DuoSSO-issued certs (fully restorable via PFX in CertFolder) ----
    Get-ChildItem Cert:\LocalMachine\My -ErrorAction SilentlyContinue |
      Where-Object { $_.Subject -match "DuoSSO-RootCA" -or $_.Issuer -match "DuoSSO-RootCA" } |
      ForEach-Object {
                $file = Join-Path $runBackup (Get-CertificateBackupFileName -Certificate $_ -Prefix "My")
        Invoke-CertificateExport -Certificate $_ -FilePath $file -Format "CER" -Description "Backup [My] certificate"
        Write-Log "    Backed up [My]: $($_.Subject) [$($_.Thumbprint)]"
        Write-Restore "  # [My] $($_.Subject)  [$($_.Thumbprint)]"
        Write-Restore "  Import-Certificate -FilePath `"$file`" -CertStoreLocation Cert:\LocalMachine\My"
        Write-Restore ""
        $count++
      }

    # ---- LocalMachine\Root - DuoSSO trust anchors (fully restorable, public cert only needed) ----
    Get-ChildItem Cert:\LocalMachine\Root -ErrorAction SilentlyContinue |
      Where-Object { $_.Subject -match "DuoSSO-RootCA" } |
      ForEach-Object {
                $file = Join-Path $runBackup (Get-CertificateBackupFileName -Certificate $_ -Prefix "Root")
        Invoke-CertificateExport -Certificate $_ -FilePath $file -Format "CER" -Description "Backup [Root] certificate"
        Write-Log "    Backed up [Root]: $($_.Subject) [$($_.Thumbprint)]"
        Write-Restore "  # [Root] $($_.Subject)  [$($_.Thumbprint)]"
        Write-Restore "  Import-Certificate -FilePath `"$file`" -CertStoreLocation Cert:\LocalMachine\Root"
        Write-Restore ""
        $count++
      }

    # ---- LocalMachine\My - legacy self-signed Server Auth certs ----
    # These are PARTIAL RESTORE ONLY: public cert can be re-imported but the
    # private key is not exportable, so the DC cannot use them for TLS again
    # without the original key material.
    Get-ChildItem Cert:\LocalMachine\My -ErrorAction SilentlyContinue |
      Where-Object {
        $_.HasPrivateKey -and
        $_.EnhancedKeyUsageList.FriendlyName -contains "Server Authentication" -and
        $_.Subject -eq $_.Issuer
      } |
      ForEach-Object {
                $file = Join-Path $runBackup (Get-CertificateBackupFileName -Certificate $_ -Prefix "LegacySelfSigned")
        Invoke-CertificateExport -Certificate $_ -FilePath $file -Format "CER" -Description "Backup legacy self-signed certificate"
        Write-Log "    Backed up [Legacy Self-Signed]: $($_.Subject) [$($_.Thumbprint)]"
        Write-Restore "  # [Legacy Self-Signed] $($_.Subject)  [$($_.Thumbprint)]"
        Write-Restore "  # NOTE: Private key is NOT recoverable. Public cert restored only."
        Write-Restore "  #       This cert CANNOT be used for LDAPS after restore."
        Write-Restore "  Import-Certificate -FilePath `"$file`" -CertStoreLocation Cert:\LocalMachine\My"
        Write-Restore ""
        $count++

        $irrecoverable.Add([PSCustomObject]@{
            Label      = "Legacy Self-Signed Server Auth Cert"
            Subject    = $_.Subject
            Thumbprint = $_.Thumbprint
            NotAfter   = $_.NotAfter
            BackupFile = $file
            Reason     = "Private key is not exportable. The public certificate can be re-imported but this cert cannot be used for LDAPS again without the original private key."
        })
      }

    # ---- NTDS registry store ----
    # The NTDS registry blob contains only the public cert, not the private key,
    # so it is fully restorable (it just re-registers which cert NTDS presents).
    if (Test-Path $NtdsRegPath) {
        Get-ChildItem $NtdsRegPath -ErrorAction SilentlyContinue | ForEach-Object {
            $thumb = Split-Path $_.Name -Leaf
            $blob  = (Get-ItemProperty -Path $_.PSPath -Name Blob -ErrorAction SilentlyContinue).Blob
            if ($blob) {
                $file = Join-Path $runBackup ("NTDS_" + $thumb + ".cer")
                Invoke-FileWrite -FilePath $file -Content $blob -Description "Backup NTDS certificate blob"
                Write-Log "    Backed up [NTDS Registry]: $thumb"
                Write-Restore "  # [NTDS Registry] $thumb"
                Write-Restore "  `$blob = [System.IO.File]::ReadAllBytes(`"$file`")"
                Write-Restore "  New-Item -Path `"$NtdsRegPath\$thumb`" -Force | Out-Null"
                Write-Restore "  Set-ItemProperty -Path `"$NtdsRegPath\$thumb`" -Name Blob -Value `$blob -Type Binary"
                Write-Restore "  Restart-Service NTDS -Force"
                Write-Restore ""
                $count++
            }
        }
    }

    if ($count -eq 0) {
        Write-Log "  - Nothing to back up (clean slate)."
        Write-Restore "  (No certs present before this run)"
        Write-Restore ""
    } else {
        Write-Log "  - Backed up $count cert(s).  Restore log: $RestoreLog"
    }

    return @{
        BackupFolder       = $runBackup
        TotalCount         = $count
        IrrecoverableItems = $irrecoverable
    }
}

# ----------------------------------------------------------------
# CONFIRM-WIPE-OR-RESTORE
# Called after Backup-CertsBeforeWipe. If the backup result contains
# any irrecoverable items, warns the user and offers:
#   [C] Continue - proceed with deletion knowing some items cannot
#                  be fully restored
#   [S] Stop     - abort immediately. Nothing has been deleted yet
#                  at this point so no restore action is needed.
#
# If the user stops, exits the script cleanly.
# If no irrecoverable items exist, returns silently.
# ----------------------------------------------------------------
function Confirm-WipeOrRestore {
    param(
        [hashtable]$BackupResult,
        [string]$RunLabel
    )

    $items = $BackupResult.IrrecoverableItems
    if (!$items -or $items.Count -eq 0) { return }

    Write-Log ""
    Write-Log "  WARNING: $($items.Count) item(s) about to be deleted CANNOT be fully restored." "WARN"

    Write-Host ""
    Write-Host "  ========================================================"
    Write-Host "  WARNING: PARTIAL RESTORE ITEMS DETECTED" -ForegroundColor Yellow
    Write-Host "  ========================================================"
    Write-Host ""
    Write-Host "  The following certificate(s) are about to be deleted."
    Write-Host "  Their PUBLIC certificate has been backed up, but their"
    Write-Host "  PRIVATE KEY is not exportable and will be permanently lost."
    Write-Host "  These certs CANNOT be used for LDAPS again after deletion."
    Write-Host ""

    foreach ($item in $items) {
        Write-Host "  Certificate: $($item.Subject)" -ForegroundColor Yellow
        Write-Host "  Thumbprint:  $($item.Thumbprint)"
        Write-Host "  Expires:     $($item.NotAfter)"
        Write-Host "  Backup:      $($item.BackupFile)"
        Write-Host "  Impact:      $($item.Reason)"
        Write-Host ""
        Write-Log "    Irrecoverable: $($item.Subject) [$($item.Thumbprint)]  $($item.Reason)" "WARN"
    }

    Write-Host "  ========================================================"
    Write-Host ""
    Write-Host "  [C] Continue  - I understand. Delete and proceed."
    Write-Host "  [S] Stop      - Abort now. Nothing has been deleted yet."
    Write-Host ""

    do {
        $answer = (Read-Host "  Enter C to continue or S to stop").Trim().ToUpper()
    } while ($answer -ne "C" -and $answer -ne "S")

    if ($answer -eq "S") {
        Write-Log ""
        Write-Log "  User chose to STOP. No certificates have been deleted." "WARN"
        Write-Log "  Backup folder preserved at: $($BackupResult.BackupFolder)"
        Write-Host ""
        Write-Host "  Aborted. No changes were made to this system."
        Write-Host "  Backup folder: $($BackupResult.BackupFolder)"
        Write-Host ""
        exit 0
    }

    Write-Log "  - User confirmed continuation despite irrecoverable items."
}

function Wipe-Certs {
    param([switch]$LeafOnly)

    if (!$LeafOnly) {
        Get-ChildItem Cert:\LocalMachine\My -ErrorAction SilentlyContinue |
          Where-Object { $_.Subject -match "DuoSSO-RootCA" -or $_.Issuer -match "DuoSSO-RootCA" } |
          ForEach-Object {
            Write-Log "    Removing [My]: $($_.Subject) [$($_.Thumbprint)]"
            Invoke-CertificateDelete -Thumbprint $_.Thumbprint -Store "Cert:\LocalMachine\My" -Description "DuoSSO Root/Leaf from My"
          }

        Get-ChildItem Cert:\LocalMachine\Root -ErrorAction SilentlyContinue |
          Where-Object { $_.Subject -match "DuoSSO-RootCA" } |
          ForEach-Object {
            Write-Log "    Removing [Root]: $($_.Subject) [$($_.Thumbprint)]"
            Invoke-CertificateDelete -Thumbprint $_.Thumbprint -Store "Cert:\LocalMachine\Root" -Description "DuoSSO Root from trust store"
          }
    } else {
        # Secondary: remove leaf certs only, leave Root CA trust intact
        Get-ChildItem Cert:\LocalMachine\My -ErrorAction SilentlyContinue |
          Where-Object { $_.Issuer -match "DuoSSO-RootCA" -and $_.Subject -notmatch "DuoSSO-RootCA" } |
          ForEach-Object {
            Write-Log "    Removing leaf [My]: $($_.Subject) [$($_.Thumbprint)]"
            Invoke-CertificateDelete -Thumbprint $_.Thumbprint -Store "Cert:\LocalMachine\My" -Description "DuoSSO Leaf from My"
          }
    }

    # Always clear NTDS store and legacy self-signed
    if (Test-Path $NtdsRegPath) {
        Get-ChildItem $NtdsRegPath -ErrorAction SilentlyContinue | ForEach-Object {
            $thumb = Split-Path $_.Name -Leaf
            Write-Log "    Removing [NTDS]: $thumb"
            Invoke-RegistryDelete -Path $_.PSPath -Description "NTDS cert binding"
        }
    }

    Get-ChildItem Cert:\LocalMachine\My -ErrorAction SilentlyContinue |
      Where-Object {
        $_.HasPrivateKey -and
        $_.EnhancedKeyUsageList.FriendlyName -contains "Server Authentication" -and
        $_.Subject -eq $_.Issuer
      } |
      ForEach-Object {
        Write-Log "    Removing [Legacy Self-Signed]: $($_.Subject) [$($_.Thumbprint)]"
                Invoke-CertificateDelete -Thumbprint $_.Thumbprint -Store "Cert:\LocalMachine\My" -Description "Legacy self-signed certificate from My"
      }

    Write-Log "  - Wipe complete."
}

function New-RootCA {
    $root = $null
    try {
        Log-PlannedAction -ActionType "CertCreate" -Details @{
            Subject     = "CN=DuoSSO-RootCA"
            KeyLength   = 2048
            HashAlgorithm = "sha256"
        }
        
        if ($RunContext.RunMode -eq "ReportOnly") {
            Write-Log "  [DRY-RUN] Would create Root CA certificate" "INFO"
            $root = @{ Thumbprint = "REPORTONLY-ROOT"; Subject = "CN=DuoSSO-RootCA"; NotAfter = (Get-Date).AddYears(10) }
        } else {
            $root = New-SelfSignedCertificate `
              -Type Custom `
              -Subject "CN=DuoSSO-RootCA" `
              -KeyUsage DigitalSignature, KeyEncipherment, DataEncipherment, CertSign, CRLSign `
              -KeyLength 2048 `
              -HashAlgorithm sha256 `
              -CertStoreLocation "Cert:\LocalMachine\My" `
              -KeyExportPolicy Exportable `
              -NotAfter (Get-Date).AddYears(10) `
              -KeySpec KeyExchange `
              -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.1,1.3.6.1.5.5.7.3.2") `
              -ErrorAction Stop
            Log-ExecutedAction -ActionType "CertCreate" -Details @{ Thumbprint = $root.Thumbprint }
        }
    } catch {
        Write-Log "ERROR: Root CA creation failed: $($_.Exception.Message)" "ERROR"; exit 1
    }

    if (!$root -or !$root.Thumbprint) { Write-Log "ERROR: Root CA returned null." "ERROR"; exit 1 }

    Invoke-CertificateExport -Certificate $root -FilePath $rootCer -Format "CER" -Description "Root CA CER"
    Invoke-FileDelete -FilePath $rootPem -Description "Root CA PEM (old)"
    
    if ($RunContext.RunMode -eq "Execution") {
        & $Certutil -encode $rootCer $rootPem | Out-Null
    } else {
        Write-Log "  [DRY-RUN] Would encode Root CA to PEM" "INFO"
    }
    
    Invoke-CertificateExport -Certificate $root -FilePath $rootPfx -Format "PFX" -Password $PfxPassword -Description "Root CA PFX"

    Write-Log "  - Root CA created.  Thumbprint: $($root.Thumbprint)  NotAfter: $($root.NotAfter)"
    return $root
}

function Import-SharedRootCA {
    param([string]$SharedRootPfxPath)

    if (!(Test-Path $SharedRootPfxPath)) {
        Write-Log "ERROR: Shared Root PFX not found: $SharedRootPfxPath" "ERROR"; exit 1
    }

    try {
        $imported = Invoke-CertificateImport -FilePath $SharedRootPfxPath -Store "Cert:\LocalMachine\My" -Password $PfxPassword -Description "Import shared Root PFX into My"
        if ($RunContext.RunMode -eq "ReportOnly" -and $imported.Thumbprint -eq "REPORTONLY-IMPORTED") {
            Write-Log "  [DRY-RUN] Shared Root CA import simulated." "INFO"
            return @{ Thumbprint = "REPORTONLY-ROOT"; Subject = "CN=DuoSSO-RootCA" }
        }

        if (!$imported) { Write-Log "ERROR: Shared Root CA import failed." "ERROR"; exit 1 }

        $root = Get-ChildItem Cert:\LocalMachine\My |
            Where-Object { $_.Thumbprint -eq $imported.Thumbprint } | Select-Object -First 1

        if (!$root) { Write-Log "ERROR: Imported Root CA not found in store." "ERROR"; exit 1 }

        Invoke-FileCopy -SourcePath $SharedRootPfxPath -DestinationPath $rootPfx -Description "Copy shared Root PFX to working path"
        Invoke-CertificateExport -Certificate $root -FilePath $rootCer -Format "CER" -Description "Export imported root CER"
        Invoke-FileDelete -FilePath $rootPem -Description "Remove existing root PEM"
        if ($RunContext.RunMode -eq "Execution") {
            & $Certutil -encode $rootCer $rootPem | Out-Null
        } else {
            Log-PlannedAction -ActionType "ExternalCommand" -Details @{ Command = "certutil -encode"; Input = $rootCer; Output = $rootPem }
            Write-Log "  [DRY-RUN] Would encode Root CA CER to PEM" "INFO"
        }

        Write-Log "  - Shared Root CA imported.  Thumbprint: $($root.Thumbprint)"
        return $root
    } catch {
        Write-Log "ERROR: Import failed: $($_.Exception.Message)" "ERROR"; exit 1
    }
}

function Trust-RootCA {
    param($RootCert)
    if (!(Get-ChildItem Cert:\LocalMachine\Root | Where-Object { $_.Thumbprint -eq $RootCert.Thumbprint })) {
        Invoke-CertificateImport -FilePath $rootCer -Store "Cert:\LocalMachine\Root" -Description "Trust Root CA in LocalMachine\\Root" | Out-Null
        Write-Log "  - Root CA added to Trusted Root store."
    } else {
        Write-Log "  - Root CA already trusted."
    }
}

function New-LdapsCert {
    param($RootSigner, [string]$FQDN, [string]$Short, [string]$Domain)

    $leaf = $null
    try {
        Log-PlannedAction -ActionType "CertCreate" -Details @{
            Subject     = "CN=$FQDN"
            DnsNames    = "$FQDN, $Short, $Domain"
            KeyLength   = 2048
            Signer      = if ($RootSigner.Subject) { $RootSigner.Subject } else { "DuoSSO-RootCA" }
        }
        
        if ($RunContext.RunMode -eq "ReportOnly") {
            Write-Log "  [DRY-RUN] Would create LDAPS leaf certificate: CN=$FQDN" "INFO"
            $leaf = @{ Thumbprint = "REPORTONLY-LEAF"; Subject = "CN=$FQDN"; NotAfter = (Get-Date).AddYears(5) }
        } else {
            $leaf = New-SelfSignedCertificate `
              -Type Custom `
              -Subject "CN=$FQDN" `
              -DnsName $FQDN, $Short, $Domain, $FQDN.ToUpper(), $Short.ToUpper() `
              -KeyLength 2048 `
              -KeyUsage DigitalSignature, KeyEncipherment, DataEncipherment `
              -HashAlgorithm sha256 `
              -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.1,1.3.6.1.5.5.7.3.2") `
              -Signer $RootSigner `
              -CertStoreLocation "Cert:\LocalMachine\My" `
              -NotAfter (Get-Date).AddYears(5) `
              -KeySpec KeyExchange `
              -ErrorAction Stop
            Log-ExecutedAction -ActionType "CertCreate" -Details @{ Thumbprint = $leaf.Thumbprint; Subject = $leaf.Subject }
        }
    } catch {
        Write-Log "ERROR: LDAPS cert creation failed: $($_.Exception.Message)" "ERROR"; exit 1
    }

    if (!$leaf -or !$leaf.Thumbprint) { Write-Log "ERROR: LDAPS cert returned null." "ERROR"; exit 1 }

    Invoke-CertificateExport -Certificate $leaf -FilePath $ldapsCer -Format "CER" -Description "LDAPS Leaf CER"
    Invoke-CertificateExport -Certificate $leaf -FilePath $ldapsPfx -Format "PFX" -Password $PfxPassword -Description "LDAPS Leaf PFX"

    Write-Log "  - Leaf cert created."
    Write-Log "    Subject: $($leaf.Subject)  Issuer: $($leaf.Issuer)"
    Write-Log "    Thumbprint: $($leaf.Thumbprint)  NotAfter: $($leaf.NotAfter)"
    return $leaf
}

function Validate-LdapsCert {
    param($Cert)

    if ($RunContext -and $RunContext.RunMode -eq "ReportOnly") {
        Write-Log "  [DRY-RUN] Would validate LDAPS certificate SAN, EKU, KeySpec, and store presence" "INFO"
        return
    }

    if ($Cert.Thumbprint -eq "REPORTONLY-LEAF") {
        Write-Log "  [DRY-RUN] Validation skipped for report-only placeholder certificate" "INFO"
        return
    }

    $san = ($Cert.Extensions | Where-Object { $_.Oid.FriendlyName -eq "Subject Alternative Name" })
    if (!$san) { Write-Log "ERROR: No SAN extension." "ERROR"; exit 1 }
    $san.Format(1).Split("`n") | Where-Object { $_ -match '\S' } | ForEach-Object { Write-Log "    SAN: $_" }

    $eku = $Cert.EnhancedKeyUsageList.FriendlyName
    Write-Log "    EKU: $($eku -join ', ')"
    if ($eku -notcontains "Server Authentication") { Write-Log "ERROR: Missing Server Authentication EKU." "ERROR"; exit 1 }
    if ($eku -notcontains "Client Authentication")  { Write-Log "ERROR: Missing Client Authentication EKU."  "ERROR"; exit 1 }

    & $Certutil -v -store my $Cert.Thumbprint | Select-String "KeySpec" | ForEach-Object { Write-Log "    $_" }

    if (!(& $Certutil -store my | Select-String $Cert.Thumbprint -SimpleMatch)) {
        Write-Log "ERROR: Cert not found in LocalMachine\My." "ERROR"; exit 1
    }
    Write-Log "  - Validation passed."
}

function Inject-IntoNTDS {
    param($Cert)

    if (!(Test-Path $NtdsRegPath)) { 
        Invoke-RegistryKeyCreate -Path $NtdsRegPath -Description "Create NTDS certificate store path"
    }

    # Grant NETWORK SERVICE + SYSTEM read on private key
    if ($Cert.Thumbprint -ne "REPORTONLY-LEAF") {
        try {
            $keyName = $null
            try   { $keyName = $Cert.PrivateKey.CspKeyContainerInfo.UniqueKeyContainerName } catch {}
            if (!$keyName) {
                try { $keyName = ([System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($Cert)).Key.UniqueName } catch {}
            }
            if ($keyName) {
                $keyFile = Join-Path "C:\ProgramData\Microsoft\Crypto\RSA\MachineKeys" $keyName
                if (Test-Path $keyFile) {
                    if ($RunContext.RunMode -eq "Execution") {
                        $acl = Get-Acl $keyFile
                        $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule("NETWORK SERVICE","Read","Allow")))
                        $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule("SYSTEM","FullControl","Allow")))
                        Set-Acl -Path $keyFile -AclObject $acl
                        Log-ExecutedAction -ActionType "ACLUpdate" -Details @{ Path = $keyFile }
                    }
                    Write-Log "  - Private key ACL would be granted: $keyFile"
                }
            }
        } catch {
            Write-Log "  WARNING: ACL grant failed: $($_.Exception.Message)" "WARN"
        }
    } else {
        Write-Log "  [DRY-RUN] Would grant ACL for private key" "INFO"
    }

    # Write cert blob into NTDS registry via wrapper
    $regKey = Join-Path $NtdsRegPath $Cert.Thumbprint.ToUpper()
    
    try {
        Invoke-RegistryKeyCreate -Path $regKey -Description "Create NTDS certificate thumbprint key"
        Invoke-RegistryWrite -Path $regKey -Name "Blob" -Value $Cert.RawData -Type Binary -Description "NTDS cert binding"
        if ($RunContext.RunMode -eq "Execution") { Write-Log "  - Cert written to NTDS registry." }
    } catch {
        Write-Log "ERROR: NTDS registry write failed: $($_.Exception.Message)" "ERROR"; exit 1
    }

    if ($RunContext.RunMode -eq "Execution") {
        & $Certutil -repairstore my $Cert.Thumbprint 2>&1 | ForEach-Object { Write-Log "    $_" }
        $ok = & $Certutil -store "\\.\NTDS\My" 2>&1 | Select-String $Cert.Thumbprint -SimpleMatch
        Write-Log $(if ($ok) { "  - Confirmed in NTDS service store." } else { "  WARNING: Not confirmed via certutil - registry write should apply on restart." })
    } else {
        Write-Log "  [DRY-RUN] Would verify cert in NTDS store" "INFO"
    }
}

function Restart-NTDSAndVerify {
    param([string]$Thumbprint, [string]$FQDN)

    if ($RunContext.RunMode -eq "ReportOnly") {
        Write-Log "  [DRY-RUN] Would stop Netlogon service" "INFO"
        Write-Log "  [DRY-RUN] Would restart NTDS service" "INFO"
        Write-Log "  [DRY-RUN] Would wait 15 seconds for service startup" "INFO"
        Write-Log "  [DRY-RUN] Would start Netlogon service" "INFO"
        Write-Log "  [DRY-RUN] Would verify DNS service is running (max 60s)" "INFO"
        Write-Log "  [DRY-RUN] Would verify cert binding on LDAPS port 636" "INFO"
        Write-Log "  [IMPORTANT] In Report-Only: no actual services are restarted" "INFO"
        return
    }

    # Execution mode: perform actual service operations
    Invoke-ServiceAction -Action "stop" -ServiceName "Netlogon" -Description "Stop Netlogon before NTDS restart"
    Invoke-ServiceAction -Action "restart" -ServiceName "NTDS" -Description "Restart NTDS service to bind new cert"
    Write-Log "  - NTDS restarted. Waiting 15 seconds..."
    Start-Sleep -Seconds 15
    Invoke-ServiceAction -Action "start" -ServiceName "Netlogon" -Description "Restart Netlogon"

    $waited = 0
    do {
        Start-Sleep -Seconds 5; $waited += 5
        $dns = (Get-Service DNS -ErrorAction SilentlyContinue).Status
        Write-Log "    DNS at ${waited}s: $dns"
    } while ($dns -ne "Running" -and $waited -lt 60)

    if ($dns -ne "Running") { Write-Log "  WARNING: DNS not Running after 60s." "WARN" }

    $cert = Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Thumbprint -eq $Thumbprint }
    if (!$cert) { Write-Log "ERROR: Could not re-fetch cert after restart." "ERROR"; exit 1 }

    $remote = $null
    for ($i = 1; $i -le 3; $i++) {
        try {
            $tcp = New-Object System.Net.Sockets.TcpClient($FQDN, 636)
            $ssl = New-Object System.Net.Security.SslStream($tcp.GetStream(), $false, ({ $true }))
            $ssl.AuthenticateAsClient($FQDN)
            $remote = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($ssl.RemoteCertificate)
            $tcp.Close()
            Write-Log "  - LDAPS connected on attempt $i."
            break
        } catch {
            Write-Log "  WARNING: Attempt $i failed: $($_.Exception.Message)" "WARN"
            if ($i -lt 3) { Start-Sleep -Seconds 10 }
        }
    }

    if (!$remote) { Write-Log "ERROR: Could not connect to port 636 after 3 attempts." "ERROR"; exit 1 }

    Write-Log "    Presented: $($remote.Subject)  [$($remote.Thumbprint)]  NotAfter: $($remote.NotAfter)"

    if ($remote.Thumbprint -ne $Thumbprint) {
        Write-Log "ERROR: Wrong cert on 636.  Expected: $Thumbprint  Got: $($remote.Thumbprint)" "ERROR"
        exit 1
    }

    Write-Log "  - SUCCESS: Correct cert presented on port 636."

    if (!(Test-NetConnection -ComputerName $FQDN -Port 636).TcpTestSucceeded) {
        Write-Log "ERROR: Port 636 not reachable." "ERROR"; exit 1
    }
    Write-Log "  - Port 636 open and reachable."
}

# ================================================================
# REPORTING: JSON + HTML from RunContext
# ================================================================

function Generate-JsonReport {
    param([string]$Mode, [string]$FQDN, [string]$RootThumb, [string]$LeafThumb)
    
    $report = @{
        Metadata = @{
            ScriptVersion    = "1.0-Report"
            ExecutionMode    = $RunContext.RunMode
            SessionId        = $RunContext.SessionId
            Timestamp        = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            Hostname         = $env:COMPUTERNAME
            Domain           = $env:USERDNSDOMAIN
            OperationMode    = $Mode
        }
        Summary = @{
            TargetFQDN       = $FQDN
            RootThumbprint   = $RootThumb
            LeafThumbprint   = $LeafThumb
            PlannedActions   = $RunContext.PlannedActions.Count
            ExecutedActions  = $RunContext.ExecutedActions.Count
            RestoreLines     = $RunContext.RestoreInstructions.Count
            Warnings         = $RunContext.Warnings.Count
            Errors           = $RunContext.Errors.Count
        }
        PlannedActions = @($RunContext.PlannedActions | ForEach-Object {
            @{
                Timestamp = $_.Timestamp.ToString("yyyy-MM-dd HH:mm:ss")
                Type      = $_.Type
                Details   = $_.Details
            }
        })
        ExecutedActions = @($RunContext.ExecutedActions | ForEach-Object {
            @{
                Timestamp = $_.Timestamp.ToString("yyyy-MM-dd HH:mm:ss")
                Type      = $_.Type
                Details   = $_.Details
            }
        })
        RestoreInstructions = @($RunContext.RestoreInstructions)
        Warnings = $RunContext.Warnings
        Errors   = $RunContext.Errors
        Findings = $RunContext.Findings
    }
    
    if ($RunContext.RunMode -eq "ReportOnly") {
        $report.Metadata | Add-Member -NotePropertyName "Important" -NotePropertyValue "REPORT-ONLY: No changes were made to the system."
    }
    
    return $report | ConvertTo-Json -Depth 10
}

function Generate-HtmlReport {
    param([string]$JsonData)
    
    $json = $JsonData | ConvertFrom-Json
    $modeClass = if ($json.Metadata.ExecutionMode -eq "Execution") { "exec" } else { "report" }
    $modeBadge = if ($json.Metadata.ExecutionMode -eq "Execution") { "✓ EXECUTION MODE" } else { "⚠ REPORT-ONLY MODE" }
    $importantHtml = ""
    $plannedActionsHtml = ""

    if ($json.Metadata.PSObject.Properties.Name -contains "Important" -and $json.Metadata.Important) {
        $importantHtml = "<div class='no-changes'>$($json.Metadata.Important)</div>"
    }

    if ($json.Summary.PlannedActions -gt 0) {
        $plannedRows = $json.PlannedActions | ForEach-Object {
            "<tr class='planned'><td>$($_.Type)</td><td>$($_.Details | ConvertTo-Json -Compress)</td></tr>"
        }
        $plannedActionsHtml = "<div class='section'><h2>Planned Actions</h2><table><tr><th>Type</th><th>Details</th></tr>$($plannedRows -join '')</table></div>"
    }
    
    $html = @"
<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>DuoSSO CertTool Report</title>
<style>
body{font-family:Segoe UI,sans-serif;margin:20px;background:#f5f5f5}
.container{max-width:1200px;margin:0 auto;background:white;padding:20px;border-radius:8px}
.header{border-bottom:3px solid #0078d4;padding-bottom:10px;margin-bottom:20px}
.header h1{margin:0;color:#0078d4}
.mode-badge{display:inline-block;padding:4px 12px;border-radius:4px;font-weight:bold;font-size:12px;margin-top:8px}
.mode-badge.exec{background:#d4edda;color:#155724}
.mode-badge.report{background:#fff3cd;color:#856404}
.section{margin-bottom:30px}
.section h2{background:#f0f0f0;padding:10px;border-left:4px solid #0078d4;margin-top:0}
.summary-grid{display:grid;grid-template-columns:repeat(2,1fr);gap:15px}
.summary-item{background:#f9f9f9;padding:10px;border-radius:4px}
.summary-item label{font-weight:bold;color:#333}
.summary-item value{color:#666;display:block;margin-top:4px}
table{width:100%;border-collapse:collapse}
th{background:#0078d4;color:white;padding:10px;text-align:left}
td{padding:10px;border-bottom:1px solid #ddd;font-family:monospace;font-size:11px}
tr:hover{background:#f9f9f9}
.planned{background:#e3f2fd}
.executed{background:#e8f5e9}
.warning{color:#ff6f00;font-weight:bold}
.error{color:#c62828;font-weight:bold}
.footer{margin-top:40px;padding-top:20px;border-top:1px solid #ddd;color:#666;font-size:12px}
.no-changes{background:#e8f5e9;border-left:4px solid #4caf50;padding:12px;margin:15px 0;border-radius:4px;color:#2e7d32;font-weight:bold}
</style></head><body>
<div class="container">
<div class="header"><h1>DuoSSO Certificate Tool Report</h1><div class="mode-badge $modeClass">$modeBadge</div></div>
<div class="section"><h2>Execution Summary</h2>
<div class="summary-grid">
<div class="summary-item"><label>Mode:</label><value>$($json.Metadata.ExecutionMode)</value></div>
<div class="summary-item"><label>Operation:</label><value>$($json.Metadata.OperationMode)</value></div>
<div class="summary-item"><label>Hostname:</label><value>$($json.Metadata.Hostname)</value></div>
<div class="summary-item"><label>Timestamp:</label><value>$($json.Metadata.Timestamp)</value></div>
</div></div>
$importantHtml
<div class="section"><h2>Actions Summary</h2>
<div class="summary-grid">
<div class="summary-item"><label>Planned:</label><value>$($json.Summary.PlannedActions)</value></div>
<div class="summary-item"><label>Executed:</label><value>$($json.Summary.ExecutedActions)</value></div>
<div class="summary-item"><label>Warnings:</label><value class="warning">$($json.Summary.Warnings)</value></div>
<div class="summary-item"><label>Errors:</label><value class="error">$($json.Summary.Errors)</value></div>
</div></div>
$plannedActionsHtml
<div class="footer"><p>Report ID: $($json.Metadata.SessionId)</p></div>
</div></body></html>
"@
    return $html
}

function Write-Reports {
    param([string]$Mode, [string]$FQDN, [string]$RootThumb, [string]$LeafThumb)
    
    if (!$RunContext) { return }

    if (!(Test-Path $ReportsDir)) {
        [System.IO.Directory]::CreateDirectory($ReportsDir) | Out-Null
    }
    
    $timestamp = $RunContext.SessionId
    $jsonFile = Join-Path $ReportsDir "Report-$timestamp.json"
    $htmlFile = Join-Path $ReportsDir "Report-$timestamp.html"
    
    try {
        # Generate and write JSON report
        $jsonData = Generate-JsonReport -Mode $Mode -FQDN $FQDN -RootThumb $RootThumb -LeafThumb $LeafThumb
        [System.IO.File]::WriteAllText($jsonFile, $jsonData)
        Write-Log "  - Report: $jsonFile"
        
        # Generate and write HTML report
        $htmlData = Generate-HtmlReport -JsonData $jsonData
        [System.IO.File]::WriteAllText($htmlFile, $htmlData)
        Write-Log "  - Report: $htmlFile"
    } catch {
        Write-Log "  WARNING: Report write failed: $($_.Exception.Message)" "WARN"
    }
}

function Print-Summary {
    param([string]$Mode, [string]$FQDN, [string]$RootThumb, [string]$LeafThumb, [string]$SharedPfx = "")

    Write-Log ""
    Write-Log "========================================================"
    Write-Log "  COMPLETE  [$Mode]"
    Write-Log "  DC:              $FQDN"
    Write-Log "  Root Thumbprint: $RootThumb"
    Write-Log "  Leaf Thumbprint: $LeafThumb"
    Write-Log ""

    switch ($Mode) {
        "Single-DC" {
            Write-Log "  *** Upload this PEM to Duo after EVERY run ***"
            Write-Log "      $rootPem"
        }
        "Multi-DC-Primary" {
            Write-Log "  *** Upload this PEM to Duo ONCE ***"
            Write-Log "      $rootPem"
            Write-Log ""
            Write-Log "  *** Distribute Root PFX to all secondary DCs ***"
            Write-Log "      $rootPfx"
            Write-Log "      Password will be displayed separately after execution."
        }
        "Multi-DC-Secondary" {
            Write-Log "  Shared Root PFX used: $SharedPfx"
            Write-Log "  Do NOT re-upload PEM to Duo."
        }
        "Multi-DC-Agent" {
            Write-Log "  *** Upload this PEM to Duo ONCE ***"
            Write-Log "      $rootPem"
            Write-Log ""
            Write-Log "  Agent deployed leaf certs to all DCs. See log for per-DC results."
        }
    }

    Write-Log ""
    Write-Log "  Backup folder: $BackupDir"
    Write-Log "  Restore log:   $RestoreLog"
    Write-Log "========================================================"
}


# ================================================================
# DEPLOY-TO-DC  (used by Agent mode)
# Copies the script + shared Root PFX to the target DC over admin$
# then invokes Secondary mode via PSRemoting (WinRM).
# ================================================================
function Deploy-ToDC {
    param([string]$TargetDC, [string]$SharedRootPfxPath)

    Write-Log ""
    Write-Log "  [Agent] --> $TargetDC"

    if (!(Test-WSMan -ComputerName $TargetDC -ErrorAction SilentlyContinue)) {
        Write-Log "  [Agent] SKIPPED: WinRM not reachable on $TargetDC." "WARN"
        return [PSCustomObject]@{ DC = $TargetDC; Status = "SKIPPED"; Reason = "WinRM unreachable" }
    }

    try {
        $remoteAdmin  = "\\$TargetDC\C$\Admin"
        $remoteCerts  = "$remoteAdmin\Certificates"
        $remoteScript = "$remoteAdmin\DuoSSO-CertTool.ps1"
        $remotePfx    = "$remoteCerts\DuoSSO-RootCert-Shared.pfx"

        Invoke-DirectoryCreate -Path $remoteCerts -Description "Create remote Certificates folder on admin share"
        Invoke-RemoteCopy -SourcePath $PSCommandPath -TargetPath $remoteScript -ComputerName $TargetDC -Description "Copy script to target DC"
        Invoke-RemoteCopy -SourcePath $SharedRootPfxPath -TargetPath $remotePfx -ComputerName $TargetDC -Description "Copy shared Root PFX to target DC"
        Write-Log "  [Agent]   Copied script and Root PFX to $TargetDC."

        $remoteOutput = Invoke-RemoteCommand -ComputerName $TargetDC -Description "Invoke secondary mode on target DC" -ScriptBlock {
            param($script, $pfx)
            & powershell.exe -NonInteractive -ExecutionPolicy Bypass -File $script 3 $pfx
        } -ArgumentList "C:\Admin\DuoSSO-CertTool.ps1", "C:\Admin\Certificates\DuoSSO-RootCert-Shared.pfx"

        if ($remoteOutput) {
            $remoteOutput | ForEach-Object { Write-Log "  [Agent]   [$TargetDC] $_" }
        }

        # Confirm success by checking the remote log
        $remoteLog = "\\$TargetDC\C$\Admin\DuoSSO-CertTool.log"
        $ok = Test-Path $remoteLog -and
              (Get-Content $remoteLog | Select-String "SUCCESS: Correct cert presented" -SimpleMatch).Count -gt 0

        if ($ok) {
            Write-Log "  [Agent] SUCCESS: $TargetDC"
            return [PSCustomObject]@{ DC = $TargetDC; Status = "SUCCESS"; Reason = "" }
        } else {
            Write-Log "  [Agent] FAILED: $TargetDC - cert not confirmed. Check: $remoteLog" "WARN"
            return [PSCustomObject]@{ DC = $TargetDC; Status = "FAILED"; Reason = "Cert verification failed. Log: $remoteLog" }
        }

    } catch {
        Write-Log "  [Agent] ERROR on $TargetDC : $($_.Exception.Message)" "ERROR"
        return [PSCustomObject]@{ DC = $TargetDC; Status = "ERROR"; Reason = $_.Exception.Message }
    }
}


# ================================================================
# MODE RUNNERS
# ================================================================

function Run-SingleDC {
    Write-Log "=== MODE: Single DC  [$(Get-Date)] ==="
    Ensure-Folders
    $dc = Resolve-DCNames
    Write-Log "  FQDN: $($dc.FQDN)  Short: $($dc.Short)  Domain: $($dc.Domain)"

    $chainDecision = Find-ExistingValidChain -FQDN $dc.FQDN
    if ($chainDecision -eq "use-existing") {
        Write-Reports -Mode "Single-DC" -FQDN $dc.FQDN -RootThumb "existing-chain" -LeafThumb "existing-chain"
        return
    }

    Write-Log "`n--- Backing up ---"
    $backup = Backup-CertsBeforeWipe -RunLabel "SingleDC-$($dc.Short)"

    Confirm-WipeOrRestore -BackupResult $backup -RunLabel "SingleDC-$($dc.Short)"

    Write-Log "`n--- Wiping ---"
    Wipe-Certs

    Write-Log "`n--- Root CA ---"
    $root   = New-RootCA
    Trust-RootCA -RootCert $root

    Write-Log "`n--- LDAPS Leaf Cert ---"
    $signer = Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Thumbprint -eq $root.Thumbprint } | Select-Object -First 1
    $leaf   = New-LdapsCert -RootSigner $signer -FQDN $dc.FQDN -Short $dc.Short -Domain $dc.Domain

    Write-Log "`n--- Validating ---"
    Validate-LdapsCert -Cert $leaf

    Write-Log "`n--- NTDS Injection ---"
    Inject-IntoNTDS -Cert $leaf

    Write-Log "`n--- Restart + Verify ---"
    Restart-NTDSAndVerify -Thumbprint $leaf.Thumbprint -FQDN $dc.FQDN

    Print-Summary -Mode "Single-DC" -FQDN $dc.FQDN -RootThumb $root.Thumbprint -LeafThumb $leaf.Thumbprint
    Write-Reports -Mode "Single-DC" -FQDN $dc.FQDN -RootThumb $root.Thumbprint -LeafThumb $leaf.Thumbprint
}

function Run-MultiDCPrimary {
    Write-Log "=== MODE: Multi-DC Primary  [$(Get-Date)] ==="
    Ensure-Folders
    $dc = Resolve-DCNames
    Write-Log "  FQDN: $($dc.FQDN)  Short: $($dc.Short)  Domain: $($dc.Domain)"

    $chainDecision = Find-ExistingValidChain -FQDN $dc.FQDN
    if ($chainDecision -eq "use-existing") {
        Write-Reports -Mode "Multi-DC-Primary" -FQDN $dc.FQDN -RootThumb "existing-chain" -LeafThumb "existing-chain"
        return
    }

    Write-Log "`n--- Backing up ---"
    $backup = Backup-CertsBeforeWipe -RunLabel "MultiDCPrimary-$($dc.Short)"

    Confirm-WipeOrRestore -BackupResult $backup -RunLabel "MultiDCPrimary-$($dc.Short)"

    Write-Log "`n--- Wiping ---"
    Wipe-Certs

    Write-Log "`n--- Root CA ---"
    $root   = New-RootCA
    Trust-RootCA -RootCert $root

    Write-Log "`n--- LDAPS Leaf Cert ---"
    $signer = Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Thumbprint -eq $root.Thumbprint } | Select-Object -First 1
    $leaf   = New-LdapsCert -RootSigner $signer -FQDN $dc.FQDN -Short $dc.Short -Domain $dc.Domain

    Write-Log "`n--- Validating ---"
    Validate-LdapsCert -Cert $leaf

    Write-Log "`n--- NTDS Injection ---"
    Inject-IntoNTDS -Cert $leaf

    Write-Log "`n--- Restart + Verify ---"
    Restart-NTDSAndVerify -Thumbprint $leaf.Thumbprint -FQDN $dc.FQDN

    Print-Summary -Mode "Multi-DC-Primary" -FQDN $dc.FQDN -RootThumb $root.Thumbprint -LeafThumb $leaf.Thumbprint
    Write-Reports -Mode "Multi-DC-Primary" -FQDN $dc.FQDN -RootThumb $root.Thumbprint -LeafThumb $leaf.Thumbprint
}

function Run-MultiDCSecondary {
    param([string]$SharedRootPfxPath)

    Write-Log "=== MODE: Multi-DC Secondary  [$(Get-Date)] ==="
    Write-Log "    Shared Root PFX: $SharedRootPfxPath"
    Ensure-Folders
    $dc = Resolve-DCNames
    Write-Log "  FQDN: $($dc.FQDN)  Short: $($dc.Short)  Domain: $($dc.Domain)"

    $chainDecision = Find-ExistingValidChain -FQDN $dc.FQDN
    if ($chainDecision -eq "use-existing") {
        Write-Reports -Mode "Multi-DC-Secondary" -FQDN $dc.FQDN -RootThumb "existing-chain" -LeafThumb "existing-chain"
        return
    }

    Write-Log "`n--- Backing up ---"
    $backup = Backup-CertsBeforeWipe -RunLabel "MultiDCSecondary-$($dc.Short)"

    Confirm-WipeOrRestore -BackupResult $backup -RunLabel "MultiDCSecondary-$($dc.Short)"

    Write-Log "`n--- Wiping leaf certs only ---"
    Wipe-Certs -LeafOnly

    Write-Log "`n--- Importing Shared Root CA ---"
    $root = Import-SharedRootCA -SharedRootPfxPath $SharedRootPfxPath
    Trust-RootCA -RootCert $root

    Write-Log "`n--- LDAPS Leaf Cert ---"
    $signer = Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Thumbprint -eq $root.Thumbprint } | Select-Object -First 1
    $leaf   = New-LdapsCert -RootSigner $signer -FQDN $dc.FQDN -Short $dc.Short -Domain $dc.Domain

    Write-Log "`n--- Validating ---"
    Validate-LdapsCert -Cert $leaf

    Write-Log "`n--- NTDS Injection ---"
    Inject-IntoNTDS -Cert $leaf

    Write-Log "`n--- Restart + Verify ---"
    Restart-NTDSAndVerify -Thumbprint $leaf.Thumbprint -FQDN $dc.FQDN

    Print-Summary -Mode "Multi-DC-Secondary" -FQDN $dc.FQDN -RootThumb $root.Thumbprint `
        -LeafThumb $leaf.Thumbprint -SharedPfx $SharedRootPfxPath
    Write-Reports -Mode "Multi-DC-Secondary" -FQDN $dc.FQDN -RootThumb $root.Thumbprint -LeafThumb $leaf.Thumbprint
}

function Run-MultiDCAgent {
    Write-Log "=== MODE: Multi-DC Agent  [$(Get-Date)] ==="
    Ensure-Folders

    # Step 1: Run Primary on this DC to generate the shared Root CA
    Write-Log "`n--- Running Primary on this DC ---"
    Run-MultiDCPrimary

    # Step 2: Discover all other DCs
    Write-Log "`n--- Discovering domain controllers ---"
    $thisFQDN = (Resolve-DCNames).FQDN
    $otherDCs = $null
    try {
        $otherDCs = Get-ADDomainController -Filter * -ErrorAction Stop |
            Where-Object { $_.HostName.ToLower() -ne $thisFQDN } |
            Select-Object -ExpandProperty HostName
    } catch {
        Write-Log "ERROR: Could not enumerate DCs: $($_.Exception.Message)" "ERROR"; exit 1
    }

    if (!$otherDCs -or $otherDCs.Count -eq 0) {
        Write-Log "  - No additional DCs found. Single-DC environment."
        Print-Summary -Mode "Multi-DC-Agent" -FQDN $thisFQDN -RootThumb "see above" -LeafThumb "see above"
        Write-Reports -Mode "Multi-DC-Agent" -FQDN $thisFQDN -RootThumb "see above" -LeafThumb "see above"
        return
    }

    Write-Log "  - $($otherDCs.Count) additional DC(s) found:"
    $otherDCs | ForEach-Object { Write-Log "    $_" }

    # Step 3: Deploy to each secondary DC
    $results = $otherDCs | ForEach-Object { Deploy-ToDC -TargetDC $_ -SharedRootPfxPath $rootPfx }

    # Step 4: Agent summary
    Write-Log ""
    Write-Log "========================================================"
    Write-Log "  AGENT DEPLOYMENT SUMMARY"
    Write-Log "========================================================"

    foreach ($r in $results) {
        $icon = if ($r.Status -eq "SUCCESS") { "[OK]" } else { "[!!]" }
        Write-Log "  $icon  $($r.DC)  [$($r.Status)]$(if ($r.Reason) { "  - $($r.Reason)" })"
    }

    $failed = $results | Where-Object { $_.Status -ne "SUCCESS" }
    Write-Log ""
    Write-Log "  Succeeded: $(($results | Where-Object { $_.Status -eq 'SUCCESS' }).Count)   Failed/Skipped: $($failed.Count)"

    if ($failed.Count -gt 0) {
        Write-Log ""
        Write-Log "  For failed DCs, distribute the Root PFX manually and run mode [3]:"
        Write-Log "    Root PFX: $rootPfx  (password: $PlainPfxPass)"
        $failed | ForEach-Object { Write-Log "    - $($_.DC)" }
    }

    Print-Summary -Mode "Multi-DC-Agent" -FQDN $thisFQDN -RootThumb "see above" -LeafThumb "see above"
    Write-Reports -Mode "Multi-DC-Agent" -FQDN $thisFQDN -RootThumb "see above" -LeafThumb "see above"
}


# ================================================================
# ENTRY POINT  
# Perform preflight checks first, then determine execution mode
# Non-interactive: .\DuoSSO-CertTool.ps1 3 "C:\path\to\shared.pfx"
#   (used by Agent when invoking Secondary remotely, always Execution mode)
# Interactive: run with no args to get mode selector then operation menu
# ================================================================
Test-PreflightRequirements -Mode "Interactive"
Initialize-PfxPassword

if ($args.Count -ge 2 -and $args[0] -eq "3") {
    $RunContext = Initialize-RunContext -RunMode "Execution"
    $RunContext.Interactive = $false
    Invoke-FileDelete -FilePath $LogFile -Description "Clear old logfile"
    Run-MultiDCSecondary -SharedRootPfxPath $args[1]
    exit 0
}

Write-Host ""
Write-Host "========================================================"
Write-Host "  EXECUTION MODE"
Write-Host "========================================================"
Write-Host ""
Write-Host "  [E] Execution Mode (default)"
Write-Host "      Perform all operations: create certs, backup existing ones,"
Write-Host "      wipe and replace certs, modify registry, restart services."
Write-Host "      Changes WILL be made to this system."
Write-Host ""
Write-Host "  [R] Report-Only Mode"
Write-Host "      Plan all operations without making ANY changes."
Write-Host "      Generates a detailed report of what WOULD happen."
Write-Host "      Perfect for validation and pre-change reviews."
Write-Host ""
Write-Host "========================================================"
Write-Host ""

$modeChoice = Invoke-InteractivePrompt -Prompt "Select mode (E/R)" -ValidAnswers @("E", "R", "")
if ($modeChoice -eq "R") {
    $RunContext = Initialize-RunContext -RunMode "ReportOnly"
    Write-Host "" 
    Write-Host "*** REPORT-ONLY MODE ACTIVE ***" -ForegroundColor Cyan
    Write-Host "No changes will be made to this system." -ForegroundColor Cyan
    Write-Host ""
} else {
    $RunContext = Initialize-RunContext -RunMode "Execution"
    Invoke-FileDelete -FilePath $LogFile -Description "Clear old logfile"
}

Write-Host ""
Write-Host "========================================================"
Write-Host "  SELECT OPERATION"
Write-Host "========================================================"
Write-Host ""
Write-Host "  [1] Single DC"
Write-Host "      Full chain on this DC. Upload PEM to Duo after every run."
Write-Host ""
Write-Host "  [2] Multi-DC - Primary"
Write-Host "      Creates shared Root CA + leaf cert for this DC."
Write-Host "      Distribute Root PFX to other DCs. Upload PEM to Duo once."
Write-Host ""
Write-Host "  [3] Multi-DC - Secondary"
Write-Host "      Import shared Root CA. Issue leaf cert for this DC only."
Write-Host "      Do NOT re-upload PEM to Duo."
Write-Host ""
Write-Host "  [4] Multi-DC - Agent  (requires WinRM on all DCs)"
Write-Host "      Runs Primary on this DC then auto-deploys Secondary"
Write-Host "      to ALL other domain controllers via PSRemoting."
Write-Host ""
Write-Host "========================================================"
Write-Host ""

switch (Read-Host "Enter selection (1-4)") {
    "1" { Run-SingleDC }
    "2" { Run-MultiDCPrimary }
    "3" {
        Write-Host ""
        Write-Host "  Path to shared Root CA PFX from the Primary DC."
        Write-Host "  Example: \\DC1\C$\Admin\Certificates\DuoSSO-RootCert.pfx"
        Write-Host ""
        $pfx = Read-Host "  Shared Root CA PFX path"
        if (!$pfx) { Write-Log "ERROR: No PFX path provided." "ERROR"; exit 1 }
        Run-MultiDCSecondary -SharedRootPfxPath $pfx
    }
    "4" { Run-MultiDCAgent }
    default { Write-Log "ERROR: Invalid selection." "ERROR"; exit 1 }
}
