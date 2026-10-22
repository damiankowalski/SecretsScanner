#requires -Version 5.1
<#
.SYNOPSIS
    Secret Scanner - finds hardcoded credentials, keys, tokens and sensitive data in an application folder.

.DESCRIPTION
    Copy this script into the application's working directory and run it. It scans that folder and all
    subfolders for file types that can hold readable secrets (configuration, scripts, installer answer
    files, logs and data exports) and lists the findings in a window with two columns: File and Proof.

    What is scanned
      * Files whose extension is in $IncludeExtensions or whose name is in $IncludeFileNames.
      * Renamed and backup copies of those files, such as web.config.bak, appsettings.json.old,
        App.exe.config.deploy (ClickOnce) or .env.local.
      * Executables, libraries, installers, archives and media are not read.
      * This script, any copy of it (Find-Secrets*.ps1) and its CSV exports (SecretScan_*.csv) are
        skipped; see $ExcludeFileNames.
      * Key stores, password databases and local databases (.pfx, .kdbx, .mdf, ...) are reported by type
        without being read. Unread documents and archives are reported when their name suggests
        credentials, for example passwords.xlsx or credentials.zip. Programs and packages are not
        (CredentialProvider.dll).
      * Folders matching $ExcludePaths are skipped with everything below them (empty by default).

    How the scan works
      * Files are discovered and scanned at the same time by a pool of background workers, so the
        window stays responsive and large folders finish quickly.
      * Every file is read once, in 4 MB chunks with a small overlap, so memory use stays flat even for
        very large files.
      * Findings show a line number. A file that contains null bytes without a UTF-16 marker (for
        example a UTF-16 log without BOM) is read as raw strings and shows the byte offset instead.

    The script only reads files. It never changes, moves or sends anything.

.PARAMETER Path
    Folder scanned when the window opens. Defaults to the folder that contains this script. Another folder can
    be scanned later by pasting its path into the path field in the window.

.PARAMETER MaxFileSizeMB
    Files larger than this are skipped (default 200). Sensitive file types are still reported by name.

.PARAMETER Threads
    Number of parallel scan workers. Default: number of CPU cores, between 2 and 12.

.EXAMPLE
    .\Find-Secrets.ps1

.EXAMPLE
    .\Find-Secrets.ps1 -Path 'D:\Apps\Contoso' -MaxFileSizeMB 500

.NOTES
    Version 1.4.0 (2026-10-22). Version history: see README.md.
    Windows PowerShell 5.1 or PowerShell 7 on Windows.
    The Proof column and the CSV export contain full secret values. Treat an export like any credential file.
#>
[CmdletBinding()]
param(
    [string]$Path,
    [ValidateRange(1, 4096)][int]$MaxFileSizeMB = 200,
    [ValidateRange(0, 64)][int]$Threads = 0
)

$ScriptVersion = '1.4.0'   # MAJOR.MINOR.PATCH - update together with .NOTES and README.md

# WPF needs a single-threaded apartment. Both PowerShell editions default to STA; restart if launched in MTA.
if ([Threading.Thread]::CurrentThread.GetApartmentState() -ne [Threading.ApartmentState]::STA) {
    $relaunch = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-STA', '-File', ('"{0}"' -f $PSCommandPath),
                  '-MaxFileSizeMB', $MaxFileSizeMB, '-Threads', $Threads)
    if ($Path) { $relaunch += @('-Path', ('"{0}"' -f $Path.TrimEnd('\'))) }
    Start-Process -FilePath (Get-Process -Id $PID).Path -ArgumentList $relaunch
    return
}

if (-not $Path) { $Path = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).ProviderPath } }
$Root = (Resolve-Path -LiteralPath $Path -ErrorAction Stop).ProviderPath
if ($Threads -le 0) { $Threads = [Math]::Max(2, [Math]::Min([Environment]::ProcessorCount, 12)) }

#region Configuration ------------------------------------------------------------------------------------

# File types that are opened and scanned. Add or remove extensions here.
$IncludeExtensions = @(
    # Settings and configuration
    '.config', '.ini', '.xml', '.json', '.yaml', '.yml', '.properties', '.conf', '.cfg', '.cnf', '.toml',
    '.env', '.settings', '.resx', '.reg',
    # Connection, credential and publish profiles
    '.udl', '.dsn', '.rdp', '.ica', '.publishsettings', '.pubxml', '.dtsconfig',
    '.netrc', '.git-credentials', '.npmrc', '.pypirc', '.s3cfg',
    # Installer answer files (InstallShield, Oracle and similar silent installs)
    '.iss', '.rsp',
    # Scripts
    '.ps1', '.psm1', '.psd1', '.cmd', '.bat', '.vbs', '.wsf', '.js', '.au3', '.ahk', '.kix',
    '.py', '.sh', '.sql', '.asp', '.asa', '.php',
    # Logs, notes and data exports
    '.txt', '.log', '.csv', '.tsv',
    # Keys and certificates in text form
    '.pem'
)

# Files that are never scanned or reported. Wildcards allowed. Covers copies of this script, which contain
# the detection patterns, and CSV exports, which contain every secret found. The running script is always
# skipped by its path as well, even if renamed.
$ExcludeFileNames = @('Find-Secrets*.ps1', 'SecretScan_*.csv')

# Files without a useful extension that are scanned by exact name.
$IncludeFileNames = @('id_rsa', 'id_dsa', 'id_ecdsa', 'id_ed25519', 'credentials', '_netrc')

# Programs, packages and media. They are never read, are not treated as renamed copies
# (Newtonsoft.Json.dll is not a .json file) and are not reported for their name (CredentialProvider.dll).
$BinaryExtensions = @(
    '.exe', '.dll', '.sys', '.drv', '.ocx', '.cpl', '.scr', '.com', '.efi', '.mui', '.winmd', '.pdb',
    '.lib', '.obj', '.o', '.a', '.so', '.dylib', '.bin', '.node', '.pyd', '.class',
    '.msi', '.msp', '.msu', '.mst', '.msm', '.cab', '.appx', '.appxbundle', '.msix', '.msixbundle',
    '.nupkg', '.jar', '.war', '.ear', '.apk', '.whl', '.vsix', '.intunewin', '.asar',
    '.png', '.jpg', '.jpeg', '.gif', '.bmp', '.ico', '.cur', '.ani', '.tif', '.tiff', '.webp', '.heic', '.svg',
    '.mp3', '.wav', '.wma', '.ogg', '.flac', '.m4a', '.aac',
    '.mp4', '.avi', '.mkv', '.mov', '.wmv', '.webm', '.m4v', '.mpg', '.mpeg',
    '.ttf', '.otf', '.woff', '.woff2', '.eot', '.fon'
)

# Archives, disk images and encrypted containers. Never read or unpacked, but reported when their name
# suggests credentials (credentials.zip, hasla.7z, passwords.gpg).
$ArchiveExtensions = @(
    '.zip', '.7z', '.rar', '.gz', '.tgz', '.bz2', '.xz', '.zst', '.tar', '.iso', '.img', '.vhd', '.vhdx',
    '.wim', '.esd', '.enc', '.gpg', '.pgp'
)

# Folders skipped with everything below them, matched against the full folder path (wildcards allowed).
# Use for vendor content you do not own, for example Visual Studio's own project and item templates:
#   $ExcludePaths = @('*\ProjectTemplates', '*\ItemTemplates')
$ExcludePaths = @()

# Unread documents and archives whose name suggests stored credentials (passwords.xlsx, credentials.zip).
$SuspiciousNamePattern = 'passw|kennwort|credential|secret|(?<![a-z])(?:pwds?|has(?:l|\u0142)[oa])(?![a-z])'

# Source code: an unquoted value after "password =" is a variable or a function call, so only quoted
# literals count as hardcoded secrets in these files.
$CodeExtensions = @(
    '.ps1', '.psm1', '.psd1', '.cs', '.vb', '.fs', '.js', '.mjs', '.cjs', '.ts', '.tsx', '.jsx', '.py',
    '.java', '.kt', '.go', '.rb', '.php', '.c', '.cc', '.cpp', '.h', '.hpp', '.rs', '.swift', '.scala',
    '.groovy', '.lua', '.pl', '.vbs', '.wsf', '.au3', '.ahk', '.kix', '.asp', '.asa', '.sql', '.dart'
)

# Files reported by type or name alone, whatever their content. Format: 'Finding|Detail'.
$FileTypeFindings = @{
    '.pfx'      = 'Certificate / key file|PKCS#12 store, may contain a private key'
    '.p12'      = 'Certificate / key file|PKCS#12 store, may contain a private key'
    '.key'      = 'Certificate / key file|Private key file'
    '.p8'       = 'Certificate / key file|PKCS#8 private key'
    '.pvk'      = 'Certificate / key file|Microsoft private key file'
    '.ppk'      = 'Certificate / key file|PuTTY private key'
    '.snk'      = 'Certificate / key file|Strong-name signing key pair (contains a private key)'
    '.jks'      = 'Certificate / key file|Java keystore'
    '.keystore' = 'Certificate / key file|Keystore file'
    '.kdbx'     = 'Password database|KeePass database'
    '.kdb'      = 'Password database|KeePass database'
    '.psafe3'   = 'Password database|Password Safe database'
    '.mdf'      = 'Local data store|SQL Server database file, may hold business or customer data'
    '.ldf'      = 'Local data store|SQL Server transaction log, may hold business or customer data'
    '.mdb'      = 'Local data store|Access database'
    '.accdb'    = 'Local data store|Access database'
    '.sdf'      = 'Local data store|SQL Server Compact database'
    '.sqlite'   = 'Local data store|SQLite database'
    '.sqlite3'  = 'Local data store|SQLite database'
    '.db3'      = 'Local data store|SQLite database'
    '.pst'      = 'Local data store|Outlook data file (mailbox)'
    '.ost'      = 'Local data store|Outlook offline mailbox'
}
$FileNameFindings = @{
    '.pgpass'   = 'Credential store file|PostgreSQL password file'
    '.htpasswd' = 'Credential store file|Apache password hashes'
}

# Values that are placeholders, variables, prompts or UI text rather than real secrets.
$PlaceholderPattern = '^(?:\$|%[A-Za-z_]|@[A-Za-z_]|#\{|\{(?:\d*\}|\{|[A-Za-z:]+[\s}])|\[[^\]]*\]$|<[^>]*>$|\(|env:|[A-Za-z]:\\|\\\\|\.{0,2}/|__\w+__$|#\w+#$)|^(?:\*+|x+|\.+|_+|-+|\?+|0+|none|null|nil|true|false|yes|no|undefined|empty|string|value|required|optional|redacted|removed|hidden|masked|placeholder|dummy|sample|example|password|passwd|pwd|secret|token|apikey|api_key|default|todo|tbd|n/?a|unknown|notset|not_set|(?:your|enter|insert|replace|put)[_\- ]?\S*)$|\)$|\$\{|\$\(|\{\{|\}\}|%[A-Za-z_]\w*%|@@\w+@@|^[A-Za-z][A-Za-z,.!?:\x27\-]*(?:\s+[A-Za-z,.!?:\x27\-]+){2,}$'

# Key names that clearly hold a secret (apikey, client_secret, access_token...). Their value only needs to
# look like a literal key: 8+ characters, no spaces, with a digit or random-looking. Other names matched by
# the API key rule (api, token, auth, credentials) need a generated-looking value of 16+ characters.
$StrongKeyPattern = 'api[_.\-]?(?:key|secret|token)|access[_.\-]?(?:key|token)|auth[_.\-]?token|refresh[_.\-]?token|bearer[_.\-]?token|client[_.\-]?secret|secret[_.\-]?key|private[_.\-]?key|app[_.\-]?(?:key|secret)|subscription[_.\-]?key|consumer[_.\-]?(?:key|secret)|signing[_.\-]?key|encryption[_.\-]?key|master[_.\-]?key|license[_.\-]?key|instrumentation[_.\-]?key|sas[_.\-]?token'

# Setting names that contain "password" or "token" but describe something else (passwordLength, tokenUrl...).
# Names with "public" are public by definition: .NET PublicKeyToken, publicKey, publishableKey.
# Names ending in Description, Message, Title, Tooltip, Caption, Instructions, Error or Warning are UI text in
# any language (secretStoreComponentDescription, passwordErrorMessage).
$KeyNoisePattern = '(?:length|polic|expir|complex|hint|reset|label|prompt|regex|pattern|minimum|maximum|history|required|strength|validat|lastset|last_set|enabled|attempt|forgot|confirm|placeholder|provider|endpoint|lifetime|timeout|interval|rotation|algorithm|version|public)|(?:file|path|dir|folder|url|uri|name|type|mode|field|column|header|format|count|limit|id|ref|age|days|ttl|chars|len|min|max|date|time|created|updated|modified|description|message|title|tooltip|caption|instructions?|error|warning)$'

# License and attribution files (ThirdPartyNotices.txt, LICENSE-MIT.txt, NOTICE.txt, AUTHORS.txt...). E-mail
# addresses in them are authors' public contacts, so they are not counted as personal data. Every other rule
# still scans these files.
$LicenseFilePattern = '^(?:.*third[-_ ]?party[-_ ]?(?:notices?|licen[cs]es?).*|(?:licen[cs]es?|notices?|copying|authors|credits|contributors)(?:[-_. ].*)?)\.txt$'

# E-mail addresses that are not personal data (documentation domains, role mailboxes, image names like icon@2x.png).
$EmailNoisePattern = '@(?:example|test|domain|email|sample|company|yourcompany|yourdomain|localhost)\.|\.(?:png|jpe?g|gif|svg|webp|bmp|ico|css|js|dll|exe|xml|json|txt|log|html?)$|^(?:no-?reply|donotreply|do-not-reply|postmaster|abuse|support|info|admin|webmaster|hostmaster|security|sales|contact|help)@'

$IbanCountries = 'AD AE AL AT AZ BA BE BG BH BR BY CH CR CY CZ DE DK DO EE EG ES FI FO FR GB GE GI GL GR GT HR HU IE IL IQ IS IT JO KW KZ LB LC LI LT LU LV MC MD ME MK MR MT MU NL NO PK PL PS PT QA RO RS SA SC SE SI SK SM ST SV TL TN TR UA VA VG XK'

# Detection rules, most specific first: when two rules hit the same text, the earlier one wins.
# Check: none = match is the proof | cred = value must not be a placeholder | secret = assignment of a
# password-like value | token = assignment of a key/token (needs letters, digits and randomness) |
# shape = token-like value | card = Luhn-valid card number | iban = valid IBAN | email = counted per file.
# Patterns are case-insensitive unless CaseSensitive = $true. \x27 is a single quote.
$RuleDefinitions = @(
    @{ Name = 'Private key'; Check = 'none'; CaseSensitive = $true
       Pattern = '-----BEGIN (?:[A-Z0-9]+ ){0,3}PRIVATE KEY(?: BLOCK)?-----[^-]{0,72}' }
    @{ Name = 'PuTTY private key'; Check = 'none'; CaseSensitive = $true
       Pattern = 'PuTTY-User-Key-File-\d+: *[^\r\n]{1,60}' }
    @{ Name = 'Embedded certificate (PEM)'; Check = 'none'; CaseSensitive = $true
       Pattern = '-----BEGIN (?:TRUSTED )?CERTIFICATE-----[^-]{0,48}' }
    @{ Name = 'AWS access key ID'; Check = 'none'; CaseSensitive = $true
       Pattern = '(?<![A-Z0-9])(?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}(?![A-Z0-9])' }
    @{ Name = 'AWS secret access key'; Check = 'cred'
       Pattern = 'aws_?secret_?access_?key["\x27]?[ \t]*[:=][ \t]*["\x27]?(?<v>[A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])' }
    @{ Name = 'Azure Storage account key'; Check = 'cred'
       Pattern = '(?:DefaultEndpointsProtocol=https?;[^\s"\x27<>]{0,300}?)?AccountKey=(?<v>[A-Za-z0-9+/]{40,}={0,2})' }
    @{ Name = 'Azure shared access key (Service Bus, Event Hubs, IoT Hub)'; Check = 'cred'
       Pattern = '(?:Endpoint=sb://[^;\s"\x27<>]+;[^\s"\x27<>]{0,200}?)?SharedAccessKey=(?<v>[A-Za-z0-9+/]{20,}={0,2})' }
    @{ Name = 'Azure SAS token'; Check = 'none'
       Pattern = '(?<![A-Za-z0-9])(?:sv|sp|se|st|spr|sr|ss|srt)=[^&\s"\x27<>]{1,120}&(?:[a-z]{2,6}=[^&\s"\x27<>]{0,200}&){0,14}sig=[A-Za-z0-9%+/]{30,}={0,2}' }
    @{ Name = 'Microsoft Entra ID client secret'; Check = 'none'; CaseSensitive = $true
       Pattern = '(?<![A-Za-z0-9_~.\-])[A-Za-z0-9_~.\-]{3}\d[QR]~[A-Za-z0-9_~.\-]{31,34}(?![A-Za-z0-9_~.\-])' }
    @{ Name = 'GitHub / GitLab token'; Check = 'none'; CaseSensitive = $true
       Pattern = '(?<![A-Za-z0-9_\-])(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{60,255}|glpat-[A-Za-z0-9_\-]{20,})' }
    @{ Name = 'Slack token'; Check = 'none'; CaseSensitive = $true
       Pattern = '(?<![A-Za-z0-9])xox[abposr]-[A-Za-z0-9\-]{10,250}' }
    @{ Name = 'Webhook URL with embedded secret'; Check = 'none'
       Pattern = 'https://(?:hooks\.slack\.com/(?:services|workflows)/[A-Za-z0-9/_\-]{20,}|[A-Za-z0-9.\-]+\.webhook\.office\.com/webhookb2/[^\s"\x27<>]{20,}|[A-Za-z0-9.\-]+\.logic\.azure\.com[^\s"\x27<>]{0,300}?sig=[A-Za-z0-9_\-%]{20,}|(?:discord|discordapp)\.com/api/webhooks/\d+/[A-Za-z0-9_\-]{20,})' }
    @{ Name = 'Google API key / OAuth client secret'; Check = 'none'; CaseSensitive = $true
       Pattern = '(?<![A-Za-z0-9_\-])(?:AIza[0-9A-Za-z_\-]{35}|GOCSPX-[A-Za-z0-9_\-]{28})(?![A-Za-z0-9_\-])' }
    @{ Name = 'Google Cloud service account key'; Check = 'none'
       Pattern = '"type"\s*:\s*"service_account"' }
    @{ Name = 'SaaS API key (Stripe, SendGrid, OpenAI, Anthropic)'; Check = 'none'; CaseSensitive = $true
       Pattern = '(?<![A-Za-z0-9_\-])(?:(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{24,99}|SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}|sk-ant-[a-z]{3,8}\d{2}-[A-Za-z0-9_\-]{80,}|sk-(?:proj|svcacct|admin)-[A-Za-z0-9_\-]{40,}|sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20})' }
    @{ Name = 'Package registry token (npm, NuGet, PyPI)'; Check = 'none'; CaseSensitive = $true
       Pattern = '(?<![A-Za-z0-9_])(?:npm_[A-Za-z0-9]{36}|oy2[a-z0-9]{43}|pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{50,})(?![A-Za-z0-9_])' }
    @{ Name = 'JSON Web Token (JWT)'; Check = 'none'; CaseSensitive = $true
       Pattern = '(?<![A-Za-z0-9_\-])eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}' }
    @{ Name = 'Group Policy Preferences password (cpassword)'; Check = 'cred'
       Pattern = 'cpassword="(?<v>[^"]{8,})"' }
    @{ Name = 'Unattend / sysprep password'; Check = 'cred'
       Pattern = '<(?:AdministratorPassword|Password)>\s*<Value>(?<v>[^<]{1,256})</Value>' }
    @{ Name = 'Plaintext password converted to SecureString'; Check = 'cred'
       Pattern = 'ConvertTo-SecureString\s+(?:-String\s+)?(?:"(?<v>[^"\r\n]{1,256})"|\x27(?<v>[^\x27\r\n]{1,256})\x27)[^\r\n]{0,80}?-AsPlainText' }
    @{ Name = 'Credentials on a command line (net use, cmdkey, schtasks, psexec)'; Check = 'cred'
       Pattern = '(?:\bnet(?:\.exe)?[ \t]+use[ \t][^\r\n]{0,200}?(?:/u(?:ser)?:\S+[ \t]+(?<v>[^\s/*"\\]\S*)|[ \t](?<v>[^\s/*"\\]\S*)[ \t]+/u(?:ser)?:)|\bcmdkey(?:\.exe)?[ \t][^\r\n]{0,200}?/pass(?:word)?:(?<v>"[^"\r\n]+"|\S+)|\bschtasks(?:\.exe)?[ \t][^\r\n]{0,300}?/RP[ \t]+(?<v>"[^"\r\n]+"|[^\s/]\S*)|\bpsexec(?:64)?(?:\.exe)?[ \t][^\r\n]{0,200}?[ \t]-p[ \t]+(?<v>"[^"\r\n]+"|\S+))' }
    @{ Name = 'AutoIt RunAs with embedded password'; Check = 'cred'
       Pattern = '\bRunAs(?:Wait)?\s*\(\s*(?:"[^"\r\n]*"|\x27[^\x27\r\n]*\x27)\s*,\s*(?:"[^"\r\n]*"|\x27[^\x27\r\n]*\x27)\s*,\s*(?:"(?<v>[^"\r\n]{1,128})"|\x27(?<v>[^\x27\r\n]{1,128})\x27)' }
    @{ Name = 'RDP file with saved password'; Check = 'none'
       Pattern = 'password 51:b:[0-9A-Fa-f]{32}' }
    @{ Name = 'netrc credentials'; Check = 'cred'
       Pattern = '\bmachine\s+\S+\s+login\s+\S+\s+password\s+(?<v>\S+)' }
    @{ Name = 'Connection string with password'; Check = 'cred'
       Pattern = '(?<![A-Za-z])(?:Server|Data Source|DataSource|Address|Addr|Host|Hostname|Network Address|DSN|Provider|Initial Catalog|Database)\s*=[^\r\n"\x27<>]{1,400}?(?<![A-Za-z])(?:Password|Pwd)\s*=\s*(?<v>\{[^}\r\n]{1,128}\}|[^;"\x27<>\r\n]{1,128})' }
    @{ Name = 'URL with embedded credentials'; Check = 'cred'
       Pattern = '(?<![A-Za-z0-9+.\-])[A-Za-z][A-Za-z0-9+.\-]{1,20}://[^\s:@/"\x27<>]{1,128}:(?<v>[^\s@/"\x27<>]{1,128})@[A-Za-z0-9._\-\[\]]{1,253}' }
    @{ Name = 'PHP constant with secret'; Check = 'cred'
       Pattern = 'define\(\s*["\x27]\w*(?:PASSWORD|PASS|PWD|SECRET|KEY|SALT|TOKEN)\w*["\x27]\s*,\s*["\x27](?<v>[^"\x27\r\n]{4,256})["\x27]' }
    @{ Name = 'Config setting with secret value'; Check = 'secret'
       Pattern = '<(?:add\s+key|setting\s+name)\s*=\s*"(?<k>[^"]*(?:password|passwd|pwd|secret|token|api[_\-.]?key)[^"]*)"(?:\s+value\s*=\s*"(?<v>[^"]{3,512})"|[^>]*>\s*<value>(?<v>[^<]{3,512})</value>)' }
    @{ Name = 'XML element with secret'; Check = 'secret'
       Pattern = '<(?<k>[A-Za-z0-9_:.\-]{0,40}(?:password|passwd|pwd|secret|apikey|api_key|token|clientsecret)[A-Za-z0-9_.\-]{0,20})>\s*(?<v>[^<\s][^<]{2,255}?)\s*</\k<k>>' }
    @{ Name = 'Password passed as command-line argument'; Check = 'cred'
       Pattern = '(?<![A-Za-z0-9_])(?:--?|/)(?<k>[A-Za-z]{0,20}(?:password|passwd|pwd|pass|secret|token|apikey|api-key))(?:[:=]|[ \t]+)(?<v>"[^"\r\n]{3,256}"|\x27[^\x27\r\n]{3,256}\x27|[^\s"\x27$%(\[{<\-/][^\s"\x27]{2,255})' }
    @{ Name = 'HTTP authorization credential (Bearer / Basic)'; Check = 'shape'
       Pattern = '(?<![A-Za-z])(?:Bearer|Basic)[ \t]+(?<v>[A-Za-z0-9._~+/\-]{16,}={0,2})' }
    @{ Name = 'API key / token / credential'; Check = 'token'
       Pattern = '(?<![A-Za-z0-9_.\-])(?<k>[A-Za-z0-9_.\-]{0,40}?(?:api[_.\-]?key|api[_.\-]?token|api[_.\-]?secret|access[_.\-]?key|access[_.\-]?token|auth[_.\-]?token|refresh[_.\-]?token|bearer[_.\-]?token|client[_.\-]?secret|secret[_.\-]?key|private[_.\-]?key|app[_.\-]?(?:key|secret)|subscription[_.\-]?key|consumer[_.\-]?(?:key|secret)|signing[_.\-]?key|encryption[_.\-]?key|master[_.\-]?key|license[_.\-]?key|instrumentation[_.\-]?key|sas[_.\-]?token|token|api|auth|creds?|credentials?)[A-Za-z0-9_.\-]{0,40})["\x27]?[ \t]*(?:=>|:=|=|:)[ \t]*(?:"(?<v>[^"\r\n]{8,512})"|\x27(?<v>[^\x27\r\n]{8,512})\x27|(?<v>[^\s"\x27<>;,)\]}]{8,512}))' }
    @{ Name = 'Hardcoded password / secret'; Check = 'secret'
       Pattern = '(?<![A-Za-z0-9_.\-])(?<k>[A-Za-z0-9_.\-]{0,40}?(?:password|passwd|passphrase|pwd|secret|has(?:l|\u0142|\xC5\x82)o)[A-Za-z0-9_.\-]{0,40})["\x27]?[ \t]*(?:=>|:=|=|:)[ \t]*(?:"(?<v>[^"\r\n]{3,256})"|\x27(?<v>[^\x27\r\n]{3,256})\x27|(?<v>[^\s"\x27<>;,)\]}]{4,256}))' }
    @{ Name = 'Payment card number'; Check = 'card'
       Pattern = '(?<![\w.,\-])(?:\d[ \-]?){12,18}\d(?![\w\-]|[.,]\d)' }
    @{ Name = 'Bank account number (IBAN)'; Check = 'iban'; CaseSensitive = $true
       Pattern = '(?<![A-Za-z0-9])[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,3})?(?![A-Za-z0-9])' }
    @{ Name = 'Bulk e-mail addresses (personal data)'; Check = 'email'
       Pattern = '(?<![A-Za-z0-9._%+\-])[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9\-]{1,63}(?:\.[A-Za-z0-9\-]{1,63})*\.[A-Za-z]{2,24}(?![A-Za-z0-9\-])' }
)

$Settings = @{
    Root               = $Root
    SelfPath           = $PSCommandPath
    Threads            = $Threads
    MaxBytes           = [long]$MaxFileSizeMB * 1MB
    ChunkSize          = 4MB      # bytes read per step
    Overlap            = 2KB      # carried between chunks so a secret on a chunk boundary is not missed
    MaxPerRule         = 25       # findings listed per rule per file; more are summarised in one row
    MaxProofLength     = 300      # characters of proof shown per finding
    EmailThreshold     = 10       # unique e-mail addresses in one file before it is reported
    LicenseFilePattern = $LicenseFilePattern
    IncludeExtensions  = $IncludeExtensions
    IncludeFileNames   = $IncludeFileNames
    ExcludeFileNames   = $ExcludeFileNames
    BinaryExtensions   = $BinaryExtensions
    ArchiveExtensions  = $ArchiveExtensions
    ExcludePaths       = $ExcludePaths
    SuspiciousName     = $SuspiciousNamePattern
    CodeExtensions     = $CodeExtensions
    FileTypeFindings   = $FileTypeFindings
    FileNameFindings   = $FileNameFindings
    PlaceholderPattern = $PlaceholderPattern
    KeyNoisePattern    = $KeyNoisePattern
    StrongKeyPattern   = $StrongKeyPattern
    EmailNoisePattern  = $EmailNoisePattern
    IbanCountries      = $IbanCountries
}
#endregion

#region Scan engine (runs in background runspaces) ------------------------------------------------------

# Coordinator: compiles the rules, starts the worker pool and feeds it files while it walks the folder tree.
$CoordinatorScript = {
    param($Sync, $Settings, $RuleDefinitions, [string]$WorkerCode)

    function New-Rx([string]$Pattern, [switch]$CaseSensitive) {
        $o = [Text.RegularExpressions.RegexOptions]'Compiled, CultureInvariant'
        if (-not $CaseSensitive) { $o = $o -bor [Text.RegularExpressions.RegexOptions]::IgnoreCase }
        [regex]::new($Pattern, $o, [TimeSpan]::FromSeconds(5))
    }

    $workers = [Collections.Generic.List[object]]::new()
    $pool = $null
    try {
        $Sync.Phase = 'Preparing'
        $rules = foreach ($d in $RuleDefinitions) {
            try { @{ Name = $d.Name; Check = $d.Check; Rx = (New-Rx $d.Pattern -CaseSensitive:([bool]$d.CaseSensitive)) } }
            catch { throw ("Rule '{0}' has an invalid pattern: {1}" -f $d.Name, $_.Exception.GetBaseException().Message) }
        }
        $ci = [StringComparer]::OrdinalIgnoreCase
        $included      = [Collections.Generic.HashSet[string]]::new([string[]]@($Settings.IncludeExtensions), $ci)
        $includedNames = [Collections.Generic.HashSet[string]]::new([string[]]@($Settings.IncludeFileNames), $ci)
        $binary        = [Collections.Generic.HashSet[string]]::new([string[]]@($Settings.BinaryExtensions), $ci)
        $archives      = [Collections.Generic.HashSet[string]]::new([string[]]@($Settings.ArchiveExtensions), $ci)
        $skipDirs = @(foreach ($n in $Settings.ExcludePaths) {
            [Management.Automation.WildcardPattern]::new($n, [Management.Automation.WildcardOptions]::IgnoreCase)
        })
        $suspiciousRx  = New-Rx $Settings.SuspiciousName
        $skipNames = @(foreach ($n in $Settings.ExcludeFileNames) {
            [Management.Automation.WildcardPattern]::new($n, [Management.Automation.WildcardOptions]::IgnoreCase)
        })
        $cfg = @{
            ChunkSize      = [int]$Settings.ChunkSize
            Overlap        = [int]$Settings.Overlap
            MaxPerRule     = [int]$Settings.MaxPerRule
            MaxProofLength = [int]$Settings.MaxProofLength
            EmailThreshold = [int]$Settings.EmailThreshold
            LicenseRx      = New-Rx $Settings.LicenseFilePattern
            CodeExt        = [Collections.Generic.HashSet[string]]::new([string[]]@($Settings.CodeExtensions), $ci)
            IbanCountries  = [Collections.Generic.HashSet[string]]::new([string[]]($Settings.IbanCountries -split ' '))
            PlaceholderRx  = New-Rx $Settings.PlaceholderPattern
            KeyNoiseRx     = New-Rx $Settings.KeyNoisePattern
            StrongKeyRx    = New-Rx $Settings.StrongKeyPattern
            TokenCharsRx   = New-Rx '^[A-Za-z0-9+/=_.~\-]+$' -CaseSensitive
            GuidRx         = New-Rx '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
            EmailNoiseRx   = New-Rx $Settings.EmailNoisePattern
            NonPrintRx     = New-Rx '[^\x20-\x7E\t]+' -CaseSensitive
            WideProbeRx    = New-Rx '(?:[\x20-\x7E]\x00){4}' -CaseSensitive
            WsRx           = New-Rx '\s+' -CaseSensitive
            HighCharRx     = New-Rx '[\x80-\xFF]' -CaseSensitive
            NonAlphaRx     = New-Rx '[^A-Za-z]' -CaseSensitive
        }

        $iss = [Management.Automation.Runspaces.InitialSessionState]::CreateDefault2()
        $pool = [runspacefactory]::CreateRunspacePool(1, $Settings.Threads, $iss, $Host)
        $pool.Open()
        for ($i = 0; $i -lt $Settings.Threads; $i++) {
            $ps = [powershell]::Create()
            $ps.RunspacePool = $pool
            [void]$ps.AddScript($WorkerCode).AddArgument($i).AddArgument($Sync).AddArgument($rules).AddArgument($cfg)
            $workers.Add(@{ PS = $ps; Handle = $ps.BeginInvoke() })
        }
        $Sync.Phase = 'Scanning'

        # Iterative walk: an inaccessible folder is counted and skipped instead of aborting the scan.
        $stack = [Collections.Generic.Stack[IO.DirectoryInfo]]::new()
        $stack.Push([IO.DirectoryInfo]::new($Settings.Root))
        while ($stack.Count -gt 0 -and -not $Sync.Cancel) {
            $dir = $stack.Pop()
            try {
                foreach ($f in $dir.EnumerateFiles()) {
                    if ($Settings.SelfPath -and $f.FullName -eq $Settings.SelfPath) { continue }
                    $skip = $false
                    foreach ($w in $skipNames) { if ($w.IsMatch($f.Name)) { $skip = $true; break } }
                    if ($skip) { continue }
                    $Sync.Found++
                    $ext = $f.Extension
                    $isArchive = $archives.Contains($ext)
                    $isBinary = $isArchive -or $binary.Contains($ext)
                    $scan = $included.Contains($ext) -or $includedNames.Contains($f.Name)
                    if (-not $scan -and -not $isBinary -and $ext) {
                        # Renamed or backup copy of a scanned type: web.config.bak, settings.json.old, .env.local
                        $inner = [IO.Path]::GetFileNameWithoutExtension($f.Name)
                        $scan = $included.Contains([IO.Path]::GetExtension($inner)) -or $includedNames.Contains($inner)
                    }

                    $hit = $Settings.FileTypeFindings[$ext]; $where = 'file type'
                    if (-not $hit) { $hit = $Settings.FileNameFindings[$f.Name] }
                    if (-not $hit -and -not $scan -and ($isArchive -or -not $isBinary) -and $suspiciousRx.IsMatch($f.Name)) {
                        $hit = if ($isArchive) { 'Suspicious file name|Name suggests stored credentials; archive content is not unpacked' }
                               else { 'Suspicious file name|Name suggests stored credentials; this file type is not read' }
                        $where = 'file name'
                    }
                    if ($hit) {
                        $parts = $hit -split '\|', 2
                        $Sync.Results.Enqueue([Tuple]::Create($f.FullName, $parts[0], $where, $parts[1]))
                    }

                    if (-not $scan) { $Sync.SkippedType++; continue }
                    if ($f.Length -gt $Settings.MaxBytes) { $Sync.SkippedSize++; continue }
                    $Sync.TotalBytes += $f.Length
                    $Sync.Queued++
                    $Sync.Queue.Enqueue($f)
                }
                foreach ($sub in $dir.EnumerateDirectories()) {
                    # Junctions and symbolic links can loop back into the tree.
                    if ($sub.Attributes -band [IO.FileAttributes]::ReparsePoint) { continue }
                    $skip = $false
                    foreach ($w in $skipDirs) { if ($w.IsMatch($sub.FullName)) { $skip = $true; break } }
                    if ($skip) { $Sync.DirExcluded++ } else { $stack.Push($sub) }
                }
            } catch {
                $Sync.DirErrors++
            }
        }
        $Sync.EnumDone = $true

        foreach ($w in $workers) {
            try { [void]$w.PS.EndInvoke($w.Handle) } catch { $Sync.WorkerError = $_.Exception.GetBaseException().Message }
            if ($w.PS.Streams.Error.Count -gt 0) { $Sync.WorkerError = [string]$w.PS.Streams.Error[0] }
        }
    } catch {
        $Sync.Fatal = $_.Exception.GetBaseException().Message
        $Sync.Cancel = $true
    } finally {
        $Sync.EnumDone = $true
        foreach ($w in $workers) { try { $w.PS.Dispose() } catch { } }
        if ($pool) { try { $pool.Close(); $pool.Dispose() } catch { } }
        $Sync.Phase = 'Done'
    }
}

# Worker: takes files from the shared queue until it is empty and discovery has finished.
$WorkerScript = {
    param([int]$Id, $Sync, $Rules, $Cfg)

    $latin1    = [Text.Encoding]::GetEncoding(28591)   # 1 byte = 1 char, so char index = byte offset
    $utf8      = [Text.UTF8Encoding]::new($false, $false)
    $unicode   = [Text.Encoding]::Unicode
    $buffer    = [byte[]]::new($Cfg.ChunkSize)
    $queue     = $Sync.Queue
    $results   = $Sync.Results
    $doneArr   = $Sync.Done
    $bytesArr  = $Sync.Bytes
    $errorsArr = $Sync.Errors
    $current   = $Sync.Current

    function Add-Finding($St, [string]$Rule, [string]$Location, [string]$Value) {
        $results.Enqueue([Tuple]::Create($St.Path, $Rule, $Location, $Value))
    }

    function Test-Placeholder([string]$Value) {
        $v = $Value.Trim().Trim([char]34, [char]39).Trim()
        if ($v.Length -lt 3) { return $true }
        return $Cfg.PlaceholderRx.IsMatch($v)
    }

    function Get-Entropy([string]$v) {
        $counts = @{}
        foreach ($c in $v.ToCharArray()) { $counts[[int]$c] = 1 + $counts[[int]$c] }
        $entropy = 0.0
        foreach ($n in $counts.Values) { $p = $n / $v.Length; $entropy -= $p * [Math]::Log($p, 2) }
        return $entropy
    }

    # Generated-looking value: key/token characters only, letters and digits, random enough. Not a GUID.
    function Test-TokenShape([string]$Value, [int]$MinLength = 12) {
        $v = $Value.Trim().Trim([char]34, [char]39)
        if ($v.Length -lt $MinLength -or -not $Cfg.TokenCharsRx.IsMatch($v)) { return $false }
        if ($v -notmatch '\d' -or $v -notmatch '[A-Za-z]' -or $Cfg.GuidRx.IsMatch($v)) { return $false }
        return (Get-Entropy $v) -ge 3.0
    }

    # Value under an explicit key name (apikey, client_secret...): any literal key, numeric keys included.
    function Test-KeyValue([string]$Value) {
        $v = $Value.Trim().Trim([char]34, [char]39)
        if ($v.Length -lt 8 -or $v -match '\s') { return $false }
        return ($v -match '\d') -or ($v.Length -ge 16 -and (Get-Entropy $v) -ge 3.0)
    }

    function Test-SecretValue($M, [string]$Scan, [string]$Mode, [bool]$IsCode) {
        $g = $M.Groups['v']
        if (-not $g.Success) { return $false }
        $v = $g.Value.Trim()
        $quoted = $false
        if ($g.Index -gt 0) { $c = $Scan[$g.Index - 1]; $quoted = ($c -eq [char]34) -or ($c -eq [char]39) }
        if (-not $quoted) {
            if ($IsCode -or $v.Length -lt 4) { return $false }
            if ($Mode -eq 'binary' -and -not $Cfg.NonAlphaRx.IsMatch($v)) { return $false }
        }
        if (Test-Placeholder $v) { return $false }
        $k = $M.Groups['k']
        if ($k.Success -and (($v -eq $k.Value) -or $Cfg.KeyNoiseRx.IsMatch($k.Value))) { return $false }
        return $true
    }

    function Test-Card([string]$Value) {
        $d = $Value -replace '[ \-]', ''
        if ($d.Length -lt 13 -or $d.Length -gt 19 -or $d -match '^(\d)\1+$') { return $false }
        $p2 = [int]$d.Substring(0, 2); $p3 = [int]$d.Substring(0, 3); $p4 = [int]$d.Substring(0, 4)
        $known = ($d[0] -eq '4' -and $d.Length -in 13, 16, 19) -or
                 ($p2 -ge 51 -and $p2 -le 55 -and $d.Length -eq 16) -or
                 ($p4 -ge 2221 -and $p4 -le 2720 -and $d.Length -eq 16) -or
                 (($p2 -eq 34 -or $p2 -eq 37) -and $d.Length -eq 15) -or
                 (($p4 -eq 6011 -or $p2 -eq 65 -or ($p3 -ge 644 -and $p3 -le 649)) -and $d.Length -ge 16) -or
                 ($p4 -ge 3528 -and $p4 -le 3589 -and $d.Length -ge 16) -or
                 (($p2 -eq 36 -or $p2 -eq 38 -or ($p3 -ge 300 -and $p3 -le 305)) -and $d.Length -eq 14)
        if (-not $known) { return $false }
        $sum = 0; $double = $false
        for ($i = $d.Length - 1; $i -ge 0; $i--) {
            $n = [int]$d[$i] - 48
            if ($double) { $n *= 2; if ($n -gt 9) { $n -= 9 } }
            $sum += $n; $double = -not $double
        }
        return ($sum % 10) -eq 0
    }

    function Test-Iban([string]$Value) {
        $s = $Value.Replace(' ', '')
        if ($s.Length -lt 15 -or $s.Length -gt 34 -or -not $Cfg.IbanCountries.Contains($s.Substring(0, 2))) { return $false }
        $mod = 0
        foreach ($ch in ($s.Substring(4) + $s.Substring(0, 4)).ToCharArray()) {
            $c = [int]$ch
            if ($c -ge 48 -and $c -le 57) { $mod = ($mod * 10 + ($c - 48)) % 97 }
            else { $mod = ($mod * 100 + ($c - 55)) % 97 }
        }
        return $mod -eq 1
    }

    function Test-Match($Rule, $M, [string]$Scan, [string]$Mode, [bool]$IsCode) {
        $v = $M.Groups['v']
        switch ($Rule.Check) {
            'none'   { return $true }
            'cred'   { return (-not $v.Success) -or -not (Test-Placeholder $v.Value) }
            'shape'  { return $v.Success -and -not (Test-Placeholder $v.Value) -and (Test-TokenShape $v.Value) }
            'secret' { return Test-SecretValue $M $Scan $Mode $IsCode }
            'token'  {
                if (-not (Test-SecretValue $M $Scan $Mode $IsCode)) { return $false }
                if ($Cfg.StrongKeyRx.IsMatch($M.Groups['k'].Value)) { return Test-KeyValue $v.Value }
                return Test-TokenShape $v.Value 16
            }
            'card'   { return Test-Card $M.Value }
            'iban'   { return Test-Iban $M.Value }
        }
        return $false
    }

    function Format-Value([string]$Value, [string]$Mode) {
        if ($Mode -eq 'text' -and $Cfg.HighCharRx.IsMatch($Value)) {
            # Text was read byte-for-byte; show UTF-8 characters (e.g. Polish letters) correctly.
            $decoded = $utf8.GetString($latin1.GetBytes($Value))
            if ($decoded.IndexOf([char]0xFFFD) -lt 0) { $Value = $decoded }
        }
        $Value = $Cfg.WsRx.Replace($Value, ' ').Trim()
        if ($Value.Length -gt $Cfg.MaxProofLength) { $Value = $Value.Substring(0, $Cfg.MaxProofLength) + ' ' + [char]0x2026 }
        return $Value
    }

    function Get-NewlineIndex([string]$Text) {
        $list = [Collections.Generic.List[int]]::new()
        $p = $Text.IndexOf([char]10)
        while ($p -ge 0) { $list.Add($p); $p = $Text.IndexOf([char]10, $p + 1) }
        return , $list
    }

    function Test-Claimed($St, [long]$Start, [long]$End) {
        foreach ($r in $St.Claimed) { if ($Start -lt $r[1] -and $End -gt $r[0]) { return $true } }
        return $false
    }

    # Runs every rule over one block of text. $Base/$Mult convert a char index into a file byte offset.
    function Invoke-Rules($St, [string]$Scan, [string]$Raw, [string]$Mode, [long]$Base, [int]$Mult, [long]$LineBase) {
        $newlines = $null
        foreach ($rule in $Rules) {
            if ($Sync.Cancel) { return }
            if ($St.Capped.Contains($rule.Name)) { continue }
            if ($St.IsLicense -and $rule.Check -eq 'email') { continue }
            try {
                $m = $rule.Rx.Match($Scan)
                while ($m.Success) {
                    if ($rule.Check -eq 'email') {
                        $St.EmailRule = $rule.Name
                        if ($St.Emails.Count -lt 5000 -and -not $Cfg.EmailNoiseRx.IsMatch($m.Value)) { [void]$St.Emails.Add($m.Value) }
                        $m = $m.NextMatch()
                        continue
                    }
                    if (Test-Match $rule $m $Scan $Mode $St.IsCode) {
                        if ($Mode -eq 'binary') {
                            # Binary text was cleaned up for matching; locate the hit in the raw bytes.
                            $needle = $m.Value
                            $cut = $needle.IndexOf([char]10)
                            if ($cut -gt 0) { $needle = $needle.Substring(0, $cut) }
                            $pos = $Raw.IndexOf($needle, [StringComparison]::Ordinal)
                            $abs = if ($pos -ge 0) { $Base + [long]$pos * $Mult } else { [long]-1 }
                        } else {
                            $abs = $Base + [long]$m.Index * $Mult
                        }
                        $absEnd = $abs + [long]$m.Length * $Mult
                        if ($abs -lt 0 -or -not (Test-Claimed $St $abs $absEnd)) {
                            $value = Format-Value $m.Value $Mode
                            if ($St.Seen.Add($rule.Name + [char]1 + $value)) {
                                if ($abs -ge 0) { $St.Claimed.Add([long[]]@($abs, $absEnd)) }
                                if ($Mode -eq 'binary') {
                                    $loc = if ($abs -ge 0) { 'offset 0x{0:X}' -f $abs } else { 'binary string' }
                                } else {
                                    if ($null -eq $newlines) { $newlines = Get-NewlineIndex $Scan }
                                    $i = $newlines.BinarySearch($m.Index)
                                    if ($i -lt 0) { $i = -bnot $i }
                                    $loc = 'line {0}' -f ($LineBase + $i)
                                }
                                Add-Finding $St $rule.Name $loc $value
                                $hits = 1 + [int]$St.Hits[$rule.Name]
                                $St.Hits[$rule.Name] = $hits
                                if ($hits -ge $Cfg.MaxPerRule) {
                                    [void]$St.Capped.Add($rule.Name)
                                    if ($m.NextMatch().Success) { $St.More.Add($rule.Name) }
                                    break
                                }
                            }
                        }
                    }
                    $m = $m.NextMatch()
                }
            } catch {
                $errorsArr[$Id]++    # regex timeout on pathological content: skip this rule for this block
            }
        }
    }

    function Invoke-FileScan([IO.FileInfo]$File) {
        if ($File.Length -eq 0) { return }
        $st = @{
            Path      = $File.FullName
            IsCode    = $Cfg.CodeExt.Contains($File.Extension)
            IsLicense = $Cfg.LicenseRx.IsMatch($File.Name)
            Seen      = [Collections.Generic.HashSet[string]]::new()
            Claimed   = [Collections.Generic.List[long[]]]::new()
            Hits      = @{}
            Capped    = [Collections.Generic.HashSet[string]]::new()
            More      = [Collections.Generic.List[string]]::new()
            Emails    = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
            EmailRule = $null
        }
        $fs = [IO.FileStream]::new($File.FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read,
                                   [IO.FileShare]'ReadWrite, Delete', 65536, [IO.FileOptions]::SequentialScan)
        try {
            $mode = $null; $chunkStart = [long]0; $carry = 0; $lineBase = [long]1; $ov = $Cfg.Overlap
            while (-not $Sync.Cancel) {
                $read = $fs.Read($buffer, $carry, $buffer.Length - $carry)
                if ($read -le 0) { break }
                $valid = $carry + $read
                $eof = $fs.Position -ge $fs.Length
                if ($null -eq $mode) {
                    if ($valid -ge 2 -and $buffer[0] -eq 0xFF -and $buffer[1] -eq 0xFE) { $mode = 'utf16' }
                    elseif ([Array]::IndexOf($buffer, [byte]0, 0, [Math]::Min($valid, 8000)) -ge 0) { $mode = 'binary' }
                    else { $mode = 'text' }
                }
                $text = $null
                if ($mode -eq 'text') {
                    $text = $latin1.GetString($buffer, 0, $valid)
                    Invoke-Rules $st $text $text 'text' $chunkStart 1 $lineBase
                } elseif ($mode -eq 'utf16') {
                    $text = $unicode.GetString($buffer, 0, $valid - ($valid % 2))
                    Invoke-Rules $st $text $text 'utf16' $chunkStart 2 $lineBase
                } else {
                    # Binary: scan printable ASCII runs, then UTF-16 strings at both byte alignments.
                    $raw = $latin1.GetString($buffer, 0, $valid)
                    Invoke-Rules $st ($Cfg.NonPrintRx.Replace($raw, "`n")) $raw 'binary' $chunkStart 1 0
                    if ($Cfg.WideProbeRx.IsMatch($raw)) {
                        foreach ($shift in 0, 1) {
                            $n = $valid - $shift; $n -= $n % 2
                            if ($n -le 0) { continue }
                            $wide = $unicode.GetString($buffer, $shift, $n)
                            Invoke-Rules $st ($Cfg.NonPrintRx.Replace($wide, "`n")) $wide 'binary' ($chunkStart + $shift) 2 0
                        }
                    }
                }
                if ($eof) { break }
                if ($valid -le $ov) { $chunkStart += $valid; $carry = 0; continue }
                if ($mode -ne 'binary') {
                    $adv = $valid - $ov
                    if ($mode -eq 'utf16') { $adv = [int]($adv / 2) }
                    $head = $text.Substring(0, [Math]::Min($adv, $text.Length))
                    $lineBase += $head.Length - $head.Replace("`n", '').Length
                }
                [Buffer]::BlockCopy($buffer, $valid - $ov, $buffer, 0, $ov)
                $chunkStart += $valid - $ov
                $carry = $ov
            }
        } finally {
            $fs.Dispose()
        }

        if ($st.Emails.Count -ge $Cfg.EmailThreshold) {
            $sample = [Collections.Generic.List[string]]::new()
            foreach ($e in $st.Emails) { $sample.Add($e); if ($sample.Count -ge 3) { break } }
            Add-Finding $st $st.EmailRule 'whole file' ('{0} unique addresses, e.g. {1}' -f $st.Emails.Count, ($sample -join ', '))
        }
        foreach ($name in $st.More) {
            Add-Finding $st $name 'whole file' ('More matches not listed (limit {0} per file)' -f $Cfg.MaxPerRule)
        }
    }

    $file = $null
    while (-not $Sync.Cancel) {
        if (-not $queue.TryDequeue([ref]$file)) {
            if ($Sync.EnumDone -and $queue.IsEmpty) { break }
            [Threading.Thread]::Sleep(20)
            continue
        }
        $current[$Id] = $file.FullName
        try { Invoke-FileScan $file } catch { $errorsArr[$Id]++ }
        $doneArr[$Id]++
        $bytesArr[$Id] += $file.Length
    }
    $current[$Id] = $null
}
#endregion

#region Window layout (XAML) ----------------------------------------------------------------------------

$Xaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Secret Scanner" Width="1240" Height="800" MinWidth="880" MinHeight="540"
        WindowStartupLocation="CenterScreen" Background="#1B1F27" Foreground="#E3E6EC"
        FontFamily="Segoe UI Variable Text, Segoe UI" FontSize="13"
        UseLayoutRounding="True" SnapsToDevicePixels="True" TextOptions.TextFormattingMode="Display">
  <Window.Resources>

    <!-- Buttons: one neutral style, one primary style -->
    <Style x:Key="BaseButton" TargetType="Button">
      <Setter Property="Foreground" Value="#E3E6EC"/>
      <Setter Property="Background" Value="#2A303C"/>
      <Setter Property="BorderBrush" Value="#3A4252"/>
      <Setter Property="BorderThickness" Value="1"/>
      <Setter Property="Padding" Value="16,7"/>
      <Setter Property="Margin" Value="8,0,0,0"/>
      <Setter Property="Cursor" Value="Hand"/>
      <Setter Property="FocusVisualStyle" Value="{x:Null}"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="Button">
            <Grid>
              <Border x:Name="Bd" CornerRadius="5" Background="{TemplateBinding Background}"
                      BorderBrush="{TemplateBinding BorderBrush}" BorderThickness="{TemplateBinding BorderThickness}"/>
              <Border x:Name="Hover" CornerRadius="5" Background="#FFFFFF" Opacity="0"/>
              <ContentPresenter Margin="{TemplateBinding Padding}" HorizontalAlignment="Center" VerticalAlignment="Center"/>
            </Grid>
            <ControlTemplate.Triggers>
              <Trigger Property="IsMouseOver" Value="True"><Setter TargetName="Hover" Property="Opacity" Value="0.07"/></Trigger>
              <Trigger Property="IsPressed" Value="True"><Setter TargetName="Hover" Property="Opacity" Value="0.02"/></Trigger>
              <Trigger Property="IsKeyboardFocused" Value="True"><Setter TargetName="Bd" Property="BorderBrush" Value="#5AA9F0"/></Trigger>
              <Trigger Property="IsEnabled" Value="False"><Setter Property="Opacity" Value="0.45"/></Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>
    <Style x:Key="PrimaryButton" TargetType="Button" BasedOn="{StaticResource BaseButton}">
      <Setter Property="Background" Value="#5AA9F0"/>
      <Setter Property="BorderBrush" Value="#5AA9F0"/>
      <Setter Property="Foreground" Value="#0E1B29"/>
      <Setter Property="FontWeight" Value="SemiBold"/>
    </Style>

    <!-- Filter box with placeholder text taken from Tag -->
    <Style x:Key="SearchBox" TargetType="TextBox">
      <Setter Property="Foreground" Value="#E3E6EC"/>
      <Setter Property="CaretBrush" Value="#E3E6EC"/>
      <Setter Property="SelectionBrush" Value="#5AA9F0"/>
      <Setter Property="Background" Value="#232833"/>
      <Setter Property="BorderBrush" Value="#3A4252"/>
      <Setter Property="Padding" Value="10,7"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="TextBox">
            <Border x:Name="Bd" CornerRadius="5" Background="{TemplateBinding Background}"
                    BorderBrush="{TemplateBinding BorderBrush}" BorderThickness="1">
              <Grid>
                <TextBlock x:Name="Hint" Text="{Binding Tag, RelativeSource={RelativeSource TemplatedParent}}"
                           Foreground="#7D8696" Margin="{TemplateBinding Padding}" Padding="2,0,0,0"
                           VerticalAlignment="Center" Visibility="Collapsed" IsHitTestVisible="False"/>
                <ScrollViewer x:Name="PART_ContentHost" Margin="{TemplateBinding Padding}" VerticalAlignment="Center"/>
              </Grid>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="Text" Value=""><Setter TargetName="Hint" Property="Visibility" Value="Visible"/></Trigger>
              <Trigger Property="IsKeyboardFocused" Value="True"><Setter TargetName="Bd" Property="BorderBrush" Value="#5AA9F0"/></Trigger>
              <Trigger Property="IsReadOnly" Value="True"><Setter Property="Foreground" Value="#8C94A3"/></Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>

    <!-- Summary tiles -->
    <Style x:Key="Tile" TargetType="Border">
      <Setter Property="Background" Value="#232833"/>
      <Setter Property="BorderBrush" Value="#2E3441"/>
      <Setter Property="BorderThickness" Value="1"/>
      <Setter Property="CornerRadius" Value="6"/>
      <Setter Property="Padding" Value="14,9,14,10"/>
    </Style>
    <Style x:Key="TileLabel" TargetType="TextBlock">
      <Setter Property="Foreground" Value="#8C94A3"/>
      <Setter Property="FontSize" Value="12"/>
    </Style>
    <Style x:Key="TileValue" TargetType="TextBlock">
      <Setter Property="FontFamily" Value="Segoe UI Variable Display, Segoe UI"/>
      <Setter Property="FontSize" Value="22"/>
      <Setter Property="FontWeight" Value="SemiBold"/>
    </Style>

    <!-- Thin progress bar -->
    <Style TargetType="ProgressBar">
      <Setter Property="Height" Value="6"/>
      <Setter Property="Foreground" Value="#5AA9F0"/>
      <Setter Property="Background" Value="#2E3441"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="ProgressBar">
            <Grid>
              <Border x:Name="PART_Track" CornerRadius="3" Background="{TemplateBinding Background}"/>
              <Border x:Name="PART_Indicator" CornerRadius="3" Background="{TemplateBinding Foreground}" HorizontalAlignment="Left"/>
            </Grid>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>

    <!-- Slim scroll bars -->
    <Style x:Key="ScrollThumb" TargetType="Thumb">
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="Thumb">
            <Border x:Name="T" CornerRadius="4" Background="#3D4555"/>
            <ControlTemplate.Triggers>
              <Trigger Property="IsMouseOver" Value="True"><Setter TargetName="T" Property="Background" Value="#566075"/></Trigger>
              <Trigger Property="IsDragging" Value="True"><Setter TargetName="T" Property="Background" Value="#6C788F"/></Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>
    <Style x:Key="ScrollPage" TargetType="RepeatButton">
      <Setter Property="Focusable" Value="False"/>
      <Setter Property="IsTabStop" Value="False"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="RepeatButton"><Border Background="Transparent"/></ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>
    <ControlTemplate x:Key="VScroll" TargetType="ScrollBar">
      <Border Background="Transparent" Padding="2">
        <Track x:Name="PART_Track" IsDirectionReversed="True">
          <Track.DecreaseRepeatButton><RepeatButton Style="{StaticResource ScrollPage}" Command="ScrollBar.PageUpCommand"/></Track.DecreaseRepeatButton>
          <Track.Thumb><Thumb Style="{StaticResource ScrollThumb}" MinHeight="24"/></Track.Thumb>
          <Track.IncreaseRepeatButton><RepeatButton Style="{StaticResource ScrollPage}" Command="ScrollBar.PageDownCommand"/></Track.IncreaseRepeatButton>
        </Track>
      </Border>
    </ControlTemplate>
    <ControlTemplate x:Key="HScroll" TargetType="ScrollBar">
      <Border Background="Transparent" Padding="2">
        <Track x:Name="PART_Track" IsDirectionReversed="False">
          <Track.DecreaseRepeatButton><RepeatButton Style="{StaticResource ScrollPage}" Command="ScrollBar.PageLeftCommand"/></Track.DecreaseRepeatButton>
          <Track.Thumb><Thumb Style="{StaticResource ScrollThumb}" MinWidth="24"/></Track.Thumb>
          <Track.IncreaseRepeatButton><RepeatButton Style="{StaticResource ScrollPage}" Command="ScrollBar.PageRightCommand"/></Track.IncreaseRepeatButton>
        </Track>
      </Border>
    </ControlTemplate>
    <Style TargetType="ScrollBar">
      <Setter Property="Width" Value="12"/>
      <Setter Property="MinWidth" Value="0"/>
      <Setter Property="Template" Value="{StaticResource VScroll}"/>
      <Style.Triggers>
        <Trigger Property="Orientation" Value="Horizontal">
          <Setter Property="Width" Value="Auto"/>
          <Setter Property="Height" Value="12"/>
          <Setter Property="MinHeight" Value="0"/>
          <Setter Property="Template" Value="{StaticResource HScroll}"/>
        </Trigger>
      </Style.Triggers>
    </Style>

    <Style TargetType="ToolTip">
      <Setter Property="Background" Value="#2A303C"/>
      <Setter Property="Foreground" Value="#E3E6EC"/>
      <Setter Property="BorderBrush" Value="#3A4252"/>
    </Style>

    <!-- Results table -->
    <Style x:Key="HeaderGripper" TargetType="Thumb">
      <Setter Property="Width" Value="8"/>
      <Setter Property="Cursor" Value="SizeWE"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="Thumb"><Border Background="Transparent"/></ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>
    <Style TargetType="DataGridColumnHeader">
      <Setter Property="Background" Value="#20242D"/>
      <Setter Property="Foreground" Value="#8C94A3"/>
      <Setter Property="FontWeight" Value="SemiBold"/>
      <Setter Property="Padding" Value="14,10"/>
      <Setter Property="BorderBrush" Value="#2E3441"/>
      <Setter Property="BorderThickness" Value="0,0,0,1"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="DataGridColumnHeader">
            <Grid>
              <Border Background="{TemplateBinding Background}" BorderBrush="{TemplateBinding BorderBrush}"
                      BorderThickness="{TemplateBinding BorderThickness}" Padding="{TemplateBinding Padding}">
                <DockPanel>
                  <Path x:Name="SortArrow" DockPanel.Dock="Right" Visibility="Collapsed" Width="8" Height="5"
                        Stretch="Fill" Margin="8,0,0,0" VerticalAlignment="Center" Fill="#8C94A3" Data="M0,0 L1,0 0.5,1 z"/>
                  <ContentPresenter VerticalAlignment="Center"/>
                </DockPanel>
              </Border>
              <Thumb x:Name="PART_RightHeaderGripper" HorizontalAlignment="Right" Style="{StaticResource HeaderGripper}"/>
            </Grid>
            <ControlTemplate.Triggers>
              <Trigger Property="SortDirection" Value="Ascending">
                <Setter TargetName="SortArrow" Property="Visibility" Value="Visible"/>
                <Setter TargetName="SortArrow" Property="Data" Value="M0,1 L1,1 0.5,0 z"/>
              </Trigger>
              <Trigger Property="SortDirection" Value="Descending">
                <Setter TargetName="SortArrow" Property="Visibility" Value="Visible"/>
              </Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>
    <Style TargetType="DataGridCell">
      <Setter Property="BorderThickness" Value="0"/>
      <Setter Property="Padding" Value="14,9"/>
      <Setter Property="FocusVisualStyle" Value="{x:Null}"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="DataGridCell">
            <Border Background="{TemplateBinding Background}" Padding="{TemplateBinding Padding}">
              <ContentPresenter VerticalAlignment="Top"/>
            </Border>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
      <Style.Triggers>
        <Trigger Property="IsSelected" Value="True">
          <Setter Property="Background" Value="#2B3B52"/>
          <Setter Property="Foreground" Value="#FFFFFF"/>
        </Trigger>
      </Style.Triggers>
    </Style>
    <Style TargetType="DataGridRow">
      <Style.Triggers>
        <Trigger Property="IsMouseOver" Value="True"><Setter Property="Background" Value="#262C37"/></Trigger>
      </Style.Triggers>
    </Style>
    <Style x:Key="PathCell" TargetType="TextBlock">
      <Setter Property="TextWrapping" Value="Wrap"/>
      <Setter Property="Foreground" Value="#C9CED8"/>
    </Style>
  </Window.Resources>

  <Grid Margin="24,18,24,14">
    <Grid.RowDefinitions>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="*"/>
      <RowDefinition Height="Auto"/>
    </Grid.RowDefinitions>

    <!-- Header -->
    <StackPanel Grid.Row="0" Orientation="Horizontal" Margin="0,0,0,14">
      <Viewbox Width="34" Height="34" VerticalAlignment="Center">
        <Grid Width="24" Height="24">
          <Path Fill="#5AA9F0" Data="M12,1 L21,4.8 V11 C21,16.6 17.2,21.4 12,23 C6.8,21.4 3,16.6 3,11 V4.8 Z"/>
          <Path Fill="#1B1F27" Data="M13,11.6 A2.4,2.4 0 1 0 11,11.6 L10.4,15.6 H13.6 Z"/>
        </Grid>
      </Viewbox>
      <TextBlock Margin="14,0,0,0" VerticalAlignment="Center" FontFamily="Segoe UI Variable Display, Segoe UI" FontSize="21" FontWeight="SemiBold"><Run Text="Secret Scanner"/><Run x:Name="TxtVersion" FontSize="13" FontWeight="Normal" Foreground="#8C94A3"/></TextBlock>
    </StackPanel>

    <!-- Folder to scan -->
    <Grid Grid.Row="1" Margin="0,0,0,12">
      <Grid.ColumnDefinitions>
        <ColumnDefinition Width="*"/>
        <ColumnDefinition Width="Auto"/>
      </Grid.ColumnDefinitions>
      <TextBox x:Name="PathBox" Style="{StaticResource SearchBox}" Tag="Folder to scan: paste a path and press Enter"
               ToolTip="Folder to scan. Paste or type a path, then press Enter or Scan again. Esc restores the last scanned folder."/>
      <Button x:Name="BtnAction" Grid.Column="1" Style="{StaticResource PrimaryButton}" Content="Stop scan" MinWidth="120"/>
    </Grid>

    <!-- Summary -->
    <UniformGrid Grid.Row="2" Rows="1" Columns="5" Margin="0,0,0,12">
      <Border Style="{StaticResource Tile}" Margin="0,0,8,0">
        <StackPanel>
          <TextBlock Text="Files found" Style="{StaticResource TileLabel}"/>
          <TextBlock x:Name="TxtFound" Text="0" Style="{StaticResource TileValue}"/>
        </StackPanel>
      </Border>
      <Border Style="{StaticResource Tile}" Margin="0,0,8,0">
        <StackPanel>
          <TextBlock Text="Files scanned" Style="{StaticResource TileLabel}"/>
          <TextBlock x:Name="TxtScanned" Text="0" Style="{StaticResource TileValue}"/>
        </StackPanel>
      </Border>
      <Border Style="{StaticResource Tile}" Margin="0,0,8,0">
        <StackPanel>
          <TextBlock Text="Data read" Style="{StaticResource TileLabel}"/>
          <TextBlock x:Name="TxtData" Text="0 B" Style="{StaticResource TileValue}"/>
        </StackPanel>
      </Border>
      <Border Style="{StaticResource Tile}" Margin="0,0,8,0">
        <StackPanel>
          <TextBlock x:Name="TxtFindingFiles" Text="Findings" Style="{StaticResource TileLabel}"/>
          <TextBlock x:Name="TxtFindings" Text="0" Foreground="#F2B544" Style="{StaticResource TileValue}"/>
        </StackPanel>
      </Border>
      <Border Style="{StaticResource Tile}">
        <StackPanel>
          <TextBlock Text="Elapsed" Style="{StaticResource TileLabel}"/>
          <TextBlock x:Name="TxtElapsed" Text="00:00:00" Style="{StaticResource TileValue}"/>
        </StackPanel>
      </Border>
    </UniformGrid>

    <!-- Progress -->
    <Border Grid.Row="3" Style="{StaticResource Tile}" Margin="0,0,0,12" Padding="16,12,16,12">
      <StackPanel>
        <Grid>
          <TextBlock x:Name="TxtStatus" Text="Starting" FontWeight="SemiBold" Margin="0,0,60,0" TextTrimming="CharacterEllipsis"/>
          <TextBlock x:Name="TxtPercent" HorizontalAlignment="Right" Foreground="#8C94A3"/>
        </Grid>
        <ProgressBar x:Name="Progress" Maximum="100" Margin="0,10,0,9"/>
        <TextBlock x:Name="TxtCurrent" Foreground="#8C94A3" FontSize="12" TextTrimming="CharacterEllipsis"/>
      </StackPanel>
    </Border>

    <!-- Toolbar -->
    <Grid Grid.Row="4" Margin="0,0,0,10">
      <Grid.ColumnDefinitions>
        <ColumnDefinition Width="*"/>
        <ColumnDefinition Width="Auto"/>
      </Grid.ColumnDefinitions>
      <TextBox x:Name="FilterBox" Style="{StaticResource SearchBox}" Width="440" HorizontalAlignment="Left"
               Tag="Filter by path, finding or value (Ctrl+F)"/>
      <StackPanel Grid.Column="1" Orientation="Horizontal">
        <Button x:Name="BtnCopy" Style="{StaticResource BaseButton}" Content="Copy selected"/>
        <Button x:Name="BtnOpen" Style="{StaticResource BaseButton}" Content="Open file location"/>
        <Button x:Name="BtnExport" Style="{StaticResource BaseButton}" Content="Export to CSV"/>
      </StackPanel>
    </Grid>

    <!-- Results -->
    <Border Grid.Row="5" Background="#1F232C" BorderBrush="#2E3441" BorderThickness="1" CornerRadius="6" Padding="1">
      <Grid>
        <DataGrid x:Name="ResultsGrid" AutoGenerateColumns="False" IsReadOnly="True" SelectionMode="Extended"
                  SelectionUnit="FullRow" HeadersVisibility="Column" GridLinesVisibility="Horizontal"
                  HorizontalGridLinesBrush="#2A303B" Background="#1F232C" RowBackground="#1F232C"
                  AlternatingRowBackground="#222731" Foreground="#E3E6EC" BorderThickness="0"
                  CanUserResizeRows="False" CanUserReorderColumns="False" EnableRowVirtualization="True"
                  VirtualizingPanel.VirtualizationMode="Recycling" ScrollViewer.HorizontalScrollBarVisibility="Disabled">
          <DataGrid.Columns>
            <DataGridTextColumn Header="File" Width="5*" Binding="{Binding Item1, Mode=OneWay}"
                                ElementStyle="{StaticResource PathCell}" SortMemberPath="Item1"/>
            <DataGridTemplateColumn Header="Proof" Width="7*" SortMemberPath="Item2">
              <DataGridTemplateColumn.CellTemplate>
                <DataTemplate>
                  <StackPanel>
                    <TextBlock Text="{Binding Item2, Mode=OneWay}" Foreground="#F2B544" FontWeight="SemiBold" TextWrapping="Wrap"/>
                    <TextBlock TextWrapping="Wrap" Margin="0,3,0,0"><Run Text="{Binding Item3, Mode=OneWay}" Foreground="#8C94A3"/><Run Text="    "/><Run Text="{Binding Item4, Mode=OneWay}" FontFamily="Cascadia Mono, Consolas" FontSize="12.5"/></TextBlock>
                  </StackPanel>
                </DataTemplate>
              </DataGridTemplateColumn.CellTemplate>
            </DataGridTemplateColumn>
          </DataGrid.Columns>
        </DataGrid>
        <TextBlock x:Name="TxtEmpty" Visibility="Collapsed" HorizontalAlignment="Center" VerticalAlignment="Center"
                   Foreground="#8C94A3" FontSize="15"/>
      </Grid>
    </Border>

    <!-- Footer -->
    <Grid Grid.Row="6" Margin="2,10,2,0">
      <TextBlock x:Name="TxtFooter" Foreground="#8C94A3" FontSize="12"
                 Text="Double-click a row to open its folder. Ctrl+C copies the selected rows."/>
      <TextBlock x:Name="TxtCount" HorizontalAlignment="Right" Foreground="#8C94A3" FontSize="12"/>
    </Grid>
  </Grid>
</Window>
'@
#endregion

#region User interface ----------------------------------------------------------------------------------

Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase

# Optional dark title bar (Windows 10 20H1 and later). Skipped silently where Add-Type is not allowed.
if (-not ('SecretScanner.NativeMethods' -as [type])) {
    try {
        Add-Type -Namespace SecretScanner -Name NativeMethods -ErrorAction Stop -MemberDefinition @'
[System.Runtime.InteropServices.DllImport("dwmapi.dll")]
public static extern int DwmSetWindowAttribute(System.IntPtr hwnd, int attribute, ref int value, int size);
'@
    } catch { }
}

$window = [Windows.Markup.XamlReader]::Parse($Xaml)
$ui = @{}
foreach ($name in 'PathBox', 'TxtVersion', 'BtnAction', 'TxtFound', 'TxtScanned', 'TxtData', 'TxtFindings', 'TxtFindingFiles',
                  'TxtElapsed', 'TxtStatus', 'TxtPercent', 'Progress', 'TxtCurrent', 'FilterBox', 'BtnCopy',
                  'BtnOpen', 'BtnExport', 'ResultsGrid', 'TxtEmpty', 'TxtFooter', 'TxtCount') {
    $ui[$name] = $window.FindName($name)
}

$brushes  = [Windows.Media.BrushConverter]::new()
$AmberBrush = $brushes.ConvertFromString('#F2B544')
$GreenBrush = $brushes.ConvertFromString('#6CCB8F')
$Ellipsis = [string][char]0x2026
$FooterHint = $ui.TxtFooter.Text

$State = @{
    Sync        = $null
    Coordinator = $null
    Items       = $null
    View        = $null
    FilterText  = ''
    Started     = $false
    Files       = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    Stopwatch   = [Diagnostics.Stopwatch]::new()
    Timer       = [Windows.Threading.DispatcherTimer]::new()
    FilterTimer = [Windows.Threading.DispatcherTimer]::new()
}
$State.Timer.Interval = [TimeSpan]::FromMilliseconds(200)
$State.FilterTimer.Interval = [TimeSpan]::FromMilliseconds(250)
$State.FilterPredicate = [Predicate[object]] {
    param($Row)
    $f = $State.FilterText
    $Row.Item1.IndexOf($f, [StringComparison]::OrdinalIgnoreCase) -ge 0 -or
    $Row.Item2.IndexOf($f, [StringComparison]::OrdinalIgnoreCase) -ge 0 -or
    $Row.Item4.IndexOf($f, [StringComparison]::OrdinalIgnoreCase) -ge 0
}

function Format-Size([double]$Bytes) {
    if ($Bytes -ge 1GB) { return '{0:N2} GB' -f ($Bytes / 1GB) }
    if ($Bytes -ge 1MB) { return '{0:N1} MB' -f ($Bytes / 1MB) }
    if ($Bytes -ge 1KB) { return '{0:N0} KB' -f ($Bytes / 1KB) }
    return '{0:N0} B' -f $Bytes
}

function Get-RelativePath([string]$FullPath) {
    $base = $Root.TrimEnd('\')
    if ($FullPath.StartsWith($base, [StringComparison]::OrdinalIgnoreCase)) { return '.' + $FullPath.Substring($base.Length) }
    return $FullPath
}

function Get-Total([Array]$Values) {
    $sum = [long]0
    foreach ($v in $Values) { $sum += $v }
    return $sum
}

function Set-Results([object[]]$Rows) {
    $State.Items = [Collections.ObjectModel.ObservableCollection[object]]::new()
    foreach ($r in $Rows) { $State.Items.Add($r) }
    $ui.ResultsGrid.ItemsSource = $State.Items
    $State.View = [Windows.Data.CollectionViewSource]::GetDefaultView($State.Items)
    Update-Filter
}

function Update-Filter {
    $State.FilterText = $ui.FilterBox.Text.Trim()
    if ($State.FilterText) { $State.View.Filter = $State.FilterPredicate } else { $State.View.Filter = $null }
    Update-Counter
}

function Update-Counter {
    $total = $State.Items.Count
    if ($State.FilterText) { $ui.TxtCount.Text = 'Showing {0:N0} of {1:N0} findings' -f $State.View.Count, $total }
    else { $ui.TxtCount.Text = '{0:N0} findings' -f $total }
}

function Show-FooterMessage([string]$Text) {
    $ui.TxtFooter.Text = $Text
}

# Turns what the user typed or pasted into a full folder path. Quotes from Explorer's "Copy as path" are
# removed and environment variables such as %ProgramFiles% are expanded.
function Resolve-ScanPath([string]$Text) {
    $p = $Text.Trim().Trim([char]34, [char]39).Trim()
    if (-not $p) { return @{ Error = 'Enter the folder to scan.' } }
    $p = [Environment]::ExpandEnvironmentVariables($p)
    try { $resolved = Resolve-Path -LiteralPath $p -ErrorAction Stop }
    catch { return @{ Error = 'Folder not found: ' + $p } }
    if ($resolved.Provider.Name -ne 'FileSystem') { return @{ Error = 'Not a file system folder: ' + $p } }
    $full = $resolved.ProviderPath
    if (-not (Test-Path -LiteralPath $full -PathType Container)) { return @{ Error = 'This is a file, not a folder: ' + $full } }
    return @{ Path = $full }
}

function Set-ScanRoot([string]$Path) {
    $script:Root = $Path
    $Settings.Root = $Path
    $ui.PathBox.Text = $Path
    $ui.PathBox.CaretIndex = $Path.Length
    $window.Title = 'Secret Scanner {0} - {1}' -f $ScriptVersion, $Path
}

# Scans the folder in the path field, or explains why it cannot.
function Start-ScanFromPathBox {
    $target = Resolve-ScanPath $ui.PathBox.Text
    if ($target.Error) {
        $ui.TxtStatus.Text = $target.Error
        [void]$ui.PathBox.Focus()
        $ui.PathBox.SelectAll()
        return
    }
    Set-ScanRoot $target.Path
    Start-Scan
}

function Start-Scan {
    $State.Files.Clear()
    Set-Results @()
    $n = $Settings.Threads
    $sync = [hashtable]::Synchronized(@{
        Phase = 'Starting'; Cancel = $false; EnumDone = $false; Fatal = $null; WorkerError = $null
        Found = 0; Queued = 0; SkippedType = 0; SkippedSize = 0; DirErrors = 0; DirExcluded = 0; TotalBytes = [long]0
        Queue   = [Collections.Concurrent.ConcurrentQueue[IO.FileInfo]]::new()
        Results = [Collections.Concurrent.ConcurrentQueue[object]]::new()
        Done    = [int[]]::new($n)
        Bytes   = [long[]]::new($n)
        Errors  = [int[]]::new($n)
        Current = [string[]]::new($n)
    })
    $State.Sync = $sync

    $rs = [runspacefactory]::CreateRunspace([Management.Automation.Runspaces.InitialSessionState]::CreateDefault2())
    $rs.Open()
    $ps = [powershell]::Create()
    $ps.Runspace = $rs
    [void]$ps.AddScript($CoordinatorScript.ToString()).AddArgument($sync).AddArgument($Settings).AddArgument($RuleDefinitions).AddArgument($WorkerScript.ToString())
    $State.Coordinator = @{ PS = $ps; Runspace = $rs; Handle = $ps.BeginInvoke() }

    $ui.Progress.Value = 0
    $ui.TxtPercent.Text = ''
    $ui.TxtStatus.Text = 'Preparing detection rules' + $Ellipsis
    $ui.TxtCurrent.Text = ''
    $ui.TxtFindings.Foreground = $AmberBrush
    $ui.TxtEmpty.Visibility = 'Collapsed'
    $ui.BtnAction.Content = 'Stop scan'
    $ui.BtnAction.IsEnabled = $true
    $ui.PathBox.IsReadOnly = $true
    Show-FooterMessage $FooterHint
    $State.Stopwatch.Restart()
    $State.Timer.Start()
}

function Update-Progress {
    $s = $State.Sync
    if (-not $s) { return }

    # Move new findings into the list in batches so the window stays smooth.
    $item = $null; $added = 0
    while ($added -lt 1500 -and $s.Results.TryDequeue([ref]$item)) {
        $State.Items.Add($item)
        [void]$State.Files.Add($item.Item1)
        $added++
    }

    $done = Get-Total $s.Done
    $bytes = Get-Total $s.Bytes
    $total = [long]$s.TotalBytes
    $elapsed = $State.Stopwatch.Elapsed
    $ui.TxtFound.Text = '{0:N0}' -f $s.Found
    $ui.TxtScanned.Text = '{0:N0}' -f $done
    $ui.TxtData.Text = Format-Size $bytes
    $ui.TxtFindings.Text = '{0:N0}' -f $State.Items.Count
    $ui.TxtFindingFiles.Text = if ($State.Files.Count) { 'Findings in {0:N0} files' -f $State.Files.Count } else { 'Findings' }
    $ui.TxtElapsed.Text = $elapsed.ToString('hh\:mm\:ss')
    if ($added) { Update-Counter }

    if ($s.Phase -eq 'Done' -and $s.Results.IsEmpty) { Complete-Scan; return }

    $pct = 0.0
    if ($total -gt 0) { $pct = 100.0 * $bytes / $total } elseif ($s.Queued -gt 0) { $pct = 100.0 * $done / $s.Queued }
    $pct = [Math]::Min(100.0, $pct)
    $ui.Progress.Value = $pct
    $ui.TxtPercent.Text = '{0:N0} %' -f [Math]::Floor($pct)

    if ($s.Cancel) {
        $ui.TxtStatus.Text = 'Stopping' + $Ellipsis
    } elseif ($s.Phase -ne 'Scanning') {
        $ui.TxtStatus.Text = 'Preparing detection rules' + $Ellipsis
    } elseif (-not $s.EnumDone) {
        $ui.TxtStatus.Text = 'Scanning while discovering files: {0:N0} of {1:N0} found so far' -f $done, $s.Queued
    } else {
        $rate = if ($elapsed.TotalSeconds -ge 1) { ', ' + (Format-Size ($bytes / $elapsed.TotalSeconds)) + '/s' } else { '' }
        $ui.TxtStatus.Text = 'Scanning {0:N0} of {1:N0} files, {2} of {3}{4}' -f $done, $s.Queued, (Format-Size $bytes), (Format-Size $total), $rate
    }
    $now = $null
    foreach ($p in $s.Current) { if ($p) { $now = $p; break } }
    $ui.TxtCurrent.Text = if ($now) { Get-RelativePath $now } else { '' }
}

function Complete-Scan {
    $State.Timer.Stop()
    $State.Stopwatch.Stop()
    $s = $State.Sync
    $c = $State.Coordinator
    if ($c) {
        try { [void]$c.PS.EndInvoke($c.Handle) } catch { if (-not $s.Fatal) { $s.Fatal = $_.Exception.GetBaseException().Message } }
        $c.PS.Dispose(); $c.Runspace.Dispose()
        $State.Coordinator = $null
    }

    # Results arrive in parallel; sort them by file, finding and position so related rows sit together.
    $rows = [object[]]::new($State.Items.Count)
    $State.Items.CopyTo($rows, 0)
    $keys = [string[]]::new($rows.Length)
    for ($i = 0; $i -lt $rows.Length; $i++) {
        $loc = $rows[$i].Item3
        if ($loc.StartsWith('line ')) { $loc = 'line ' + $loc.Substring(5).PadLeft(12, '0') }
        elseif ($loc.StartsWith('offset 0x')) { $loc = 'offset ' + $loc.Substring(9).PadLeft(12, '0') }
        $keys[$i] = $rows[$i].Item1 + [char]1 + $rows[$i].Item2 + [char]1 + $loc
    }
    [Array]::Sort($keys, $rows, [StringComparer]::OrdinalIgnoreCase)
    Set-Results $rows

    $done = Get-Total $s.Done
    $bytes = Get-Total $s.Bytes
    $errors = Get-Total $s.Errors
    $elapsed = $State.Stopwatch.Elapsed.ToString('hh\:mm\:ss')
    if ($s.Fatal) {
        $ui.TxtStatus.Text = 'Scan failed: ' + $s.Fatal
    } elseif ($s.Cancel) {
        $ui.TxtStatus.Text = 'Stopped after {0}: {1:N0} of {2:N0} files scanned' -f $elapsed, $done, $s.Queued
    } else {
        $ui.Progress.Value = 100
        $ui.TxtPercent.Text = '100 %'
        $ui.TxtStatus.Text = 'Finished in {0}: {1:N0} files scanned ({2})' -f $elapsed, $done, (Format-Size $bytes)
    }
    $notes = '{0:N0} files not in the scan list, {1:N0} over the size limit, {2:N0} could not be read, {3:N0} folders not accessible' -f $s.SkippedType, $s.SkippedSize, $errors, $s.DirErrors
    if ($s.DirExcluded) { $notes += ', {0:N0} folders excluded by path' -f $s.DirExcluded }
    if ($s.WorkerError) { $notes += '. Worker error: ' + $s.WorkerError }
    $ui.TxtCurrent.Text = $notes

    $count = $State.Items.Count
    $ui.TxtFindings.Text = '{0:N0}' -f $count
    $ui.TxtFindings.Foreground = if ($count) { $AmberBrush } else { $GreenBrush }
    $ui.TxtEmpty.Text = if ($s.Cancel) { 'Scan stopped before anything was found' } else { 'No secrets found in this folder' }
    $ui.TxtEmpty.Visibility = if ($count) { 'Collapsed' } else { 'Visible' }
    $ui.BtnAction.Content = 'Scan again'
    $ui.BtnAction.IsEnabled = $true
    $ui.PathBox.IsReadOnly = $false
}

function Get-RowItem($Source) {
    $d = $Source
    while ($d -and $d -isnot [Windows.Controls.DataGridRow]) {
        if ($d -is [Windows.Controls.Primitives.DataGridColumnHeader]) { return $null }
        if ($d -is [Windows.Media.Visual]) { $d = [Windows.Media.VisualTreeHelper]::GetParent($d) }
        else { $d = [Windows.LogicalTreeHelper]::GetParent($d) }
    }
    if ($d) { return $d.Item }
    return $null
}

function Copy-Selected {
    $rows = @($ui.ResultsGrid.SelectedItems)
    if ($rows.Count -eq 0) { Show-FooterMessage 'Select one or more rows to copy.'; return }
    $sb = [Text.StringBuilder]::new()
    foreach ($r in $rows) { [void]$sb.AppendLine(($r.Item1, $r.Item2, $r.Item3, $r.Item4) -join "`t") }
    try {
        [Windows.Clipboard]::SetText($sb.ToString())
        Show-FooterMessage ('Copied {0:N0} rows to the clipboard (tab-separated).' -f $rows.Count)
    } catch {
        Show-FooterMessage 'The clipboard is busy. Try copying again.'
    }
}

function Open-Location($Row) {
    if (-not $Row) { Show-FooterMessage 'Select a row to open its folder.'; return }
    if (Test-Path -LiteralPath $Row.Item1) {
        Start-Process -FilePath explorer.exe -ArgumentList ('/select,"{0}"' -f $Row.Item1)
    } else {
        Show-FooterMessage ('The file no longer exists: ' + $Row.Item1)
    }
}

function Export-Results {
    if (-not $State.View -or $State.View.Count -eq 0) { Show-FooterMessage 'There are no findings to export.'; return }
    $leaf = (Split-Path -Path $Root -Leaf) -replace '[\\/:*?"<>|]', ''
    $dlg = [Microsoft.Win32.SaveFileDialog]::new()
    $dlg.Title = 'Export findings'
    $dlg.Filter = 'CSV file (*.csv)|*.csv'
    $dlg.InitialDirectory = [Environment]::GetFolderPath('MyDocuments')
    $dlg.FileName = 'SecretScan_{0}_{1:yyyyMMdd_HHmm}.csv' -f $leaf, (Get-Date)
    if (-not $dlg.ShowDialog($window)) { return }
    try {
        $encoding = if ($PSVersionTable.PSVersion.Major -ge 6) { 'utf8BOM' } else { 'UTF8' }
        $export = foreach ($r in $State.View) {
            [pscustomobject]@{ File = $r.Item1; Finding = $r.Item2; Location = $r.Item3; Proof = $r.Item4 }
        }
        $export | Export-Csv -LiteralPath $dlg.FileName -NoTypeInformation -UseCulture -Encoding $encoding
        Show-FooterMessage ('Exported {0:N0} findings to {1}' -f @($export).Count, $dlg.FileName)
    } catch {
        Show-FooterMessage ('Export failed: ' + $_.Exception.Message)
    }
}

# --- Events ----------------------------------------------------------------------------------------------

$State.Timer.Add_Tick({
    try { Update-Progress } catch { $ui.TxtStatus.Text = 'Display error: ' + $_.Exception.Message }
})
$State.FilterTimer.Add_Tick({ $State.FilterTimer.Stop(); Update-Filter })
$ui.FilterBox.Add_TextChanged({ $State.FilterTimer.Stop(); $State.FilterTimer.Start() })
$ui.FilterBox.Add_KeyDown({ param($s, $e) if ($e.Key -eq 'Escape') { $ui.FilterBox.Clear() } })

$ui.BtnAction.Add_Click({
    if ($State.Timer.IsEnabled) {
        $State.Sync.Cancel = $true
        $ui.BtnAction.IsEnabled = $false
        $ui.TxtStatus.Text = 'Stopping' + $Ellipsis
    } else {
        Start-ScanFromPathBox
    }
})
$ui.PathBox.Add_KeyDown({
    param($s, $e)
    if ($State.Timer.IsEnabled) { return }
    if ($e.Key -eq 'Enter') { Start-ScanFromPathBox; $e.Handled = $true }
    elseif ($e.Key -eq 'Escape') { $ui.PathBox.Text = $Root; $ui.PathBox.CaretIndex = $Root.Length; $e.Handled = $true }
})
$ui.BtnCopy.Add_Click({ Copy-Selected })
$ui.BtnOpen.Add_Click({ Open-Location $ui.ResultsGrid.SelectedItem })
$ui.BtnExport.Add_Click({ Export-Results })

$ui.ResultsGrid.Add_MouseDoubleClick({
    param($s, $e)
    $row = Get-RowItem $e.OriginalSource
    if ($row) { Open-Location $row }
})
$ui.ResultsGrid.Add_PreviewKeyDown({
    param($s, $e)
    $ctrl = [Windows.Input.Keyboard]::Modifiers -band [Windows.Input.ModifierKeys]::Control
    if ($ctrl -and $e.Key -eq 'C') { Copy-Selected; $e.Handled = $true }
    elseif ($e.Key -eq 'Enter') { Open-Location $ui.ResultsGrid.SelectedItem; $e.Handled = $true }
})
$window.Add_PreviewKeyDown({
    param($s, $e)
    $ctrl = [Windows.Input.Keyboard]::Modifiers -band [Windows.Input.ModifierKeys]::Control
    if ($ctrl -and $e.Key -eq 'F') { [void]$ui.FilterBox.Focus(); $ui.FilterBox.SelectAll(); $e.Handled = $true }
})

$window.Add_SourceInitialized({
    if (-not ('SecretScanner.NativeMethods' -as [type])) { return }
    try {
        $hwnd = [Windows.Interop.WindowInteropHelper]::new($window).Handle
        $on = 1
        if ([SecretScanner.NativeMethods]::DwmSetWindowAttribute($hwnd, 20, [ref]$on, 4) -ne 0) {
            [void][SecretScanner.NativeMethods]::DwmSetWindowAttribute($hwnd, 19, [ref]$on, 4)
        }
        $caption = 0x00271F1B   # title bar colour #1B1F27 as 0x00BBGGRR (Windows 11)
        [void][SecretScanner.NativeMethods]::DwmSetWindowAttribute($hwnd, 35, [ref]$caption, 4)
    } catch { }
})
$window.Add_ContentRendered({
    if (-not $State.Started) { $State.Started = $true; Start-Scan }
})
$window.Add_Closing({
    $State.Timer.Stop()
    if ($State.Sync) { $State.Sync.Cancel = $true }
})

$ui.TxtVersion.Text = '   v' + $ScriptVersion
Set-ScanRoot $Root
Set-Results @()
[void]$window.ShowDialog()

# The window is closed: give background work a moment to stop, then release it.
if ($State.Coordinator) {
    [void]$State.Coordinator.Handle.AsyncWaitHandle.WaitOne(10000)
    try { $State.Coordinator.PS.Dispose(); $State.Coordinator.Runspace.Dispose() } catch { }
}
#endregion
