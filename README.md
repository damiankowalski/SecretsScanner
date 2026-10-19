# Secret Scanner (`Find-Secrets.ps1`)

**Version 1.3.1** (2026-10-19)

Secret Scanner is a read-only PowerShell tool with a graphical window. It searches an application folder and all its subfolders for hardcoded passwords, API keys, tokens, certificates, connection strings, service account credentials and sensitive business data, and lists every finding with the file and the matching text as proof.

> **Handle the output with care.** The window and the CSV export show full secret values. Treat an export like a credential file.

---

## What it is

- A single PowerShell script (`.ps1`), not a compiled program. There is nothing to install, and it needs no modules and no network access.
- **Read-only.** It never changes, moves, deletes or uploads any file.
- **Interactive.** It opens a window, so it needs a logged-on desktop session. It is not meant to run unattended as SYSTEM through Intune or SCCM.
- **Fast on large folders.** Files are scanned in parallel while the folder tree is still being discovered, and memory use stays flat even for very large files.
![Secret Scanner window](docs/screenshot.png)

## Requirements

| Item | Requirement |
|---|---|
| Operating system | Windows 10 or 11, or Windows Server with Desktop Experience |
| PowerShell | Windows PowerShell 5.1 (built into Windows) or PowerShell 7.x |
| Permissions | Read access to the scanned folder. Administrator rights are only needed for folders a standard user cannot read. |
| Execution policy | Must allow the script to run, or start it with `-ExecutionPolicy Bypass` |

## Download

Download only `Find-Secrets.ps1`, either from this page (open the file, then **Download raw file**) or with PowerShell:

```powershell
Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/damiankowalski/SecretsScanner/main/Find-Secrets.ps1' -OutFile .\Find-Secrets.ps1
```

You can also clone the repository:

```powershell
git clone https://github.com/damiankowalski/SecretsScanner.git
```

## Quick start

1. Copy `Find-Secrets.ps1` into the application folder you want to check.
2. Start it, either by right-clicking the file and choosing **Run with PowerShell**, or from a console:
   ```powershell
   powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Find-Secrets.ps1
   ```
3. The scan starts as soon as the window opens. Findings appear in the list while it runs.
4. Review the findings, filter them, copy them or export them to CSV.

If Windows refuses to run the file because it was downloaded from the internet, unblock it once:

```powershell
Unblock-File .\Find-Secrets.ps1
```

## Parameters

| Parameter | Default | Description |
|---|---|---|
| `-Path` | The folder that contains the script | Folder to scan, including all subfolders |
| `-MaxFileSizeMB` | `200` | Files larger than this are skipped (allowed range 1 to 4096) |
| `-Threads` | Number of CPU cores, between 2 and 12 | Number of parallel scan workers. `0` means automatic; the maximum is 64. |

```powershell
# Scan the folder the script is in
.\Find-Secrets.ps1

# Scan another folder and allow larger log files
.\Find-Secrets.ps1 -Path 'D:\Apps\Contoso' -MaxFileSizeMB 500

# Use fewer workers on a shared server
.\Find-Secrets.ps1 -Threads 2
```

Built-in help is available with `Get-Help .\Find-Secrets.ps1 -Full`.

---

## Using the window

### Summary tiles

| Tile | Meaning |
|---|---|
| Files found | All files in the folder tree, including those that are not read |
| Files scanned | Files whose content was read and checked |
| Data read | Total size of the scanned files |
| Findings | Number of findings and the number of files they are in. The number turns green when nothing was found. |
| Elapsed | Scan duration |

### Progress and summary

The progress bar follows the amount of data scanned, and the line below it shows the file being read. When the scan ends, the summary line shows:

- how many files were not in the scan list,
- how many were over the size limit,
- how many could not be read,
- how many folders were not accessible,
- how many folders were excluded by path, if any.

### Results list

| Column | Content |
|---|---|
| **File** | Full path of the file |
| **Proof** | The finding name (in amber), its location, and the matching text including the full secret value |

The location tells you where the finding is:

| Location | Meaning |
|---|---|
| `line 12` | Line number in a text file |
| `offset 0x1A2B` | Byte position, used when a file has to be read as raw strings (for example a UTF-16 log without an encoding marker) |
| `file type` | Reported because of its extension. The file is not read. |
| `file name` | Reported because of its name. The file is not read. |
| `whole file` | A summary for the whole file: bulk e-mail addresses, or more matches than the per-file limit |

When the scan finishes, results are sorted by file, finding and position. Click a column header to sort differently.

### Actions

| Action | How |
|---|---|
| Filter | Type in the filter box or press **Ctrl+F**. The filter matches the path, the finding name and the value. **Esc** clears it. |
| Copy rows | Select rows, then press **Copy selected** or **Ctrl+C**. Rows are copied tab-separated (File, Finding, Location, Proof) and paste straight into Excel. |
| Open file location | Double-click a row, press **Enter**, or press **Open file location**. Explorer opens with the file selected. |
| Export to CSV | Saves the rows currently shown, so an active filter applies |
| Stop or rescan | **Stop scan** while running, **Scan again** when finished |

The CSV export has the columns File, Finding, Location and Proof. It uses the list separator from the Windows regional settings (a semicolon with Polish settings) and is saved as UTF-8 with BOM, so Excel shows accented characters correctly. The default file name is `SecretScan_<folder>_<yyyyMMdd_HHmm>.csv`, saved in Documents.

---

## How it works

1. **Discovery.** The folder tree is walked one folder at a time. Junctions and symbolic links to folders are not followed, so the walk cannot loop. A folder that cannot be opened is counted and skipped rather than stopping the scan. Each file is sorted into one of three groups: *scan the content*, *report by type or name*, or *skip*.
2. **Parallel scanning.** A pool of background workers takes files from a shared queue. Scanning starts while discovery is still running, and the window stays responsive throughout.
3. **Reading.** Every file is read exactly once, in 4 MB chunks that overlap by 2 KB, so a secret split across a chunk boundary is still found. Memory use does not grow with file size.
4. **Encoding.** UTF-8, ANSI and UTF-16 files with a byte-order mark are read as text, and findings show line numbers. A file that contains null bytes without a marker is read as raw strings, both single-byte and UTF-16 at either byte alignment, and findings show byte offsets.
5. **Matching.** 36 detection rules (precompiled regular expressions) run over each chunk, most specific first. When two rules match the same text, only the more specific one is reported. Each rule has a 5-second time limit per chunk, so unusual content cannot hang the scan.
6. **Validation.** Candidate matches are checked before they are reported. Placeholders and setting names that are not secrets are dropped, values must look like real keys where that matters, card numbers must pass the Luhn checksum, and IBANs must pass the country and check-digit test. The full list is under [How false positives are kept down](#how-false-positives-are-kept-down).
7. **Limits.** Each rule reports at most 25 findings per file, followed by one summary row if there are more. Proof text is cut at 300 characters, and duplicate values in the same file are reported once.

---

## Which files are scanned

### Read and scanned

51 extensions and 6 exact file names:

| Group | Extensions |
|---|---|
| Settings and configuration | `.config` `.ini` `.xml` `.json` `.yaml` `.yml` `.properties` `.conf` `.cfg` `.cnf` `.toml` `.env` `.settings` `.resx` `.reg` |
| Connection, credential and publish files | `.udl` `.dsn` `.rdp` `.ica` `.publishsettings` `.pubxml` `.dtsconfig` `.netrc` `.git-credentials` `.npmrc` `.pypirc` `.s3cfg` |
| Installer answer files | `.iss` `.rsp` |
| Scripts | `.ps1` `.psm1` `.psd1` `.cmd` `.bat` `.vbs` `.wsf` `.js` `.au3` `.ahk` `.kix` `.py` `.sh` `.sql` `.asp` `.asa` `.php` |
| Logs and data | `.txt` `.log` `.csv` `.tsv` |
| Keys | `.pem` |
| Exact file names | `id_rsa` `id_dsa` `id_ecdsa` `id_ed25519` `credentials` `_netrc` |

**Renamed and backup copies** are scanned as well. A file counts when the extension before its last one is on the list, for example `web.config.bak`, `web.config.20240315`, `appsettings.json.old`, `.env.local`, `App.exe.config.deploy` (ClickOnce) or `MSBuild.exe.config.template`. Files whose last extension is a program, package, archive or media type are never treated this way, so `Newtonsoft.Json.dll` is not read as a `.json` file.

### Reported without being read

| Type | Extensions or names | Reported as |
|---|---|---|
| Key and certificate stores | `.pfx` `.p12` `.key` `.p8` `.pvk` `.ppk` `.snk` `.jks` `.keystore` | Certificate / key file |
| Password databases | `.kdbx` `.kdb` `.psafe3` | Password database |
| Local data stores | `.mdf` `.ldf` `.mdb` `.accdb` `.sdf` `.sqlite` `.sqlite3` `.db3` `.pst` `.ost` | Local data store |
| Credential store files | `.pgpass` `.htpasswd` | Credential store file |
| Documents and archives with telling names | Names containing *passw*, *kennwort*, *credential*, *secret*, *pwd* or *hasło* / *hasla*. Examples: `Passwords.xlsx`, `credentials.zip`, `hasla.7z`, `secrets.gpg` | Suspicious file name |

Programs and packages are never reported by name, so files such as `CredentialProvider.dll` or `CredentialProvider.Microsoft.nupkg` do not produce findings.

### Never read

- **Programs and libraries:** `.exe` `.dll` `.sys` `.ocx` `.pdb` and similar.
- **Installers and packages:** `.msi` `.msp` `.mst` `.cab` `.msix` `.nupkg` `.intunewin` `.jar` and similar.
- **Archives, disk images and encrypted containers:** `.zip` `.7z` `.rar` `.gz` `.tar` `.iso` `.vhdx` `.wim` `.gpg` and similar. These are checked by name only and never unpacked.
- **Images, audio, video and fonts.**
- **Office documents and anything else not on the scan list.** Office files are compressed, so their text is not readable without unpacking. They are checked by name only.
- **Files larger than `-MaxFileSizeMB`.**

### Always excluded

- The running script itself, even if renamed.
- Files matching `$ExcludeFileNames`. By default these are `Find-Secrets*.ps1` (copies of the script, which contain the detection patterns) and `SecretScan_*.csv` (exports, which contain the secrets found).
- Folders matching `$ExcludePaths`. This list is empty by default.

---

## What it looks for

The rules are grouped by the original requirements. All example values below are made up.

### Hardcoded passwords or credentials

| Rule | Detects | Example |
|---|---|---|
| Hardcoded password / secret | A setting whose name contains *password*, *passwd*, *passphrase*, *pwd*, *secret* or *hasło* / *haslo*, with a literal value | `DB_PASSWORD=Summer2024!`, `"hasło": "Zażółć123"` |
| Plaintext password converted to SecureString | A plain-text password passed to `ConvertTo-SecureString -AsPlainText` | `ConvertTo-SecureString "P@ssw0rd1" -AsPlainText -Force` |
| Password passed as command-line argument | Password or token switches with literal values | `-Password "CliPass#77"`, `/pwd:Secret1` |
| URL with embedded credentials | A user name and password inside a URL | `mongodb://admin:M0ngoS3cret@host:27017` |
| PHP constant with secret | A `define()` with a password, key, salt or token | `define('DB_PASSWORD', 'secret123')` |
| netrc credentials | Credentials in netrc format | `machine host login user password pass123` |

### API keys, tokens and certificates

| Rule | Detects |
|---|---|
| API key / token / credential | Settings named like keys or tokens, in two strengths. **Explicit names** (`apikey`, `api_token`, `client_secret`, `access_token`, `subscription_key` and similar) accept any value of 8+ characters without spaces that contains a digit or looks random, so numeric keys are included. **Generic names** (`api`, `token`, `auth`, `credentials`) need a generated-looking value: 16+ characters, letters and digits, random, and not a URL or GUID. |
| AWS access key ID / AWS secret access key | `AKIA…` key IDs and 40-character secret keys |
| Azure Storage account key | `AccountKey=` in storage connection strings |
| Azure shared access key | `SharedAccessKey=` for Service Bus, Event Hubs and IoT Hub |
| Azure SAS token | Shared access signature query strings (`sv=…&sig=…`) |
| Microsoft Entra ID client secret | App registration secrets (`…Q~…` format) |
| GitHub / GitLab token | `ghp_`, `gho_`, `github_pat_`, `glpat-` tokens |
| Slack token | `xoxb-`, `xoxp-` and similar tokens |
| Webhook URL with embedded secret | Slack, Microsoft Teams, Azure Logic Apps and Discord webhook URLs |
| Google API key / OAuth client secret | `AIza…` keys and `GOCSPX-` secrets |
| Google Cloud service account key | JSON key files with `"type": "service_account"` |
| SaaS API key | Stripe, SendGrid, OpenAI and Anthropic secret keys |
| Package registry token | npm, NuGet and PyPI publish tokens |
| JSON Web Token (JWT) | `eyJ….eyJ….…` tokens |
| HTTP authorization credential | `Bearer …` and `Basic …` values |
| Private key / PuTTY private key | PEM private keys (RSA, EC, OpenSSH, PKCS#8, encrypted) and PuTTY key text |
| Embedded certificate (PEM) | `-----BEGIN CERTIFICATE-----` blocks |

### Connection strings with authentication details

| Rule | Detects |
|---|---|
| Connection string with password | Any connection string that has a server-type part (`Server`, `Data Source`, `Host`, `Provider`, `DSN`, `Initial Catalog`…) and a `Password` or `Pwd` part. This covers SQL Server, OLE DB / UDL, ODBC / DSN, MySQL, PostgreSQL and Oracle. |
| Azure Storage / shared access keys | See the API key table above |

### Service account credentials

| Rule | Detects | Example |
|---|---|---|
| Credentials on a command line | Passwords in `net use`, `cmdkey /pass:`, `schtasks /RP` and `psexec -p` commands | `net use Z: \\fs01\share Pa55 /user:DOMAIN\svc_app` |
| AutoIt RunAs with embedded password | `RunAs` and `RunAsWait` with a literal password | `RunAs("admin", "DOMAIN", "Secret1", 0, "setup.exe")` |
| Group Policy Preferences password | `cpassword=` in GPP XML files. The key that encrypts these values is publicly known, so they can be decrypted. | `cpassword="j1Uyj3Vx8TY9…"` |
| Unattend / sysprep password | `<AdministratorPassword>` and `<Password><Value>` in answer files | `<Password><Value>Pw1</Value>` |
| RDP file with saved password | `password 51:b:` entries in `.rdp` files | |
| Installer answer files | Passwords in InstallShield `.iss` and Oracle `.rsp` files, found by the password rule | `szPassword=Silent5` |

### Sensitive business or customer data stored locally

| Rule | Detects |
|---|---|
| Payment card number | Visa, Mastercard, American Express, Discover, JCB and Diners numbers that have a valid brand prefix, a valid length and pass the Luhn checksum |
| Bank account number (IBAN) | IBANs with a valid country code and valid check digits |
| Bulk e-mail addresses (personal data) | Files with 10 or more unique e-mail addresses, typically customer lists. Single addresses are ignored. License and attribution files (`ThirdPartyNotices.txt`, `LICENSE*.txt`, `NOTICE*.txt`, `AUTHORS*.txt` and similar) are not counted, because the addresses there are authors' public contacts. All other rules still scan those files. |
| Local data store (by type) | Database and mailbox files: `.mdf` `.sqlite` `.pst` and others |
| Suspicious file name (by name) | Documents and archives such as `Passwords.xlsx` or `credentials.zip` |

### Configuration files containing plaintext secrets

| Rule | Detects | Example |
|---|---|---|
| Config setting with secret value | .NET `appSettings` and `userSettings` entries whose key names a password, secret, token or API key | `<add key="SmtpPassword" value="Mail#Pass99" />` |
| XML element with secret | XML elements named like passwords, keys or tokens | `<ApiKey>a8F3kLm29XqP0vR7</ApiKey>` |
| Hardcoded password / secret and API key / token / credential | Plain assignments in `.ini`, `.json`, `.yaml`, `.env`, `.properties`, `.reg` and similar files | `"password": "Js0n-Pass!"` |
| Key stores, password databases, credential stores (by type) | `.pfx` `.kdbx` `.pgpass` `.htpasswd` and others | |

---

## How false positives are kept down

- **Placeholders are ignored.** Variables and template tokens such as `$var`, `$password$`, `%VAR%`, `${VAR}`, `$(VAR)`, `{{ var }}`, `#{Var}#`, `__Var__`, `@@Var@@` and `<your-password>` are skipped. So are fill-in values like `YOUR_PASSWORD`, `yourStrong(!)Password` or `Enter password`, masked values (`****`, `xxxx`), empty values, and words like `null`, `none`, `dummy`, `example` or `redacted`. File paths, environment references and sentences of UI text are skipped too.
- **Setting names that are not secrets are ignored.** Names such as `passwordLength`, `passwordPolicy`, `passwordExpiryDays`, `tokenUrl`, `tokenType`, `apiVersion`, `apiKeyHeader` and `apiKeyCreated` are skipped. So is anything containing *public*, which covers .NET `PublicKeyToken`, `publicKey` and `publishableKey`. Names ending in *Description*, *Message*, *Title*, *Tooltip*, *Caption*, *Instructions*, *Error* or *Warning* are treated as user-interface text in any language, for example `secretStoreComponentDescription` in localized Visual Studio files. Only the end of the name is checked, so `clientSecret` is still examined.
- **In source code only quoted literals count.** In scripts and code (`.ps1`, `.js`, `.py`, `.vbs`, `.sql` and others), `password = Get-Secret` is a function call, not a hardcoded secret, so it is not reported. In batch, `.env` and config files, unquoted values are checked, because that is how values are normally written there.
- **Generated-looking values are required where the name alone is weak.** See the API key rule above.
- **Checksums are used for structured data.** Card numbers and IBANs must pass their checksums, so random digit strings, phone numbers and order IDs are ignored.
- **Personal data is reported per file, not per address.** E-mail addresses at example and test domains, role mailboxes (`noreply@`, `support@`, `info@`, `admin@`…) and image names like `icon@2x.png` are not counted. Neither are addresses in license and attribution files.
- **Overlapping matches are reported once.** A connection string is reported as one finding, not as a separate connection string, password and URL.

---

## Configuration

All settings are near the top of the script.

| Setting | Purpose |
|---|---|
| `$IncludeExtensions` | File extensions whose content is scanned |
| `$IncludeFileNames` | Exact file names that are scanned (files without a useful extension) |
| `$ExcludeFileNames` | File names never scanned or reported. Wildcards are allowed. |
| `$ExcludePaths` | Folders skipped with everything below them, matched against the full path. Example: `@('*\ProjectTemplates', '*\ItemTemplates')` for Visual Studio's own templates. |
| `$BinaryExtensions` | Programs, packages and media: never read and never reported by name |
| `$ArchiveExtensions` | Archives, disk images and encrypted containers: never read, but checked by name |
| `$CodeExtensions` | Languages where only quoted values count as hardcoded |
| `$FileTypeFindings` / `$FileNameFindings` | Types and names that are reported without being read |
| `$SuspiciousNamePattern` | File-name pattern for documents and archives that suggest credentials |
| `$PlaceholderPattern` | Values treated as placeholders |
| `$KeyNoisePattern` | Setting names that are not secrets |
| `$LicenseFilePattern` | License and attribution files, where e-mail addresses are not counted as personal data |
| `$StrongKeyPattern` | Setting names that clearly hold a secret |
| `$RuleDefinitions` | The detection rules |
| `$Settings` | Limits: `MaxPerRule` (25 findings per rule per file), `MaxProofLength` (300 characters), `EmailThreshold` (10 addresses), `ChunkSize` (4 MB), `Overlap` (2 KB) |

### Adding a rule

Add an entry to `$RuleDefinitions`. Rules near the top win when two rules match the same text.

```powershell
@{ Name = 'Contoso license key'; Check = 'none'; CaseSensitive = $true
   Pattern = 'CTSO-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}' }
```

| `Check` | Meaning |
|---|---|
| `none` | The match itself is the proof |
| `cred` | The captured value (`(?<v>…)`) must not be a placeholder |
| `secret` | Assignment of a password-like value. The name (`(?<k>…)`) and value are both checked for noise. |
| `token` | Assignment of a key or token. The value check depends on how strong the name is. |
| `shape` | The value must look like a generated token |
| `card` / `iban` | Card or IBAN checksum validation |
| `email` | Addresses are counted per file |

Patterns are case-insensitive unless `CaseSensitive = $true`. Write a single quote inside a pattern as `\x27`.

---

## Limitations

- **Binaries are not scanned.** Secrets compiled into `.exe` or `.dll` files are not found. Antivirus and EDR products check binaries for malware, not for embedded secrets, so source-code scanning is the right place to catch those.
- **Archives and installers are not unpacked.** That includes ZIP, MSI, CAB and NuGet packages. MSI and MST property tables (for example `SERVICEPASSWORD` in a transform) are not read.
- **Encoded or encrypted values are not decoded.** DPAPI-protected values, base64-encoded configuration and encoded VBScript (`.vbe`) are not readable as text.
- **Detection is heuristic.** Very short or simple values under generic names (for example `api = "abc123"`) are ignored on purpose, and unusual formats may slip through. Occasional false positives are also possible.
- **Windows only.** The window uses WPF.

## Security notes

- Scan only systems and folders you are authorized to check.
- The tool only reads files and never connects to the network. No data leaves the computer.
- The Proof column and CSV exports contain **full secret values**. Store exports securely, do not save them into the scanned folder, and delete them when you are done.
- A secret that was found should be **rotated**, not only removed from the file. It may already have been copied or backed up elsewhere.

## Troubleshooting

| Symptom | Fix |
|---|---|
| "Running scripts is disabled on this system" | Start with `powershell.exe -ExecutionPolicy Bypass -File .\Find-Secrets.ps1` |
| "File cannot be loaded… not digitally signed" | Run `Unblock-File .\Find-Secrets.ps1` once |
| No window appears | A desktop session is required. Server Core, remote PowerShell sessions and SYSTEM context have no desktop. |
| Folders are reported as "not accessible" | Run as a user with read rights to those folders, or elevated |
| The scan is slow | Exclude large vendor folders with `$ExcludePaths`, lower `-MaxFileSizeMB`, or check whether antivirus scanning on file access is slowing the reads |
| A known false positive keeps appearing | Add the folder to `$ExcludePaths` or the file name to `$ExcludeFileNames`. For a placeholder style that is not recognised, extend `$PlaceholderPattern`. |

---

## Versioning

The script uses semantic versioning, `MAJOR.MINOR.PATCH`:

- **MAJOR:** changes that need users to adapt, such as removed parameters or a changed CSV format.
- **MINOR:** new rules, new file types or new features.
- **PATCH:** fixes, including false-positive fixes.

The version is shown in the window header and title bar. When releasing a new version, update all three places: `$ScriptVersion` near the top of the script, the `.NOTES` section of its built-in help, and this file. Each release is also tagged in Git as `v<version>`, for example `v1.3.1`.

## Version history

### 1.3.1 (2026-10-19)
- Fixed: e-mail addresses in license and attribution files (`ThirdPartyNotices.txt`, `LICENSE*.txt`, `NOTICE*.txt`, `AUTHORS*.txt`…) are no longer reported as personal data. All other rules still scan these files. New `$LicenseFilePattern` setting.
- Fixed: setting names ending in *Description*, *Message*, *Title*, *Tooltip*, *Caption*, *Instructions*, *Error* or *Warning* are treated as user-interface text, in any language. This fixes localized Visual Studio `strings.json` entries such as `secretStoreComponentDescription`.

### 1.3.0
- Archives, disk images and encrypted containers are now reported when their name suggests credentials (`credentials.zip`, `passwords.gpg`). Their content is still not unpacked.
- New `$ExcludePaths` setting skips whole folders, such as vendor template folders. The number of excluded folders is shown in the summary.
- More template placeholders are recognised: `@@Name@@` tokens and fill-in values such as `yourStrong(!)Password`.
- The version number is shown in the window header, the title bar and the built-in help.

### 1.2.2
- Fixed: .NET `PublicKeyToken` values in configuration files, and other setting names containing *public*, are no longer reported.

### 1.2.1
- Copies of the script (`Find-Secrets*.ps1`) and its CSV exports (`SecretScan_*.csv`) are excluded by name. New `$ExcludeFileNames` setting.

### 1.2.0
- API key detection reworked. Explicit names such as `apikey` or `client_secret` now accept numeric and letters-only keys, and generic names such as `api`, `token`, `auth` and `credentials` are recognised when the value looks generated.
- The finding was renamed to "API key / token / credential".
- More setting names are ignored: `*Version`, `*Date`, `*Time`, `*Created`, `*Updated`, `*Modified`.

### 1.1.0
- Switched to a list of 51 scanned extensions plus exact file names. Programs, libraries, installers, archives and media are no longer read.
- Renamed and backup copies of scanned file types are now included (`web.config.bak`, `.env.local`, `*.config.deploy`).
- Key stores, password databases and local databases are reported by type, and unread documents are reported when their name suggests credentials.
- New rule: AutoIt `RunAs` with an embedded password.
- The summary now separates files outside the scan list from files over the size limit.

### 1.0.0
- First release. Dark WPF window with a progress bar, live results, a two-column list (File and Proof) with full values, filtering, copying, opening the file location, and CSV export.
- Recursive, parallel scan of all files (text and binary; archives scanned raw), with 35 detection rules, including Polish *hasło* / *haslo*.
