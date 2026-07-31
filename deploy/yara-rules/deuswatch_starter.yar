/*
 * DeusWatch starter YARA rules.
 *
 * These are a minimal, universally-safe starter set so a fresh install has SOMETHING firing —
 * proof-of-life for the manager-side scan path. They are not a substitute for a real ruleset;
 * see docs/yara.md for pointers to community-maintained repositories.
 */

rule DeusWatch_EICAR_Test_String
{
    meta:
        author      = "DeusWatch"
        description = "EICAR anti-virus test string (harmless, industry standard test signature)"
        reference   = "https://www.eicar.org/download-anti-malware-testfile/"
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $eicar
}

rule DeusWatch_Suspicious_PHP_Webshell
{
    meta:
        author      = "DeusWatch"
        description = "Common one-line PHP webshell pattern (system/exec/passthru/shell_exec via GET/POST/REQUEST)"
        severity    = "high"
    strings:
        $php_open = "<?php" nocase
        $sys1     = "system("   nocase
        $sys2     = "exec("     nocase
        $sys3     = "passthru(" nocase
        $sys4     = "shell_exec(" nocase
        $get      = "$_GET"     nocase
        $post     = "$_POST"    nocase
        $req      = "$_REQUEST" nocase
    condition:
        $php_open and any of ($sys*) and any of ($get, $post, $req)
}

rule DeusWatch_Suspicious_Reverse_Shell_bash
{
    meta:
        author      = "DeusWatch"
        description = "Bash reverse-shell one-liner (bash -i >& /dev/tcp/HOST/PORT 0>&1)"
        severity    = "high"
    strings:
        $rs = /bash\s+-i\s*>&\s*\/dev\/tcp\/[0-9a-zA-Z\.\-]+\/[0-9]+\s+0>&1/
    condition:
        $rs
}

rule DeusWatch_Suspicious_Powershell_Downloader
{
    meta:
        author      = "DeusWatch"
        description = "PowerShell IEX (New-Object Net.WebClient).DownloadString / Invoke-Expression download-and-run pattern"
        severity    = "high"
    strings:
        $iex1 = "IEX(New-Object Net.WebClient).DownloadString"   nocase
        $iex2 = "Invoke-Expression (New-Object Net.WebClient).DownloadString" nocase
        $iex3 = "iex(iwr"    nocase
    condition:
        any of ($iex*)
}
