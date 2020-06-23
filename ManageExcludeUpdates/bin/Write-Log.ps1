Function Write-Log {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true)][String] $message,
        [ValidateSet("start", "stop", "info","warning","error","success")][String] $Status = "info"
    )

    $logdate = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")

    Switch ($Status) {
        "info" { $colormsg = "White"; $statusmsg = "INFO" }
        "warning" { $colormsg = "Yellow"; $statusmsg = "WARN"; $objResult.Warning++ }
        "error" { $colormsg = "Red"; $statusmsg = "FAIL"; $objResult.Error++ }
        "success" { $colormsg = "Green"; $statusmsg = "GOOD"; $objResult.Success++ }
        "start" {
            $message = "--- Started Script Execution (USER: $env:USERDOMAIN\$env:USERNAME) ---"
            $colormsg = "Cyan"
            $statusmsg = "INFO"
        }
        "stop" {
            $message = "--- Stopped Script Execution ---`r"
            $colormsg = "Cyan"
            $statusmsg = "INFO"
        }
        default { $colormsg = "White"; $statusmsg = "INFO" }
    }

    "[$statusmsg][$($logdate)]`t $message" | Out-File $output -Append
    Write-Host "[$statusmsg]`t $message" -ForegroundColor $colormsg

    If ($Status -eq "error") {
        throw "[$statusmsg]`t $message"
    }
}
