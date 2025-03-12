Clear-Host

Write-Host @"
 `$`$`$`$`$`$\            `$`$\                     `$`$\                         
`$`$  __`$`$\           `$`$ |                    \__|                        
`$`$ /  \__| `$`$`$`$`$`$\  `$`$ | `$`$`$`$`$`$\  `$`$`$`$`$`$`$\  `$`$\ `$`$\   `$`$\ `$`$`$`$`$`$\`$`$`$`$\  
\`$`$`$`$`$`$\  `$`$  __`$`$\ `$`$ |`$`$  __`$`$\ `$`$  __`$`$\ `$`$ |`$`$ |  `$`$ |`$`$  _`$`$  _`$`$\ 
 \____`$`$\ `$`$`$`$`$`$`$`$ |`$`$ |`$`$`$`$`$`$`$`$ |`$`$ |  `$`$ |`$`$ |`$`$ |  `$`$ |`$`$ / `$`$ / `$`$ |
`$`$\   `$`$ |`$`$   ____|`$`$ |`$`$   ____|`$`$ |  `$`$ |`$`$ |`$`$ |  `$`$ |`$`$ | `$`$ | `$`$ |
\`$`$`$`$`$`$  |\`$`$`$`$`$`$`$\ `$`$ |\`$`$`$`$`$`$`$\ `$`$ |  `$`$ |`$`$ |\`$`$`$`$`$`$  |`$`$ | `$`$ | `$`$ |
 \______/  \_______|\__| \_______|\__|  \__|\__| \______/ \__| \__| \__|


"@ -ForegroundColor Red
Write-Host @"
by Dexwi
discord.gg/cVwShsZkqp (selenium)

"@ -ForegroundColor Blue

function Test-Admin {;$currentUser = New-Object Security.Principal.WindowsPrincipal $([Security.Principal.WindowsIdentity]::GetCurrent());$currentUser.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator);}
if (!(Test-Admin)) {
    Write-Warning "Please Run This Script as Admin."
	Pause
    Exit
}
Start-Sleep -s 3

Clear-Host

function CreateLibsDir {
    if (-Not(Test-Path -Path libs)) {
        New-Item -Name "libs" -ItemType "directory"
    }
}

function Everything {
    CreateLibsDir
    if (-Not(Test-Path -Path libs/Everything.exe)) {
        Invoke-WebRequest "https://www.voidtools.com/Everything-1.4.1.1026.x64-Setup.exe" -OutFile libs/Everything.exe
    }
    .\libs\Everything.exe
}

function DownloadEverythingCLI {
    CreateLibsDir
    if (-Not(Test-Path -Path libs/ES)) {
        Invoke-WebRequest "https://www.voidtools.com/ES-1.1.0.27.x64.zip" -OutFile libs/ES.zip
        Expand-Archive -DestinationPath "libs/ES" -Path "libs/ES.Zip"
        Remove-Item -Path "libs/ES.zip"
    }
}

$global:7zPath = ""
function Find7Zip {
    DownloadEverythingCLI
    $global:7zPath = .\libs\ES\es.exe "Program Files\7-Zip\7z.exe"
    if ($global:7zPath -eq "") {
        throw [CustomException]::new("Couldn't find 7zip installed")
    }
    $global:7zPath = $global:7zPath.Split("`r`n")[0]
}

function Download7Zip {
    try {
        Find7Zip
    } catch [CustomException] {
        Write-Host "Installing 7zip..."
        if (-Not(Test-Path -Path libs/7z.exe)) {
            CreateLibsDir
            $url = "https://api.github.com/repos/ip7z/7zip/releases/latest"
            $resp = Invoke-WebRequest $url
            if ($resp.StatusCode -ne 200) {
                Write-Host "Status code $($resp.StatusCode)"
                Pause
                Return
            }
            $content = $resp.Content | ConvertFrom-Json
            foreach ($asset in $content.assets) {
                if ($asset.name.EndsWith("x64.exe")) {
                    Invoke-WebRequest $asset.browser_download_url -OutFile libs/7z.exe
                    break
                }
            }
        }
        .\libs\7z.exe
        Write-Host "After installing, Press enter..."
        Pause
        Find7Zip
    }
}

function SystemUpTime {
    $os = Get-WmiObject Win32_OperatingSystem
    Return (Get-Date).Subtract($os.ConvertToDateTime($os.LastBootUpTime))
}

function TimeSpanToString {
    Param (
        $timespan
    )
    Return "$($timespan.Days):$($timespan.Hours):$($timespan.Minutes):$($timespan.Seconds)"
}

function CheckAlts {
    Download7Zip
    DownloadEverythingCLI
    $mcDirs = .\libs\ES\es.exe folder:regex:^\.minecraft$
    $totalData = 0
    $logFiles = @()
    $usercacheFiles = @()
    $usernamecacheFiles = @()
    $archivedLogFiles = @()
    foreach ($mcDir in $mcDirs) {
        $mcDir = $mcDir.Replace("`"", "")

        foreach($logFile in Get-ChildItem -Path "$mcDir\*.log" -Recurse -Force) {
            $totalData += $logFile.Length
            $logFiles += $logFile
        }
        
        foreach ($usercacheFile in Get-ChildItem -Path "$mcDir\usercache.json" -Recurse -Force) {
            $totalData += $usercacheFile.Length
            $usercacheFiles += $usercacheFile
        }

        foreach ($usernamecacheFile in Get-ChildItem -Path "$mcDir\usernamecache.json" -Recurse -Force) {
            $totalData += $usernamecacheFile.Length
            $usernamecacheFiles += $usernamecacheFile
        }

        foreach ($archivedLogFile in Get-ChildItem -Path "$mcDir\*.log.gz" -Recurse -Force) {
            $totalData += $archivedLogFile.Length
            $archivedLogFiles += $archivedLogFile
        }
    }

    $data = 0
    $progressID = 1
    $results = @()
    foreach ($logFile in $logFiles) {
        $progress = [int]($data / $totalData * 100)
        Write-Progress -Activity "Search in Progress" -Status "$progress% Complete:" -PercentComplete $progress -Id $progressID
        $data += $logFile.Length

        foreach ($stringFound in Get-Content $logFile | Select-String -Pattern "setting user: ([a-z0-9_]+)" -AllMatches) {
            foreach ($match in $stringFound.Matches) {
                $stringDetails = New-Object PSObject
                $stringDetails | Add-Member Noteproperty FileName $logfile.Fullname
                $stringDetails | Add-Member Noteproperty IGN $match.Groups.Item(1).Value
                $stringDetails | Add-Member Noteproperty UUID "NULL"
                $results += $stringDetails
            }
            break;
        }
        Write-Debug "Processed $($logFile.Fullname)"
    }

    foreach ($usercacheFile in $usercacheFiles) {
        $progress = [int]($data / $totalData * 100)
        Write-Progress -Activity "Search in Progress" -Status "$progress% Complete:" -PercentComplete $progress -Id $progressID
        $data += $usercacheFile.Length

        foreach ($stringFound in Get-Content $usercacheFile | Select-String -Pattern "\{\s*`"name`"\s*:\s*`"([a-z0-9_]+)`"\s*,\s*`"uuid`"\s*:\s*`"([^`"]+)`"" -AllMatches) {
            foreach ($match in $stringFound.Matches) {
                $stringDetails = New-Object PSObject
                $stringDetails | Add-Member Noteproperty FileName $usercacheFile.Fullname
                $stringDetails | Add-Member Noteproperty IGN $match.Groups.Item(1).Value
                $stringDetails | Add-Member Noteproperty UUID $match.Groups.Item(2).Value
                $results += $stringDetails
            }
        }

        Write-Debug "Processed $($usercacheFile.Fullname)"
    }

    foreach ($usernamecacheFile in $usernamecacheFiles) {
        $progress = [int]($data / $totalData * 100)
        Write-Progress -Activity "Search in Progress" -Status "$progress% Complete:" -PercentComplete $progress -Id $progressID
        $data += $usernamecacheFile.Length

        foreach ($stringFound in Get-Content $usernamecacheFile | Select-String -Pattern "`"([^`"]+)`"\s*:\s*`"([a-z0-9_]+)`"" -AllMatches) {
            foreach ($match in $stringFound.Matches) {
                $stringDetails = New-Object PSObject
                $stringDetails | Add-Member Noteproperty FileName $usernamecacheFile.Fullname
                $stringDetails | Add-Member Noteproperty IGN $match.Groups.Item(2).Value
                $stringDetails | Add-Member Noteproperty UUID $match.Groups.Item(1).Value
                $results += $stringDetails
            }
        }

        Write-Debug "Processed $($usernamecacheFile.Fullname)"
    }

    foreach ($archivedLogFile in $archivedLogFiles) {
        $progress = [int]($data / $totalData * 100)
        Write-Progress -Activity "Search in Progress" -Status "$progress% Complete:" -PercentComplete $progress -Id $progressID
        $data += $archivedLogFile.Length

        & $global:7zPath e -otemp "$archivedLogFile" > $null

        foreach ($logFile in Get-ChildItem -Path "temp\*.log" -Recurse -Force) {
            foreach ($stringFound in Get-Content $logFile | Select-String -Pattern "setting user: ([a-z0-9_]+)" -AllMatches) {
                foreach ($match in $stringFound.Matches) {
                    $stringDetails = New-Object PSObject
                    $stringDetails | Add-Member Noteproperty FileName $archivedLogFile.Fullname
                    $stringDetails | Add-Member Noteproperty IGN $match.Groups.Item(1).Value
                    $stringDetails | Add-Member Noteproperty UUID "NULL"
                    $results += $stringDetails
                }
                break;
            }
        }

        Remove-Item "temp" -Recurse

        Write-Debug "Processed $($archivedLogFile.Fullname)"
    }

    $results | Out-GridView -PassThru -Title 'Results'
}

function WinPrefetchView {
    CreateLibsDir
    Download7Zip
    if (-Not(Test-Path -Path libs/wpv)) {
        Invoke-WebRequest "https://www.nirsoft.net/utils/winprefetchview-x64.zip" -OutFile libs/wpv.zip
        & $global:7zPath e -olibs/wpv libs/wpv.zip > $null
        Remove-Item -Path "libs/wpv.zip"
    }
    & .\libs\wpv\WinPrefetchView.exe
}

function SystemInformer {
    CreateLibsDir
    if (-Not(Test-Path -Path libs/systeminformer.exe)) {
        $url = "https://api.github.com/repos/winsiderss/si-builds/releases/latest"
        $resp = Invoke-WebRequest $url
        if ($resp.StatusCode -ne 200) {
            Write-Host "Status code $($resp.StatusCode)"
            Pause
            Return
        }
        $content = $resp.Content | ConvertFrom-Json
        foreach ($asset in $content.assets) {
            if ($asset.name.EndsWith("canary-setup.exe")) {
                Invoke-WebRequest $asset.browser_download_url -OutFile libs/systeminformer.exe
                break
            }
        }
    }
    .\libs\systeminformer.exe
}

function BamParser {
    CreateLibsDir
    if (-Not(Test-Path -Path libs/BAMParser.exe)) {
        $url = "https://api.github.com/repos/spokwn/BAM-parser/releases/latest"
        $resp = Invoke-WebRequest $url
        if ($resp.StatusCode -ne 200) {
            Write-Host "Status code $($resp.StatusCode)"
            Pause
            Return
        }
        $content = $resp.Content | ConvertFrom-Json
        foreach ($asset in $content.assets) {
            if ($asset.name.EndsWith(".exe")) {
                Invoke-WebRequest $asset.browser_download_url -OutFile libs/BAMParser.exe
                break
            }
        }
    }
    .\libs\BAMParser.exe
}

function JournalTrace {
    CreateLibsDir
    if (-Not(Test-Path -Path libs/JournalTrace.exe)) {
        $url = "https://api.github.com/repos/spokwn/JournalTrace/releases/latest"
        $resp = Invoke-WebRequest $url
        if ($resp.StatusCode -ne 200) {
            Write-Host "Status code $($resp.StatusCode)"
            Pause
            Return
        }
        $content = $resp.Content | ConvertFrom-Json
        foreach ($asset in $content.assets) {
            if ($asset.name.EndsWith(".exe")) {
                Invoke-WebRequest $asset.browser_download_url -OutFile libs/JournalTrace.exe
                break
            }
        }
    }
    .\libs\JournalTrace.exe
}

function PathsParser {
    CreateLibsDir
    if (-Not(Test-Path -Path libs/PathsParser.exe)) {
        $url = "https://api.github.com/repos/spokwn/PathsParser/releases/latest"
        $resp = Invoke-WebRequest $url
        if ($resp.StatusCode -ne 200) {
            Write-Host "Status code $($resp.StatusCode)"
            Pause
            Return
        }
        $content = $resp.Content | ConvertFrom-Json
        foreach ($asset in $content.assets) {
            if ($asset.name.EndsWith(".exe")) {
                Invoke-WebRequest $asset.browser_download_url -OutFile libs/PathsParser.exe
                break
            }
        }
    }
    Start-Process .\libs\PathsParser.exe
}

function Services {
    $serviceNames = @(
        "DPS", "SysMain", "Schedule", "PcaSvc", "EventLog"
    )
    $results = @()
    $currentDate = Get-Date
    foreach ($serviceName in $serviceNames) {
        $service = (Get-WmiObject Win32_Service | Where-Object {$_.Name -eq $serviceName})
        $serviceProcess = Get-Process -Id $service.ProcessId
        $uptime = $currentDate.Subtract($serviceProcess.StartTime)
        
        $resultObj = New-Object PSObject
        $resultObj | Add-Member Noteproperty Name $service.Name
        $resultObj | Add-Member Noteproperty State $service.State
        $resultObj | Add-Member Noteproperty Uptime (TimeSpanToString -timespan $uptime)

        $results += $resultObj
    }
    Write-Host "System Uptime $(TimeSpanToString -timespan $(SystemUpTime))"
    $results | Format-Table -AutoSize
    Pause
}

while (1) {
    Clear-Host
    Write-Host @"
- everything: search everything
- alt: to check for alts
- wpv: WinPrefetchView
- sysinf: System Informer
- bam: spokwn's bam parser
- jrnl: spokwn's JournalTrace
- pathsparser: spokwn's PathsParser
- services: see services and their uptime
- exit: to exit
"@
    $userInput = Read-Host "Enter one of the options above"
	
    Clear-Host
    try {
        if ($userInput.Equals("exit")) {
            break
        } elseif ($userInput.Equals("everything")) {
            Everything
        } elseif ($userInput.Equals("alt")) {
            CheckAlts
        } elseif ($userInput.Equals("wpv")) { 
            WinPrefetchView
        } elseif ($userInput.Equals("sysinf")) {
            SystemInformer
        } elseif ($userInput.Equals("bam")) {
            BamParser
        } elseif ($userInput.Equals("jrnl")) {
            JournalTrace
        } elseif ($userInput.Equals("pathsparser")) {
            PathsParser
        } elseif ($userInput.Equals("services")) {
            Services
        } else {
            Write-Host "Invalid option..."
            Start-Sleep -s 1
        }   
    } catch {
        $_
        Pause
    }
}

Clear-Host
