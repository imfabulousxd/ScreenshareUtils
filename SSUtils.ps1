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

function Test-Admin {
    $currentUser = New-Object Security.Principal.WindowsPrincipal $([Security.Principal.WindowsIdentity]::GetCurrent()) 
    $currentUser.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

if (!(Test-Admin)) {
    Write-Warning "Please Run This Script as Admin."
	Pause
    Exit
}
Start-Sleep -s 3

Clear-Host

function New-LibsDirectory {
    if (-Not(Test-Path -Path libs)) {
        New-Item -Name "libs" -ItemType "directory" > $null
    }
}

function Get-FileFromWeb { # Credits: https://gist.github.com/ChrisStro/37444dd012f79592080bd46223e27adc
    param (
        # Parameter help description
        [Parameter(Mandatory)]
        [string]$URL,
  
        # Parameter help description
        [Parameter(Mandatory)]
        [string]$File 
    )
    Begin {
        function Show-Progress {
            param (
                # Enter total value
                [Parameter(Mandatory)]
                [Single]$TotalValue,
        
                # Enter current value
                [Parameter(Mandatory)]
                [Single]$CurrentValue,
        
                # Enter custom progresstext
                [Parameter(Mandatory)]
                [string]$ProgressText,
        
                # Enter value suffix
                [Parameter()]
                [string]$ValueSuffix,
        
                # Enter bar lengh suffix
                [Parameter()]
                [int]$BarSize = 40,

                # show complete bar
                [Parameter()]
                [switch]$Complete
            )
            
            # calc %
            $percent = $CurrentValue / $TotalValue
            $percentComplete = $percent * 100
            if ($ValueSuffix) {
                $ValueSuffix = " $ValueSuffix" # add space in front
            }
            if ($psISE) {
                Write-Progress "$ProgressText $CurrentValue$ValueSuffix of $TotalValue$ValueSuffix" -id 0 -percentComplete $percentComplete            
            }
            else {
                # build progressbar with string function
                $curBarSize = $BarSize * $percent
                $progbar = ""
                $progbar = $progbar.PadRight($curBarSize,[char]9608)
                $progbar = $progbar.PadRight($BarSize,[char]9617)
        
                if (!$Complete.IsPresent) {
                    Write-Host -NoNewLine "`r$ProgressText $progbar [ $($CurrentValue.ToString("#.###").PadLeft($TotalValue.ToString("#.###").Length))$ValueSuffix / $($TotalValue.ToString("#.###"))$ValueSuffix ] $($percentComplete.ToString("##0.00").PadLeft(6)) % complete"
                }
                else {
                    Write-Host -NoNewLine "`r$ProgressText $progbar [ $($TotalValue.ToString("#.###").PadLeft($TotalValue.ToString("#.###").Length))$ValueSuffix / $($TotalValue.ToString("#.###"))$ValueSuffix ] $($percentComplete.ToString("##0.00").PadLeft(6)) % complete"                    
                }                
            }   
        }
    }
    Process {
        try {
            $storeEAP = $ErrorActionPreference
            $ErrorActionPreference = 'Stop'
        
            # invoke request
            $request = [System.Net.HttpWebRequest]::Create($URL)
            $response = $request.GetResponse()
  
            if ($response.StatusCode -eq 401 -or $response.StatusCode -eq 403 -or $response.StatusCode -eq 404) {
                throw "Remote file either doesn't exist, is unauthorized, or is forbidden for '$URL'."
            }
  
            if($File -match '^\.\\') {
                $File = Join-Path (Get-Location -PSProvider "FileSystem") ($File -Split '^\.')[1]
            }
            
            if($File -and !(Split-Path $File)) {
                $File = Join-Path (Get-Location -PSProvider "FileSystem") $File
            }

            if ($File) {
                $fileDirectory = $([System.IO.Path]::GetDirectoryName($File))
                if (!(Test-Path($fileDirectory))) {
                    [System.IO.Directory]::CreateDirectory($fileDirectory) | Out-Null
                }
            }

            [long]$fullSize = $response.ContentLength
            $fullSizeMB = $fullSize / 1024 / 1024
  
            # define buffer
            [byte[]]$buffer = new-object byte[] 1048576
            [long]$total = [long]$count = 0
  
            # create reader / writer
            $reader = $response.GetResponseStream()
            $writer = new-object System.IO.FileStream $File, "Create"
  
            # start download
            $finalBarCount = 0 #show final bar only one time
            do {
          
                $count = $reader.Read($buffer, 0, $buffer.Length)
          
                $writer.Write($buffer, 0, $count)
              
                $total += $count
                $totalMB = $total / 1024 / 1024
          
                if ($fullSize -gt 0) {
                    Show-Progress -TotalValue $fullSizeMB -CurrentValue $totalMB -ProgressText "Downloading $($File.Name)" -ValueSuffix "MB"
                }

                if ($total -eq $fullSize -and $count -eq 0 -and $finalBarCount -eq 0) {
                    Show-Progress -TotalValue $fullSizeMB -CurrentValue $totalMB -ProgressText "Downloading $($File.Name)" -ValueSuffix "MB" -Complete
                    $finalBarCount++
                    #Write-Host "$finalBarCount"
                }

            } while ($count -gt 0)
        }
  
        catch {
        
            $ExeptionMsg = $_.Exception.Message
            Write-Host "Download breaks with error : $ExeptionMsg"
        }
  
        finally {
            # cleanup
            if ($reader) { $reader.Close() }
            if ($writer) { $writer.Flush(); $writer.Close() }
        
            $ErrorActionPreference = $storeEAP
            [GC]::Collect()
        }    
    }
}

function Get-SearchEverythingInstaller {
    try {
        $EverythingInstallerPath = Resolve-Path -Path "libs/Everything.exe" -ErrorAction Stop
        Return $EverythingInstallerPath
    } catch [System.Management.Automation.ItemNotFoundException] {
        New-LibsDirectory

        $url = if ([System.Environment]::Is64BitOperatingSystem) {"https://www.voidtools.com/Everything-1.4.1.1026.x64-Setup.exe"} else {"https://www.voidtools.com/Everything-1.4.1.1026.x86-Setup.exe"}
        Get-FileFromWeb -URL $url -File "libs/Everything.exe"

        Return Get-SearchEverythingInstaller
    }
}

function Start-SearchEverythingInstaller {
    Start-Process (Get-SearchEverythingInstaller).Path
}

function Get-SearchEverythingCLI {
    try {
        $EverythingCLIPath = Resolve-Path -Path "libs/EverythingCLI/es.exe" -ErrorAction Stop
        while ((& $EverythingCLIPath.Path -get-everything-version).StartsWith("Error 8")) {
            Write-Host "Please make sure Search Everything is running..."
            Pause
        }
        Return $EverythingCLIPath
    } catch [System.Management.Automation.ItemNotFoundException] {
        New-LibsDirectory

        $url = if ([System.Environment]::Is64BitOperatingSystem) {"https://www.voidtools.com/ES-1.1.0.27.x64.zip"} else {"https://www.voidtools.com/ES-1.1.0.27.x86.zip"}
        Get-FileFromWeb -URL $url -File "libs/ES.Zip"

        Expand-Archive -DestinationPath "libs/EverythingCLI" -Path "libs/ES.Zip" > $null
        Remove-Item -Path "libs/ES.zip" > $null

        Return Get-SearchEverythingCLI
    }
}

function Get-7ZipInstaller {
    try {
        $7ZipInstallerPath = Resolve-Path -Path "7-Zip/7z.exe" -ErrorAction Stop
        Return $7ZipInstallerPath
    } catch [System.Management.Automation.ItemNotFoundException] {
        New-LibsDirectory
        
        $url = "https://api.github.com/repos/ip7z/7zip/releases/latest"
        $resp = Invoke-WebRequest $url -Headers $(Get-GitHubAPIHeadersDict)
        if ($resp.StatusCode -ne 200) {
            Write-Host "Status code $($resp.StatusCode)"
            Pause
            Return
        }
        $content = $resp.Content | ConvertFrom-Json
        $regex = if ([System.Environment]::Is64BitOperatingSystem) {"7z\d+-x64\.exe"} else {"7z\d+\.exe"}
        foreach ($asset in $content.assets) {
            if ($asset.name -imatch $regex) {
                Get-FileFromWeb -URL $asset.browser_download_url -File "libs/7z.exe"
                break
            }
        }

        Return Get-7ZipInstaller
    }
}

function Get-7Zip {
    $7ZipRawPath = & (Get-SearchEverythingCLI).Path "Program Files\7-Zip\7z.exe"
    if ($7ZipRawPath.Length -eq 0) {
        Get-7ZipInstaller
        Write-Host "Please install 7-zip"
        Pause
    }
    Return Resolve-Path -Path $7ZipRawPath
}

$script:GitHubToken = ""
$script:GitHubTokenAsked = $false
function Get-GitHubToken {
    if ($script:GitHubTokenAsked) {
        Return
    }
    $script:GitHubToken = Read-Host "Please enter your GitHub token"
    $script:GitHubTokenAsked = $true
    Clear-Host
}

function Get-GitHubAPIHeadersDict {
    Get-GitHubToken
    if ($script:GitHubToken.Length -eq 0) {
        return @{}
    } else {
        return @{
            "Authorization"= "Bearer $script:GitHubToken"
        }
    }
}

function Get-SystemUpTime {
    $os = Get-CimInstance -ClassName Win32_OperatingSystem
    Return (Get-Date).Subtract($os.LastBootUpTime)
}

function Format-Timespan {
    Param (
        $timespan
    )
    Return "$($timespan.Days):$($timespan.Hours):$($timespan.Minutes):$($timespan.Seconds)"
}

function Invoke-AltCheck {
    $7ZipPath = Get-7Zip
    $mcDirs = & (Get-SearchEverythingCLI) folder:regex:^\.minecraft$
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

        foreach ($stringFound in [System.IO.File]::ReadAllText("$logFile") | & findstr /i /x "setting user: ([a-z0-9_]+)") {
            $match = [regex]::Matches($stringFound, "setting user: ([a-z0-9_]+)", [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
            $stringDetails = New-Object PSObject
            $stringDetails | Add-Member Noteproperty FileName $logfile.Fullname
            $stringDetails | Add-Member Noteproperty IGN $match.Groups.Item(1).Value
            $stringDetails | Add-Member Noteproperty UUID "NULL"
            $results += $stringDetails
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

        & $7ZipPath e -otemp "$archivedLogFile" > $null

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

        Remove-Item "temp" -Recurse > $null

        Write-Debug "Processed $($archivedLogFile.Fullname)"
    }

    $results | Out-GridView -PassThru -Title 'Results'
}

function Invoke-AltCheckBACKUP {
    $7ZipPath = Get-7Zip
    $mcDirs = & (Get-SearchEverythingCLI) folder:regex:^\.minecraft$
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

        & $7ZipPath e -otemp "$archivedLogFile" > $null

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

        Remove-Item "temp" -Recurse > $null

        Write-Debug "Processed $($archivedLogFile.Fullname)"
    }

    $results | Out-GridView -PassThru -Title 'Results'
}

function Get-WinPrefetchView {
    try {
        Return Resolve-Path -Path "libs/wpv/WinPrefetchView.exe" -ErrorAction Stop
    } catch [System.Management.Automation.ItemNotFoundException] {
        New-LibsDirectory

        $url = if ([System.Environment]::Is64BitOperatingSystem) {"https://www.nirsoft.net/utils/winprefetchview-x64.zip"} else {"https://www.nirsoft.net/utils/winprefetchview.zip"}
        Get-FileFromWeb -URL $url -File "libs/wpv.zip"

        Expand-Archive -Path "libs/wpv.zip" -DestinationPath "libs/wpv" > $null
        Remove-Item -Path "libs/wpv.zip" > $null

        Return Get-WinPrefetchView
    }
}

function Get-SystemInformerInstaller {
    try {
        Return Resolve-Path -Path "libs/systeminformer.exe" -ErrorAction Stop
    } catch [System.Management.Automation.ItemNotFoundException] {
        New-LibsDirectory

        $url = "https://api.github.com/repos/winsiderss/si-builds/releases/latest"
        $resp = Invoke-WebRequest -Uri $url -Headers $(Get-GitHubAPIHeadersDict)
        if ($resp.StatusCode -ne 200) {
            Write-Host "Status code $($resp.StatusCode)"
            Pause
            Return
        }
        $content = $resp.Content | ConvertFrom-Json
        foreach ($asset in $content.assets) {
            if ($asset.name.EndsWith("canary-setup.exe")) {
                Get-FileFromWeb -URL $asset.browser_download_url -File "libs/systeminformer.exe"
                break
            }
        }
        
        Return Get-SystemInformerInstaller
    }
}

function Get-BamParser {
    try {
        Return Resolve-Path -Path "libs/BAMParser.exe" -ErrorAction Stop
    } catch [System.Management.Automation.ItemNotFoundException] {
        New-LibsDirectory

        $url = "https://api.github.com/repos/spokwn/BAM-parser/releases/latest"
        $resp = Invoke-WebRequest $url -Headers $(Get-GitHubAPIHeadersDict)
        if ($resp.StatusCode -ne 200) {
            Write-Host "Status code $($resp.StatusCode)"
            Pause
            Return
        }
        $content = $resp.Content | ConvertFrom-Json
        foreach ($asset in $content.assets) {
            if ($asset.name.EndsWith(".exe")) {
                Get-FileFromWeb -URL $asset.browser_download_url -File "libs/BAMParser.exe"
                break
            }
        }

        Return Get-BamParser
    }
}

function Get-JournalTrace {
    try {
        Return Resolve-Path -Path "libs/JournalTrace.exe" -ErrorAction Stop
    } catch [System.Management.Automation.ItemNotFoundException] {
        New-LibsDirectory

        $url = "https://api.github.com/repos/spokwn/JournalTrace/releases/latest"
        $resp = Invoke-WebRequest $url -Headers $(Get-GitHubAPIHeadersDict)
        if ($resp.StatusCode -ne 200) {
            Write-Host "Status code $($resp.StatusCode)"
            Pause
            Return
        }
        $content = $resp.Content | ConvertFrom-Json
        foreach ($asset in $content.assets) {
            if ($asset.name.EndsWith(".exe")) {
                Get-FileFromWeb -URL $asset.browser_download_url -File "libs/JournalTrace.exe"
                break
            }
        }

        Return Get-JournalTrace
    }
}

function Get-PathsParser {
    try {
        Return Resolve-Path -Path "libs/PathsParser.exe" -ErrorAction Stop
    } catch [System.Management.Automation.ItemNotFoundException] {
        New-LibsDirectory

        $url = "https://api.github.com/repos/spokwn/PathsParser/releases/latest"
        $resp = Invoke-WebRequest $url -Headers $(Get-GitHubAPIHeadersDict)
        if ($resp.StatusCode -ne 200) {
            Write-Host "Status code $($resp.StatusCode)"
            Pause
            Return
        }
        $content = $resp.Content | ConvertFrom-Json
        foreach ($asset in $content.assets) {
            if ($asset.name.EndsWith(".exe")) {
                Get-FileFromWeb -URL $asset.browser_download_url -File "libs/PathsParser.exe"
                break
            }
        }

        Return Get-PathsParser
    }
}

function Show-ServicesState {
    $serviceNames = @(
        "DPS", "SysMain", "Schedule", "PcaSvc", "EventLog", "DcomLaunch"
    )
    $results = @()
    $currentDate = Get-Date
    foreach ($serviceName in $serviceNames) {
        $service = (Get-CimInstance -ClassName Win32_Service | Where-Object {$_.Name -eq $serviceName})
        $serviceProcess = Get-Process -Id $service.ProcessId
        $uptime = $currentDate.Subtract($serviceProcess.StartTime)
        
        $resultObj = New-Object PSObject
        $resultObj | Add-Member Noteproperty Name $service.Name
        $resultObj | Add-Member Noteproperty State $service.State
        $resultObj | Add-Member Noteproperty Uptime (Format-Timespan -timespan $uptime)

        $results += $resultObj
    }
    Write-Host "System Uptime $(Format-Timespan -timespan $(Get-SystemUpTime))"
    $results | Format-Table -AutoSize
    Pause
}

function Get-Hayabusa {
    try {
        Return Resolve-Path -Path "libs/Hayabusa/Hayabusa.exe" -ErrorAction Stop
    } catch [System.Management.Automation.ItemNotFoundException] {
        New-LibsDirectory

        $url = "https://api.github.com/repos/Yamato-Security/hayabusa/releases/latest"
        $resp = Invoke-WebRequest $url -Headers $(Get-GitHubAPIHeadersDict)
        if ($resp.StatusCode -ne 200) {
            Write-Host "Status code $($resp.StatusCode)"
            Pause
            Return
        }
        $content = $resp.Content | ConvertFrom-Json
        $fileName = ""
        $regex = if ([System.Environment]::Is64BitOperatingSystem) {".*win-x64\.zip"} else {".*win-x86\.zip"}
        foreach ($asset in $content.assets) {
            if ($asset.name -imatch $regex) {
                $fileName =$asset.name
                Get-FileFromWeb -URL $asset.browser_download_url -File "libs/Hayabusa.zip"
                break
            }
        }
        Expand-Archive -DestinationPath "libs/Hayabusa" -Path "libs/Hayabusa.zip" > $null
        Remove-Item -Path "libs/Hayabusa.zip" > $null
        Rename-Item -Path "libs/Hayabusa/$($fileName.Remove($fileName.Length-4)).exe" -NewName "Hayabusa.exe" > $null

        Return Get-Hayabusa
    }
    # Remove-Item -Path hayabusa.csv > $null
    # .\libs\Hayabusa\Hayabusa.exe csv-timeline -l -o hayabusa.csv -U -A -D -n -u -w

    # Invoke-DownloadTimelimeExplorer
    # & .\libs\TimelineExplorer\TimelineExplorer.exe hayabusa.csv
}

function Get-FTKImager {
    try {
        Return Resolve-Path -Path "libs/FTKImager.exe" -ErrorAction Stop
    } catch [System.Management.Automation.ItemNotFoundException] {
        New-LibsDirectory

        $url = "https://d1kpmuwb7gvu1i.cloudfront.net/AccessData_FTK_Imager_4.7.1.exe"
        Get-FileFromWeb -URL $url -File "libs/FTKImager.exe"

        Return Get-FTKImager
    }
}

function Get-USBDriveLog {
    try {
        Return Resolve-Path -Path "libs/USBDriveLog/USBDriveLog.exe" -ErrorAction Stop
    } catch [System.Management.Automation.ItemNotFoundException] {
        New-LibsDirectory
        
        $url = "https://www.nirsoft.net/utils/usbdrivelog.zip"
        Get-FileFromWeb -URL $url -File "libs/USBDriveLog.zip"

        Expand-Archive -DestinationPath "libs/USBDriveLog" -Path "libs/USBDriveLog.zip"
        Remove-Item -Path "libs/USBDriveLog.zip"

        Return Get-USBDriveLog
    }
}

function Get-DetectItEasy {
    try {
        Return Resolve-Path -Path "libs/DetectItEasy/die.exe" -ErrorAction Stop
    } catch [System.Management.Automation.ItemNotFoundException] {
        New-LibsDirectory
        
        $url = if ([System.Environment]::Is64BitOperatingSystem) {"https://github.com/horsicq/DIE-engine/releases/download/3.10/die_win64_portable_3.10_x64.zip"} else {"https://github.com/horsicq/DIE-engine/releases/download/3.10/die_win32_portable_3.10_x86.zip"}
        Get-FileFromWeb -URL $url -File "libs/DetectItEasy.zip"

        Expand-Archive -DestinationPath "libs/DetectItEasy" -Path "libs/DetectItEasy.zip"
        Remove-Item -Path "libs/DetectItEasy.zip"

        Return Get-DetectItEasy
    }
}

function Get-AlternateStreamView {
    try {
        Return Resolve-Path -Path "libs/AlternateStreamView/AlternateStreamView.exe" -ErrorAction Stop
    } catch [System.Management.Automation.ItemNotFoundException] {
        New-LibsDirectory
        
        $url = if ([System.Environment]::Is64BitOperatingSystem) {"https://www.nirsoft.net/utils/alternatestreamview-x64.zip"} else {"https://www.nirsoft.net/utils/alternatestreamview.zip"}
        Get-FileFromWeb -URL $url -File "libs/AlternateStreamView.zip"

        Expand-Archive -DestinationPath "libs/AlternateStreamView" -Path "libs/AlternateStreamView.zip"
        Remove-Item -Path "libs/AlternateStreamView.zip"

        Return Get-AlternateStreamView
    }
}

function Get-Bstrings {
    try {
        Return Resolve-Path -Path "libs/bstrings/bstrings.exe" -ErrorAction Stop
    } catch [System.Management.Automation.ItemNotFoundException] {
        New-LibsDirectory
        
        $url = "https://download.ericzimmermanstools.com/net9/bstrings.zip"
        Get-FileFromWeb -URL $url -File "libs/bstrings.zip"

        Expand-Archive -DestinationPath "libs/bstrings" -Path "libs/bstrings.zip"
        Remove-Item -Path "libs/bstrings.zip"

        Return Get-Bstrings
    }
}

function Get-TimelimeExplorer {
    try {
        Return Resolve-Path -Path "libs/TimelineExplorer/TimelineExplorer.exe" -ErrorAction Stop
    } catch [System.Management.Automation.ItemNotFoundException] {
        New-LibsDirectory
        
        $url = "https://download.ericzimmermanstools.com/net9/TimelineExplorer.zip"
        Get-FileFromWeb -URL $url -File "libs/TimelineExplorer.zip"

        Expand-Archive -DestinationPath "libs" -Path "libs/TimelineExplorer.zip"
        Remove-Item -Path "libs/TimelineExplorer.zip"
    }
}

function Get-Ocean {
    Start-Process "https://anticheat.ac/download"
}

function Invoke-SignatureCheck {
    param (
        [String] $Path
    )
    Remove-Item -Path "libs/paths.txt" -ErrorAction SilentlyContinue
    Copy-Item -Path $Path -Destination "libs/paths.txt"
    Start-Process (Get-PathsParser).Path
}

function Invoke-CsrssSignatureCheck {
    while (-Not (Test-Path -Path "csrss.exe.bin")) {
        Write-Host "Please put csrss.exe.bin in the running directory"
        Pause
    }
    Remove-Item -Path "csrss.txt" -ErrorAction SilentlyContinue
    $Bstrings = Get-Bstrings
    & $Bstrings.Path -f "csrss.exe.bin" --lr "^[A-Z]:\\.+\.(exe|dll)$" --ro -o "csrss.txt" > $null
    Invoke-SignatureCheck -Path "csrss.txt"
}

function Get-HardDiskVolumeNamesDict {
    $HardDiskVolumeNumbers = @{}
    foreach ($partition in Get-Partition) {
        if ($partition.DriveLetter.Length -gt 0) {
            $HardDiskVolumeNumbers[[string]$partition.PartitionNumber] = $partition.DriveLetter
        }
    }
    Return $HardDiskVolumeNumbers
}

function Invoke-DPSSignatureCheck {
    while (-Not (Test-Path -Path "svchost.exe.bin")) {
        Write-Host "Please put svchost.exe.bin in the running directory"
        Pause
    }
    Remove-Item -Path "dps.txt" -ErrorAction SilentlyContinue
    $Bstrings = Get-Bstrings
    & $Bstrings.Path -f "svchost.exe.bin" --lr "^\\device\\harddiskvolume\d+\\.+\.(exe|dll)$" --ro -o "dps.txt" > $null

    $HardDiskVolumeNamesDict = Get-HardDiskVolumeNamesDict
    
    $streamWriter = [System.IO.StreamWriter]::new("new_dps.txt", $true, [System.Text.Encoding]::UTF8)
    foreach ($path in Get-Content -Path "dps.txt") {
        $match = [regex]::Matches($path, "^\\device\\harddiskvolume(\d+)(.*)", [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
        $HardDiskVolumeNumber = $match.Groups[1].Value
        $NewPath = "$($HardDiskVolumeNamesDict[$HardDiskVolumeNumber]):$($match.Groups[2].Value)"
        if ($NewPath -match "$($env:SystemDrive)\\Windows\\System32\\svchost\.exe") {
            continue
        }
        $streamWriter.WriteLine($NewPath)
    }
    $streamWriter.Close()
    Remove-Item -Path "dps.txt"
    Rename-Item -Path "new_dps.txt" -NewName "dps.txt"
    Invoke-SignatureCheck -Path "dps.txt"
}

function Invoke-Cleanup {
    Remove-Item -Path libs -Recurse
}

while (1) {
    Clear-Host
    Write-Host @"
- evr: search everything
- wpv: WinPrefetchView
- sysinf: System Informer
- bam: spokwn's bam parser
- jrnl: spokwn's JournalTrace
- pathsparser: spokwn's PathsParser
- hybs: Hayabusa
- ftkimg: FTKImager
- usbdl: USBDriveLog
- die: Detect-It-Easy
- tlex: Timeline Explorer
- ocean: ocean scanner
- asv: AlternateStreamView

- services: see services and their uptime
- alt: to check for alts
- csrss: to signature check paths in csrss
- dps: to signature check paths in dps

- cleanup: to cleanup after screenshare
- exit: to exit
"@
    $userInput = Read-Host "Enter one of the options above"
	
    Clear-Host
    try {
        if ($userInput.Equals("exit")) 
        {
            break
        } 
        elseif ($userInput.Equals("cleanup")) 
        {
            Invoke-Cleanup
        } 
        elseif ($userInput.Equals("evr")) 
        {
            Start-Process "$(Get-SearchEverythingInstaller)"
        } 
        elseif ($userInput.Equals("alt")) 
        {
            Invoke-AltCheck
        } 
        elseif ($userInput.Equals("wpv")) 
        { 
            Start-Process "$(Get-WinPrefetchView)"
        } 
        elseif ($userInput.Equals("sysinf")) 
        {
            Start-Process "$(Get-SystemInformerInstaller)"
        } 
        elseif ($userInput.Equals("bam")) 
        {
            Start-Process "$(Get-BamParser)"
        } 
        elseif ($userInput.Equals("jrnl")) 
        {
            Start-Process "$(Get-JournalTrace)"
        } 
        elseif ($userInput.Equals("pathsparser")) 
        {
            Start-Process "$(Get-PathsParser)"
        } 
        elseif ($userInput.Equals("asv")) 
        {
            Start-Process "$(Get-AlternateStreamView)"
        }
        elseif ($userInput.Equals("services")) 
        {
            Show-ServicesState
        } 
        elseif ($userInput.Equals("hybs")) 
        {
            Remove-Item -Path hayabusa.csv -ErrorAction SilentlyContinue > $null
            & (Get-Hayabusa) csv-timeline -l -o hayabusa.csv -U -A -D -n -u -w
            Start-Process ((Get-TimelimeExplorer).Path) -ArgumentList "hayabusa.csv"
        } 
        elseif ($userInput.Equals("ftkimg")) 
        {
            Start-Process "$(Get-FTKImager)"
        } 
        elseif ($userInput.Equals("usbdl")) 
        {
            Start-Process "$(Get-USBDriveLog)"
        } 
        elseif ($userInput.Equals("die")) 
        {
            Start-Process "$(Get-DetectItEasy)"
        }
        elseif ($userInput.Equals("tlex")) 
        {
            Start-Process "$(Get-TimelimeExplorer)"
        } 
        elseif ($userInput.Equals("ocean")) 
        {
            Get-Ocean
        } 
        elseif ($userInput.Equals("csrss")) 
        {
            Invoke-CsrssSignatureCheck
        } 
        elseif ($userInput.Equals("dps")) 
        {
            Invoke-DPSSignatureCheck
        } 
        else {
            Write-Host "Invalid option..."
            Pause
        }   
    } catch {
        $_
        Pause
    }
}

Clear-Host
