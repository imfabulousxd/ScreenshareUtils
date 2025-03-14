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

$global:Is64BitOperatingSystem = [System.Environment]::Is64BitOperatingSystem

function CreateLibsDir {
    if (-Not(Test-Path -Path libs)) {
        New-Item -Name "libs" -ItemType "directory"
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

function Everything {
    CreateLibsDir
    if (-Not(Test-Path -Path libs/Everything.exe)) {
        if ($global:Is64BitOperatingSystem) {
            Invoke-WebRequest "https://www.voidtools.com/Everything-1.4.1.1026.x64-Setup.exe" -OutFile libs/Everything.exe
        } else {
            Invoke-WebRequest "https://www.voidtools.com/Everything-1.4.1.1026.x86-Setup.exe" -OutFile libs/Everything.exe
        }
    }
    .\libs\Everything.exe
}

function DownloadEverythingCLI {
    CreateLibsDir
    if (-Not(Test-Path -Path libs/ES)) {
        if ($global:Is64BitOperatingSystem) {
            Invoke-WebRequest "https://www.voidtools.com/ES-1.1.0.27.x64.zip" -OutFile libs/ES.zip
        } else {
            Invoke-WebRequest "https://www.voidtools.com/ES-1.1.0.27.x86.zip" -OutFile libs/ES.zip
        }
        Expand-Archive -DestinationPath "libs/ES" -Path "libs/ES.Zip"
        Remove-Item -Path "libs/ES.zip"
    }
}

$global:7zPath = ""
function Find7Zip {
    DownloadEverythingCLI
    $global:7zPath = .\libs\ES\es.exe "Program Files\7-Zip\7z.exe"
    if ($global:7zPath.Length -eq 0) {
        throw [System.IO.FileNotFoundException]::new("Couldn't find 7zip installed")
    }
    $global:7zPath = $global:7zPath.Split("`r`n")[0]
}

$global:githubToken = ""
$global:githubTokenAsked = $false
function Get-GithubToken {
    if ($global:githubTokenAsked) {
        Return
    }
    $global:githubToken = Read-Host "Please enter your github token"
    $global:githubTokenAsked = $true
    Clear-Host
}

function Get-GithubAPI-Headers {
    if ($global:githubToken.Length -eq 0) {
        return @{}
    } else {
        return @{"Authorization"= "Bearer $global:githubToken"}
    }
}

function Download7Zip {
    try {
        Find7Zip
    } catch [System.IO.FileNotFoundException] {
        Write-Host "Installing 7zip..."
        if (-Not(Test-Path -Path libs/7z.exe)) {
            CreateLibsDir
            Get-GithubToken
            $url = "https://api.github.com/repos/ip7z/7zip/releases/latest"
            $resp = Invoke-WebRequest $url -Headers $(Get-GithubAPI-Headers)
            if ($resp.StatusCode -ne 200) {
                Write-Host "Status code $($resp.StatusCode)"
                Pause
                Return
            }
            $content = $resp.Content | ConvertFrom-Json
            $regex = if ($global:Is64BitOperatingSystem) {"7z\d+-x64\.exe"} else {"7z\d+\.exe"}
            foreach ($asset in $content.assets) {
                if ($asset.name -imatch $regex) {
                    Invoke-WebRequest $asset.browser_download_url -OutFile libs/7z.exe
                    break
                }
            }
        }
        .\libs\7z.exe
        Write-Host "After installing, Press enter..."
        Pause
        Clear-Host
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
        $url = if ($global:Is64BitOperatingSystem) {"https://www.nirsoft.net/utils/winprefetchview-x64.zip"} else {"https://www.nirsoft.net/utils/winprefetchview.zip"}
        Invoke-WebRequest $url -OutFile libs/wpv.zip
        & $global:7zPath e -olibs/wpv libs/wpv.zip > $null
        Remove-Item -Path "libs/wpv.zip"
    }
    & .\libs\wpv\WinPrefetchView.exe
}

function SystemInformer {
    CreateLibsDir
    if (-Not(Test-Path -Path libs/systeminformer.exe)) {
        Get-GithubToken
        $url = "https://api.github.com/repos/winsiderss/si-builds/releases/latest"
        $resp = Invoke-WebRequest -Uri $url -Headers $(Get-GithubAPI-Headers)
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
        Get-GithubToken
        $url = "https://api.github.com/repos/spokwn/BAM-parser/releases/latest"
        $resp = Invoke-WebRequest $url -Headers $(Get-GithubAPI-Headers)
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
        Get-GithubToken
        $url = "https://api.github.com/repos/spokwn/JournalTrace/releases/latest"
        $resp = Invoke-WebRequest $url -Headers $(Get-GithubAPI-Headers)
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
        Get-GithubToken
        $url = "https://api.github.com/repos/spokwn/PathsParser/releases/latest"
        $resp = Invoke-WebRequest $url -Headers $(Get-GithubAPI-Headers)
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

function Hayabusa {
    CreateLibsDir
    if (-Not(Test-Path -Path libs/Hayabusa/Hayabusa.exe)) {
        Get-GithubToken
        $url = "https://api.github.com/repos/Yamato-Security/hayabusa/releases/latest"
        $resp = Invoke-WebRequest $url -Headers $(Get-GithubAPI-Headers)
        if ($resp.StatusCode -ne 200) {
            Write-Host "Status code $($resp.StatusCode)"
            Pause
            Return
        }
        $content = $resp.Content | ConvertFrom-Json
        $fileName = ""
        $regex = if ($global:Is64BitOperatingSystem) {".*win-x64\.zip"} else {".*win-x86\.zip"}
        foreach ($asset in $content.assets) {
            if ($asset.name -imatch $regex) {
                $fileName =$asset.name
                Invoke-WebRequest $asset.browser_download_url -OutFile libs/Hayabusa.zip
                break
            }
        }
        Find7Zip
        & $global:7zPath x -olibs/Hayabusa libs/Hayabusa.zip > $null
        Remove-Item -Path "libs/Hayabusa.zip"
        Rename-Item -Path "libs/Hayabusa/$($fileName.Remove($fileName.Length-4)).exe" -NewName "Hayabusa.exe"
    }
    .\libs\Hayabusa\Hayabusa.exe csv-timeline -l -o hayabusa.csv -U
}

function FTKImager {
    CreateLibsDir
    if (-Not(Test-Path -Path libs/FTKImager.exe)) {
        $url = "https://d1kpmuwb7gvu1i.cloudfront.net/AccessData_FTK_Imager_4.7.1.exe"
        Invoke-WebRequest $url -OutFile libs/FTKImager.exe
    }
    & .\libs\FTKImager.exe
}

function USBDriveLog {
    CreateLibsDir
    if (-Not(Test-Path -Path libs/USBDriveLog.exe)) {
        Download7Zip
        $url = "https://www.nirsoft.net/utils/usbdrivelog.zip"
        Invoke-WebRequest $url -OutFile libs/USBDriveLog.zip
        & $global:7zPath x -olibs/USBDriveLog libs/USBDriveLog.zip
        Remove-Item -Path "libs/USBDriveLog.zip"
    }
    & .\libs\USBDriveLog\USBDriveLog.exe
}

function DetectItEasy {
    CreateLibsDir
    if (-Not(Test-Path -Path libs/DetectItEasy/die.exe)) {
        Download7Zip
        $url = if ($global:Is64BitOperatingSystem) {"https://github.com/horsicq/DIE-engine/releases/download/3.10/die_win64_portable_3.10_x64.zip"} else {"https://github.com/horsicq/DIE-engine/releases/download/3.10/die_win32_portable_3.10_x86.zip"}
        Invoke-WebRequest $url -OutFile libs/DetectItEasy.zip
        & $global:7zPath x -olibs/DetectItEasy libs/DetectItEasy.zip
        Remove-Item -Path "libs/DetectItEasy.zip"
    }
    & .\libs\DetectItEasy\die.exe
}

function Cleanup {
    Remove-Item -Path libs -Recurse
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
- hybs: Hayabusa
- ftkimg: FTKImager
- usbdl: USBDriveLog
- die: Detect-It-Easy
- cleanup: to cleanup after screenshare
- exit: to exit
"@
    $userInput = Read-Host "Enter one of the options above"
	
    Clear-Host
    try {
        if ($userInput.Equals("exit")) {
            break
        } elseif ($userInput.Equals("cleanup")) {
            Cleanup
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
        } elseif ($userInput.Equals("hybs")) {
            Hayabusa
        } elseif ($userInput.Equals("ftkimg")) {
            FTKImager
        } elseif ($userInput.Equals("usbdl")) {
            USBDriveLog
        } elseif ($userInput.Equals("die")) {
            DetectItEasy
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
