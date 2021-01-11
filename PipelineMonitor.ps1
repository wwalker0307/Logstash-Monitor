#Look for Logstash service
While (Get-Service Logstash) {
  #$ScriptPath = "D:\LogstashMonitor"
  $ScriptPath = split-path -parent $MyInvocation.MyCommand.Definition
  Try {
    $log += "$(Get-Date -Format '[MM-dd-yyyyTHH:mm:ss]') [INFO] Attempting to read configuration from $($ScriptPath)\config.xml`n"
    [xml]$config = Get-Content "$($ScriptPath)\config.xml"
  }
  Catch {
    log += "$(Get-Date -Format '[MM-dd-yyyyTHH:mm:ss]') [ERROR] $($error[0].CategoryInfo.Activity)"+": "+"$($error[0].Exception.Message)`n"
    log += "$(Get-Date -Format '[MM-dd-yyyyTHH:mm:ss]') [ERROR] Failed to read configuration file"
    $log | Out-File "$ScriptPath\MonitorService_(Get-Date -Format "MMddyyyy").log" -Append
    Exit
  }
  $Elasticsearch = @{
    'Host' = $config.config.Elasticsearch.Host
    'Port' = $config.config.Elasticsearch.Port
    'Protocol' = $config.config.Elasticsearch.Protocol
  }
  $Headers = @{
      Authorization = "ApiKey $([Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(("{0}:{1}" -f $config.config.Elasticsearch.API_Id, $config.config.Elasticsearch.API_Key))))"
    }
  $Logstash = @{
    'Host' = $config.config.Logstash.Host
    'Port' = $config.config.Logstash.Port
    'Protocol' = $config.config.Logstash.Protocol
  }
  $SMTPEnable = $config.config.SMTP.Enable
  $SMTP = @{
    SmtpServer = $config.config.SMTP.Server
    To = $config.config.SMTP.To
    From = $config.config.SMTP.From
    Port = $config.config.SMTP.Port
  }
  $LogRoot = $config.config.Logging.Folder
  if ((Test-Path $LogRoot ) -eq $false) {
    New-Item -Type Directory $LogRoot | Out-Null
  }
  $Date = Get-Date -Format "MMddyyyy_HHmmss"
  #Verify service is running
  if ((Get-Service Logstash).Status -eq "Running") {
    #Collect list of pipelines
    $Pipelines = ((Invoke-RestMethod -Uri "$($Logstash.Protocol)://$($Logstash.Host):$($Logstash.Port)/_node/stats/pipelines").pipelines.PSObject.Properties | Where-Object {$_.MemberType -eq "NoteProperty"}).Name
    $log += "$(Get-Date -Format '[MM-dd-yyyyTHH:mm:ss]') [INFO] Running pipelines: $($pipelines.count)`n"
    $log += "$(Get-Date -Format '[MM-dd-yyyyTHH:mm:ss]') [INFO] Pipelines: $($pipelines -join ', ')`n"
    $log += "$(Get-Date -Format '[MM-dd-yyyyTHH:mm:ss]') [INFO] Starting pipeline health checks`n"
    $down = @()
    #Check health of each pipeline
    foreach ($pipeline in $pipelines) {
      $pipelineinfo = Invoke-RestMethod -Uri "$($Logstash.Protocol)://$($Logstash.Host):$($Logstash.Port)/_node/stats/pipelines/$($pipeline)"
      $queueinfo = $pipelineinfo.pipelines.$pipeline.queue
      $log += "$(Get-Date -Format '[MM-dd-yyyyTHH:mm:ss]') [INFO] $($pipeline) ephemeral id $($pipelineinfo.ephemeral_id)`n"
      $log += "$(Get-Date -Format '[MM-dd-yyyyTHH:mm:ss]') [INFO] $($pipeline) queue size (bytes) $([string]::Format('{0:N0}',($queueinfo.queue_size_in_bytes)))`n"
      $log += "$(Get-Date -Format '[MM-dd-yyyyTHH:mm:ss]') [INFO] $($pipeline) queue capacity (bytes) $([string]::Format('{0:N0}',($queueinfo.max_queue_size_in_bytes)))`n"
      $log += "$(Get-Date -Format '[MM-dd-yyyyTHH:mm:ss]') [INFO] $($pipeline) queued events $($queueinfo.events)`n"
      if ($pipelineinfo.pipelines.$pipeline.hash -eq $null) {
        $log += "$(Get-Date -Format '[MM-dd-yyyyTHH:mm:ss]') [WARN] $($pipeline) down`n"
        $down += $pipeline
      }
      if (
        ($queueinfo.queue_size_in_bytes -eq $queueinfo.max_queue_size_in_bytes) -and 
        ($queueinfo.max_queue_size_in_bytes -ne 0)
      ) {
        $log += "$(Get-Date -Format '[MM-dd-yyyyTHH:mm:ss]') [WARN] $($pipeline) queue at max capacity`n"
        if ($SMTPEnable -eq 1) {
          Try {
            Send-MailMessage @SMTP -Subject "Pipeline Queue Full" -Body "Pipeline $($pipeline)'s queue appears to be at full capacity"
          }
          Catch {
             log += "$(Get-Date -Format '[MM-dd-yyyyTHH:mm:ss]')  $($error[0].CategoryInfo.Activity)"+": "+"$($error[0].Exception.Message)`n"
          }
        }
      }
      if (
        ($queueinfo.queue_size_in_bytes -ne $queueinfo.max_queue_size_in_bytes) -and
        ($pipelineinfo.pipelines.$pipeline.hash -ne $null) -and
        ($queueinfo.max_queue_size_in_bytes -ne 0)
      ) {
        $log += "$(Get-Date -Format '[MM-dd-yyyyTHH:mm:ss]') [INFO] $($pipeline) up`n"
      }
    }
    #Actions on unhealthy pipelines
    if ($down.count -gt 0) {
      #Create temp dir for log files
      New-Item -Type Directory -Path "$($LogRoot)\Temp" | Out-Null
      foreach ($pipe in $down) {
        Write-Host "$(Get-Date)  Pipeline $($pipe) appears to be down. Collecting logs..."
        #Compress logs for each failed pipeline
        $log += "$(Get-Date -Format '[MM-dd-yyyyTHH:mm:ss]') [INFO] Collecting $($pipe) logs...`n"
        Try {
          Copy-Item -Path "$($LogRoot)\pipeline_$($pipe).log" -Destination "$($LogRoot)\Temp\pipeline_$($pipe).log"
          Compress-Archive -LiteralPath "$($LogRoot)\Temp\pipeline_$($pipe).log" -CompressionLevel Fastest -DestinationPath "$($LogRoot)\Temp\pipeline_$($pipe)_$($Date).zip"
        }
        Catch {
           log += "$(Get-Date -Format '[MM-dd-yyyyTHH:mm:ss]')  $($error[0].CategoryInfo.Activity)"+": "+"$($error[0].Exception.Message)`n"
        }
      }
      #Compress logstash log
      $log += "$(Get-Date -Format '[MM-dd-yyyyTHH:mm:ss]') [INFO] Collecting logstash-plain.log...`n"
      Try {
        Copy-Item -Path "$($LogRoot)\logstash-plain.log" -Destination "$($LogRoot)\Temp\logstash-plain.log"
        Compress-Archive -LiteralPath "$($LogRoot)\Temp\logstash-plain.log" -CompressionLevel Fastest -DestinationPath "$($LogRoot)\Temp\logstash-plain_$($Date).zip"
      }
      Catch {
        log += "$(Get-Date -Format '[MM-dd-yyyyTHH:mm:ss]')  $($error[0].CategoryInfo.Activity)"+": "+"$($error[0].Exception.Message)`n"
      }
      #Send compressed logs in email notification
      if ($SMTPEnable -eq 1) {
        $log += "$(Get-Date -Format '[MM-dd-yyyyTHH:mm:ss]') [INFO] Sending mail notification to $($SMTP.To)`n"
        Try {
          Send-MailMessage @SMTP -Subject "Pipeline Down Detected" -Attachments (Get-ChildItem "$LogRoot\Temp\*.zip")
        }
        Catch {
          $log += "$(Get-Date -Format '[MM-dd-yyyyTHH:mm:ss]') [ERROR] $($error[0].CategoryInfo.Activity)"+": "+"$($error[0].Exception.Message)`n"
        }
      }
      #Remove temp dir and files
      Remove-Item "$($LogRoot)\Temp" -Force -Recurse -Confirm:$false
      Restart-Service Logstash
      Remove-Variable down
      Do {
        (Get-Service Logstash).Status
        Start-Sleep -Seconds $config.config.CheckInterval
      }
      Until (((Get-Service Logstash).Status) -eq "Running")
      if ($SMTPEnable -eq 1) {
        Send-MailMessage @SMTP -Subject "Logstash Successfully Restarted"
      }
    #Actions on no unhealthy pipelines
    } else {
      $log += "$(Get-Date -Format '[MM-dd-yyyyTHH:mm:ss]') [INFO] All pipelines running`n"
      Write-Host "$(Get-Date)  All pipelines up"
    }
    #Check logs for index write blocks
    $log += "$(Get-Date -Format '[MM-dd-yyyyTHH:mm:ss]') [INFO] Starting check for index write blockage`n"
    foreach ($logfile in ((Get-Childitem $LogRoot\pipeline*.log).FullName)) {
      $indices += ((Select-String -Path $logfile -Pattern "index \[(.*?)\].*?FORBIDDEN\/.\/index write").matches.value | Get-Unique) -replace "index \[|\].*","`n"
    }
    $indices = $indices.Split("`n") | Where-Object {$_ -ne ""}
    if ($indices -ne $null) {
      $log += "$(Get-Date -Format '[MM-dd-yyyyTHH:mm:ss]') [WARN] Possible write blocks detected in the following indices: $($indices | foreach {"$_,"})`n"
      foreach ($index in $indices) {
        if (((Invoke-RestMethod -Method GET -Uri "$($Elasticsearch.Protocol)://$($Elasticsearch.Host):$($Elasticsearch.Port)/$index/_settings" -Headers $Headers).$index.settings.index.blocks.write) -eq "true") {
          $log += "$(Get-Date -Format '[MM-dd-yyyyTHH:mm:ss]') [WARN] $($index) is blocking writes`n"
          $body = '{"blocks.write":false}'
          $log += "$(Get-Date -Format '[MM-dd-yyyyTHH:mm:ss]') [INFO] Attempting to disable write blocks on $($index)...`n"
          $IndexWrite = (Invoke-RestMethod -Method PUT -Uri "$($Elasticsearch.Protocol)://$($Elasticsearch.Host):$($Elasticsearch.Port)/$($matches.index)/_settings" -Body $body -ContentType Application/Json -Headers $Headers).acknowledged
          if ($IndexWrite -eq "True") {
            $log += "$(Get-Date -Format '[MM-dd-yyyyTHH:mm:ss]') [INFO] Removing write blocks on $($index) successful`n"
          } else {
            $log += "$(Get-Date -Format '[MM-dd-yyyyTHH:mm:ss]') [ERROR] Unable to remove write block on $($index)`n"
          }
        } else {
          $log += "$(Get-Date -Format '[MM-dd-yyyyTHH:mm:ss]') [INFO] $($index) is not blocking writes`n"
        }
      }
      Remove-Variable indices
    }
  }
  if ($config.config.logging.enabled -eq 1) {
    $logging = $config.config.logging
    if ($Logging.Rotation.Enabled -eq 1) {
      switch ($Logging.Rotation.Type) {
        "Age" {
          $log += "$(Get-Date -Format '[MM-dd-yyyyTHH:mm:ss]') [INFO] Rotation type set to age`n"
          $log += "$(Get-Date -Format '[MM-dd-yyyyTHH:mm:ss]') [INFO] Rotation age set to $($Logging.Rotation.Age) hours`n"
          if (
            (Test-Path $("$LogRoot\MonitorService.log") -eq $true) -and 
            ((Get-ChildItem "$($LogRoot)\MonitorService.log").CreationTime -le (Get-Date).AddHours(-$Logging.Rotation.Age))
          ) {
            switch ($Logging.Retain) {
              0 {
                $log += "$(Get-Date -Format '[MM-dd-yyyyTHH:mm:ss]') [INFO] Log retention is disabled, deleting log`n"
                Remove-Item "$($LogRoot)\MonitorService.log" -Force -Confirm:$false
              }
              1 {
                $log += "$(Get-Date -Format '[MM-dd-yyyyTHH:mm:ss]') [INFO] Log older than $($Logging.Rotation.Age) hours, saving to $($LogRoot)\MonitorService.log_$($Date).zip`n"
                Compress-Archive -LiteralPath "$($LogRoot)\MonitorService.log" -CompressionLevel Fastest -DestinationPath "$($LogRoot)\MonitorService.log_$($Date).zip"
                Remove-Item "$($LogRoot)\MonitorService.log" -Confirm:$false -Force
              }
            }
          } else {
            $log += "$(Get-Date -Format '[MM-dd-yyyyTHH:mm:ss]') [INFO] Log file less than $($Logging.Rotation.Age) hours old, not rotating`n"
          }
        }
        "Size" {
          [float]$size = $Logging.Rotation.Size
          $log += "$(Get-Date -Format '[MM-dd-yyyyTHH:mm:ss]') [INFO] Rotation type set to size`n"
          $log += "$(Get-Date -Format '[MM-dd-yyyyTHH:mm:ss]') [INFO] Rotation size set to $([string]::Format('{0:N0}',($size*1048576))) bytes`n"
          if ((Get-ChildItem "$($LogRoot)\MonitorService.log").length -ge ($Size*1048576)) {
            switch ($Logging.Retain) {
              0 {
                $log += "$(Get-Date -Format '[MM-dd-yyyyTHH:mm:ss]') [INFO] Log file is $([string]::Format('{0:N0}',((Get-ChildItem "$($LogRoot)\MonitorService.log").length))) bytes, rotating`n"
                $log += "$(Get-Date -Format '[MM-dd-yyyyTHH:mm:ss]') [INFO] Log retention is disabled, deleting log`n"
                Remove-Item "$($LogRoot)\MonitorService.log" -Force -Confirm:$false
              }
              1 {
                $log += "$(Get-Date -Format '[MM-dd-yyyyTHH:mm:ss]') [INFO] Log file is $([string]::Format('{0:N0}',((Get-ChildItem "$($LogRoot)\MonitorService.log").length))) bytes, rotating`n"
                $log += "$(Get-Date -Format '[MM-dd-yyyyTHH:mm:ss]') [INFO] Log retention enabled, saving to $($LogRoot)\MonitorService.log_$($Date).zip`n"
                Compress-Archive -LiteralPath "$($LogRoot)\MonitorService.log" -CompressionLevel Fastest -DestinationPath "$($LogRoot)\MonitorService.log_$($Date).zip"
                Remove-Item "$($LogRoot)\MonitorService.log" -Confirm:$false -Force
                }
            }
          } else {
            $log += "$(Get-Date -Format '[MM-dd-yyyyTHH:mm:ss]') [INFO] Log file is $([string]::Format('{0:N0}',((Get-ChildItem "$($LogRoot)\MonitorService.log").length))) bytes, not rotating`n"
          }
        }
        "Both" {
          [float]$size = $Logging.Rotation.Size
          $log += "$(Get-Date -Format '[MM-dd-yyyyTHH:mm:ss]') [INFO] Rotation type set to size or age`n"
          $log += "$(Get-Date -Format '[MM-dd-yyyyTHH:mm:ss]') [INFO] Rotation size set to $([string]::Format('{0:N0}',($size*1048576))) bytes and age set to $($Logging.Rotation.Age) hours`n"
          if (
            (Test-Path $("$LogRoot\MonitorService.log") -eq $true) -and 
            ((Get-ChildItem "$($LogRoot)\MonitorService.log").CreationTime -le (Get-Date).AddHours(-$Logging.Rotation.Age)) -or
            ((Get-ChildItem "$($LogRoot)\MonitorService.log").length -ge ($Size*1048576))
          ) {
            switch ($Logging.Retain) {
              0 {
                $log += "$(Get-Date -Format '[MM-dd-yyyyTHH:mm:ss]') [INFO] Log retention is disabled, deleting log`n"
                Remove-Item "$($LogRoot)\MonitorService.log" -Force -Confirm:$false
              }
              1 {
                $log += "$(Get-Date -Format '[MM-dd-yyyyTHH:mm:ss]') [INFO] Log retention enabled, saving to $($LogRoot)\MonitorService.log_$($Date).zip`n"
                Compress-Archive -LiteralPath "$($LogRoot)\MonitorService.log" -CompressionLevel Fastest -DestinationPath "$($LogRoot)\MonitorService.log_$($Date).zip"
                Remove-Item "$($LogRoot)\MonitorService.log" -Confirm:$false -Force
              }
            }
          } else {
		    $log += "Log file is $([string]::Format('{0:N0}',((Get-ChildItem "$($LogRoot)\MonitorService.log").length))) bytes and was created less than $($Logging.Rotation.Age) hours old, not rotating"
		  }
        }
      }
    }
  $log | Out-File "$($LogRoot)\MonitorService.log" -Append
  Remove-Variable log
  }
  Start-Sleep -Seconds $config.config.CheckInterval
}