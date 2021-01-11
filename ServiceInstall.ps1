$ScriptPath = split-path -parent $MyInvocation.MyCommand.Definition
$args = "-ExecutionPolicy Bypass -NoProfile -File $($ScriptPath)\PipelineMonitor.ps1"
& "$($ScriptPath)\nssm-2.24\win64\nssm.exe" Install LogstashMonitor ((Get-Command powershell).Source) $args