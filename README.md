##Logstash Monitor
Logstash monitor is a PowerShell script designed to query the health of Logstash pipelines and persisted queues.  In the event
that a pipeline fails, Logstash monitor will:

* Collect the failed pipeline log (if per pipeline logging is enabled) and logstash-plain.log files
* Send an email to the specified email address
* Restart Logstash

Logstash Monitor will also send an email notification if a persisted queue appears to be full and monitor pipeline logs for index
write blocks.  If a write block is detected, Logstash Monitor will make a call to Elasticsearch to unblock writes to the required index.

##Running Interactively
You can run the monitor interactively by running PipelineMonitor.ps1 in a Windows PowerShell window

##Running As A Service
Logstash Monitor can be installed as a Windows service by executing ServiceInstall.ps1.  NSSM is used to install/manage the service.

##Configuring Logstash Monitor
Config.xml contains the settings the monitor will use and is read from everytime a health check is performed.  Prior to running,
if your Elasticsearch installation is secured, you must create an API key first.  Refer to Elasticsearch documentation on how to do this.

####Config.xml settings
* CheckInterval is the number of seconds between health checks
* When Log Retention is set to 1, Logstash Monitor will compress and delete the log file based on rotation settings
* Log Rotation Type can be set to 'age', 'size', or 'both.
	* When set to both, log rotation action occurs when either age or size limit is reached.
* SMTP to can be set to multiple users by separating each email address with a comma (IE "sysadmin@contoso.com","elasticadmin@contoso.com")