# Notes on Detecting Cobalt Strike Activity
from Binary Defense webinar on 2021-02-24

## Hunting Netflow Patterns
> This is the most reliable and fastest way to detect not only CS Beacon but many other RATs as well.
- Expect false positives, because legitimate software checks in regularly with servers, too
- Tune out any known good beacon-like activity in the hunting rule to avoid repeat investigations
- Don't dismiss activity just because it comes from signed system utilities - it could be process injection

### Binary Defense Jupyter Notebook for Beacon Hunting
https://github.com/BinaryDefense/ThreatHuntingJupyterNotebooks
- Note: This notebook requires either Sysmon or Microsoft Defender for Endpoint data in Sentinel

### RITA from Active Countermeasures
https://www.activecountermeasures.com/free-tools/rita/
- Note: RITA requires Zeek logs

### KQL Query for Hunting in Sysmon


        let starttime = 48h; // Go back as many days as you want to look
        let endtime = 1m; // Usually you want to check up to the current time but set this if not
        let  TimeDeltaThreshold = 2; // don't count anything under 2 seconds between connections
        let TotalEventsThreshold = 15; // only show beaconing that had at least this many connections
        let DurationThreshold = 900; // only show beaconing that lasted at least this many seconds
        let StandardDeviationThreshold = 100; // Set to filter out false positives: lower number is tighter filtering/fewer results
        Sysmon
        | where EventID==3
        | where TimeGenerated between (ago(starttime)..ago(endtime))
        | project TimeGenerated, Computer, process_path, src_ip, src_port, dst_ip, dst_port
        | sort by src_ip asc, dst_ip asc, TimeGenerated asc // sort to put all connections between two hosts next to each other in time order
        | serialize 
        | extend nextTimeGenerated = next(TimeGenerated, 1), nextDeviceId = next(Computer, 1), nextDstIP = next(dst_ip, 1) 
        | extend TimeDeltaInSeconds = datetime_diff("second", nextTimeGenerated, TimeGenerated) // compute time difference between subsequent connections
        | where Computer == nextDeviceId and nextDstIP == dst_ip // only compute time difference if next host pair is the same as current
        | where TimeDeltaInSeconds > TimeDeltaThreshold // filter out connections that happen too close together
        | project TimeGenerated, TimeDeltaInSeconds, Computer, process_path, src_ip, src_port, dst_ip, dst_port
        | summarize avg(TimeDeltaInSeconds), count(), min(TimeGenerated), max(TimeGenerated),  // compute statistics including standard deviation
        Duration=datetime_diff("second", max(TimeGenerated), min(TimeGenerated)), 
        StandardDeviation=stdev(TimeDeltaInSeconds), TimeDeltaList=make_list(TimeDeltaInSeconds) by Computer, src_ip, dst_ip, process_path
        | where count_ > TotalEventsThreshold 
        // comment out the next line if you don't want to filter out short-term beacons that aren't still active
        //| where count_ > datetime_diff("second", ago(endtime), min_TimeGenerated) / (avg_TimeDeltaInSeconds*2)
        | where StandardDeviation < StandardDeviationThreshold
        | where Duration >= DurationThreshold
        | order by StandardDeviation asc

### KQL Query for Hunting in Microsoft Defender for Endpoint


        let starttime = 2d; // Go back as many days as you want to look
        let endtime = 1m; // Usually you want to check up to the current time but set this if not
        let TimeDeltaThreshold = 2; // don't count anything under 2 seconds between connections
        let TotalEventsThreshold = 15; // only show beaconing that had at least this many connections
        let DurationThreshold = 1200; // only show beaconing that lasted at least this many seconds
        let StandardDeviationThreshold = 100; // Set to filter out false positives: lower number is tighter filtering/fewer results
        DeviceNetworkEvents
        | where RemoteIPType !in ("Reserved", "Private", "LinkLocal", "Loopback")
        | where isnotempty(RemoteIP) and RemoteIP !in ("0.0.0.0") 
        | where ActionType in ("ConnectionSuccess", "ConnectionRequest", "ConnectionFailed")
        | project TimeGenerated, DeviceId, DeviceName, InitiatingProcessFileName, LocalIP, LocalPort, RemoteIP, RemotePort
        | sort by LocalIP asc, RemoteIP asc, TimeGenerated asc
        | serialize
        | extend nextTimeGenerated = next(TimeGenerated, 1), nextDeviceId = next(DeviceId, 1), nextRemoteIP = next(RemoteIP, 1)
        | extend TimeDeltaInSeconds = datetime_diff("second", nextTimeGenerated, TimeGenerated)
        | where DeviceId == nextDeviceId and RemoteIP == nextRemoteIP
        | where TimeDeltaInSeconds > TimeDeltaThreshold
        | project TimeGenerated, TimeDeltaInSeconds, DeviceName, InitiatingProcessFileName, LocalIP, LocalPort, RemoteIP, RemotePort
        | summarize avg(TimeDeltaInSeconds), count(), min(TimeGenerated), max(TimeGenerated), Duration=datetime_diff("second", max(TimeGenerated), min(TimeGenerated)), StandardDeviation=stdev(TimeDeltaInSeconds), TimeDeltaList=make_list(TimeDeltaInSeconds) by DeviceName, LocalIP, RemoteIP, InitiatingProcessFileName
        | where count_ > TotalEventsThreshold 
        // comment out the next line if you don't want to filter out short-term beacons that aren't still active
        //| where count_ > datetime_diff("second", ago(endtime), min_TimeGenerated) / (avg_TimeDeltaInSeconds*2)
        | where StandardDeviation < StandardDeviationThreshold
        | where Duration >= DurationThreshold
        | order by StandardDeviation asc
        | extend HostCustomEntity = DeviceName
        | extend IPCustomEntity = RemoteIP
        | extend TimestampCustomEntity = max_TimeGenerated

## Time Series Analysis of Process Access (Sysmon Event ID 10)
- In practical testing with Cobalt Strike Beacon, something that the threat actor did caused the number of Process Access events (EID 10 in Sysmon) to jump from an average of 150 events per hour on a particular machine to over 30,000 EID 10 events in the timespan of 5 minutes. 
- The target_processes included firefox.exe, Teams, powershell, conhost, sihost, etc. and varied from about 600 events to over 5000 events per process, all in the same five minutes.


        let starttime = 30d;
        let endtime = 1d;
        let timeframe = 1h;
        let TotalEventsThreshold = 50;
        let TimeSeriesData = 
        Sysmon
        | where TimeGenerated between (startofday(ago(starttime))..startofday(ago(endtime)))
        | where EventID == 10
        | make-series PerHourCount=count() 
        on TimeGenerated from startofday(ago(starttime)) to startofday(ago(endtime)) 
        step timeframe by Computer;
        let TimeSeriesAlerts=TimeSeriesData
        | extend (anomalies, score, baseline) = series_decompose_anomalies(PerHourCount, 1.5, -1, 'linefit')
        | mv-expand PerHourCount to typeof(double), 
                    TimeGenerated to typeof(datetime), 
                    anomalies to typeof(double),
                    score to typeof(double), 
                    baseline to typeof(long)
        | where anomalies > 0
        | where score > 150
        | project Computer, TimeGenerated, PerHourCount, baseline, anomalies, score
        | where PerHourCount > TotalEventsThreshold;
        TimeSeriesAlerts
        | order by PerHourCount desc

## Detecting Exposed CS Team Servers in the Wild
- JARM hashing of live servers (DIY): https://github.com/salesforce/jarm
- List of JARM hashes for known servers: https://github.com/cedowens/C2-JARM  
- Shodan query for Cobalt Strike JARM: https://beta.shodan.io/search?query=ssl.jarm%3A07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1
- Nmap script to grab beacon configs from CS stagers: https://github.com/whickey-r7/grab_beacon_config/blob/main/grab_beacon_config.nse
- Over 70% of recent Beacon configs had Polling=60sec. 16% had polling=5sec
- Over 75% of recent Beacon configs had zero Jitter. 10% and 20% Jitter were the next most popular settings.
- Over 90% of recent Beacon configs had rundll32.exe as their spawn target for both x86 and x64. mstsc, gpupdate, mavinject, dllhost and werfault are other popular choices.

## Process Injection Patterns in Thread Start Address
- Expect this query to produce some false positives, especially Anti-Virus injecting into other processes. You'll need to filter those out.


        Sysmon
        | where EventID == 8
        | where binary_and(tolong(thread_start_address), 0xFFFF) < 0x1000
        | where process_path != target_process_path

## Default Named Pipe Patterns for Cobalt Strike Beacon as of Feb 2021
- Watch for these to change with new versions of CS
- Reference: https://blog.cobaltstrike.com/2021/02/09/learn-pipe-fitting-for-all-of-your-offense-projects/


        Sysmon
        | where EventID in (17,18)
        | where pipe_name has "\\postex_" 
        or pipe_name matches regex "MSSE-\\d+-server"
        or pipe_name matches regex "status_\\d+"
        or pipe_name matches regex "msagent_\\d+"
        | extend HostCustomEntity = Computer

## User Agent String Anomalies
- Profile your environment for normally observed user agents and alert on new ones that try to blend in but don't
- Pay attention to OS version and browser version (e.g. IE8 on Windows XP probably doesn't match your env!)
- The User Agents below were the most commonly observed settings in CS Beacon Configs (the number in front is the # of times that appeared)


        86 "User Agent": "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko"  
        66 "User Agent": "Windows-Update-Agent/10.0.10011.16384 Client-Protocol/1.40"
        64 "User Agent": "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko)” 
        50 "User Agent": "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0)"             
        40 "User Agent": "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.2; WOW64; Trident/6.0)"
        40 "User Agent": "Mozilla/5.0 (Windows NT 6.1; rv:24.0) Gecko/20100101 Firefox/24.0"
        37 "User Agent": "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; WOW64; Trident/5.0; BOIE9;ENUS)"
        35 "User Agent": "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; WOW64; Trident/5.0)"
        34 "User Agent": "Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/5.0)"
        32 "User Agent": "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)"
        29 "User Agent": "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; QQDownload 733; .NET CLR 2.0.50727)"
        28 "User Agent": "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.0; Trident/5.0)"
        28 "User Agent": "Mozilla/5.0 (compatible, MSIE 11, Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko"
        27 "User Agent": "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; WOW64; Trident/5.0; BOIE9;ENUSMSE)"
        27 "User Agent": "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.0; WOW64; Trident/5.0)"
        24 "User Agent": "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0) LBBROWSER"
        23 "User Agent": "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.2; Trident/6.0)"
        21 "User Agent": "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0; MALC)”
        20 "User Agent": "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.2; Win64; x64; Trident/6.0)"
        20 "User Agent": "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; Trident/4.0)"
        19 "User Agent": "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; WOW64; Trident/5.0; BOIE9;ENGB)"
        19 "User Agent": "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727)"

## Files Named as System Utilities Running from the Wrong Location
- Watch out for any executable file named the same as a legitimate system utility but running from the wrong location, not signed by Microsoft, or with the wrong file version information metadata

## System Utilities Renamed
- Watch out for any legitimate system utility (e.g. powershell.exe, mshta.exe) that has been copied elsewhere on the system and renamed. 
- Olaf Hartong wrote a great blog that explains this hunting technique very well: https://medium.com/falconforce/falconfriday-masquerading-lolbin-file-renaming-0xff0c-b01e0ab5a95d
