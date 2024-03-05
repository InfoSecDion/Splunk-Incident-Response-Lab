# Beyond the Breach: Splunk Strategies for Incident Response

I came across Splunk which is a famous SIEM tool used for monitoring and searching for anomalies and etc. and can be used to create report, visualizations and alerts. This is a common tool which is found in most Security Operations Centre (SOC) toolkit.

Based on the example in TryHackMe’s challenge “Incident Handling with Splunk”, I will share my thought process of investigating a cyber attack which has defaced the victim’s website named “imreallynotbatman.com”. The incident handling life cycle are as below:

![image](https://github.com/InfoSecDion/Splunk-Incident-Response-Lab/assets/105241007/105941c9-c232-4b21-a715-786efd7815b7)


Incident Handling Lifecyle. Picture taken from: https://swimlane.com/blog/the-role-of-preparation-and-process-in-incident-response/

As a SOC analyst, any incident should be handled in the above manner. For this example, we will start off the investigation under the “Detection and Analyst” phase.

To understand how an incident happened, we need to also think as an attacker’s point of view. And the best way to start is to break a problem into smaller problems. We will use the Cyber Kill Chain Phases as a guide.

To recap, the Cyber Kill Chain process are as below image:

![image](https://github.com/InfoSecDion/Splunk-Incident-Response-Lab/assets/105241007/fca03be0-37ba-46aa-b18a-95d5afe46396)


The Cyber Kill Chain model. The picture is taken from https://www.lockheedmartin.com/en-us/capabilities/cyber/cyber-kill-chain.html

The sequences just serve as a guide to show a flow which an attacker takes. But most of time, when doing investigation, its hard to follow the sequence as we might find the sequence out of order.

So, lets begin.

Data Sources
We are given a few data sources which has been monitoring the customer’s site. These are from the windows event logs, logs related to registry creation, sysmon event log, fornite firewall log, IIS web server log, results from the Nessus vulnerability scanner, details of alerts from Suricata IDS, network flow related to http traffic, DNS traffic and icmp traffic.

For easier access, all these data are stored in an index named botsv1, “index=botsv1”.

Phase 1- RECONNAISANCE
We are given all the data sources which could contain traces of attack from the attacker. We know that the webserver is targeted so we will start off with investigating the log sources covering network traffic. We do this in Splunk’s Search Head -> “index=botsv1 imreallynotbatman.com”. We are looking for any mention of the term “imreallynotbatman.com” in any of the logs.

The results does not show all the log sources but just a few of them. We can start with to investigate the IP address of the attacker. An attacker may perform the attack from the another IP address which is different to the IP which they use to perform reconnaisance. So, we will look for any patterns that could spark some clues.

We will perform search query “index=botsv1 imreallynotbatman.com sourcetype=stream:http” that has the traffic logs to find the source IP. This log has a field called “src_ip” which yields 2 IP address. One of it, 40.80.148.42 seems to has higher percentage of logs which makes it a prime suspect. We will examine the logs further and look at other fields in the logs such as “User-Agent, Pos-request and etc” for us to have a general feel of the that particular IP’s browsing activity.

With the general availability of scanning tools, an attacker might opt to use scanning tools like Nessus to get information. We can find this in the weblogs with “index=botsv1 imreallynotbatman.com src=40.80.148.42 sourcetype=suricata” . Suricata is an open-source based intrusion detection system and intrusion prevention system. It is able to relate any common attacks to the Common Vulnerabilities and Exposures (CVE) database. The IDS will detect these scanning attempts in the logs.

True enough, from poking around, we find that the attacker is using acunetix to perform the scanning attempts. And we found 1 Suricata alert that relates to the CVE-2014–6271. A quick Google search of this CVE value points that its vulnerability through the BASH.

![image](https://github.com/InfoSecDion/Splunk-Incident-Response-Lab/assets/105241007/2743bcef-fca2-4e42-9000-d375c27cf1ca)


Screenshot from https://nvd.nist.gov/vuln/detail/cve-2014-6271

Phase 4- EXPLOITATION
We jump to phase 4 as we want to find more traces of the attack in the log. Lets understand more about the source IP of the attack and our database IP.

We can find the number of requests by the IP aforementioned using “index=botsv1 imreallynotbatman.com sourcetype=stream* | stats count(src_ip) as Requests by src_ip | sort — Requests” . Here we are sorting downwards the requets by source ip and using Splunk’s stats command. We can create different visualization using Splunk’s visualization tab.

Next, lets move to investiage the inbound traffic to our database IP at 192.162.250.70 using the stream logs again with the command “index=botsv1 sourcetype=stream:http dest_ip=”192.168.250.70". We can find all HTTP action on our IP and by analyzing the field http_method using “index=botsv1 sourcetype=stream:http dest_ip=”192.168.250.70" http_method=POST” -> we can see that there are more POST request to our IP from the same suspected attacker’s IP. We cannot rule this as a suspicion yet as some web server may experience more POST request that GET request from normal traffic as it maybe a uploading site and etc. However, our client’s website serves just as a information website as per say so the unusually high POST request from a particular IP is suspicious.

Being a webserver, most of time the attacker will attempt to gain access into the Content Management System (CMS). In this project, the client uses Joomla and the default admin login page for a Joomla CMS is “/joomla/administrator/index.php”. Lets investirage the request sent to this login portal using “index=botsv1 imreallynotbatman.com sourcetype=stream:http dest_ip=”192.168.250.70" uri=”/joomla/administrator/index.php” . We deep further into the “form_data” field of the joomla uri to see patterns of log activity and table them using “index=botsv1 sourcetype=stream:http dest_ip=”192.168.250.70" http_method=POST uri=”/joomla/administrator/index.php” | table _time uri src_ip dest_ip form_data”. We can further display the log that contain only username and password in the form data filed by using Splunk’s Regex function using “index=botsv1 sourcetype=stream:http dest_ip=”192.168.250.70" http_method=POST form_data=*username*passwd* | rex field=form_data “passwd=(?<creds>\w+)” | table src_ip creds”. The results multiple different password being used for the same username “admin” which indicates a brute-force attack being performed.

Next, lets find the method which the attacker performed this brute force attack using “index=botsv1 sourcetype=stream:http dest_ip=”192.168.250.70" http_method=POST form_data=*username*passwd* | rex field=form_data “passwd=(?<creds>\w+)” |table _time src_ip uri http_user_agent creds”. We can see the the suspected IP has 1 password attemt from Mozilla browser and hundreds of login request using a python script. This indicates that the attacker used another IP to perform the brute force attack and a different IP to input the correct login combination to access the webserver.

Phase 5 — INSTALLATION
We know from previous phase that the attacker has managed to access the Joomla CMS system. A normal pattern is that the attacker will install a backdoor or an application for persistance or to further control the system.

Now, we will try to find out what program/payload was uploaded to the server for the attacker to attack the system. A common program has an extension “.exe” and we will find any program with this extension using the query “index=botsv1 sourcetype=stream:http dest_ip=”192.168.250.70" *.exe”. The results does not show the file name filed but we can search All Fields and we see that the field “part_filename{}” which is of particular interest. Here we see 2 results which is “3791.exe” and “agent.php”.

Lets see if any of these results originated from the suspected’s attacker IP of “40.80.148.42”. And voila! Using the field “c_ip” , we can see that it does indeed originate from the attacker’s IP.

Next, lets figure if this file was executed in the webserver. To do that, lets investigate the whole logs using “index=botsv1 “3791.exe”. We find traces in the sysmon, WinEventlog and fortigate_utm. Sysmon is a System Monitor (Sysmon) which is a Windows system service and device driver that, once installed on a system, remains resident across system reboots to monitor and log system activity to the Windows event log.

Sysmon gives results based of event code and by searching in Splunk using “index=botsv1 “3791.exe” sourcetype=”XmlWinEventLog” EventCode=1", we see that Event ID 1 : Process Creation is traced in the logs which indicates the file was executed on the server.

Phase 7 — ACTION ON OBJECTIVES
Earlier phase investigation showed that a malicious program was executed on the webserver. Here, we will investigate what did the program did on the webserver. We will start with the method of examining the IDS log which is Suricata and all IP address communicating with the webserver.

By checking the inbound and outbound communication, we notice that there is unusually high outbound traffic to external IP addresses. We can see the kind of communication that is happening on one of these IP address using “index=botsv1 src=192.168.250.70 sourcetype=suricata dest_ip=23.22.63.114” . We find that there is a .jpeg file in the results. Lets dig deeper into the source of the .jpeg file using “index=botsv1 url=”/poisonivy-is-coming-for-you-batman.jpeg” dest_ip=”192.168.250.70" | table _time src dest_ip http.hostname url”. The resulting table show that the .jpeg file was downloaded from “prankglassinebracket.jumpingcrab.com”.

Phase 6 — COMMAND AND CONTROL (C2)
We have noticed that the attacker used Dynamic DNS to hide their tracks. Dynamic DNS keeps DNS records automatically up to date when an IP address changes.

To get more information of the IP address changes, we will examine the network logs such as firewall logs. This system uses fortigate as a firewall solution. Lets find any log entries that contain the .jpg file mentions using “index=botsv1 sourcetype=fortigate_utm”poisonivy-is-coming-for-you-batman.jpeg” ”. The “url” field shows the domain name of “prankglassinebracket.jumpingcrab.com” and we can also verify this finding in the stream:http log files.

So, we can rule that the domain name of “prankglassinebracket.jumpingcrab.com” is the Command and Control server.

Phase 2 — WEAPONIZATION
We have identified a domain which acts as the C2 server. But lets move back to phase 2. We know that the attacker would need to create malware files or create similar domain name websites to trick the users. From the domain which we have identified, we can search into OSINT sites to get more information about our attackers.

There is sites such as Robtex which provides info about IP add, domain name and subdomains of the “prankglassinebracket.jumpingcrab.com”. Another source of information which we can dive further is the IP address of “23.22.63.114”. Upon investirgation, we find that this IP is associated with similar name sounding websites such as our customer’s site.

Another website which we can use is Virustotal. Upon searching for that IP address, we can see once again all domain associated with it and 1 particular domain stood out which is “www.po1s0n1vy.com’ .

We can get whois information on that site on whois.domaintools.com.

Phase 3 — DELIVERY
A typical flow of attacker mindset is once they have done the weaponization phase, they would find a way to send it to the user’s devices. We will use Threat Hunting Platform and OSINT situe to find any common malware linked with the attacker.

Threatminer leads us to results of 3 files which is associated with this IP with a hash value. Upon searching for the hash value on Virustotal, we find more info about that malware. We can also use Hybrid-Analysis to see the behaviour analysis of any malware.

CONCLUSION
In this post, we have explored using Splunk to gain knowledge of how an attack happened to what happened during an attack. Splunk is a useful tool due to its powerful search query function and ability to analyse common security related logs. By combining Splunk and our own intuitive incident response knowledge, this makes the whole process of incident response smoother.
