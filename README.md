**Splunk Enterprise JSON Failed Login Monitoring Lab**

## Introduction

This lab introduces the use of JSON log data within Splunk Enterprise for Security Operations Center (SOC) monitoring and analysis. JSON (JavaScript Object Notation) is one of the most common formats used by modern security products, cloud platforms, identity providers, firewalls, endpoint detection tools, and web applications.

In this lab, a JSON-based failed login dataset is created and ingested into Splunk Enterprise. Each JSON event represents a user authentication attempt containing fields such as timestamp, username, source IP address, login action, and authentication status. After uploading the dataset into Splunk, the analyst will learn how to search, filter, and analyze failed authentication events.

The purpose of this lab is to familiarize SOC analysts with JSON log structures, field extraction, security event investigation, brute-force detection, and user authentication monitoring. By completing this exercise, students gain practical experience working with one of the most widely used data formats in cybersecurity and cloud environments.

**Lab Objectives**

Upon completion of this lab, the analyst will be able to:

1.  Understand the structure of JSON log events.

2.  Create and validate a JSON dataset using Terminal.

3.  Upload JSON data into Splunk Enterprise.

4.  Search and analyze JSON-based security events.

5.  Identify failed login attempts.

6.  Investigate source IP addresses associated with failed logins.

7.  Monitor user authentication activity.

8.  Build foundational skills for future JSON-based SOC investigations.

**Dataset**

**File:** failed_logins.json

**Events:** Authentication Events

**Format:** JSON Lines (one JSON event per line)

**Source Type:** json_failed_logins

**Index:** auth

**Host:** MacBookPro

**SOC Use Cases**

This dataset can be used to investigate:

Failed login attempts\
Brute-force attacks\
Unauthorized access attempts\
Suspicious source IP addresses\
Account targeting\
Authentication anomalies\
User login trends

**Skills Practiced**

JSON Fundamentals\
Splunk Data Ingestion\
Security Monitoring\
Threat Hunting\
Authentication Analysis\
SOC Tier 1 Investigation\
Log Analysis\
Incident Detection

Failed login JSON dataset\
\
\
\
\
\
\
{"timestamp":"2026-06-18T10:00:00","user":"john","action":"login","status":"failed","src_ip":"8.8.8.8","host":"MacBookPro"}

{"timestamp":"2026-06-18T10:01:00","user":"mary","action":"login","status":"success","src_ip":"10.0.0.5","host":"MacBookPro"}

{"timestamp":"2026-06-18T10:02:00","user":"admin","action":"login","status":"failed","src_ip":"123.123.123.123","host":"MacBookPro"}

{"timestamp":"2026-06-18T10:03:00","user":"admin","action":"login","status":"failed","src_ip":"123.123.123.123","host":"MacBookPro"}

{"timestamp":"2026-06-18T10:04:00","user":"root","action":"login","status":"failed","src_ip":"45.33.32.156","host":"MacBookPro"}\
\
\
Testing

python3 -m json.tool failed_logins.json

\
\
\
\
\
\
\
Verifying the Dataset
----------------------------------------------------------------------------------------------------------------------------------------------------------------

Bash: cat failed_logins.json

Count events:

Bash: wc -l failed_logins.json

\
Validate Each Event
----------------------------------------------------------------------------------------------------------------------------------------------------------------

Bash: while read line; do\
echo "\$line" \| python3 -m json.tool \> /dev/null\
done \< failed_logins.json

\
\
\
\
\
\
\
\
\
\
\
\
\
\
Viewing Formatted Events
----------------------------------------------------------------------------------------------------------------------------------------------------------------

Bash: while read line; do\
echo "\$line" \| python3 -m json.tool\
done \< failed_logins.json

\
\
\
\
\
\
\
\
\
\
\
\
\
\
\
\
\
\
\
SOC Analyst Questions:
----------------------------------------------------------------------------------------------------------------------------------------------------------------

### How many events? Bash: wc -l failed_logins.json\
5 failed_logins.json

### \
Are there any users? Bash: grep -o '"user":"\[^"\]\*"' failed_logins.json

### "user":"john"

### "user":"mary"

### "user":"admin"

### "user":"admin"

### "user":"root"\
\
\
Are there any failed logins? Bash: grep '"status":"failed"' failed_logins.json

### {"timestamp":"2026-06-18T10:00:00","user":"john","action":"login","status":"failed","src_ip":"8.8.8.8","host":"MacBookPro"}

### {"timestamp":"2026-06-18T10:02:00","user":"admin","action":"login","status":"failed","src_ip":"123.123.123.123","host":"MacBookPro"}

### {"timestamp":"2026-06-18T10:03:00","user":"admin","action":"login","status":"failed","src_ip":"123.123.123.123","host":"MacBookPro"}

### {"timestamp":"2026-06-18T10:04:00","user":"root","action":"login","status":"failed","src_ip":"45.33.32.156","host":"MacBookPro"}

### \
\
How many Count failed logins? Bash: grep -c '"status":"failed"' failed_logins.json\
4

### \
Any IPs responsible for failed logins? Bash: grep '"status":"failed"' failed_logins.json

8.8.8.8\
123.123.123.123\
123.123.123.123\
45.33.32.156

\
\
\
Next Step: Splunk
-----------------

Uploading: failed_logins.json to Splunk Enterprise.

Index: auth\
Sourcetype: json_failed_logins\
Host: MacBookPro

Testing:

index=auth sourcetype=json_failed_logins

**Settings → Add Data → Upload → failed_logins.json**

Using:\
\
index = auth\
sourcetype = json_failed_logins\
host = MacBookPro

\
\
\
\
\
\
Search: source="failed_logins.json" host="MacBookPro" index="auth" sourcetype="\_json"

\
\
\
\
\
\
\
\
\
search: index=auth sourcetype="\_json"\
\
\
\
\
\
\
\
\
Search: index=auth sourcetype="\_json" status=failed \| stats count by user, src_ip\
\
\
\
\

| **user** | **src_ip**      | **count** |
|----------|-----------------|-----------|
| admin    | 123.123.123.123 | 2         |
| john     | 8.8.8.8         | 1         |
| root     | 45.33.32.156    | 1         |

### \_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\
\
**Which users attempted logins?**\

Search: index=auth sourcetype="\_json"\
\| stats count by user

\
\
**.** Which users attempted authentication?\
admin\
john\
mary\
root

### **Which login attempts failed?**

### \
Search: index=auth sourcetype="\_json" status=failed

### \| table timestamp user src_ip status

**\
\**
\
\
\
\
\**
Which authentication attempts failed?

| **timestamp**       | **user** | **src_ip**      | **status** |
|---------------------|----------|-----------------|------------|
| 2026-06-18T10:00:00 | john     | 8.8.8.8         | failed     |
| 2026-06-18T10:02:00 | admin    | 123.123.123.123 | failed     |
| 2026-06-18T10:03:00 | admin    | 123.123.123.123 | failed     |
| 2026-06-18T10:04:00 | root     | 45.33.32.156    | failed     |

### **How many failed logins occurred?**

Search: index=auth sourcetype="\_json" status=failed\
\| stats count as failed_logins

**\**
How many failed login events were recorded?

failed_logins = 4

### **Which source IP addresses generated failed logins?**

Search: index=auth sourcetype="\_json" status=failed\
\| stats count by src_ip\
\| sort -count

\
\**
Which source IP addresses generated failed login attempts?\
\
123.123.123.123\
45.33.32.156\
8.8.8.8

Which users experienced failed logins?\
\
Search: index=auth sourcetype="\_json" status=failed\
\| stats count by user\
\
\
\
\
Which users experienced failed logins?\
\
admin\
john\
root

### \
**Which IP address generated the most failed logins?**

Search: index=auth sourcetype="\_json" status=failed\
\| stats count by src_ip\
\| sort -count\
\| head 1

\
\
\
Which IP address generated the most failed logins?\
\
123.123.123.123

### \
**Which user account was targeted most frequently?**

Search: index=auth sourcetype="\_json" status=failed\
\| stats count by user\
\| sort -count\
\| head 1

\
Which user account was targeted most frequently?\
\
admin

### **Display all authentication events.**

Search: index=auth sourcetype="\_json"\
\| table timestamp user action status src_ip host\
\
\
\

**Panel 1**

index=auth sourcetype="\_json"\
\| stats count by status

Visualization: Pie Chart\
\
\
\
**Panel 2**

index=auth sourcetype="\_json" status=failed\
\| stats count by src_ip

Visualization: Bar Chart\
\
\
\
\
\
**Panel 3**

index=auth sourcetype="\_json"\
\| stats count by user

Visualization: Column Chart\
\
\
\
