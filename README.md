---
![ServiceNow Incident](screenshots/01-servicenow-incidents.png)

## Overview
This project demonstrates a realistic **SOC Tier 1** workflow using enterprise-grade tools commonly found in production environments.

The goal is to detect suspicious authentication activity in AWS, analyze it in a SIEM, and manage the incident lifecycle using ITSM processes.

---

## Stack
- **AWS**
  - IAM
  - CloudTrail
  - CloudWatch Logs
- **Splunk Enterprise (Windows)**
  - SPL-based detection
  - Alerting
- **ServiceNow (Developer Program)**
  - ITSM
  - Incident Management

### AWS CloudTrail enabled
CloudTrail is enabled to capture AWS ConsoleLogin events and send them to CloudWatch Logs.

![AWS CloudTrail](/assets/img/cloud-soc/02-cloudtrail-created.png)

### CloudWatch Logs
CloudTrail events are delivered to CloudWatch Logs for centralized collection.

![CloudWatch Logs](/assets/img/cloud-soc/03-cloudwatch-loggroup.png)

---

## Use case
Detection of **AWS ConsoleLogin brute force / noisy authentication** patterns:
- Multiple failed login attempts
- Followed by a successful authentication
- From the same source IP in a short time window

---

## Detection logic (Splunk)
The detection is based on AWS CloudTrail `ConsoleLogin` events.

Logic:
- Count consecutive authentication failures per source IP
- Trigger when a successful login occurs after multiple failures

### Splunk search results
AWS ConsoleLogin events are ingested into Splunk and validated by SOC L1.

![Splunk search](/assets/img/cloud-soc/05-splunk-consolelogin-detection.png)

Example SPL:

```spl
index=main sourcetype=aws:cloudtrail eventName=ConsoleLogin
| spath path=responseElements.ConsoleLogin output=consoleLogin
| eval is_fail=if(consoleLogin="Failure",1,0)
| streamstats sum(is_fail) as fail_count by sourceIPAddress
| where consoleLogin="Success" AND fail_count>=3
| eval identity=coalesce(userIdentity.userName, userIdentity.principalId, userIdentity.arn, "UNKNOWN")
| table _time sourceIPAddress identity fail_count userAgent additionalEventData.MFAUsed
| sort - _time
```

### Splunk alert
The detection is saved as a scheduled alert to notify SOC L1.

![Splunk alert](/assets/img/cloud-soc/06-splunk-alert-config.png)

---

## Alerting and triage

When the detection conditions are met, a Splunk alert is triggered and reviewed by SOC L1.

SOC L1 actions:
- Alert validation
- Review of CloudTrail authentication events
- Context analysis (source IP, user, MFA usage)
- Decision to escalate based on impact and risk

---

## Incident handling (ServiceNow ITSM)

When the alert is validated by SOC L1, an incident is created in ServiceNow ITSM and handled through the standard lifecycle:
- Categorization and prioritization (Impact + Urgency)
- Technical analysis documented in Work notes
- Escalation from SOC L1 to SOC L2 / Cloud Security
- Resolution and closure

### ServiceNow incident
After validation, a security incident is created in ServiceNow ITSM.

![ServiceNow incident](/assets/img/cloud-soc/01-servicenow-incidents.png)

---

## Evidence

Below is a real incident created in a ServiceNow Developer Program instance after validating the Splunk alert.

--- 

## Skills demonstrated

- SIEM alert triage and SPL-based detection
- AWS CloudTrail authentication log analysis
- ServiceNow ITSM Incident Management
- SOC Tier 1 operational workflows

---

## Scope

This project focuses on SOC Tier 1 responsibilities: detection, triage, documentation and escalation.
Containment and remediation actions are intentionally handled by SOC L2 / Cloud Security.

---
