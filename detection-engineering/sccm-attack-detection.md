# Microsoft Configuration Manager (SCCM/MECM) Threat Detection KQL Queries for Azure Monitor / Microsoft Sentinel

The following Kusto Query Language (KQL) queries can be used to monitor administrative activities performed within Microsoft Configuration Manager (ConfigMgr/SCCM). These events help detect unauthorized administrative changes, suspicious deployments, privilege escalation, and remote administration activities.

---

# 1. Security → New Security Role Created

**Purpose**

Detects when a new Configuration Manager security role is created.

```kql
// New Security Role Created

Event
| where EventLog == "ConfigurationManager"
| where EventID == 31200
| extend ParsedData = tostring(parse_xml(EventData))
| extend Administrator = extractjson("$['DataItem']['EventData']['Data'][1]", ParsedData)
| extend SecurityRoleName = extractjson("$['DataItem']['EventData']['Data'][2]", ParsedData)
| project
    TimeGenerated,
    Administrator,
    SecurityRoleName,
    Computer
```

---

# 2. Applications → New Application Deployment

**Purpose**

Detects deployment of a new application to a collection.

```kql
// New Application Deployment

Event
| where EventLog == "ConfigurationManager"
| where EventID == 30226
| extend ParsedData = tostring(parse_xml(EventData))
| extend Administrator = extractjson("$['DataItem']['EventData']['Data'][1]", ParsedData)
| extend Application = extractjson("$['DataItem']['EventData']['Data'][2]", ParsedData)
| extend Collection = extractjson("$['DataItem']['EventData']['Data'][3]", ParsedData)
| project
    TimeGenerated,
    Administrator,
    Application,
    Collection,
    Computer
```

---

# 3. Operating System Deployment → Task Sequence Modified

**Purpose**

Detects modifications to an Operating System Deployment (OSD) task sequence.

```kql
// Task Sequence Modified

Event
| where EventLog == "ConfigurationManager"
| where EventID == 30001
| extend ParsedData = tostring(parse_xml(EventData))
| extend Administrator = extractjson("$['DataItem']['EventData']['Data'][1]", ParsedData)
| extend TaskSequenceID = extractjson("$['DataItem']['EventData']['Data'][2]", ParsedData)
| extend TaskSequenceName = extractjson("$['DataItem']['EventData']['Data'][3]", ParsedData)
| project
    TimeGenerated,
    Administrator,
    TaskSequenceID,
    TaskSequenceName,
    Computer
```

---

# 4. Remote Control → Session Started

**Purpose**

Detects when a Remote Control session is initiated.

```kql
// Remote Control Session Started

Event
| where EventLog == "ConfigurationManager"
| where EventID == 30076
| extend ParsedData = tostring(parse_xml(EventData))
| extend Administrator = extractjson("$['DataItem']['EventData']['Data'][1]", ParsedData)
| extend SourceComputer = extractjson("$['DataItem']['EventData']['Data'][2]", ParsedData)
| extend TargetComputer = extractjson("$['DataItem']['EventData']['Data'][3]", ParsedData)
| extend ProcessID = extractjson("$['DataItem']['EventData']['Data'][4]", ParsedData)
| extend ThreadID = extractjson("$['DataItem']['EventData']['Data'][5]", ParsedData)
| project
    TimeGenerated,
    Administrator,
    SourceComputer,
    TargetComputer,
    ProcessID,
    ThreadID,
    Computer
```

---

# 5. Remote Control → Session Ended

**Purpose**

Detects when a Remote Control session ends.

```kql
// Remote Control Session Ended

Event
| where EventLog == "ConfigurationManager"
| where EventID == 30077
| extend ParsedData = tostring(parse_xml(EventData))
| extend Administrator = extractjson("$['DataItem']['EventData']['Data'][1]", ParsedData)
| extend SourceComputer = extractjson("$['DataItem']['EventData']['Data'][2]", ParsedData)
| extend TargetComputer = extractjson("$['DataItem']['EventData']['Data'][3]", ParsedData)
| extend ProcessID = extractjson("$['DataItem']['EventData']['Data'][4]", ParsedData)
| extend ThreadID = extractjson("$['DataItem']['EventData']['Data'][5]", ParsedData)
| project
    TimeGenerated,
    Administrator,
    SourceComputer,
    TargetComputer,
    ProcessID,
    ThreadID,
    Computer
```

---

# 6. Site Configuration → Client Settings Modified

**Purpose**

Detects changes made to Configuration Manager Client Settings.

```kql
// Client Settings Modified

Event
| where EventLog == "ConfigurationManager"
| where EventID == 30043
| extend ParsedData = tostring(parse_xml(EventData))
| extend Administrator = extractjson("$['DataItem']['EventData']['Data'][1]", ParsedData)
| extend ClientSettingName = extractjson("$['DataItem']['EventData']['Data'][2]", ParsedData)
| project
    TimeGenerated,
    Administrator,
    ClientSettingName,
    Computer
```

---

# 7. Site Configuration → Primary Site Settings Modified

**Purpose**

Detects changes to Primary Site configuration.

```kql
// Primary Site Settings Modified

Event
| where EventLog == "ConfigurationManager"
| where EventID == 30031
| extend ParsedData = tostring(parse_xml(EventData))
| extend Administrator = extractjson("$['DataItem']['EventData']['Data'][1]", ParsedData)
| extend SiteName = extractjson("$['DataItem']['EventData']['Data'][2]", ParsedData)
| project
    TimeGenerated,
    Administrator,
    SiteName,
    Computer
```

---

# Security Monitoring Recommendations

These detections should be configured as Microsoft Sentinel analytics rules with the following settings:

| Detection | Severity | MITRE ATT&CK |
|-----------|----------|--------------|
| New Security Role Created | High | T1098 – Account Manipulation |
| Application Deployment | Medium | T1608 – Stage Capabilities |
| Task Sequence Modified | High | T1562 – Impair Defenses |
| Remote Control Session Started | High | T1021 – Remote Services |
| Remote Control Session Ended | Informational | Audit Trail |
| Client Settings Modified | High | T1562 – Modify Security Controls |
| Primary Site Settings Modified | High | T1484 – Domain or Trust Modification |

## Best Practices

- Enable Microsoft Sentinel analytics rules for each query.
- Generate incidents only for successful administrative actions.
- Create automation rules to notify the SOC team.
- Correlate Configuration Manager events with Microsoft Entra ID sign-in logs.
- Correlate administrator identities with Privileged Identity Management (PIM) activation events.
- Enrich alerts with device information from Microsoft Defender for Endpoint.
- Maintain a baseline of approved administrators and approved maintenance windows to reduce false positives.
- Configure alert suppression for planned maintenance activities while preserving audit logs.
