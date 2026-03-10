
<p align="center">

<img width="1536" height="1024" alt="image" src="https://github.com/user-attachments/assets/acf272e4-3a5e-458c-ac8e-8f5be657f767" />

</p>




# 🛡️ Threat Hunt Report – The-Helpdesk-Deception-11-08-25


---

## 📌 Scenario

A routine support request should have ended with a reset and reassurance. Instead, the so-called “help” left behind a trail of anomalies that don’t add up.

What was framed as troubleshooting looked more like an audit of the system itself — probing, cataloging, leaving subtle traces in its wake. Actions chained together in suspicious sequence: first gaining a foothold, then expanding reach, then preparing to linger long after the session ended.

And just when the activity should have raised questions, a neat explanation appeared — a story planted in plain sight, designed to justify the very behavior that demanded scrutiny.

This wasn’t remote assistance. It was a misdirection.

Your mission this time is to reconstruct the timeline, connect the scattered remnants of this “support session”, and decide what was legitimate, and what was staged.

The evidence is here. The question is whether you’ll see through the story or believe it.


---

## 🧭 Scope & Environment

- **Analyst:**  Shane Baker-Oropeza 
- **Environment:**  Microsoft - Log Analytics Workspace (LAW - Cyber Range)  
- **Timeframe:**  2025-10-01 → 2025-10-15
- **Attack Type:** Fake Remote Session/Malicious Help Desk

---

## 📚 Table of Contents

- [🧠 Preparation](#-Preparation)
- [🔍 Flag Analysis](#-flag-analysis)
  - [🚩 Flag 1](#-flag-1)
  - [🚩 Flag 2](#-flag-2)
  - [🚩 Flag 3](#-flag-3)
  - [🚩 Flag 4](#-flag-4)
  - [🚩 Flag 5](#-flag-5)
  - [🚩 Flag 6](#-flag-6)
  - [🚩 Flag 7](#-flag-7)
  - [🚩 Flag 8](#-flag-8)
  - [🚩 Flag 9](#-flag-9)
  - [🚩 Flag 10](#-flag-10)
  - [🚩 Flag 11](#-flag-11)
  - [🚩 Flag 12](#-flag-12)
  - [🚩 Flag 13](#-flag-13)
  - [🚩 Flag 14](#-flag-14)
  - [🚩 Flag 15](#-flag-15)
- [🧬 MITRE ATT&CK Summary](#-mitre-attck-summary)
- [🚨 Detection Gaps & Recommendations](#-detection-gaps--recommendations)
- [🧾 Final Assessment](#-final-assessment)

---

# 🧠 Preparation

<img width="655" height="304" alt="image" src="https://github.com/user-attachments/assets/b1c16415-33c4-43fb-a771-b5595fb8b812" />

<img width="644" height="140" alt="image" src="https://github.com/user-attachments/assets/de5b5080-0279-4099-99fc-db3620b8673e" />


---

### KQL Query Used

```
let start = datetime(2025-10-01);
let end   = datetime(2025-10-15);
DeviceFileEvents
| where TimeGenerated between (datetime(2025-10-01) .. datetime(2025-10-15))
| where FileName has_any ("desk", "help", "support", "tool")
| project TimeGenerated, ActionType, DeviceName, FileName, FolderPath, InitiatingProcessAccountDomain, 
InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine
| order by TimeGenerated desc

```
- I decided to look in DeviceFileEvents since there were indications that malicious activity was originating from the Downloads folders.
- I decided to look at a specified timeframe that started on 2025-10-01 till 2025-10-15.
- I looked for the keywords "desk", "help", "support" and "tool" in any of the file folders.
- I projected specific columns that would narrow down the information given and help me to focus on specific areas.
- I found the DeviceName gab-intern-vm and I also found the suspicious FileName Support_701.txt.

---

<img width="1860" height="408" alt="image" src="https://github.com/user-attachments/assets/87485515-b1db-4cda-995c-bcd47fdd9667" />
</p>

- This allowed me to answer the starting question and allow me to proceed to the first flag.
</p>


<img width="650" height="140" alt="image" src="https://github.com/user-attachments/assets/1b112c27-6bf0-4346-a77a-abce35d8f262" />
</p>


## 🔍 Flag Analysis

_All flags below are collapsible for readability._

---


<summary id="-flag-1">🚩 <strong>Flag 1: <Technique Name></strong></summary>

# **Detection and Analysis**

# Flag 1 - Initial Execution Detection  
[Table of Contents](#table-of-contents)

<img width="644" height="382" alt="image" src="https://github.com/user-attachments/assets/c5200be3-2446-41b8-b505-9a6f87da9547" />
<img width="647" height="168" alt="image" src="https://github.com/user-attachments/assets/f8712f19-b257-471d-a4b7-9a68d2c9e203" />


- I used the table `DeviceProcessEvents` in order to examine the logs.

- For Flag 1 I was looking for the earliest anomalous execution.

- When I read atypical script or interactive command activity, I started to think about Powershell and added that as a query parameter.

- I also was able to add the `AccountName` of `g4bri3lintern` as a new query parameter.

`"What was the first CLI (command line interface) parameter name used during the execution of the suspicious program?"`

- The earliest anomalous execution of powershell being executed was `2025-10-06T06:00:48.7549551Z`

### KQL Query Used
```
//---------------FLAG 1-----------------------
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-10-01) .. datetime(2025-10-15)) 
| where DeviceName == "gab-intern-vm"
| where AccountName == "g4bri3lintern"
| where FileName == "powershell.exe"
| project TimeGenerated, DeviceName, AccountName, ActionType, FileName, FolderPath, ProcessCommandLine, InitiatingProcessCommandLine, InitiatingProcessFileName 
```



<img width="1842" height="351" alt="image" src="https://github.com/user-attachments/assets/ce9d4aab-438b-40d0-b68e-2927f1b9cbfa" />


- After looking at the log activity for powershell executables I saw the first CLI parameter was set to `-ExecutionPolicy`.  

- This also occurred for a powershell.exe process called `SupportTool.ps1` on `2025-10-09T12:22:27.6588913Z`

- I was able to answer Flag 1 with the CLI parameter.

<img width="646" height="165" alt="Screenshot 2026-03-03 231743" src="https://github.com/user-attachments/assets/00c1500b-5181-4884-9455-3f6c1038f282" />

	
---------------------------------------------------

		
<summary id="-flag-2">🚩 <strong>Flag 2: <Technique Name></strong></summary>

# Flag 2 - Defense Disabling 
[Table of Contents](#table-of-contents)

<img width="649" height="515" alt="image" src="https://github.com/user-attachments/assets/f7a2e02e-7e2c-422e-b685-6dd506f9a365" />




- I decided to use the `DeviceFileEvents` table since I was looking for a file related to the exploit.

- I looked for any files containing the word Artifact in the `FileName` column.



### KQL Query Used
```
//---------------FLAG 2-----------------------
DeviceFileEvents
| where TimeGenerated between (datetime(2025-10-01) .. datetime(2025-10-15)) 
| where DeviceName == "gab-intern-vm"
| where FileName contains "Artifact"
| project TimeGenerated, DeviceName, InitiatingProcessAccountName, ActionType, FileName, FolderPath, InitiatingProcessCommandLine, InitiatingProcessFileName 
| order by TimeGenerated desc
```


- I saw the filename `DefenderTamperArtifact.lnk` and believed this to be the file related to the exploit.
  
</p>
  
<img width="1740" height="175" alt="image" src="https://github.com/user-attachments/assets/bcc95414-e44d-417b-a307-4ab80c5c0bd2" />

</p>

- I was able to answer Flag 2 with the filename `DefenderTamperArtifact.lnk`.
  
</p>

<img width="646" height="147" alt="image" src="https://github.com/user-attachments/assets/169db8cd-e2a2-4000-a1e9-bc1e4f53a3db" />

</p>


---------------------------------------------------



<summary id="-flag-3">🚩 <strong>Flag 3: <Technique Name></strong></summary>

# Flag 3 - Quick Data Probe 
[Table of Contents](#table-of-contents)

<img width="650" height="555" alt="image" src="https://github.com/user-attachments/assets/5c7b7f54-5b1e-4d0f-b1e9-39513d2c6aaf" />



- For this flag I looked under the `DeviceFileEvents` table.

- I decided to check the `InitiateProcessCommandLine` column for any mention of the word `clip`.






### KQL Query Used
```
//---------------FLAG 3-----------------------
DeviceFileEvents
| where TimeGenerated between (datetime(2025-10-01) .. datetime(2025-10-15)) 
| where DeviceName == "gab-intern-vm"
| where InitiatingProcessCommandLine contains "clip"
| project TimeGenerated, DeviceName, InitiatingProcessAccountName, ActionType, FileName, FolderPath, InitiatingProcessCommandLine, InitiatingProcessFileName 
| order by TimeGenerated desc
```

- After querying for the results, I found the `InitiatingProcessCommandLine` that contained the script "powershell.exe" -NoProfile -Sta -Command "try { Get-Clipboard | Out-Null } catch { }"

</p>

<img width="1777" height="382" alt="image" src="https://github.com/user-attachments/assets/ca5f45d7-311c-4267-a6e9-7d265121b652" />

</p>

- I was able to answer Flag 3 with the script `"powershell.exe" -NoProfile -Sta -Command "try { Get-Clipboard | Out-Null } catch { }"`.

</p>

<img width="647" height="139" alt="image" src="https://github.com/user-attachments/assets/16230e50-bb3d-4d5c-bab2-369a653f3fd5" />

</p>

---------------------------------------------------


<summary id="-flag-4">🚩 <strong>Flag 4: <Technique Name></strong></summary>

# Flag 4 - Host Context Recon 
[Table of Contents](#table-of-contents)

<img width="647" height="492" alt="image" src="https://github.com/user-attachments/assets/de42c069-7646-4681-a4cb-c6340f5ce3ed" />



- I started my search in the `DeviceProcessEvents` query table.

- I added the query of `Filename` contains "qwi" to narrow down my search..


### KQL Query Used

```
//---------------FLAG 4-----------------------
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-10-01) .. datetime(2025-10-15)) 
| where DeviceName == "gab-intern-vm"
| where AccountName == "g4bri3lintern"
| where FileName contains "qwi"
| project TimeGenerated, DeviceName, AccountName, ActionType, FileName, FolderPath, ProcessCommandLine, InitiatingProcessCommandLine, InitiatingProcessFileName 
| order by TimeGenerated desc
```
<img width="1398" height="159" alt="image" src="https://github.com/user-attachments/assets/18b913be-edd4-42e4-a128-2ed9652d9d8e" />

</p>

- I saw that there was a query session with the `FileName` of `qwinsta.exe`, which included the "qwi" that I was looking for.

- I was able to answer Flag 4 with the last recon attempt time using the `FileName` of `qwinsta.exe` at `2025-10-09T12:51:44.3425653Z`.

</p>

<img width="640" height="141" alt="image" src="https://github.com/user-attachments/assets/3c6826e9-5d68-4d16-8764-504c22763a03" />

</p>



---------------------------------------------------
	

<summary id="-flag-5">🚩 <strong>Flag 5: <Technique Name></strong></summary>

# Flag 5 - Storage Surface Mapping 
[Table of Contents](#table-of-contents)

<img width="648" height="494" alt="image" src="https://github.com/user-attachments/assets/2ed24206-93e8-492d-ab82-cd4529cb0f5d" />


- I decide to look under the `DeviceProcessEvents` table to look for a command that had to deal with "storage".

- Regarding the previous query, I noticed that the "cmd.exe" command was used in the `InitiatingProcessCommandLine`.

- I adjusted my search to look for `FileName` that contained "cmd".
  
- I noticed the `wmic` command included in the `ProcessCommandLine` along with 'logicaldisk` at 2025-10-09T12:51:18.3848072Z.

- `Wmic` is a legitimate Windows tool that attackers use to blend in with normal administrative activity and avoid detection by basic antivirus.

- "Logicaldisk` is used to query Windows for information about a computer's local drives.


### KQL Query Used

```
//---------------FLAG 5-----------------------
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-10-01) .. datetime(2025-10-15)) 
| where DeviceName == "gab-intern-vm"
| where AccountName == "g4bri3lintern"
| where FileName contains "cmd"
| project TimeGenerated, DeviceName, AccountName, ActionType, FileName, FolderPath, ProcessCommandLine, InitiatingProcessCommandLine, InitiatingProcessFileName 
| order by TimeGenerated desc
```

</p>

<img width="1773" height="458" alt="image" src="https://github.com/user-attachments/assets/bde3b3c5-08ae-4324-93eb-55505b51fc89" />

</p>

<img width="1780" height="440" alt="image" src="https://github.com/user-attachments/assets/95f04046-f3d1-4a0d-bf6c-30bd7ae5c4f6" />

</p>

- I was able to answer Flag 5 by using the `ProcessCommandLine` string `"cmd.exe" /c wmic logicaldisk get name,freespace,size`.

</p>

<img width="643" height="140" alt="image" src="https://github.com/user-attachments/assets/a8995cca-fd52-42ec-8b7b-e3e4dd8d96ad" />

</p>

---------------------------------------------------

	
<summary id="-flag-6">🚩 <strong>Flag 6: <Technique Name></strong></summary>

# Flag 6 - Connectivity & Name Resolution Check 
[Table of Contents](#table-of-contents)

<img width="645" height="492" alt="image" src="https://github.com/user-attachments/assets/4c6fe7e5-536d-471b-968e-9036d82c3e6d" />


- I decided to look under the `DeviceNetworkEvents` table since the clue had to do with network events.

- I made sure to stay focused on October 9th 2025 during the time of `12:50-1:00 PM` from the previous flag activity. 

- Since the clue hinted at "session", I began to look for successful connections and included this `ActionType` in my query.

- I started my search looking under the `InitiatingProcessParentFileName` column for filename that would answer the flag question.

- I also narrowed down my search to focus on unusual PowerShell activity.


### KQL Query Used

```
//---------------FLAG 6-----------------------
DeviceNetworkEvents
| where TimeGenerated between (datetime(2025-10-09 12:50) .. datetime(2025-10-09 13:00)) 
| where DeviceName == "gab-intern-vm"
| where InitiatingProcessAccountName == "g4bri3lintern"
| where ActionType == "ConnectionSuccess"
| project TimeGenerated, DeviceName, InitiatingProcessAccountName, ActionType, InitiatingProcessParentFileName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, RemoteIP, RemotePort, Protocol
| order by TimeGenerated desc
```
</p>

<img width="2087" height="268" alt="image" src="https://github.com/user-attachments/assets/97d3d16e-31cc-4e74-bbfa-72f71b7611d2" />

</p>

- I was able to answer Flag 6 by using the `InitiatingProcessParentFileName` of `RuntimeBroker.exe`.

</p>

<img width="647" height="140" alt="image" src="https://github.com/user-attachments/assets/4235502c-374b-4285-8d54-24a1c34f13f4" />

</p>
	
---------------------------------------------------

	
<summary id="-flag-7">🚩 <strong>Flag 7: <Technique Name></strong></summary>

# Flag 7 - Interactive Session Discovery 
[Table of Contents](#table-of-contents)

<img width="648" height="456" alt="image" src="https://github.com/user-attachments/assets/47e89f1d-c073-498b-990c-f7bf6dd8d81f" />


- Since this had to do with sessions, I used the `DeviceNetworkEvents` table to start my query.

- The question asked "What is the unique ID of the initiating process?", so I added the `InitiatingProcessUniqueId` to my query.

- I kept all the rest of the fields and looked at the results from the previous flag.

</p>

 
### KQL Query Used

```
//---------------FLAG 7-----------------------
DeviceNetworkEvents
| where TimeGenerated between (datetime(2025-10-09 12:50) .. datetime(2025-10-09 13:00)) 
| where DeviceName == "gab-intern-vm"
| where InitiatingProcessAccountName == "g4bri3lintern"
| where ActionType == "ConnectionSuccess"
| project TimeGenerated, DeviceName, InitiatingProcessAccountName, ActionType, InitiatingProcessUniqueId, InitiatingProcessParentFileName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, RemoteIP, RemotePort, Protocol
| order by TimeGenerated desc
```

</p>

<img width="2104" height="261" alt="image" src="https://github.com/user-attachments/assets/950768d9-4464-457e-99e2-fcad4476f22c" />


</p>

- I was able to answer this flag with the `InitiatingProcessUniqueId` of `2533274790397065`

</p>

<img width="643" height="142" alt="image" src="https://github.com/user-attachments/assets/e7ad9d88-e482-478d-8034-5bb009a42b8e" />

</p>
	
---------------------------------------------------


<summary id="-flag-8">🚩 <strong>Flag 8: <Technique Name></strong></summary>

# Flag 8 - Runtime Application Inventory 
[Table of Contents](#table-of-contents)

<img width="651" height="538" alt="image" src="https://github.com/user-attachments/assets/a3939a43-dc51-41ef-adf2-bb314475b069" />

</p>

- I started my search under `DeviceProcessEvents` since I was tasked with searching running applications and services.
- I was given the following hints to conduct my search:
1. `Task
2. `List
3. `Last
- I added the specific query of `Filename` contains "task"
- This narrowed down my query results to 3 and I was able to easily see the pertinent `FileName` of `tasklist.exe`.


</p>

<img width="1774" height="170" alt="image" src="https://github.com/user-attachments/assets/4ef6e0c6-f3dc-4d7c-b240-45fb7f6bd60e" />

 </p>

### KQL Query Used

```
//---------------FLAG 8-----------------------
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-10-09 12:50) .. datetime(2025-10-09 13:00))
| where DeviceName == "gab-intern-vm"
| where AccountName == "g4bri3lintern"
| where FileName contains "task"
| project TimeGenerated, DeviceName, AccountName, ActionType, FileName, FolderPath, ProcessCommandLine, InitiatingProcessCommandLine, InitiatingProcessFileName 
| order by TimeGenerated desc
```

</p>

- I was able to answer this flag with the `FileName` of `tasklist.exe`.

</p>

<img width="647" height="166" alt="image" src="https://github.com/user-attachments/assets/ce67fccd-73c4-4385-82b8-2c81ef44162f" />

	
---------------------------------------------------

	
<summary id="-flag-9">🚩 <strong>Flag 9: <Technique Name></strong></summary>

# Flag 9 - Privilege Surface Check 
[Table of Contents](#table-of-contents)

<img width="647" height="476" alt="image" src="https://github.com/user-attachments/assets/2e406449-80f7-4516-8712-cb5491cdb453" />

- I continued to search under the `DeviceProcessEvents` table, but I added a couple of query strings to narrow it down.

- I added the `ProcessCommandLine` contains "who".

- I then proceeded to the specific time of the very first attempt and found the timestamp of `2025-10-09T12:52:14.3135459Z`.

</p>




### KQL Query Used

```
//---------------FLAG 9-----------------------
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-10-09 12:50) .. datetime(2025-10-15 13:00))
| where DeviceName == "gab-intern-vm"
| where AccountName == "g4bri3lintern"
| where ProcessCommandLine contains "who"
| project TimeGenerated, DeviceName, AccountName, ActionType, FileName, FolderPath, ProcessCommandLine, InitiatingProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCreationTime
| order by TimeGenerated desc
```

</p>

<img width="2026" height="310" alt="image" src="https://github.com/user-attachments/assets/081dbca6-4b1b-467c-ab97-521a250490b2" />


</p>

- I was able to answer this flag with the timestamp of `2025-10-09T12:52:14.3135459Z`.

</p>

<img width="644" height="136" alt="image" src="https://github.com/user-attachments/assets/67caec1e-582d-457b-a7bd-8ce37bb2aa11" />

	
---------------------------------------------------


<summary id="-flag-10">🚩 <strong>Flag 10: <Technique Name></strong></summary>

# Flag 10 - Proof-of-Access & Egress Validation 
[Table of Contents](#table-of-contents)

<img width="647" height="532" alt="image" src="https://github.com/user-attachments/assets/420e9f3b-eae2-4b79-94e6-26a768c9fa1f" />



- Since I was looking for evidence of outbound reachability, I started my search under the `DeviceNetworkEvents` table.

- I was looking for successful connection attempts, so I added the `ActionType == "ConnectionSuccess"` query.

- I also wanted to see the outbound destination, so I added the `RemoteUrl` column to the query.

</p>

### KQL Query Used

```
//---------------FLAG 10-----------------------
DeviceNetworkEvents
| where TimeGenerated between (datetime(2025-10-09 12:50) .. datetime(2025-10-09 13:00))
| where DeviceName == "gab-intern-vm"
| where InitiatingProcessAccountName == "g4bri3lintern"
| where ActionType == "ConnectionSuccess"
| project TimeGenerated, InitiatingProcessAccountName, ActionType, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl
| order by TimeGenerated desc
```
</p>

<img width="1385" height="256" alt="image" src="https://github.com/user-attachments/assets/3b280760-47b2-4ead-81ce-cb93b261dc1a" />

</p>

- I saw that there was a "powershell.exe" command under the `InitiatingProcessCommandLine'.
  
- I looked under the `RemoteUrl` column and saw an outbound connection to "www.msftconnecttest.com".

- I was able to answer this flag by determining that "www.msftconnecttest.com" was the first outbound destination contacted.

</p>

<img width="639" height="138" alt="image" src="https://github.com/user-attachments/assets/e4d3a054-f9bc-4f91-804e-7946e944736e" />


	

---------------------------------------------------

<summary id="-flag-11">🚩 <strong>Flag 11: <Technique Name></strong></summary>

# Flag 11 - Bundling / Staging Artifacts 
[Table of Contents](#table-of-contents)

<img width="647" height="511" alt="image" src="https://github.com/user-attachments/assets/e9d02096-1752-47b1-9e98-08d289987efb" />


- I decide to search in the `DeviceFileEvents` table since I was tasked with looking for file system events or operations.

- I added the `FileName` and `FolderPath` to my projected columns.


### KQL Query Used

```
//---------------FLAG 11-----------------------
DeviceFileEvents
| where TimeGenerated between (datetime(2025-10-09 12:50) .. datetime(2025-10-09 13:00))
| where DeviceName == "gab-intern-vm"
| where InitiatingProcessAccountName == "g4bri3lintern"
| project TimeGenerated, ActionType, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, FileName, FolderPath
| order by TimeGenerated desc
```
</p>
- I saw that the "powershell.exe" was used for a `FileName` of `ReconArtifacts.zip`.

</p>

<img width="1685" height="345" alt="image" src="https://github.com/user-attachments/assets/488624a1-d3f7-44b7-84f9-a3065249b6de" />

</p>

- I looked under the `FolderPath` for that log and found `C:\Users\Public\ReconArtifacts.zip`.

- I was able to answer the flag with `C:\Users\Public\ReconArtifacts.zip`.

</p>

<img width="644" height="143" alt="image" src="https://github.com/user-attachments/assets/6ba19658-47d9-4057-908e-1fa74efa8626" />

</p>


---------------------------------------------------

<summary id="-flag-12">🚩 <strong>Flag 12: <Technique Name></strong></summary>

# Flag 12 - Outbound Transfer Attempt 
[Table of Contents](#table-of-contents)

</p>

<img width="643" height="513" alt="image" src="https://github.com/user-attachments/assets/91fa3ebb-56fe-47bf-a1c6-831049195c28" />

</p>

- I started my search under the `DeviceNetworkEvents` table since I was looking for network events.

- I added the `InitiatingProcessFileName == "powershell.exe"` to narrow down my search.

- I also added the columns of `RemoteUrl` and `RemoteIp` to my query projection.

</p>

---------------------------------------------------
### KQL Query Used

```
//---------------FLAG 12-----------------------
DeviceNetworkEvents
| where TimeGenerated between (datetime(2025-10-09) .. datetime(2025-10-10))
| where DeviceName == "gab-intern-vm"
| where InitiatingProcessAccountName == "g4bri3lintern"
| where InitiatingProcessFileName == "powershell.exe"
| project TimeGenerated, InitiatingProcessAccountName, ActionType, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP
| order by TimeGenerated desc
```

</p>

<img width="1536" height="176" alt="image" src="https://github.com/user-attachments/assets/0272a638-7b02-4730-a09d-e5f34bcf9b52" />

</p>

- I was able to answer the flag with the `RemoteIP` of `100.29.147.161`.

</p>

<img width="643" height="141" alt="image" src="https://github.com/user-attachments/assets/138102c8-7670-4db5-9063-8d6619f64182" />


</p>

---------------------------------------------------

<summary id="-flag-13">🚩 <strong>Flag 13: <Technique Name></strong></summary>

# Flag 13 - Scheduled Re-Execution Persistence
[Table of Contents](#table-of-contents)

<img width="652" height="475" alt="image" src="https://github.com/user-attachments/assets/6aafbb84-b116-4a92-93ef-d799b5b68f8f" />

- I started my search looking under the `DeviceProcessEvents` table since I was looking for a process or scheduler-related events.

- I made sure I had the `InitiatingProcessFileName == "powershell.exe"` in my query.





### KQL Query Used

```
//---------------FLAG 13-----------------------
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-10-09) .. datetime(2025-10-10))
| where DeviceName == "gab-intern-vm"
| where AccountName == "g4bri3lintern"
| where InitiatingProcessFileName == "powershell.exe"
| project TimeGenerated, AccountName, ActionType, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName
```
- I noticed the "schtasks.exe" under the `FileName` column.

- I looked under the `ProcessCommandLine` and found the named of the task I was supposed to be looking for.

<img width="2172" height="410" alt="image" src="https://github.com/user-attachments/assets/3652a1c9-413c-496a-b90c-4ca071d85281" />

</p>

- I answered the flag with the task name of `SupportToolUpdater'.

</p>

<img width="643" height="140" alt="image" src="https://github.com/user-attachments/assets/093ac785-9dc4-4fa5-b50f-5513d90fce3c" />



---------------------------------------------------

<summary id="-flag-14">🚩 <strong>Flag 14: <Technique Name></strong></summary>

# Flag 14 - Autorun Fallback Persistence
[Table of Contents](#table-of-contents)

<img width="647" height="553" alt="image" src="https://github.com/user-attachments/assets/48a4dd89-d841-4a6c-a2d9-4fc00c25f98c" />

</p>

- The table `RemoteAssistUpdater` did not return anything.

</p>

 <img width="641" height="137" alt="image" src="https://github.com/user-attachments/assets/551c2364-6e3b-46dc-be9a-49a50087342d" />



---------------------------------------------------

<summary id="-flag-15">🚩 <strong>Flag 15: <Technique Name></strong></summary>

# Flag 15 - Planted Narrative / Cover Artifact
[Table of Contents](#table-of-contents)

<img width="645" height="513" alt="image" src="https://github.com/user-attachments/assets/6716f36d-1d3e-4f69-953d-6f3fb592514d" />



- I started my search in the `DeviceFileEvents` table since I was looking for explanatory files or user-facing artifacts.

- I kept my query search time around the time of the original event and added 5 minutes `TimeGenerated between (datetime(2025-10-09 12:50) .. datetime(2025-10-09 13:05))`.

- I was looking for a file that was created for the artifact to be left behind, so I added the query string `| where ActionType == "FileCreated"`.

</p>


### KQL Query Used

```
//---------------FLAG 15-----------------------
DeviceFileEvents
| where TimeGenerated between (datetime(2025-10-09 12:50) .. datetime(2025-10-09 13:05))
| where DeviceName == "gab-intern-vm"
| where InitiatingProcessAccountName == "g4bri3lintern"
| where ActionType == "FileCreated"
| project TimeGenerated, ActionType, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, FileName, FolderPath
| order by TimeGenerated desc
```

</p>

<img width="1709" height="379" alt="image" src="https://github.com/user-attachments/assets/5077389c-897b-482e-8982-3681ada6a3cc" />


</p>

- I saw that there was a `FileName` of `SupportChat_log.lnk` created at `2025-10-09T13:02:41.5698148Z`.

- I used the filename of `SupportChat_log.lnk` to answer the flag.

</p>

<img width="642" height="142" alt="image" src="https://github.com/user-attachments/assets/f7c9f23b-932f-4895-a980-1d0da25f17fc" />


</p>

---------------------------------------------------


## 🧬 MITRE ATT&CK Summary

# Flags → MITRE ATT&CK Mapping Table
[Table of Contents](#table-of-contents)

| Time Stamp - UTC             | **Flag #** | **Flag Title**                       | **Observed Activity**                                                                                                                                                        | **MITRE ATT&CK Technique**                                 | **Technique ID**      |
| ---------------------------- | ---------- | ------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------- | --------------------- |
| 2025-10-09T12:22:27.6588913Z | **1**      | Initial Execution Detection          | PowerShell execution using         <br><br>`-ExecutionPolicy`                                                                                                                | Command & Scripting Interpreter: PowerShell                | **T1059.001**         |
| 2025-10-09T12:34:59.1260624Z | **2**      | Defense Disabling Indicator          | Creation of malicious file <br><br>`DefenderTamperArtifact.lnk`                                                                                                              | Defense Evasion: Masquerading / Indirect Execution via LNK | **T1036 / T1204.002** |
| 2025-10-09T12:50:40.0325062Z | **3**      | Quick Data Probe                     | Clipboard access using  <br>`"powershell.exe" -NoProfile -Sta -Command "try { Get-Clipboard \| Out-Null } catch { }"`<br><br>                                                | Input Capture: Clipboard Data                              | **T1115**             |
| 2025-10-09T12:51:44.3272076Z | **4**      | Host Context Recon                   | Session enumeration (`qwinsta.exe`)<br><br>`InitiatingProcessCommandLine`<br>`"cmd.exe" /c query session `<br><br>`Time Generated`<br>`2025-10-09T12:51:44.3272076Z`<br><br> | Account Discovery / System Owner-User Discovery            | **T1087 / T1033**     |
| 2025-10-09T12:51:18.3848072Z | **5**      | Storage Surface Mapping              | Disk/volume enumeration via <br><br>`"cmd.exe" /c wmic logicaldisk get name,freespace,size`<br><br>                                                                          | System Information Discovery                               | **T1082**             |
| 2025-10-09T12:55:05.7658713Z | **6**      | Connectivity & Name Resolution Check | Outbound DNS / connectivity testing via PowerShell <br><br>`RuntimeBroker.exe`<br><br>                                                                                       | Application Layer Protocol / DNS                           | **T1071 / T1071.004** |
| 2025-10-09T12:51:44.3081129Z | **7**      | Interactive Session Discovery        | Interactive session state checked (`query session`)<br><br>`InitiatingProcessUniqueId`<br><br>`2533274790397065`<br><br>                                                     | System Information Discovery / Remote Services Discovery   | **T1082 / T1035**     |
| 2025-10-09T12:51:57.6866149Z | **8**      | Runtime Application Inventory        | Process listing using <br><br>`tasklist.exe`<br><br>                                                                                                                         | Process Discovery                                          | **T1057**             |
| 2025-10-09T12:52:14.3135459Z | **9**      | Privilege Surface Check              | Privilege/user enumeration <br>(`whoami /priv`, `/groups`)<br><br>`TimeGenerated`<br>`2025-10-09T12:52:14.3135459Z`<br><br><br>                                              | Permission Group Discovery                                 | **T1069**             |
| 2025-10-09T12:55:05.7658713Z | **10**     | Proof-of-Access & Egress Validation  | Outbound contact to <br><br>`msftconnecttest.com`                                                                                                                            | Exfiltration Test / Application Layer Protocol             | **T1041 / T1071**     |
| 2025-10-09T12:58:17.4364257Z | **11**     | Bundling / Staging Artifacts         | Staging of `ReconArtifacts.zip` in Public directory folderpath<br><br>`C:\Users\Public\ReconArtifacts.zip`<br><br>                                                           | Archive Collected Data                                     | **T1560**             |
| 2025-10-09T13:00:40.045127Z  | **12**     | Outbound Transfer Attempt            | Outbound HTTP traffic to <br><br>`100.29.147.161`<br><br>                                                                                                                    | Exfiltration Over Web Services                             | **T1567.002**         |
| 2025-10-09T13:01:29.7815532Z | **13**     | Scheduled Re-Execution Persistence   | Scheduled Task: <br><br>`SupportToolUpdater`                                                                                                                                 | Scheduled Task/Job: Scheduled Task                         | **T1053.005**         |
|-----------N/A----------      | **14**     | Autorun Fallback Persistence         | Registry persistence value <br><br>`RemoteAssistUpdater`<br><br>                                                                                                             | Registry Run Keys / Startup Folder                         | **T1547.001**         |
| 2025-10-09T13:02:41.5698148Z | **15**     | Planted Narrative / Cover Artifact   | Fake support file: <br><br>`SupportChat_log.lnk`                                                                                                                             | Masquerading (Fake File / Cover Story)                     | **T1036**             |


---------------------------------------------------


# Summary of ATT&CK Categories Used
[Table of Contents](#table-of-contents)

| Category                          | Techniques Used            |
| --------------------------------- | -------------------------- |
| **Execution**                     | T1059.001                  |
| **Defense Evasion**               | T1036, T1204.002           |
| **Credential Access**             | T1115                      |
| **Discovery**                     | T1033, T1082, T1057, T1069 |
| **Lateral Movement Prep / Recon** | T1035                      |
| **Command & Control / Network**   | T1071, T1071.004           |
| **Collection**                    | T1560                      |
| **Exfiltration**                  | T1041, T1567.002           |
| **Persistence**                   | T1053.005, T1547.001       |


---------------------------------------------------
---

## 🚨 Detection Gaps & Recommendations

### Observed Gaps
- I need to start broad and then narrow down.  If you start too narrow, you can miss important clues.
- I found that when I copied the text from the logs and pasted it for the flag answer, it would not work.  I had to type the answer manually.
- Each table has different columns that are displayed.  Learn the difference between `InitiatingProcessAccountName` and `AccountName` when searching different tables.

### Recommendations
- Start broad with your query search.  Whether it be with dates and times or just taking 10 logs to see the different columns available.
- Type the flag answers manually.
- Learn the different columns available for the different query tables.

---

## 🧾 Final Assessment

# Final Notes
[Table of Contents](#table-of-contents)

This incident simulated a realistic multi-stage intrusion:

- Initial foothold
- Reconnaissance
- Privilege assessment
- Local staging
- Persistence
- Attempted exfiltration
- Narrative manipulation

And every step was traceable using **Log Analytics KQL**, primarily through:

- `DeviceProcessEvents`
- `DeviceFileEvents`
- `DeviceNetworkEvents`



---------------------------------------------------



- Evidence reproducible via advanced hunting  
- Techniques mapped directly to MITRE ATT&CK  

---
