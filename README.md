# Production-Grade AI SOC Triage & Adaptive Feedback Pipeline

An automated Tier-1/Tier-2 SOC triage pipeline that ingests Windows Sysmon telemetry via Wazuh EDR, triggers custom MITRE ATT&CK detection rules, dispatches high-severity alerts to a FastAPI triage engine, and renders structured incident rationales and forensic IOCs inside an adaptive human-in-the-loop analyst console.

---

## System Architecture

```text
[Windows 11 Endpoint]
       │
       │ (Sysmon EventChannel: Process Create / EID 1)
       ▼
[Wazuh Manager (v4.x)]
       │
       │ (local_rules.xml: Rule 100100 Level 10 / MITRE T1059.001)
       ▼
[Wazuh Integratord Daemon]
       │
       │ (integrations/custom-ai-triage -> HTTP POST)
       ▼
[FastAPI AI Triage Backend (:5000)]
       ├── Context & IOC Extraction (CommandLine, PID, Parent Process, Hashes)
       ├── SQLite Environment Memory (Few-Shot Pattern Store)
       └── Triage Heuristic / LLM Synthesis Engine
       │
       ▼
[SOC Triage Console (Tailwind CSS)]
       ├── Collapsible Incident Drawers (MITRE Mapping, Verdict, Recommendations)
       └── Continuous Learning Loop ("Allowlist" / "Confirm Malicious")


**Repository Structure**

├── app/
│   ├── server.py              # FastAPI webhook & adaptive memory engine
│   └── templates/
│       └── dashboard.html     # Tailwind SOC incident command console
├── integrations/
│   └── custom-ai-triage       # Wazuh integrator forwarding script
├── rules/
│   └── local_rules.xml        # Custom MITRE ATT&CK detection rules
├── .gitignore
├── requirements.txt
└── README.md

**Setup & Deployment Guide**

Windows Endpoint Configuration
Install Sysmon with SwiftOnSecurity baseline:


Invoke-WebRequest -Uri "[https://live.sysinternals.com/Sysmon64.exe](https://live.sysinternals.com/Sysmon64.exe)" -OutFile "$env:TEMP\Sysmon64.exe"
Invoke-WebRequest -Uri "[https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml](https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml)" -OutFile "$env:TEMP\sysmonconfig.xml"
& "$env:TEMP\Sysmon64.exe" -accepteula -i "$env:TEMP\sysmonconfig.xml"


**Configure Wazuh Agent Ingestion:**

Append the Microsoft-Windows-Sysmon/Operational event channel into C:\Program Files (x86)\ossec-agent\ossec.conf:

<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>

**Restart Agent Service:**

Restart-Service -Name WazuhSvc

**Wazuh Manager Configuration**

Deploy Detection Rules:
Copy rules/local_rules.xml to /var/ossec/etc/rules/local_rules.xml on the Wazuh server:

<rule id="100100" level="10">
  <if_group>sysmon_event1</if_group>
  <field name="win.eventdata.image">powershell.exe$|pwsh.exe$</field>
  <field name="win.eventdata.commandLine">-enc|-encodedcommand|downloadstring|iex|invoke-expression</field>
  <description>Suspicious PowerShell execution detected (Obfuscation / Download Cradle)</description>
  <mitre>
    <id>T1059.001</id>
  </mitre>
</rule>

**Deploy Integrator Dispatcher:**

Place integrations/custom-ai-triage in /var/ossec/integrations/custom-ai-triage:

chmod 750 /var/ossec/integrations/custom-ai-triage
chown root:wazuh /var/ossec/integrations/custom-ai-triage


**Configure Alert Forwarding:**

In /var/ossec/etc/ossec.conf, add inside <ossec_config>:

<integration>
  <name>custom-ai-triage</name>
  <hook_url>[http://127.0.0.1:5000/webhook/wazuh](http://127.0.0.1:5000/webhook/wazuh)</hook_url>
  <level>10</level>
  <alert_format>json</alert_format>
</integration>

**Restart Wazuh Manager:**

systemctl restart wazuh-manager

**AI Triage Console Deployment**

Set Up Python Environment:

python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

**Launch Console Server:**

uvicorn app.server:app --host 0.0.0.0 --port 5000 --reload

----------------------------------

Open http://<MANAGER_IP>:5000 to access the SOC command console.

**Verification & Testing**

**Verification & Testing**

Trigger High-Severity Alert on Windows:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Invoke-Expression 'Write-Output Testing-SOC-Pipeline'"
------------------------------------------

**Incident Triage & Analysis:**

The event flows through Sysmon -> Wazuh Manager -> wazuh-integratord -> FastAPI Webhook.

Click anywhere on the incident row in the console to expand the drawer and inspect:

AI Triage Rationale & Confidence Score.

MITRE ATT&CK Tactics and Techniques.

Forensic Artifacts: User Account, PID, Parent Image, Parent Command Line, and SHA256 hashes.

**Continuous Learning Loop:**

Click Allowlist to train the environment memory store.

Subsequent executions of the pattern are automatically recognized as False Positive (Allowlisted) with 99% confidence.
'''

![SOC Dashboard Overview](https://github.com/user-attachments/assets/ce5ebc9f-fca8-4f94-a3f0-5d29ae896068)

![Incident Forensics & IOC Drawer](https://github.com/user-attachments/assets/cf48ab45-aa86-4e28-baae-10813d412065)
