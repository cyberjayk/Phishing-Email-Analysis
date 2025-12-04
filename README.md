# Phishing-Email-Analysis

## Objective
The objective of this project was to perform a full phishing email investigation using real-world analyst methodologies. This included analyzing email headers, identifying malicious indicators of compromise (IOCs), decoding embedded payloads, conducting URL reputation checks, and producing a structured incident report.
This project replicates the workflow used by SOC analysts during email-based threat investigations.

### Skills Learned
  * Email header analysis (Return-Path, SPF, DKIM, DMARC, Received chain)

  * Identifying sender spoofing and display-name impersonation

  * Extracting and decoding base64-encoded email bodies

  * URL reputation analysis using URLScan.io and VirusTotal

  * Conducting reverse DNS lookups and WHOIS enrichment

  * Understanding phishing infrastructure and credential-harvesting patterns

  * Writing clear, actionable incident documentation and reporting

### Tools Used
  * Ubuntu Terminal (nslookup, whois)

  * Sublime Text for viewing .eml files with header colorization

  * CyberChef for decoding base64 and extracting embedded URLs

  * URLScan.io for reputation scanning and infrastructure analysis

  * VirusTotal for multi-engine URL analysis




## Project Walk Through
<p align="center">
The suspicious email we're analyzing: <br/>
<img width="858" height="937" alt="email_itself" src="https://github.com/user-attachments/assets/198a9a23-a0d8-41cf-b853-6883199c118e" />
 
This screenshot shows the original email as received by the user. It appears to impersonate the Microsoft Support Team and claims the user’s account has been flagged for unusual activity. The vague urgency, generic greeting, and mismatched sender address are all early indicators of a phishing attempt.
<br />
<br />
<br />
<br />

Viewing the Raw .eml File in Sublime Text to Inspect Email Headers:  <br/>
<img width="1239" height="841" alt="Screenshot 2025-12-03 222834" src="https://github.com/user-attachments/assets/7d8bcdf5-af34-482b-abee-a7ba104d26cf" />

The phishing email was opened in Sublime Text using the .eml file format to view the full message headers and underlying metadata. Inspecting the raw source provides visibility into sender information, authentication results, and hidden HTML content that is not shown in normal email clients.

<br />
<br />
<br />
<br />

Finding the headers: <br/>
<img width="659" height="239" alt="emailheader" src="https://github.com/user-attachments/assets/8e120c21-98e1-44bc-8360-716cf4bcc20d" />

This screenshot highlights the key header fields such as From, Return-Path, Message-ID, and Date—used to validate the legitimacy of the sender. These fields are crucial for tracing the origin of the message and identifying spoofing or relay abuse.
<br />
<br />
Analyzing mail flow and authentication results (SPF, DKIM, DMARC):  <br/>
<img width="698" height="155" alt="mail flow and authentication analysis" src="https://github.com/user-attachments/assets/3da1f61e-73f0-4b50-9914-daf7a5e2e4c6" />

The authentication results show that while SPF and DKIM passed, they passed for the wrong domain, indicating that the attacker used a legitimate mail server (Outlook) but did not send from a legitimate Microsoft-owned domain. CompAuth/DMARC results further highlight inconsistencies that reinforce the phishing classification.
<br />
<br />
Performing a reverse DNS lookup on the sender's IP address:  <br/>
<img width="1215" height="573" alt="reverse dns lookup fail" src="https://github.com/user-attachments/assets/a6604d21-3257-448e-9310-8555c9c046e7" />

A reverse DNS lookup was attempted on the sender’s IP (40.107.22.60) to resolve the hostname. The lookup returned SERVFAIL, indicating that the PTR record could not be retrieved. This step demonstrates an attempt to validate whether the mail originated from an expected domain. Failure to resolve the hostname is a common artifact of phishing campaigns.
<br />
<br />
Querying the SPF record of the senders domain using nslookup:  <br/>
<img width="1219" height="179" alt="domainSPFrecordlookup" src="https://github.com/user-attachments/assets/c7405be0-a301-4ff7-85cc-55039a73b803" />

Using nslookup -type=txt helwan.edu.eg, the SPF record for the sender’s domain was retrieved. The record (v=spf1 include:spf.protection.outlook.com -all) shows that the domain authorizes Outlook mail servers to send on its behalf. This finding confirms that the attacker likely abused a compromised mailbox or tenant rather than spoofing the domain directly.
<br />
<br />
Decoding the email's base64 encoded HTML body using the CyberChef tool:  <br/>
<img width="1273" height="1032" alt="cyberchef" src="https://github.com/user-attachments/assets/66815a61-8417-4b2d-8180-e42a042ce90d" />
<br />
<br />
Submitting the extracted URL to URLScan.io for reputation and behavioral analysis:  <br/>
<img width="1253" height="708" alt="urlscan io" src="https://github.com/user-attachments/assets/ac8fb4ee-6539-40a0-ba56-bf9daee84ffd" />
<br />
<br />
Reviewing URLScan's JSON output showing the failed request:  <br/>
<img width="760" height="217" alt="jsonblock_errorfail" src="https://github.com/user-attachments/assets/ba2a0219-11b8-4e47-8d52-c275fadabb5e" />
<br />
<br />
Analyzing the phishing URL using VirusTotal's multi-engine scanner :  <br/>
<img width="1255" height="610" alt="virustotal" src="https://github.com/user-attachments/assets/0eb634f9-cf10-4992-b4e2-ade4affd4298" />
<br />
<br />
Phishing investigation report summarizing all findings:  <br/>
<img width="665" height="1142" alt="documentation_report" src="https://github.com/user-attachments/assets/38832843-fb38-433e-b051-f3221940ae00" />
</p>
