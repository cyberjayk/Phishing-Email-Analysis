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
<br />
<br />
Viewing the Raw .eml File in Sublime Text to Inspect Email Headers:  <br/>
<img width="1630" height="653" alt="sublopeningemail" src="https://github.com/user-attachments/assets/68a2f7e7-d1c4-46a5-b235-7c7cbe3739e0" />
<br />
<br />
Enter the number of passes: <br/>
<img src="https://i.imgur.com/nCIbXbg.png" height="80%" width="80%" alt="Disk Sanitization Steps"/>
<br />
<br />
Confirm your selection:  <br/>
<img src="https://i.imgur.com/cdFHBiU.png" height="80%" width="80%" alt="Disk Sanitization Steps"/>
<br />
<br />
Wait for process to complete (may take some time):  <br/>
<img src="https://i.imgur.com/JL945Ga.png" height="80%" width="80%" alt="Disk Sanitization Steps"/>
<br />
<br />
Sanitization complete:  <br/>
<img src="https://i.imgur.com/K71yaM2.png" height="80%" width="80%" alt="Disk Sanitization Steps"/>
<br />
<br />
Observe the wiped disk:  <br/>
<img src="https://i.imgur.com/AeZkvFQ.png" height="80%" width="80%" alt="Disk Sanitization Steps"/>
</p>
