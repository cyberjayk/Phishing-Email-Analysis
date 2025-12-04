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
<img src="width="858" height="937" alt="email_itself" src="https://github.com/user-attachments/assets/a17f70e7-054f-4432-a6bc-4755845e707e"/>
<br />
<br />
