# The Benji Protocol — Build Log

**Student Name:*Sikandar Ali Hussain*
**Student ID:*2323039*
**GitHub Repository:* https://github.com/sh10crt/benji-protocol-sh10crt*

---
24/04/2026 — Session A

What I built / changed:
Started working on log_parser.py to parse auth.log and extract login attempts.

What broke and how I fixed it:
Initially the script could not find the file due to incorrect path usage. Fixed by using full file path instead of relative path.

Decisions I made and why:
Used regex to extract timestamps, usernames, and IPs because logs are unstructured.

What the tool output when I ran it against Metasploitable:
Parsed login attempts successfully but showed a warning related to datetime parsing.

Questions or things to revisit:
Fix datetime warning for future Python versions.

24/04/2026 — Session B

What I built / changed:
Improved parsing logic and handled file input more reliably.

What broke and how I fixed it:
Datetime parsing warning appeared. Identified issue with missing year in logs.

Decisions I made and why:
Ignored warning for now since functionality is correct, will fix later if needed.

What the tool output when I ran it against Metasploitable:
Correctly extracted login attempts.

Questions or things to revisit:
Improve date parsing robustness.

## Week 2 — Task 2: Network Cartographer
24/04/2026 — Session A

What I built / changed:
Developed scan.py for port scanning and banner grabbing.

What broke and how I fixed it:
Script failed due to incorrect file path execution. Fixed by running from correct directory.

Decisions I made and why:
Used socket.connect_ex() for efficient port scanning and added banner grabbing for service identification.

Metasploitable scan output (paste key results):

{
  "target": "172.16.19.200",
  "open_ports": [21, 22, 80, 445, 631]
}

Observations — what services did you find? What do the banners tell you?
FTP (ProFTPD), SSH (OpenSSH), HTTP (Apache), SMB, and CUPS were running. SSH and FTP versions were outdated.

24/04/2026 — Session B

What I built / changed:
Added threading for faster scanning.

What broke and how I fixed it:
Some ports were missed initially due to timeout issues. Adjusted timeout settings.

Decisions I made and why:
Used threading to improve performance.

What the tool output when I ran it against Metasploitable:
Successfully detected all open ports with banners.

Questions or things to revisit:
Improve reliability of banner grabbing.

## Week 3 — Task 3: Access Validator
24/04/2026 — Session A

What I built / changed:
Worked on brute.py for SSH brute-force.

What broke and how I fixed it:
Wordlist file not found error. Fixed by using correct full file path.

Decisions I made and why:
Used paramiko for SSH authentication attempts.

What the tool output when I ran it against Metasploitable:
Initially failed due to incorrect file path.

Questions or things to revisit:
Improve error handling for file inputs.

24/04/2026 — Session B

What I built / changed:
Successfully executed brute-force attack.

What broke and how I fixed it:
No major issues after fixing path.

Decisions I made and why:
Stopped execution once valid credentials were found.

What the tool output when I ran it against Metasploitable:

[+] SUCCESS: Password found: fluffybunny

Questions or things to revisit:
Add logging for attempts.

## Week 4 — Task 4: Web Enumerator
24/04/2026 — Session A

What I built / changed:
Developed web_enum.py for HTTP enumeration.

What broke and how I fixed it:
Requests module issues fixed using virtual environment.

Decisions I made and why:
Used BeautifulSoup to extract HTML comments.

Metasploitable web recon output:
Apache/2.4.7 (Ubuntu)

HTML comments found:

s.lane username exposed
staging DB reference

Sensitive paths found:

/phpmyadmin (403)
24/04/2026 — Session B

What I built / changed:
Improved parsing of comments and paths.

What broke and how I fixed it:
Handled missing paths more cleanly.

Decisions I made and why:
Focused on extracting useful intelligence for exploitation.

## Week 5 — Vulnerability Hunt
Hunt Log

13:30 — Diagnosis phase:
Ran scan.py and web_enum.py. Identified open ports and username (s.lane).

13:40 — Vulnerability identified:
Weak SSH authentication with password login enabled.

13:50 — Exploit development:
Used brute.py to perform SSH brute-force.

13:55 — Flag retrieved:

14:05 — Remediation:
Ran fix.py to disable password authentication and harden SSH.

14:10 — Final commit and push:
All scripts tested and committed.

