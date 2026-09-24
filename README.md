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

## 2. Craqueo de credenciales (I1 — Weak/Hardcoded Passwords)

Dentro de `etc/shadow` encontré dos hashes en formato MD5 crypt (`$1$`), un esquema de hashing débil y anticuado:

```
root:$1$Jl7H1VOG$Wgw2F/C.nLNTC.4pwDa4H1:...
iotgoatuser:$1$79bz0K8z$Ii6Q/if83F1QodGmkb4Ah.:...
```

Diccionarios genéricos como `rockyou.txt` o listas de credenciales por defecto de fabricante no dieron resultado — tiene sentido, porque estas credenciales no son contraseñas "humanas" ni de panel web de router, sino del tipo que usa el malware **Mirai** para sus escaneos IoT. La lista completa real de credenciales Mirai está ofuscada con XOR dentro del código fuente filtrado del malware (`scanner.c`), así que escribí un pequeño script en Python para decodificarla y generar un diccionario dirigido:

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

Con las 60 credenciales decodificadas, extraje solo la columna de contraseñas y lancé John:

```bash
cut -d':' -f2 mirai_creds_decoded.txt | sort -u > mirai_passwords.txt
john --wordlist=mirai_passwords.txt hash.txt
```

Resultado:

```
7ujMko0vizxv     (iotgoatuser)
```

## 3. Puesta en marcha del entorno dinámico

El `.img` de Raspberry Pi es una imagen ARM y no puede ejecutarse en VirtualBox (que emula x86). Para el análisis dinámico (red, servicios, runtime) usé el artefacto que el propio proyecto ofrece para este propósito: **`IoTGoat-x86.vmdk`**.

Configuración de la VM en VirtualBox:
- Tipo: Linux, versión Linux 2.6/3.x/4.x (32-bit)
- **PAE/NX habilitado** (necesario para que arranque)
- Adaptador de red en modo **Host-only**, compartido con la máquina de Kali, para permitir el ataque entre ambas VMs (NAT las aísla entre sí)

Con ambas VMs en la misma red (`192.168.56.0/24`), confirmé conectividad y pasé al reconocimiento.

## 4. Reconocimiento de red

```bash
sudo nmap -p- --open -sS -sC -sV --min-rate 5000 -n -Pn -A 192.168.56.102
```

| Puerto | Servicio |
|---|---|
| 22/tcp | Dropbear SSH |
| 53/tcp | dnsmasq 2.73 |
| 80/tcp | LuCI (redirige a HTTPS) |
| 443/tcp | LuCI sobre TLS (cert autofirmado) |

SO detectado: OpenWrt 19.07 (Linux 4.14).

## 5. Acceso inicial vía SSH

```bash
ssh -o HostKeyAlgorithms=+ssh-rsa iotgoatuser@192.168.56.102
```

(El flag `HostKeyAlgorithms` es necesario porque Dropbear en firmware antiguo solo ofrece `ssh-rsa`, deshabilitado por defecto en clientes OpenSSH modernos.)

Login exitoso con la credencial craqueada en el paso 2. Acceso shell como `iotgoatuser`.

## 6. Enumeración post-explotación y descubrimiento del backdoor (I1)

El sistema corre BusyBox, con sintaxis reducida respecto a GNU coreutils (`ps w` en vez de `ps aux`, sin `sudo`, sin binarios SUID). La enumeración estándar (SUID, capabilities, cron, sudoers) no dio resultados.

Revisando los procesos activos:

```bash
ps w
```

Dos procesos llamaron la atención, ambos corriendo como root:

```
1671 root  668  S  /usr/bin/shellback
1685 root  1000 S  telnetd -p 65534
```

Ninguno de los dos apareció en el escaneo nmap inicial (falso negativo por el `--min-rate` agresivo, confirmado más tarde con un escaneo dirigido). `netstat -tlnp` sí los mostró escuchando en `0.0.0.0`.

Conectando directamente al puerto de `shellback`:

```bash
nc 127.0.0.1 5515
```

```
[***]Successfully Connected to IoTGoat's Backdoor[***]
```

El propio mensaje confirma la existencia de un backdoor intencionado. Dentro de esa sesión:

```
id
uid=0(root) gid=0(root)
```

**Acceso root confirmado**, sin necesidad de craquear el segundo hash.

Análisis del binario con `strings`:

```bash
strings /usr/bin/shellback
```

Las funciones importadas (`socket`, `bind`, `listen`, `accept`, `fork`, `dup2`, `execve`) describen un **bind shell clásico en C**: escucha en el puerto 5515, y al conectar redirige stdin/stdout/stderr hacia `/bin/busybox`, entregando una shell de root sin ningún tipo de autenticación adicional.

Revisé también la configuración de firewall (`/etc/config/firewall`, `/etc/firewall.user`) para descartar que el acceso al backdoor estuviera restringido por red — no lo estaba: la zona LAN acepta todo el tráfico entrante sin filtrar.

## 7. Componente desactualizado — dnsmasq 2.73 (I5)

Confirmé la versión de dnsmasq tanto en el análisis estático (opkg control file) como en el dinámico (banner `dns-nsid` de nmap):

```
Version: 2.73-1
```

Esta versión es vulnerable a varios CVEs críticos publicados en 2017:

| CVE | Tipo | CVSS |
|---|---|---|
| CVE-2017-14491 | Heap buffer overflow (respuestas DNS) | 9.8 |
| CVE-2017-14492 | Heap buffer overflow (IPv6 RA) | Alto |
| CVE-2017-14493 | Stack buffer overflow (DHCPv6) | 9.8 |
| CVE-2017-13704 | Crash por paquete UDP oversized | Medio |

Todos ellos permiten denegación de servicio remota sin autenticación, y potencialmente ejecución de código arbitrario, contra un servicio que en este dispositivo corre bajo el usuario `nobody`. No llegué a desarrollar un exploit funcional contra estos CVEs en esta sesión de práctica — el hallazgo queda documentado por versión + CVE público, que es evidencia suficiente para reportarlo con severidad crítica en un informe real.

## Resumen de la cadena de ataque

```
Extracción de firmware (binwalk)
        │
        ▼
Craqueo de credenciales — I1 (John + diccionario Mirai decodificado)
        │
        ▼
Montaje del entorno dinámico (VirtualBox, red host-only)
        │
        ▼
Reconocimiento de red (nmap) → dnsmasq 2.73 desactualizado — I5
        │
        ▼
Acceso inicial por SSH con credencial craqueada
        │
        ▼
Enumeración post-explotación → descubrimiento de backdoor — I1
        │
        ▼
Escalada a root vía backdoor (bind shell en puerto 5515)
```

## Conclusiones

IoTGoat es un buen ejercicio para practicar de punta a punta el ciclo de un pentest IoT: extracción y análisis de firmware, craqueo de credenciales con diccionarios especializados (no genéricos), configuración de un entorno de pruebas dinámico, y enumeración post-explotación en un sistema Linux embebido con herramientas limitadas (BusyBox). El hallazgo más interesante no fue el más "técnico" (el backdoor se descubre con enumeración básica de procesos), lo que refuerza que buena parte del valor de un pentest está en una enumeración metódica, no solo en explotar vulnerabilidades complejas.

---

*Practicado como preparación para la certificación VHL IoT Pentest.*