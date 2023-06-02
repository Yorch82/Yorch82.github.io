---
title: HTB - Active
published: true
categories: [Windows]
tags: [OSCP, OSEP, AD, Fácil]
---


<img src="/assets/HTB/Active/active.png">


¡Hola!
Vamos a resolver de la máquina `Active` de dificultad "Fácil" de la plataforma [HackTheBox](https://hackthebox.com/).

Técnicas Vistas: 

- **SMB Enumeration**
- **Abusing GPP Passwords**
- **Decrypting GPP Passwords - gpp-decrypt**
- **Kerberoasting Attack (GetUserSPNs.py) [Privilege Escalation]**

### Preparación Entorno

* * *

Antes de iniciar la fase de enumeración y reconocimiento procederemos a crear un directorio de trabajo con el nombre `Active`. Una vez creado accedemos al directorio y con la ayuda de la función que tenemos definida en la zshrc `mkt` crearemos cuatro directorios de trabajo `nmap, content, exploits y scripts` donde almacenaremos de una manera ordenada toda la información que vayamos recopilando de la máquina en función de su naturaleza.

```bash
function mkt(){
    mkdir {nmap,content,exploits,scripts}
}
```

### Enumeración

* * *

## Nmap

Accedemos al directorio de trabajo `nmap` e iniciamos nuestra fase de reconocimiento realizando un `ping` a la IP de la máquina para comprobar que esté activa y detectamos su sistema operativo basándonos en el `ttl` de una traza **ICMP**.

```bash
❯ ping -c 1 10.10.10.175
PING 10.10.10.175 (10.10.10.175) 56(84) bytes of data.
64 bytes from 10.10.10.175: icmp_seq=1 ttl=127 time=37.6 ms

--- 10.10.10.175 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 37.594/37.594/37.594/0.000 ms
```
Identificamos que es una maquina **Windows** debido a su ttl (time to live) correspondiente a 127 (Disminuye en 1 debido a que realiza un salto adicional en el entorno de HackTHeBox).

* TTL => 64 Linux
* TTL => 128 Windows

Continuamos con la enumeración de los **65535** puertos en la máquina.

```ruby
❯ nmap -p- --open -sS --min-rate 5000 -n -v -Pn 10.10.10.100 -oG allPorts
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-02 10:00 CEST
Initiating SYN Stealth Scan at 10:00
Scanning 10.10.10.100 [65535 ports]
Discovered open port 53/tcp on 10.10.10.100
Discovered open port 139/tcp on 10.10.10.100
Discovered open port 445/tcp on 10.10.10.100
Discovered open port 135/tcp on 10.10.10.100
Discovered open port 49154/tcp on 10.10.10.100
Discovered open port 9389/tcp on 10.10.10.100
Discovered open port 3268/tcp on 10.10.10.100
Discovered open port 47001/tcp on 10.10.10.100
Discovered open port 49155/tcp on 10.10.10.100
Discovered open port 3269/tcp on 10.10.10.100
Discovered open port 49158/tcp on 10.10.10.100
Discovered open port 49153/tcp on 10.10.10.100
Discovered open port 49169/tcp on 10.10.10.100
Discovered open port 464/tcp on 10.10.10.100
Discovered open port 389/tcp on 10.10.10.100
Discovered open port 49152/tcp on 10.10.10.100
Discovered open port 49157/tcp on 10.10.10.100
Discovered open port 636/tcp on 10.10.10.100
Discovered open port 5722/tcp on 10.10.10.100
Discovered open port 593/tcp on 10.10.10.100
Discovered open port 49165/tcp on 10.10.10.100
Discovered open port 49168/tcp on 10.10.10.100
Discovered open port 88/tcp on 10.10.10.100
Completed SYN Stealth Scan at 10:00, 14.44s elapsed (65535 total ports)
Nmap scan report for 10.10.10.100
Host is up (0.045s latency).
Not shown: 64433 closed tcp ports (reset), 1079 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE
53/tcp    open  domain
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
5722/tcp  open  msdfsr
9389/tcp  open  adws
47001/tcp open  winrm
49152/tcp open  unknown
49153/tcp open  unknown
49154/tcp open  unknown
49155/tcp open  unknown
49157/tcp open  unknown
49158/tcp open  unknown
49165/tcp open  unknown
49168/tcp open  unknown
49169/tcp open  unknown
```
Luego de identificar los puertos abiertos `OPEN`, se procede a escanear servicios y versiones que puedan estar corriendo en los puertos abiertos detectados.

```ruby
❯ nmap -sCV -p53,88,135,139,389,445,464,593,636,3268,3269,5722,9389,49152,49153,49154,49155,49157,49158,49165,49166,49170 10.10.10.100 -oN targeted
Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-02 10:06 CEST
Nmap scan report for active.htb (10.10.10.100)
Host is up (0.037s latency).

PORT      STATE  SERVICE       VERSION
53/tcp    open   domain        Microsoft DNS 6.1.7601 (1DB15D39) (Windows Server 2008 R2 SP1)
| dns-nsid: 
|_  bind.version: Microsoft DNS 6.1.7601 (1DB15D39)
88/tcp    open   kerberos-sec  Microsoft Windows Kerberos (server time: 2023-06-02 08:06:51Z)
135/tcp   open   msrpc         Microsoft Windows RPC
139/tcp   open   netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open   ldap          Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
445/tcp   open   microsoft-ds?
464/tcp   open   kpasswd5?
593/tcp   open   ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open   tcpwrapped
3268/tcp  open   ldap          Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
3269/tcp  open   tcpwrapped
5722/tcp  open   msrpc         Microsoft Windows RPC
9389/tcp  open   mc-nmf        .NET Message Framing
49152/tcp open   msrpc         Microsoft Windows RPC
49153/tcp open   msrpc         Microsoft Windows RPC
49154/tcp open   msrpc         Microsoft Windows RPC
49155/tcp open   msrpc         Microsoft Windows RPC
49157/tcp open   ncacn_http    Microsoft Windows RPC over HTTP 1.0
49158/tcp open   msrpc         Microsoft Windows RPC
49165/tcp open   msrpc         Microsoft Windows RPC
49166/tcp closed unknown
49170/tcp closed unknown
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008:r2:sp1, cpe:/o:microsoft:windows
```

## SMB

Comenzamos la enumeración SMB listando los recursos compartidos a nivel de red con la herramienta `smbmap`. Encontramos un recurso `Replication` sobre el cual tenemos permisos de lectura.

<img src="/assets/HTB/Active/smbmap.png">

Dentro de este recurso encontramos una carpeta llamada `active.htb`.

<img src="/assets/HTB/Active/activedir.png">

Seguimos enumerando y observamos una estructura de directorios similar a la que tiene `SYSVOL`. 

<img src="/assets/HTB/Active/sysvol.png">

<img src="/assets/HTB/Active/whatis.png">

Continuamos enumerando y localizamos un archivo `Groups.xml` en la ruta `Replication/active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Preferences/Groups`.

<img src="/assets/HTB/Active/groups.png">

Listando su contenido observamos un usuario y una contraseña encriptada.

<img src="/assets/HTB/Active/content.png">

Para poder desencriptar la contraseña en texto claro usaremos la herramienta [gpp-decrypt](https://github.com/t0thkr1s/gpp-decrypt).

<img src="/assets/HTB/Active/gppdecrypt.png">

<img src="/assets/HTB/Active/pass.png">

## Ataque Kerberoasting

En este punto verificamos que las credenciales obtenidas sean válidas con `crackmapexec`.

<img src="/assets/HTB/Active/valid.png">

Al disponer de credenciales válidas podemos verificar que el usuario sea kerberosteable con la herramienta `GetUserSPNs.py`.

<img src="/assets/HTB/Active/iskerb.png">

Confirmamos que podemos obtener un **TGS (Ticket Granting Service)** del usuario **Administrator**. Con la misma herramienta le añadimos el parámetro `-request` y obetenemos un hash del usuario `Administrator`.

<img src="/assets/HTB/Active/kerb.png">

Procedemos a crackear el hash con la herramienta `john`.

<img src="/assets/HTB/Active/john.png">

Verificamos con `crackmapexec` que la credencial sea válida.

<img src="/assets/HTB/Active/adminpwn.png">

Finalmente ganamos acceso como `nt authority\system` a la máquina víctima con la herramienta `impacket-psexec`.

<img src="/assets/HTB/Active/psexec.png">

La flag de usuario la encontramos en el directorio `C:\Users\SVC_TGS\Desktop\` y la de usuario privilegiado en `C:\Users\Administrator\Desktop\`.

<img src="/assets/HTB/Active/user.png">

<img src="/assets/HTB/Active/root.png">

Hemos completado la máquina **Active** de HackTheBox!! Happy Hacking!!

<img src="/assets/HTB/Active/pwned.png">