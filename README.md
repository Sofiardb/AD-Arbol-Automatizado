# AD-Arbol-Automatizado

**Implementación automatizada de una solución de Active Directory y DNS en un árbol con dominio padre e hijo, con acceso controlado de cuentas de un dominio a recursos del otro, mediante PowerShell.**

Proyecto Final – Administración Avanzada de Sistemas Operativos (AASO) – FACET – UNT.

## Integrantes
- Ason, Belén
- Rodríguez del BustO, Sofía

---

## 1. Qué hace

A partir de **un archivo de configuración y dos CSV**, un único comando (`.\Deploy.ps1`) despliega de punta a punta:

1. Un **bosque de Active Directory** con un **dominio padre** (`andina.local`) y un **dominio hijo** (`recursos.andina.local`), cada uno con su controlador de dominio y **DNS integrado**.
2. La **estructura lógica** del dominio padre (una OU por área) y el **alta masiva de cuentas** desde un CSV.
3. Los **recursos compartidos** en el dominio hijo y el **acceso de las cuentas del padre** a esos recursos según una matriz de permisos, aplicando la estrategia **AGUDLP** con permisos de **recurso compartido y NTFS**.
4. Un **equipo cliente** unido al dominio, preparado para demostrar los permisos iniciando sesión con distintos usuarios.
5. Una **validación automática** que compara lo desplegado con el diseño, prueba el acceso real de una cuenta por área a cada recurso y genera un **informe HTML**.

El usuario ingresa **una sola contraseña**; todo lo demás (nombres, IP, OU, cuentas, grupos, permisos) se **deriva** de la configuración.

### Objetivos

**General:** diseñar e implementar una solución automatizada con PowerShell que despliegue un árbol de Active Directory con dominio padre e hijo, DNS integrado y acceso controlado de cuentas de un dominio a recursos del otro.

**Específicos** (cada uno corresponde a un módulo):

| # | Objetivo específico | Módulo |
|---|---|---|
| 1 | Diseñar la arquitectura lógica y física | `01-Diseno` |
| 2 | Automatizar la preparación de servidores y la creación del dominio raíz e hijo | `02-Despliegue` |
| 3 | Automatizar la configuración y verificación de DNS (zonas, delegación, SRV, zonas inversas) | `03-DNS` |
| 4 | Automatizar la estructura lógica y el alta masiva de cuentas | `04-Estructura` |
| 5 | Dar acceso a las cuentas del padre sobre recursos del hijo con AGUDLP y permisos NTFS y de recurso compartido | `05-AccesoEntreDominios` (+ `06-Cliente` para la demostración) |
| 6 | Validar automáticamente y documentar | `07-Validacion` |

---

## 2. Modelo de la solución

```
            Bosque andina.local
 ┌──────────────────────────────┐    confianza padre-hijo   ┌────────────────────────────────────┐
 │ andina.local  (PADRE)        │◄─────────────────────────►│ recursos.andina.local  (HIJO)      │
 │ DC-RAIZ · CUENTAS            │  bidireccional/transitiva │ DC-HIJO · RECURSOS                 │
 │                              │                           │                                    │
 │ A  52 cuentas en OU por área │                           │ DL DL-<Recurso>-<Nivel>            │
 │ G  GG-ANDINA-<Área> ─────────┼──── miembro de ──────────►│ P  \\DC-HIJO\<Recurso>             │
 └──────────────────────────────┘                           │    (recurso compartido + NTFS)     │
            ▲                                               └────────────────────────────────────┘
            │ inicio de sesión con una cuenta del padre                ▲
       CLIENTE01 (miembro de andina.local) ─────── acceso SMB ─────────┘
```

- **Las cuentas se centralizan en el dominio padre** y **los recursos en el dominio hijo**. Los permisos se asignan **en un solo sentido**: cuentas del padre → recursos del hijo.
- **AGUDLP**: **A**ccount (cuenta, en el padre) → **G**lobal group por área (en el padre) → **D**omain **L**ocal group por recurso y nivel (en el hijo) → **P**ermissions (recurso compartido y NTFS, en DC-HIJO). Un grupo de dominio local admite como miembros grupos globales de cualquier dominio del bosque; la confianza padre-hijo (automática, bidireccional y transitiva) permite resolverlos.
- Ninguna cuenta recibe permisos directos: cambiar lo que puede hacer un usuario es cambiarlo de grupo, y cambiar lo que puede hacer un área es editar `accesos.csv` y volver a ejecutar el paso 5.

### Permisos (enfoque "por grupo")

| Nivel | Permiso del recurso compartido | Permiso NTFS |
|---|---|---|
| Lectura | Read | ReadAndExecute |
| Modificar | Change | Modify |
| Administradores | Full | FullControl (+ SYSTEM) |

Además: se quita `Todos` (Everyone) del recurso compartido, se deshabilita la herencia NTFS de cada carpeta y se activa la **enumeración basada en el acceso (ABE)**.

---

## 3. Estructura del repositorio

```
Deploy.ps1                         Orquestador: ejecuta los pasos en orden, guarda el estado,
                                   pide la contraseña una vez, registra todo en un log
config/
  lab.psd1                         Configuración del laboratorio (dominios, red, equipos, áreas)
  usuarios.csv                     Empleados: Nombre, Apellido, Area, Cargo, Telefono, Oficina
  accesos.csv                      Matriz de acceso: Recurso, Area, Nivel (Lectura | Modificar)
modules/
  00-Comun/Comun.psm1              Funciones compartidas: log, lectura de la configuración, estado,
                                   credenciales, nombres de cuentas y grupos, cálculos de red, remoting
  01-Diseno/Diseno.psm1            Validación de la configuración, cálculo del diseño completo,
  01-Diseno/Invoke-Diseno.ps1        tablas, diagramas y guion de la demostración
  02-Despliegue/Invoke-Despliegue.ps1      Paso 2: servidores, bosque y dominio hijo
  03-DNS/Invoke-DNS.ps1                    Paso 3: zonas, registros, reenviadores, delegación, verificación
  04-Estructura/Invoke-Estructura.ps1      Paso 4: OU y alta masiva de cuentas
  05-AccesoEntreDominios/Invoke-Acceso.ps1 Paso 5: grupos AGUDLP, recursos compartidos y NTFS
  06-Cliente/Invoke-Cliente.ps1            Paso 6: unión del cliente al dominio y kit de demostración
  07-Validacion/Validacion.psm1            Paso 7: comparaciones diseño vs. estado real (funciones puras)
  07-Validacion/Invoke-Validacion.ps1        recolección, pruebas de acceso reales e informe HTML
demo/Probar-Permisos.ps1           Script que ejecuta el usuario en el cliente durante la demostración
tools/Preparar-Equipo.ps1          Preparación única de cada VM según su rol (IP, remoting, firewall, cuentas)
tools/Crear-ISO.ps1                Opcional: empaqueta el proyecto en una ISO para copiarlo a las VM (se ejecuta en el anfitrión)
tests/Test-Offline.ps1             Pruebas automatizadas que no necesitan servidores
```

La carpeta `output/` la genera el sistema en cada ejecución y no forma parte del repositorio (`.gitignore`).

---

## 4. Qué hace cada paso

| Paso | Qué hace | Cmdlets principales |
|---|---|---|
| **1 · Diseño** | Valida la configuración (frena antes de tocar nada si hay errores) y calcula el diseño completo: nombres e IP finales, DNS de cada equipo, OU, cuentas (con desambiguación de homónimos y quita de acentos), grupos AGUDLP, permisos, matriz de acceso y escenas de la demostración. Genera `diseno.json`, tablas CSV, diagramas Mermaid, `diseno.html` y `guion-demostracion.html`. | — |
| **2 · Despliegue** | Prepara DC-RAIZ y DC-HIJO (roles, zona horaria, nombre, IP fija, DNS inicial, reinicio). Crea el bosque y el dominio padre en DC-RAIZ; crea el dominio hijo en DC-HIJO con delegación DNS en el padre. Configura el DNS definitivo y verifica la confianza padre-hijo y los maestros de operaciones. | `Install-WindowsFeature`, `Install-ADDSForest`, `Install-ADDSDomain`, `Get-ADTrust` |
| **3 · DNS** | Zona inversa integrada en AD con replicación al bosque, registros PTR, reenviadores (el hijo reenvía al padre), delegación del hijo, envejecimiento y limpieza (scavenging). Quita los registros del hijo que hayan quedado en la zona del padre durante la promoción y vacía la caché DNS. Verifica desde ambos DC los registros SRV de localización de DC, Kerberos y catálogo global, y los registros A y PTR. | `Add-DnsServerPrimaryZone`, `Add-DnsServerZoneDelegation`, `Set-DnsServerForwarder`, `Resolve-DnsName` |
| **4 · Estructura y cuentas** | En el padre: una OU por área, OU `Grupos` y OU `Equipos`, y alta o actualización de las 52 cuentas con sus atributos (cargo, área, empresa, teléfono, oficina). En el hijo: OU `Grupos`. Si una cuenta cambia de área, la mueve; si hay cuentas que no están en el CSV, las informa sin borrarlas. | `New-ADOrganizationalUnit`, `New-ADUser`, `Set-ADUser`, `Move-ADObject` |
| **5 · Acceso entre dominios** | Grupos globales por área en el padre; grupos de dominio local por recurso y nivel en el hijo, con los grupos globales del padre como miembros; carpetas compartidas en DC-HIJO con permisos de recurso compartido y NTFS. Reconcilia: quita lo que sobra y agrega lo que falta. | `New-ADGroup`, `Add-ADGroupMember`, `New-SmbShare`, `Grant-SmbShareAccess`, `Set-Acl` |
| **6 · Cliente** | Une CLIENTE01 al dominio padre (OU `Equipos`) y le instala el kit de demostración: script **Probar mis permisos** y accesos directos a los recursos en el escritorio. | `Add-Computer` |
| **7 · Validación** | Compara el estado real con el diseño (bosque, confianza, DNS, OU, cuentas, ámbito y pertenencia de cada grupo, permisos de cada recurso, cliente), ejecuta `dcdiag` y `repadmin`, y hace **pruebas de acceso reales**: crea una cuenta temporal por área, intenta listar, leer, escribir y borrar en cada recurso, compara con lo esperado y elimina las cuentas temporales. Genera el informe HTML. | `Get-AD*`, `Get-DnsServer*`, `Get-SmbShareAccess`, `Get-Acl` |

Todo el trabajo en los servidores se hace por **PowerShell Remoting** desde un equipo de administración. Todos los pasos son **idempotentes**: comprueban el estado real y solo cambian lo necesario, por lo que se pueden volver a ejecutar; si un paso se interrumpe, la siguiente ejecución retoma desde el paso pendiente.

---

## 5. Datos de entrada (`config/`)

| Archivo | Contenido |
|---|---|
| `lab.psd1` | Empresa, dominio raíz, etiqueta del hijo, red (CIDR), gateway, reenviadores DNS, IP actual y rol de cada servidor (`DCRaiz`, `DCHijo`), cliente, áreas y contraseña de la demostración. Opcionales: `ZonaHoraria`, `RutaRecursos`, `NivelFuncional`, `UsuarioAdministrador`. |
| `usuarios.csv` | `Nombre,Apellido,Area,Cargo,Telefono,Oficina` (las tres últimas, opcionales). |
| `accesos.csv` | `Recurso,Area,Nivel`: qué área accede a qué recurso y con qué nivel. De esta tabla se derivan los grupos y los permisos. |

### Valores derivados

| Elemento | Regla | Ejemplo |
|---|---|---|
| Dominio hijo | `<DominioHijo>.<DominioRaiz>` | `recursos.andina.local` |
| NetBIOS | primera etiqueta en mayúsculas | `ANDINA`, `RECURSOS` |
| Equipos | `DC-RAIZ` (.10), `DC-HIJO` (.11), `CLIENTE01` (conserva su IP) | `192.168.10.10` |
| OU (padre) | una por área + `Grupos` + `Equipos` | `OU=Finanzas,DC=andina,DC=local` |
| Cuenta / UPN | inicial del nombre + apellido, sin acentos, en minúsculas; sufijo numérico si se repite | `scampos@andina.local`, `jperez2` |
| Grupo global (padre) | `GG-<NETBIOS>-<Area>` | `GG-ANDINA-Finanzas` |
| Grupo de dominio local (hijo) | `DL-<Recurso>-<Nivel>` | `DL-Lista-Precios-Modificar` |
| Recurso compartido | `\\DC-HIJO\<Recurso>` → `C:\Recursos\<Recurso>` | `\\dc-hijo.recursos.andina.local\Lista-Precios` |

### Escenario de ejemplo incluido

**Distribuidora Andina S.A.**:
- **Cuentas:** 52 empleados en 11 áreas (Gerencia, Administración, Finanzas, RRHH, IT, Legales, Comerciales, Supervisores, Postventa, Marketing, Logística).
- **Recursos:** 10 recursos compartidos (Comunicados, Lista-Precios, Reportes-Ventas, Contratos, Legajos, Facturacion, Stock, Material-Marketing, Manuales, Soporte-IT).
- **Grupos derivados de las 46 reglas de acceso:**
  - 11 grupos globales en el padre;
  - 20 grupos de dominio local en el hijo;
  - 46 anidamientos entre dominios.

---

## 6. Laboratorio

Se probó en **VirtualBox** con una red *solo anfitrión* `192.168.10.0/24` sin DHCP y un único adaptador por VM:

| VM | Sistema | Función | IP |
|---|---|---|---|
| DC-RAIZ | Windows Server 2012 R2 | Controlador del dominio padre `andina.local` (cuentas) + DNS | 192.168.10.101 → .10 |
| DC-HIJO | Windows Server 2012 R2 | Controlador del dominio hijo `recursos.andina.local` + DNS + servidor de archivos | 192.168.10.102 → .11 |
| CLIENTE01 | Windows 8.1 Pro | Equipo de la demostración, miembro del dominio padre | 192.168.10.150 |
| ADMIN | Windows 8.1 | Equipo de administración desde el que se ejecuta `Deploy.ps1` (no se une al dominio) | 192.168.10.200 |

**Compatibilidad:**
- **Servidores:** Windows Server 2012, 2012 R2, 2016, 2019 y 2022.
- **Cliente:** Windows 8, 8.1, 10 y 11 Pro, Enterprise o Education.
- **Equipo de administración:** Windows PowerShell 3.0, 4.0 y 5.1, o PowerShell 7 en Windows.
- **Idioma:** funciona con equipos en distintos idiomas, por ejemplo servidores en inglés y equipos de administración y cliente en español.

### Preparación de las VM (una sola vez)

1. Instalar cada VM desde su ISO (sin clonar), con un único adaptador conectado a la red *solo anfitrión*. No hace falta configurar la IP ni el nombre: de eso se encargan el script de preparación y el despliegue.
2. Copiar la carpeta del proyecto a cada VM por el medio que se tenga disponible (pendrive, carpeta compartida, etc.), por ejemplo a `C:\AD-Arbol-Automatizado`. Si no hay otra opción —la red solo anfitrión no tiene Internet y las Guest Additions no siempre se instalan—, se puede empaquetar en una ISO desde el **anfitrión** y montarla en cada VM (*Dispositivos → Unidades ópticas*):
   ```powershell
   .\tools\Crear-ISO.ps1        # crea AD-Arbol-Automatizado.iso junto a la carpeta del proyecto (sin .git ni output)
   ```
   Los archivos copiados desde un CD quedan de solo lectura y bloqueados; en ese caso:
   ```powershell
   attrib -r C:\AD-Arbol-Automatizado\* /s /d
   Get-ChildItem C:\AD-Arbol-Automatizado -Recurse | Unblock-File
   ```
3. En cada VM, ejecutar, en PowerShell como administrador, el script de preparación indicando el rol del equipo:
   ```powershell
   Set-ExecutionPolicy -Scope Process Bypass -Force
   .\tools\Preparar-Equipo.ps1 -Rol DCRaiz     # servidor del dominio padre  -> 192.168.10.101
   .\tools\Preparar-Equipo.ps1 -Rol DCHijo     # servidor del dominio hijo   -> 192.168.10.102
   .\tools\Preparar-Equipo.ps1 -Rol Cliente    # cliente de la demostración  -> 192.168.10.150
   .\tools\Preparar-Equipo.ps1 -Rol Admin      # equipo de administración    -> 192.168.10.200 (al final)
   ```
   Sin `-Rol` muestra un menú. Las IP, la máscara y la puerta de enlace se toman de `config/lab.psd1`.

   | Rol | Qué configura |
   |---|---|
   | Todos | IP fija, red como privada, PowerShell Remoting con inicio automático, firewall para WinRM y ping |
   | DCRaiz, DCHijo, Cliente | Cuenta Administrador integrada activa con la contraseña indicada (**la misma en las tres VM**) y administración remota con cuentas locales |
   | Admin | Red del laboratorio en `TrustedHosts` y prueba de conexión WinRM con los otros tres equipos |

   Se puede volver a ejecutar sin efectos indeseados; no cambia la IP de un equipo que ya es controlador de dominio o que ya está unido al dominio. *Solo para laboratorio.*
4. En `config/lab.psd1`, ajustar `NivelFuncional` a la versión de los servidores (`Win2012`, `Win2012R2` o `WinThreshold` para 2016 o posterior) y `UsuarioAdministrador` (`Administrator` o `Administrador`, según el idioma de los servidores; el script de preparación avisa si no coincide).
5. Tomar una instantánea de las cuatro VM.

### Ejecución (en ADMIN, PowerShell como administrador)

```powershell
Set-ExecutionPolicy -Scope Process Bypass -Force

.\Deploy.ps1 -SoloDiseno     # paso 1: solo calcula el diseño, no toca las VM
.\Deploy.ps1 -WhatIf         # muestra qué haría cada paso, sin cambiar nada
.\Deploy.ps1                 # despliegue completo (pide la contraseña del Administrador)
```

| Opción | Efecto |
|---|---|
| `.\Deploy.ps1` | Ejecuta los pasos pendientes en orden |
| `-Paso 4,5` | Ejecuta solo los pasos indicados |
| `-SoloDiseno` / `-SoloValidar` | Solo el paso 1 / solo el paso 7 |
| `-WhatIf` | Simulación de los pasos 2 a 7 |
| `-Reiniciar` | Ignora el estado guardado y empieza de nuevo |

Duración medida en el laboratorio: unos **18 minutos** el despliegue completo. La mayor parte corresponde a los pasos 2 y 3 (creación de los dominios, con sus reinicios); los pasos 4 a 7 llevan unos 6 minutos.

---

## 7. Demostración

`Deploy.ps1 -SoloDiseno` genera `output/diseno/guion-demostracion.html` con el guion completo. Con el escenario incluido (todas las cuentas con la contraseña de la demo definida en `lab.psd1`):

| Escena | Cuenta | Recurso | Resultado esperado |
|---|---|---|---|
| 1 | `ANDINA\scampos` (Finanzas) | Lista-Precios | **Modificar**: crea, edita y borra archivos |
| 2 | `ANDINA\cnunez` (Gerencia) | Lista-Precios | **Lectura**: abre y lee; al guardar, "Acceso denegado" |
| 3 | `ANDINA\lortiz` (Administración) | Lista-Precios | **Sin acceso**: no puede abrir la carpeta |
| 4 | `ANDINA\cnunez` (Gerencia) | Comunicados | **Modificar**: el mismo usuario sí escribe en otro recurso |

En el escritorio del cliente, **Probar mis permisos** (`demo/Probar-Permisos.ps1`) muestra la cuenta, sus grupos globales y una tabla con lo que puede hacer en cada recurso, y explica la cadena AGUDLP que le da cada permiso. Los grupos de dominio local del hijo no aparecen en `whoami /groups` en el cliente porque se agregan al token recién cuando la cuenta se autentica en DC-HIJO.

---

## 8. Salidas (`output/`)

| Archivo | Contenido |
|---|---|
| `diseno.json` | Diseño completo derivado (lo usan los pasos 2 a 7) |
| `diseno/diseno.html` | Diagramas lógico y físico, matriz área × recurso, cuentas, grupos y permisos |
| `diseno/guion-demostracion.html` | Guion de la demostración |
| `diseno/*.csv`, `diseno/*.mmd` | Tablas y diagramas Mermaid para el documento del trabajo |
| `despliegue.json` | Bosque, dominios, maestros de operaciones, catálogos globales y confianza |
| `dns-verificacion.csv` | Resultado de cada consulta DNS del paso 3 |
| `estructura-resultado.csv`, `acceso-resultado.csv` | Qué se creó, actualizó o quitó en los pasos 4 y 5 |
| `validacion/informe-validacion.html` | Informe de validación con el resultado de cada prueba |
| `logs/` | Log y transcripción de cada ejecución |

---

## 9. Pruebas sin laboratorio

```powershell
powershell -File .\tests\Test-Offline.ps1
```

Verifican, sin servidores:
- **Configuración y cálculos:** cálculos de red, generación de nombres de cuenta, rechazo de configuraciones inválidas y el diseño derivado.
- **Validación:** un estado correcto da 0 fallas y se detectan 11 tipos de defectos inyectados.
- **Pasos 4 y 5:** sus bloques remotos se ejecutan contra un Active Directory simulado en memoria y se comprueban el alta, la idempotencia y la reconciliación.

Resultado: **51/51**.

---

## 10. Decisiones técnicas

- **Una sola contraseña.** Se pide una vez y se guarda cifrada (DPAPI) durante el despliegue. El Administrador local del primer DC de cada dominio pasa a ser el administrador del dominio, por eso las credenciales de dominio se derivan de ella.
- **Reinicios controlados.** El cambio de IP se delega en una tarea programada que corre como SYSTEM, porque corta la sesión remota; la tarea se ejecuta aunque el equipo informe que funciona con batería (VirtualBox le transmite a la VM el estado de la batería del anfitrión). Las promociones a DC programan su propio reinicio en la misma sesión. El orquestador espera a que cada servidor vuelva antes de seguir.
- **Anidamiento entre dominios.** DC-HIJO valida los grupos globales del padre contra su copia del catálogo global, que se actualiza por replicación: antes de anidarlos, el paso 5 fuerza la replicación entrante (`repadmin /syncall`) y reintenta si hace falta.
- **Idempotencia y reconciliación.** Cada operación compara el estado real con el deseado antes de actuar, y la pertenencia a grupos y los permisos quedan exactamente como dicen los CSV.
- **Compatibilidad entre versiones e idiomas:**
  - las cuentas integradas se identifican por SID;
  - las sesiones remotas se abren con el idioma instalado en cada servidor;
  - la zona horaria se cambia con `tzutil`;
  - el archivo de configuración se lee en modo de lenguaje restringido (solo datos) y sin requerir PowerShell 5;
  - las rutas por defecto se calculan dentro de cada script, porque en PowerShell 3.0 y 4.0 `$PSScriptRoot` puede llegar vacío a los parámetros.
- **Validación independiente de la implementación.** Las comparaciones son funciones puras sobre datos recolectados, por eso se pueden probar sin laboratorio. Además, las pruebas de acceso usan cuentas reales con una sesión nueva por cuenta, igual que un usuario en el cliente.

> La contraseña de la demostración (`ContrasenaDemo` en `lab.psd1`) y `tools/Preparar-Equipo.ps1` simplifican el laboratorio. Si se quita `ContrasenaDemo`, cada cuenta recibe una contraseña aleatoria que debe cambiarse en el primer inicio de sesión.
