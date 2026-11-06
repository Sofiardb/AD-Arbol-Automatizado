# AD-Arbol-Automatizado

Despliegue automatizado con PowerShell de un árbol de **Active Directory** con **dominio padre e hijo**, **DNS integrado** y **acceso controlado de cuentas entre dominios** mediante la estrategia **AGUDLP** (permisos de recurso compartido y NTFS por grupo).

Trabajo práctico – Administración Avanzada de Sistemas Operativos (AASO) – FACET – UNT.

## Cómo funciona

El usuario completa **un archivo de configuración y dos CSV**, ejecuta **un comando** e ingresa **una contraseña**. Todo lo demás (nombres, IP finales, OU, cuentas, grupos, recursos compartidos y permisos) se **deriva automáticamente**.

```powershell
.\Deploy.ps1 -SoloDiseno   # 1) revisar el diseño (no toca servidores)
.\Deploy.ps1 -WhatIf       # 2) ver qué haría cada paso, sin cambiar nada
.\Deploy.ps1               # 3) desplegar todo
```

| Paso | Módulo | Objetivo específico | Qué hace |
|---|---|---|---|
| 1 | `01-Diseno` | Diseñar la arquitectura lógica y física | Valida la configuración, deriva el diseño completo, genera tablas, diagramas y `diseno.html` |
| 2 | `02-Despliegue` | Preparar servidores y crear dominio raíz e hijo | Roles, zona horaria, nombre, IP fija y reinicio; `Install-ADDSForest`; `Install-ADDSDomain` (hijo con delegación DNS); unión de SRV-ARCHIVOS; DNS definitivo; verificación de la confianza |
| 3 | `03-DNS` | Configurar y verificar DNS | Zona inversa integrada en AD, PTR, reenviadores, delegación, scavenging; verificación SRV/A/PTR desde ambos DC |
| 4 | `04-Estructura` | Estructura lógica y alta masiva de cuentas | OU por área + `Grupos`; alta/actualización de cuentas con atributos; contraseñas iniciales aleatorias |
| 5 | `05-AccesoEntreDominios` | Acceso entre dominios con AGUDLP | Grupos globales en cada dominio, grupos de dominio local en el raíz con miembros de ambos dominios, recursos compartidos, NTFS y ABE |
| 6 | `06-Validacion` | Validar y documentar | Compara el estado real con el diseño, `dcdiag`/`repadmin`, **pruebas de acceso reales** con cuentas temporales e informe HTML |

Todos los pasos son **idempotentes** (comprueban el estado real y solo cambian lo necesario) y **reconcilian**: la pertenencia a grupos y los permisos quedan exactamente como dicen los CSV.

## Escenario de ejemplo incluido

**Distribuidora Andina S.A.**: casa central en el dominio raíz y red comercial en el dominio hijo.

| | Dominio raíz `andina.local` | Dominio hijo `ventas.andina.local` |
|---|---|---|
| Áreas (OU) | Gerencia, Administracion, Finanzas, RRHH, IT, Legales | Comerciales, Supervisores, Postventa, Marketing, Logistica |
| Cuentas | 21 | 31 |
| Grupos | 6 globales + 20 de dominio local | 5 globales |

- 10 recursos compartidos en `SRV-ARCHIVOS` (Comunicados, Lista-Precios, Reportes-Ventas, Contratos, Legajos, Facturacion, Stock, Material-Marketing, Manuales, Soporte-IT).
- 46 reglas de acceso; 23 de ellas dan a grupos del dominio **hijo** acceso a recursos del dominio **padre**.
- Incluye casos especiales: homónimos (`jperez`, `jperez2`), acentos y ñ (`Núñez` → `cnunez`), apellidos compuestos (`de la Fuente` → `sdelafuente`).

## Configuración (`config/`)

| Archivo | Contenido |
|---|---|
| `lab.psd1` | Empresa, dominio raíz, etiqueta del hijo, red (CIDR), gateway, reenviadores DNS, IP actual y rol de cada servidor, áreas por dominio. Opcionales: `ZonaHoraria`, `RutaRecursos`, `NivelFuncional`, `UsuarioAdministrador`, y por servidor `Nombre` e `IPFinal` |
| `usuarios.csv` | `Nombre,Apellido,Dominio,Area,Cargo,Telefono,Oficina` (Dominio = `Raiz` o `Hijo`; las tres últimas columnas son opcionales) |
| `accesos.csv` | `Recurso,Dominio,Area,Nivel` (Nivel = `Lectura` o `Modificar`): matriz de acceso de la que se derivan grupos y permisos |

### Convenciones (valores derivados)

| Elemento | Regla | Ejemplo |
|---|---|---|
| Dominio hijo | `<DominioHijo>.<DominioRaiz>` | `ventas.andina.local` |
| NetBIOS | primera etiqueta en mayúsculas | `ANDINA`, `VENTAS` |
| Servidores | `DC-RAIZ` (.10), `DC-HIJO` (.11), `SRV-ARCHIVOS` (.20) dentro de la red | `192.168.10.10` |
| OU | una por área + `Grupos`, en el dominio correspondiente | `OU=Comerciales,DC=ventas,DC=andina,DC=local` |
| Cuenta / UPN | inicial del nombre + apellido, sin acentos, minúsculas / `cuenta@dominio` | `jperez@ventas.andina.local` |
| Grupo global | `GG-<NETBIOS>-<Area>` (en el dominio del área) | `GG-VENTAS-Comerciales` |
| Grupo de dominio local | `DL-<Recurso>-<Nivel>` (en el dominio raíz) | `DL-Lista-Precios-Lectura` |
| Recurso compartido | `\\SRV-ARCHIVOS\<Recurso>` → `C:\Recursos\<Recurso>` | `\\srv-archivos.andina.local\Lista-Precios` |

### Permisos (enfoque "por grupo")

| Nivel | Recurso compartido | NTFS |
|---|---|---|
| Lectura | Read | ReadAndExecute |
| Modificar | Change | Modify |
| Administradores | Full | FullControl (+ SYSTEM) |

Se quita `Todos` (Everyone) del recurso compartido, se habilita la **enumeración basada en el acceso (ABE)** y se deshabilita la herencia NTFS de la carpeta. Las cuentas integradas se resuelven por SID, por lo que funciona también con Windows en español.

## Requisitos

- Tres VM con **Windows Server 2016/2019/2022** recién instaladas (o 2012 R2 con WMF 5.1 y `NivelFuncional = 'Win2012R2'`), en la misma red, con la IP que figura en `IPActual`.
- En las tres VM, **la contraseña del Administrador local debe ser la misma** y cumplir la complejidad: es la que se ingresa al ejecutar `Deploy.ps1` (también se usa como contraseña de modo de restauración, DSRM). Si las VM están en español, poner `UsuarioAdministrador = 'Administrador'` en `lab.psd1`.
- PowerShell Remoting habilitado en las VM (`Enable-PSRemoting -Force`; viene habilitado por defecto en Windows Server). Si la red de la VM quedó como "Pública", ejecutar antes `Set-NetConnectionProfile -NetworkCategory Private`.
- Un **equipo de administración** Windows (puede ser una cuarta VM o el host) en la misma red, desde el que se ejecuta `Deploy.ps1` **como administrador** con Windows PowerShell 5.1. No conviene ejecutarlo desde DC-RAIZ, porque se reinicia durante el paso 2.
- El orquestador agrega las IP de los servidores a `TrustedHosts`. Si no tiene permisos para hacerlo:
  ```powershell
  Set-Item WSMan:\localhost\Client\TrustedHosts -Value '192.168.10.*' -Force
  ```
- Si la política de ejecución lo impide: `Set-ExecutionPolicy -Scope Process Bypass`.

**Duración aproximada del despliegue completo:** 30 a 45 minutos (la mayor parte son reinicios y promociones de DC).

## Opciones del orquestador

```powershell
.\Deploy.ps1                 # todos los pasos (retoma desde el primero pendiente)
.\Deploy.ps1 -SoloDiseno     # solo el paso 1
.\Deploy.ps1 -Paso 4,5       # pasos indicados (siempre se recalcula el diseño antes)
.\Deploy.ps1 -SoloValidar    # solo validación
.\Deploy.ps1 -WhatIf         # simula los pasos 2 a 6
.\Deploy.ps1 -Reiniciar      # ignora el estado guardado
```

Para agregar usuarios o accesos después del despliegue: editar los CSV y ejecutar `.\Deploy.ps1 -Paso 4,5,6`.

Cada módulo también se puede ejecutar solo (lee `output\diseno.json`), por ejemplo:

```powershell
$c = Import-Clixml .\output\credencial.xml
.\modules\06-Validacion\Invoke-Validacion.ps1 -Credencial $c -RutaSalida .\output -SinPruebasDeAcceso
```

## Salidas (`output/`)

| Archivo | Contenido |
|---|---|
| `diseno.json` | Diseño completo derivado (insumo de los pasos 2 a 6) |
| `diseno/diseno.html` | Diagramas lógico y físico + tablas (servidores, usuarios, grupos, permisos, matriz de acceso) |
| `diseno/*.csv`, `diseno/*.mmd` | Tablas y diagramas Mermaid para el documento del trabajo |
| `despliegue.json` | Bosque, dominios, maestros de operaciones, catálogos globales y confianza resultantes |
| `dns-verificacion.csv` | Resultado de cada consulta DNS del paso 3 |
| `estructura-resultado.csv`, `acceso-resultado.csv` | Qué se creó, actualizó o quitó en los pasos 4 y 5 |
| `credenciales-iniciales.csv` | Contraseñas iniciales de las cuentas nuevas (**entregar por canal seguro y eliminar**) |
| `validacion/informe-validacion.html` | Informe de validación (resultado general, pruebas por categoría, fallas resaltadas) |
| `validacion/resultados.csv` | Todas las pruebas de la validación |
| `estado.json` | Pasos completados (para retomar) |
| `logs/` | Log y transcripción de cada ejecución |
| `credencial.xml` | Credencial temporal cifrada (DPAPI); se borra al completar el despliegue |

## Pruebas sin laboratorio

```powershell
pwsh -File .\tests\Test-Offline.ps1     # o: powershell -File .\tests\Test-Offline.ps1
```

Verifica, en cualquier equipo y sin servidores: cálculos de red y nombres, rechazo de configuraciones inválidas, el diseño derivado, la lógica de validación (un estado correcto da 0 fallas y 11 tipos de defecto inyectados se detectan) y los bloques remotos de los pasos 4 y 5 ejecutados contra un Active Directory simulado en memoria (alta, idempotencia y reconciliación). Resultado actual: **44/44**.

## Estructura

```
Deploy.ps1                                 orquestador (pasos, estado, log, credencial)
config/                                    lab.psd1, usuarios.csv, accesos.csv
modules/00-Comun/Comun.psm1                log, configuración, estado, credenciales, nombres, red, remoting
modules/01-Diseno/                         validación de la configuración, diseño derivado, tablas y diagramas
modules/02-Despliegue/Invoke-Despliegue.ps1     servidores, bosque, dominio hijo, unión al dominio
modules/03-DNS/Invoke-DNS.ps1                   zonas, registros, reenviadores, delegación, verificación
modules/04-Estructura/Invoke-Estructura.ps1     OU y cuentas
modules/05-AccesoEntreDominios/Invoke-Acceso.ps1  AGUDLP, recursos compartidos, NTFS
modules/06-Validacion/                     Validacion.psm1 (comparaciones) + Invoke-Validacion.ps1 (recolección, pruebas de acceso, informe)
tests/Test-Offline.ps1                     pruebas sin laboratorio
output/                                    generado por el sistema
```
