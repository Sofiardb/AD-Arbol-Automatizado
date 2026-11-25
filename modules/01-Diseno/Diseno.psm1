#Requires -Version 3.0
<#
.SYNOPSIS
    Módulo 01 – Diseño de la arquitectura lógica y física (objetivo específico 1).

.DESCRIPTION
    Modelo: las CUENTAS se centralizan en el dominio padre y los RECURSOS en el dominio hijo.
    Los permisos se asignan en un solo sentido: cuentas del padre -> recursos del hijo (AGUDLP).

    A partir de la configuración mínima del usuario:
      1. Test-ConfigLab        valida la configuración (frena antes de tocar nada si hay errores).
      2. Get-DisenoDerivado    calcula todos los valores derivados: nombres, IP finales, DNS, OU,
                               cuentas, grupos AGUDLP, recursos, permisos y escenas de la demostración.
      3. Export-Diseno         genera diseno.json (lo usan los pasos 2 a 7), tablas CSV, diagramas
                               Mermaid, un resumen HTML y el guion de la demostración.
#>

Set-StrictMode -Version 2.0

# Valores por defecto de los servidores (rol -> nombre y desplazamiento de IP dentro de la red)
$script:DefectoServidores = @{
    DCRaiz = @{ Nombre = 'DC-RAIZ'; Desplazamiento = 10; Orden = 1 }
    DCHijo = @{ Nombre = 'DC-HIJO'; Desplazamiento = 11; Orden = 2 }
}
$script:NombreClienteDefecto = 'CLIENTE01'
$script:OUReservadas = @('Grupos', 'Equipos')
$script:NivelesValidos = @('Lectura', 'Modificar')
# Mapeo de niveles a permisos (enfoque 2: recurso compartido + NTFS por grupo)
$script:MapeoPermisos = @{
    Lectura   = @{ Compartido = 'Read';   NTFS = 'ReadAndExecute'; Rango = 1 }
    Modificar = @{ Compartido = 'Change'; NTFS = 'Modify';         Rango = 2 }
}

function Get-Valor {
    <# Devuelve $Tabla[$Clave] o el valor por defecto si no existe. #>
    param($Tabla, [string]$Clave, $Defecto = $null)
    if ($Tabla -is [System.Collections.IDictionary] -and $Tabla.Contains($Clave) -and $null -ne $Tabla[$Clave]) { return $Tabla[$Clave] }
    return $Defecto
}

function Test-ContrasenaCompleja {
    <# Política por defecto de un dominio: 7 o más caracteres y 3 de 4 clases. #>
    param([string]$Texto)
    if ($Texto.Length -lt 7) { return $false }
    $clases = 0
    if ($Texto -cmatch '[A-Z]') { $clases++ }
    if ($Texto -cmatch '[a-z]') { $clases++ }
    if ($Texto -match '\d') { $clases++ }
    if ($Texto -match '[^A-Za-z0-9]') { $clases++ }
    return ($clases -ge 3)
}

# =====================================================================
#  1. Validación
# =====================================================================
function Test-ConfigLab {
    <#
    .SYNOPSIS
        Valida lab.psd1, usuarios.csv y accesos.csv.
    .OUTPUTS
        Objeto con las listas Errores y Advertencias.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Config)

    $errores = New-Object System.Collections.Generic.List[string]
    $advert  = New-Object System.Collections.Generic.List[string]
    $lab = $Config.Lab

    # --- Claves obligatorias ---
    foreach ($clave in 'DominioRaiz', 'DominioHijo', 'Red', 'Gateway', 'Servidores', 'Areas') {
        if ($null -eq (Get-Valor $lab $clave)) { $errores.Add("lab.psd1: falta la clave obligatoria '$clave'.") }
    }
    if ($errores.Count) { return [pscustomobject]@{ Errores = $errores.ToArray(); Advertencias = $advert.ToArray() } }

    # --- Dominios ---
    $raiz = [string]$lab.DominioRaiz
    if ($raiz -notmatch '^(?=.{1,253}$)([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z][A-Za-z0-9-]{0,61}[A-Za-z0-9]$') {
        $errores.Add("DominioRaiz '$raiz' no es un FQDN válido (ej.: empresa.local).")
    }
    elseif ($raiz.Split('.')[0].Length -gt 15) {
        $errores.Add("La primera etiqueta de DominioRaiz ('$($raiz.Split('.')[0])') supera 15 caracteres: no sirve como nombre NetBIOS.")
    }
    $hijo = [string]$lab.DominioHijo
    if ($hijo -notmatch '^[A-Za-z0-9]([A-Za-z0-9-]{0,13}[A-Za-z0-9])?$') {
        $errores.Add("DominioHijo '$hijo' debe ser una sola etiqueta de hasta 15 caracteres, sin puntos (ej.: recursos).")
    }
    elseif ($hijo -ieq $raiz.Split('.')[0]) {
        $errores.Add("DominioHijo no puede tener el mismo nombre NetBIOS que el dominio raíz ('$hijo').")
    }

    # --- Red ---
    $infoRed = $null
    try { $infoRed = Get-InfoRed -Cidr $lab.Red } catch { $errores.Add("Red: $($_.Exception.Message)") }
    if ($infoRed) {
        if ($infoRed.Cidr -ne $lab.Red) { $advert.Add("Red '$($lab.Red)' se normalizó a '$($infoRed.Cidr)'.") }
        if (-not (Test-IPEnRed -IP $lab.Gateway -InfoRed $infoRed)) { $errores.Add("Gateway '$($lab.Gateway)' no es un host válido de la red $($infoRed.Cidr).") }
    }
    foreach ($r in @(Get-Valor $lab 'Reenviadores' @())) {
        if (-not (Test-FormatoIPv4 $r)) { $errores.Add("Reenviador DNS '$r' no es una IPv4 válida.") }
    }
    $nivelFuncional = Get-Valor $lab 'NivelFuncional' 'WinThreshold'
    if ($nivelFuncional -notin @('Win2012', 'Win2012R2', 'WinThreshold', 'Default')) {
        $errores.Add("NivelFuncional '$nivelFuncional' no soportado (use Win2012, Win2012R2 o WinThreshold).")
    }
    $usuarioAdmin = [string](Get-Valor $lab 'UsuarioAdministrador' 'Administrator')
    if ($usuarioAdmin -notmatch '^[^\\/@"\[\]:;|=,+*?<>]{1,20}$') { $errores.Add("UsuarioAdministrador '$usuarioAdmin' no es un nombre de cuenta válido.") }
    $zona = Get-Valor $lab 'ZonaHoraria'
    if ($zona -and $zona -notmatch '^[A-Za-z0-9 ()+.,_-]{3,64}$') { $errores.Add("ZonaHoraria '$zona' no parece un identificador de zona horaria de Windows (ej.: Argentina Standard Time).") }
    $demo = Get-Valor $lab 'ContrasenaDemo'
    if ($demo) {
        if (-not (Test-ContrasenaCompleja ([string]$demo))) { $errores.Add('ContrasenaDemo no cumple la complejidad del dominio (7 o más caracteres con mayúsculas, minúsculas, números o símbolos).') }
        $advert.Add('ContrasenaDemo está definida: todas las cuentas tendrán esa contraseña (válido solo para el laboratorio).')
    }

    # --- Servidores y cliente ---
    $servidores = @($lab.Servidores)
    $roles = @($servidores | ForEach-Object { $_.Rol })
    foreach ($rol in $script:DefectoServidores.Keys) {
        $cant = @($roles | Where-Object { $_ -eq $rol }).Count
        if ($cant -ne 1) { $errores.Add("Servidores: debe haber exactamente un servidor con Rol = '$rol' (hay $cant).") }
    }
    foreach ($rol in $roles) {
        if ($rol -notin $script:DefectoServidores.Keys) { $errores.Add("Servidores: Rol '$rol' desconocido (válidos: DCRaiz, DCHijo). El equipo de la demostración se define en la clave Cliente.") }
    }
    $equipos = @($servidores | ForEach-Object {
            $def = $null; if ($script:DefectoServidores.ContainsKey([string]$_.Rol)) { $def = $script:DefectoServidores[[string]$_.Rol] }
            [pscustomobject]@{ Etiqueta = "Servidor $($_.Rol)"; Datos = $_; NombreDefecto = $(if ($def) { $def.Nombre } else { '' }); Desplazamiento = $(if ($def) { $def.Desplazamiento } else { $null }) }
        })
    $cliente = Get-Valor $lab 'Cliente'
    if ($cliente) {
        if ($cliente -isnot [System.Collections.IDictionary]) { $errores.Add("Cliente: debe ser una tabla, por ejemplo @{ IPActual = '192.168.10.150' }.") }
        else {
            $equipos += [pscustomobject]@{ Etiqueta = 'Cliente'; Datos = $cliente; NombreDefecto = $script:NombreClienteDefecto; Desplazamiento = $null }
            $domCli = [string](Get-Valor $cliente 'Dominio' 'Raiz')
            if ($domCli -notin 'Raiz', 'Hijo') { $errores.Add("Cliente: Dominio '$domCli' debe ser Raiz o Hijo.") }
        }
    }
    else { $advert.Add('No se definió Cliente: se omitirá la preparación del equipo de la demostración (paso 6).') }

    $ipsFinales = @(); $nombres = @()
    foreach ($e in $equipos) {
        $s = $e.Datos
        $ipActual = Get-Valor $s 'IPActual'
        if (-not (Test-FormatoIPv4 $ipActual)) { $errores.Add("$($e.Etiqueta): IPActual '$ipActual' no es una IPv4 válida.") }
        $nombre = Get-Valor $s 'Nombre'
        if ($nombre) {
            if ($nombre -notmatch '^[A-Za-z0-9]([A-Za-z0-9-]{0,13}[A-Za-z0-9])?$') { $errores.Add("$($e.Etiqueta): Nombre '$nombre' inválido (hasta 15 caracteres, letras, números y guiones).") }
            $nombres += $nombre.ToUpperInvariant()
        }
        elseif ($e.NombreDefecto) { $nombres += $e.NombreDefecto }
        $ipFinal = Get-Valor $s 'IPFinal'
        if ($ipFinal) {
            if ($infoRed -and -not (Test-IPEnRed -IP $ipFinal -InfoRed $infoRed)) { $errores.Add("$($e.Etiqueta): IPFinal '$ipFinal' no pertenece a la red $($infoRed.Cidr).") }
            $ipsFinales += $ipFinal
        }
        elseif ($infoRed -and $null -ne $e.Desplazamiento) { $ipsFinales += Get-IPDesplazada -InfoRed $infoRed -Desplazamiento $e.Desplazamiento }
        elseif ($ipActual) {
            if ($infoRed -and (Test-FormatoIPv4 $ipActual) -and -not (Test-IPEnRed -IP $ipActual -InfoRed $infoRed)) { $errores.Add("$($e.Etiqueta): la IP $ipActual no pertenece a la red $($infoRed.Cidr) (defina IPFinal).") }
            $ipsFinales += $ipActual
        }
    }
    foreach ($d in @($ipsFinales | Group-Object | Where-Object Count -gt 1 | ForEach-Object Name)) { $errores.Add("Servidores/Cliente: la IP final $d está repetida.") }
    if ($lab.Gateway -in $ipsFinales) { $errores.Add("Servidores/Cliente: una IP final coincide con el Gateway ($($lab.Gateway)).") }
    foreach ($d in @($nombres | Group-Object | Where-Object Count -gt 1 | ForEach-Object Name)) { $errores.Add("Servidores/Cliente: el nombre $d está repetido.") }

    # --- Áreas (todas en el dominio padre) ---
    $areas = $lab.Areas
    if ($areas -is [System.Collections.IDictionary]) {
        $errores.Add("Areas: ahora es una lista simple (todas las cuentas están en el dominio padre), por ejemplo Areas = @('Gerencia', 'IT').")
        $areas = @()
    }
    $areas = @($areas)
    if ($areas.Count -eq 0 -and -not ($errores | Where-Object { $_ -like 'Areas:*' })) { $errores.Add('Areas: debe definir al menos un área.') }
    foreach ($a in $areas) {
        if ([string]::IsNullOrWhiteSpace($a) -or $a -match '[\\/,+"<>;=#]') { $errores.Add("Areas: nombre de área inválido '$a'.") }
        if ($a -in $script:OUReservadas) { $errores.Add("Areas: '$a' está reservado (OU de grupos o de equipos).") }
    }
    foreach ($d in @($areas | Group-Object | Where-Object Count -gt 1 | ForEach-Object Name)) { $errores.Add("Areas: el área '$d' está repetida.") }

    # --- usuarios.csv ---
    $usuarios = @($Config.Usuarios)
    if ($usuarios.Count -eq 0) { $advert.Add('usuarios.csv no tiene filas: no se darán de alta usuarios.') }
    else {
        $cols = $usuarios[0].PSObject.Properties.Name
        foreach ($c in 'Nombre', 'Apellido', 'Area') { if ($c -notin $cols) { $errores.Add("usuarios.csv: falta la columna '$c'.") } }
        if ('Dominio' -in $cols) { $advert.Add('usuarios.csv: la columna Dominio se ignora (todas las cuentas se crean en el dominio padre).') }
    }
    if (-not ($errores | Where-Object { $_ -like 'usuarios.csv: falta*' })) {
        $fila = 1
        foreach ($u in $usuarios) {
            $fila++
            if ([string]::IsNullOrWhiteSpace($u.Nombre) -or [string]::IsNullOrWhiteSpace($u.Apellido)) { $errores.Add("usuarios.csv fila $($fila): Nombre y Apellido son obligatorios.") }
            if ($u.Area -notin $areas) { $errores.Add("usuarios.csv fila $($fila): el área '$($u.Area)' no está definida en Areas.") }
        }
        foreach ($d in @($usuarios | Group-Object { "$($_.Nombre) $($_.Apellido)" } | Where-Object Count -gt 1)) { $advert.Add("usuarios.csv: '$($d.Name)' aparece $($d.Count) veces (se generarán cuentas distintas).") }
        foreach ($a in $areas) { if (-not ($usuarios | Where-Object { $_.Area -eq $a })) { $advert.Add("Areas: el área '$a' no tiene usuarios (su grupo global quedará vacío).") } }
    }

    # --- accesos.csv ---
    $accesos = @($Config.Accesos)
    if ($accesos.Count -eq 0) { $advert.Add('accesos.csv no tiene filas: no se crearán recursos compartidos.') }
    else {
        $cols = $accesos[0].PSObject.Properties.Name
        foreach ($c in 'Recurso', 'Area', 'Nivel') { if ($c -notin $cols) { $errores.Add("accesos.csv: falta la columna '$c'.") } }
    }
    if (-not ($errores | Where-Object { $_ -like 'accesos.csv: falta*' })) {
        $fila = 1
        foreach ($a in $accesos) {
            $fila++
            if ($a.Recurso -notmatch '^[A-Za-z0-9][A-Za-z0-9_-]{0,39}$') { $errores.Add("accesos.csv fila $($fila): Recurso '$($a.Recurso)' inválido (letras, números, '-' y '_', sin espacios, hasta 40).") }
            if ($a.Nivel -notin $script:NivelesValidos) { $errores.Add("accesos.csv fila $($fila): Nivel '$($a.Nivel)' inválido (válidos: $($script:NivelesValidos -join ', ')).") }
            if ($a.Area -notin $areas) { $errores.Add("accesos.csv fila $($fila): el área '$($a.Area)' no está definida en Areas.") }
        }
        foreach ($c in @($accesos | Group-Object { "$($_.Recurso)|$($_.Area)" } | Where-Object Count -gt 1)) {
            $errores.Add("accesos.csv: '$($c.Name.Replace('|', ' / '))' aparece $($c.Count) veces; defina un único nivel por recurso y área.")
        }
    }

    return [pscustomobject]@{ Errores = $errores.ToArray(); Advertencias = $advert.ToArray() }
}

# =====================================================================
#  2. Valores derivados
# =====================================================================
function Get-NivelArea {
    <# Nivel de un área sobre un recurso según accesos.csv (SinAcceso, Lectura o Modificar). #>
    param([object[]]$Accesos, [string]$Area, [string]$Recurso)
    $fila = @($Accesos | Where-Object { $_.Recurso -eq $Recurso -and $_.Area -eq $Area }) | Select-Object -First 1
    if ($fila) { return [string]$fila.Nivel }
    return 'SinAcceso'
}

function Get-EscenasDemo {
    <#
    .SYNOPSIS
        Elige qué mostrar en la demostración: un recurso donde haya un área con Modificar, otra con
        Lectura y otra sin acceso, y un usuario de cada una. Agrega una escena que muestra que el mismo
        usuario tiene permisos distintos según el recurso.
    #>
    param([object[]]$Accesos, [object[]]$Usuarios, [string[]]$Areas, [object[]]$Recursos, [string]$Servidor)
    $conUsuarios = @($Areas | Where-Object { $a = $_; @($Usuarios | Where-Object { $_.Area -eq $a }).Count -gt 0 })
    $primerUsuario = { param($area) @($Usuarios | Where-Object { $_.Area -eq $area })[0] }
    $elegido = $null
    foreach ($r in $Recursos) {
        $mod = @($conUsuarios | Where-Object { (Get-NivelArea $Accesos $_ $r.Nombre) -eq 'Modificar' })
        $lec = @($conUsuarios | Where-Object { (Get-NivelArea $Accesos $_ $r.Nombre) -eq 'Lectura' })
        $sin = @($conUsuarios | Where-Object { (Get-NivelArea $Accesos $_ $r.Nombre) -eq 'SinAcceso' })
        if ($mod.Count -and $lec.Count -and $sin.Count) { $elegido = @{ Recurso = $r; Mod = $mod[0]; Lec = $lec[0]; Sin = $sin[0] }; break }
    }
    if (-not $elegido) { return @() }

    $r = $elegido.Recurso
    $escena = {
        param($n, $area, $nivel, $recurso, $titulo, $acciones, $resultado)
        $u = & $primerUsuario $area
        [ordered]@{
            Numero = $n; Titulo = $titulo; Usuario = "$($u.NetBIOS)\$($u.Sam)"; UPN = $u.UPN; Nombre = $u.NombreCompleto; Area = $area
            Grupo = Get-NombreGrupoGlobal -NetBIOS $u.NetBIOS -Area $area; Recurso = $recurso.Nombre; UNC = $recurso.UNC; Nivel = $nivel
            Acciones = $acciones; Resultado = $resultado
        }
    }
    $escenas = @(
        (& $escena 1 $elegido.Mod 'Modificar' $r 'Usuario con permiso de modificación' `
            "Abrir $($r.UNC), crear un documento, editarlo y borrarlo." 'Puede listar, leer, crear, modificar y borrar.')
        (& $escena 2 $elegido.Lec 'Lectura' $r 'Usuario con permiso de solo lectura' `
            "Abrir $($r.UNC) y LEEME.txt; intentar crear un archivo o guardar cambios." 'Puede listar y leer. Al escribir, Windows responde "Acceso denegado".')
        (& $escena 3 $elegido.Sin 'SinAcceso' $r 'Usuario sin permiso sobre el recurso' `
            "Intentar abrir $($r.UNC)." 'Windows no permite abrir la carpeta: "No tiene permiso para acceder".')
    )
    # Mismo usuario, distinto recurso: el de solo lectura con Modificar en otro recurso
    foreach ($otro in $Recursos) {
        if ($otro.Nombre -eq $r.Nombre) { continue }
        if ((Get-NivelArea $Accesos $elegido.Lec $otro.Nombre) -eq 'Modificar') {
            $escenas += (& $escena 4 $elegido.Lec 'Modificar' $otro 'El mismo usuario, en otro recurso' `
                    "Con la misma sesión de la escena 2, abrir $($otro.UNC) y crear un archivo." 'Ahora sí puede escribir: los permisos dependen del recurso y del grupo, no del usuario.')
            break
        }
    }
    return $escenas
}

function Get-DisenoDerivado {
    <#
    .SYNOPSIS
        Calcula el diseño completo (lógico y físico) a partir de la configuración ya validada.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Config)

    $lab = $Config.Lab
    $infoRed = Get-InfoRed -Cidr $lab.Red
    $empresa = [string](Get-Valor $lab 'Empresa' '')
    $areas = @($lab.Areas)
    $accesos = @($Config.Accesos)

    # --- Dominios ---
    $fqdnRaiz = ([string]$lab.DominioRaiz).ToLowerInvariant()
    $etiquetaHijo = ([string]$lab.DominioHijo).ToLowerInvariant()
    $fqdnHijo = "$etiquetaHijo.$fqdnRaiz"
    $dnDe = { param($fqdn) ($fqdn.Split('.') | ForEach-Object { "DC=$_" }) -join ',' }
    $dominios = [ordered]@{
        Raiz = [ordered]@{ FQDN = $fqdnRaiz; NetBIOS = $fqdnRaiz.Split('.')[0].ToUpperInvariant(); DN = (& $dnDe $fqdnRaiz); Funcion = 'Cuentas' }
        Hijo = [ordered]@{ FQDN = $fqdnHijo; Etiqueta = $etiquetaHijo; NetBIOS = $etiquetaHijo.ToUpperInvariant(); DN = (& $dnDe $fqdnHijo); Padre = $fqdnRaiz; Funcion = 'Recursos' }
    }

    # --- Servidores ---
    $servidores = foreach ($s in @($lab.Servidores) | Sort-Object { $script:DefectoServidores[[string]$_.Rol].Orden }) {
        $def = $script:DefectoServidores[[string]$s.Rol]
        [ordered]@{
            Rol      = [string]$s.Rol
            Nombre   = ([string](Get-Valor $s 'Nombre' $def.Nombre)).ToUpperInvariant()
            IPActual = [string]$s.IPActual
            IPFinal  = [string](Get-Valor $s 'IPFinal' (Get-IPDesplazada -InfoRed $infoRed -Desplazamiento $def.Desplazamiento))
        }
    }
    $srvRaiz = $servidores | Where-Object { $_.Rol -eq 'DCRaiz' }
    $srvHijo = $servidores | Where-Object { $_.Rol -eq 'DCHijo' }
    foreach ($s in $servidores) {
        switch ($s.Rol) {
            'DCRaiz' { $s.Dominio = $fqdnRaiz; $s.Funcion = 'Controlador del dominio padre (cuentas) y DNS'; $s.Roles = @('AD-Domain-Services', 'DNS'); $s.DnsInicial = @($s.IPFinal); $s.DnsFinal = @($s.IPFinal, $srvHijo.IPFinal) }
            'DCHijo' { $s.Dominio = $fqdnHijo; $s.Funcion = 'Controlador del dominio hijo, DNS y servidor de archivos (recursos)'; $s.Roles = @('AD-Domain-Services', 'DNS', 'FS-FileServer'); $s.DnsInicial = @($srvRaiz.IPFinal); $s.DnsFinal = @($s.IPFinal, $srvRaiz.IPFinal) }
        }
        $s.FQDN = "$($s.Nombre).$($s.Dominio)".ToLowerInvariant()
        $s.NombrePTR = Get-NombrePTR -IP $s.IPFinal -ZonaInversa $infoRed.ZonaInversa
    }

    # --- Cliente de la demostración ---
    $cliente = $null
    $cfgCli = Get-Valor $lab 'Cliente'
    if ($cfgCli) {
        $claveDom = [string](Get-Valor $cfgCli 'Dominio' 'Raiz')
        $dcPropio = $srvRaiz; $dcOtro = $srvHijo
        if ($claveDom -eq 'Hijo') { $dcPropio = $srvHijo; $dcOtro = $srvRaiz }
        $nombreCli = ([string](Get-Valor $cfgCli 'Nombre' $script:NombreClienteDefecto)).ToUpperInvariant()
        $cliente = [ordered]@{
            Nombre = $nombreCli; IPActual = [string]$cfgCli.IPActual; IPFinal = [string](Get-Valor $cfgCli 'IPFinal' $cfgCli.IPActual)
            DominioClave = $claveDom; Dominio = $dominios[$claveDom].FQDN; NetBIOSDominio = $dominios[$claveDom].NetBIOS
            FQDN = "$nombreCli.$($dominios[$claveDom].FQDN)".ToLowerInvariant(); OU = "OU=Equipos,$($dominios[$claveDom].DN)"
            DnsFinal = @($dcPropio.IPFinal, $dcOtro.IPFinal); CarpetaDemo = 'C:\Demo'
        }
    }

    # --- OU: áreas + Grupos (+ Equipos) en el padre; Grupos en el hijo ---
    $ous = New-Object System.Collections.Generic.List[object]
    foreach ($area in $areas) { $ous.Add([ordered]@{ Dominio = 'Raiz'; DominioFQDN = $fqdnRaiz; Nombre = $area; DN = "OU=$area,$($dominios.Raiz.DN)"; Padre = $dominios.Raiz.DN; Descripcion = "Cuentas del área $area" }) }
    $ous.Add([ordered]@{ Dominio = 'Raiz'; DominioFQDN = $fqdnRaiz; Nombre = 'Grupos'; DN = "OU=Grupos,$($dominios.Raiz.DN)"; Padre = $dominios.Raiz.DN; Descripcion = 'Grupos globales por área (G de AGUDLP)' })
    $ous.Add([ordered]@{ Dominio = 'Hijo'; DominioFQDN = $fqdnHijo; Nombre = 'Grupos'; DN = "OU=Grupos,$($dominios.Hijo.DN)"; Padre = $dominios.Hijo.DN; Descripcion = 'Grupos de dominio local por recurso y nivel (DL de AGUDLP)' })
    if ($cliente) {
        $d = $dominios[$cliente.DominioClave]
        $ous.Add([ordered]@{ Dominio = $cliente.DominioClave; DominioFQDN = $d.FQDN; Nombre = 'Equipos'; DN = "OU=Equipos,$($d.DN)"; Padre = $d.DN; Descripcion = 'Equipos cliente' })
    }

    # --- Usuarios (todos en el dominio padre) ---
    $d = $dominios.Raiz
    $sams = New-Object 'System.Collections.Generic.HashSet[string]'
    $usuarios = foreach ($u in @($Config.Usuarios)) {
        $sam = Get-NombreSam -Nombre $u.Nombre.Trim() -Apellido $u.Apellido.Trim() -Existentes $sams
        $opc = @{}
        foreach ($c in 'Cargo', 'Telefono', 'Oficina') {
            $opc[$c] = ''
            if ($u.PSObject.Properties.Name -contains $c -and $u.$c) { $opc[$c] = ([string]$u.$c).Trim() }
        }
        $completo = "$($u.Nombre.Trim()) $($u.Apellido.Trim())"
        [ordered]@{
            Nombre = $u.Nombre.Trim(); Apellido = $u.Apellido.Trim(); NombreCompleto = $completo
            CN = $completo   # nombre del objeto en AD; se desambigua más abajo si se repite en la misma OU
            Sam = $sam; UPN = "$sam@$($d.FQDN)"; Dominio = 'Raiz'; DominioFQDN = $d.FQDN; NetBIOS = $d.NetBIOS
            Area = $u.Area; OU = "OU=$($u.Area),$($d.DN)"
            Cargo = $opc.Cargo; Telefono = $opc.Telefono; Oficina = $opc.Oficina; Empresa = $empresa
            Descripcion = (@($opc.Cargo, $u.Area) | Where-Object { $_ }) -join ' - '
        }
    }
    $usuarios = @($usuarios)
    foreach ($g in @($usuarios | Group-Object { "$($_.OU)|$($_.CN)" } | Where-Object Count -gt 1)) {
        foreach ($u in $g.Group) { $u.CN = "$($u.NombreCompleto) ($($u.Sam))" }
    }

    # --- A -> G: grupos globales por área, en el dominio padre ---
    $gruposGlobales = foreach ($area in $areas) {
        [ordered]@{
            Nombre = Get-NombreGrupoGlobal -NetBIOS $d.NetBIOS -Area $area; Ambito = 'Global'; Dominio = 'Raiz'; DominioFQDN = $d.FQDN
            OU = "OU=Grupos,$($d.DN)"; Area = $area; Descripcion = "Usuarios del área $area"
            Miembros = @($usuarios | Where-Object { $_.Area -eq $area } | ForEach-Object { $_.Sam })
        }
    }

    # --- G -> DL: grupos de dominio local por recurso y nivel, en el dominio hijo (donde están los recursos) ---
    $h = $dominios.Hijo
    $gruposDL = foreach ($g in @($accesos | Group-Object { "$($_.Recurso)|$($_.Nivel)" })) {
        $recurso, $nivel = $g.Name.Split('|')
        [ordered]@{
            Nombre = Get-NombreGrupoDL -Recurso $recurso -Nivel $nivel; Ambito = 'DomainLocal'; Dominio = 'Hijo'; DominioFQDN = $h.FQDN
            OU = "OU=Grupos,$($h.DN)"; Recurso = $recurso; Nivel = $nivel; Descripcion = "Permiso $nivel sobre \\$($srvHijo.Nombre)\$recurso"
            Miembros = @($g.Group | ForEach-Object {
                    $gg = Get-NombreGrupoGlobal -NetBIOS $d.NetBIOS -Area $_.Area
                    [ordered]@{ Grupo = $gg; DominioFQDN = $d.FQDN; Referencia = "$($d.NetBIOS)\$gg" }
                })
        }
    }
    $gruposDL = @($gruposDL)

    # --- DL -> P: recursos compartidos en DC-HIJO (permisos por grupo en recurso compartido y NTFS) ---
    $rutaBase = [string](Get-Valor $lab 'RutaRecursos' 'C:\Recursos')
    $recursos = foreach ($nombreRecurso in @($accesos | ForEach-Object { $_.Recurso } | Select-Object -Unique)) {
        $niveles = @($gruposDL | Where-Object { $_.Recurso -eq $nombreRecurso } | ForEach-Object { $_.Nivel })
        $compartido = @([ordered]@{ Cuenta = 'BUILTIN\Administrators'; Permiso = 'Full' })
        $ntfs = @(
            [ordered]@{ Cuenta = 'BUILTIN\Administrators'; Permiso = 'FullControl' }
            [ordered]@{ Cuenta = 'NT AUTHORITY\SYSTEM'; Permiso = 'FullControl' }
        )
        foreach ($nivel in $script:NivelesValidos) {
            if ($nivel -in $niveles) {
                $cuenta = "$($h.NetBIOS)\$(Get-NombreGrupoDL -Recurso $nombreRecurso -Nivel $nivel)"
                $compartido += [ordered]@{ Cuenta = $cuenta; Permiso = $script:MapeoPermisos[$nivel].Compartido }
                $ntfs       += [ordered]@{ Cuenta = $cuenta; Permiso = $script:MapeoPermisos[$nivel].NTFS }
            }
        }
        [ordered]@{
            Nombre = $nombreRecurso; Servidor = $srvHijo.Nombre; RutaLocal = "$($rutaBase.TrimEnd('\'))\$nombreRecurso"   # ruta en el servidor remoto
            UNC = "\\$($srvHijo.FQDN)\$nombreRecurso"; ABE = $true; HerenciaDeshabilitada = $true
            PermisosCompartido = $compartido; PermisosNTFS = $ntfs
        }
    }
    $recursos = @($recursos)

    # --- Matriz de acceso esperado (para documentación, validación y demostración) ---
    $matriz = foreach ($u in $usuarios) {
        foreach ($r in $recursos) {
            $nivel = Get-NivelArea $accesos $u.Area $r.Nombre
            $red = 'Denegado'; $local = 'Denegado'
            if ($nivel -ne 'SinAcceso') {
                $red = "$nivel (compartido: $($script:MapeoPermisos[$nivel].Compartido) / NTFS: $($script:MapeoPermisos[$nivel].NTFS))"
                $local = "$nivel (NTFS: $($script:MapeoPermisos[$nivel].NTFS))"
            }
            [ordered]@{ Usuario = "$($u.NetBIOS)\$($u.Sam)"; Area = $u.Area; Recurso = $r.Nombre; NivelEsperado = $nivel; AccesoRed = $red; AccesoLocal = $local }
        }
    }
    # Nivel de cada grupo global sobre cada recurso (lo usa el script de la demostración en el cliente)
    $nivelesPorGrupo = foreach ($g in $gruposGlobales) {
        [ordered]@{ Grupo = $g.Nombre; Area = $g.Area; Niveles = @($recursos | ForEach-Object { [ordered]@{ Recurso = $_.Nombre; Nivel = (Get-NivelArea $accesos $g.Area $_.Nombre) } }) }
    }

    $contrasenaDemo = [string](Get-Valor $lab 'ContrasenaDemo' '')
    return [ordered]@{
        Generado       = (Get-Date -Format 's')
        Parametros     = [ordered]@{
            Empresa = $empresa; NivelFuncional = [string](Get-Valor $lab 'NivelFuncional' 'WinThreshold'); RutaRecursos = $rutaBase
            ZonaHoraria = [string](Get-Valor $lab 'ZonaHoraria' ''); UsuarioAdministrador = [string](Get-Valor $lab 'UsuarioAdministrador' 'Administrator')
            ContrasenaDemo = $contrasenaDemo; CambiarContrasenaAlIniciar = (-not $contrasenaDemo)
            EnfoquePermisos = 'PorGrupo (recurso compartido + NTFS)'; Sentido = "Cuentas de $fqdnRaiz -> recursos de $fqdnHijo"
        }
        Dominios       = $dominios
        Red            = [ordered]@{
            Cidr = $infoRed.Cidr; Mascara = $infoRed.Mascara; Prefijo = $infoRed.Prefijo; Gateway = [string]$lab.Gateway
            ZonaInversa = $infoRed.ZonaInversa; NetworkIdZona = $infoRed.NetworkIdZona; Reenviadores = @(Get-Valor $lab 'Reenviadores' @())
        }
        Servidores     = @($servidores)
        Cliente        = $cliente
        OUs            = $ous.ToArray()
        Usuarios       = $usuarios
        GruposGlobales = @($gruposGlobales)
        GruposDL       = $gruposDL
        Recursos       = $recursos
        MatrizAcceso   = @($matriz)
        NivelesPorGrupo = @($nivelesPorGrupo)
        Demo           = [ordered]@{ Escenas = @(Get-EscenasDemo -Accesos $accesos -Usuarios $usuarios -Areas $areas -Recursos $recursos -Servidor $srvHijo.Nombre) }
    }
}

# =====================================================================
#  3. Exportación (diseno.json, tablas, diagramas, resumen, guion de la demostración)
# =====================================================================
function ConvertTo-TablaHtml {
    param([object[]]$Filas, [string[]]$Columnas)
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append('<table><thead><tr>')
    foreach ($c in $Columnas) { [void]$sb.Append("<th>$([System.Net.WebUtility]::HtmlEncode($c))</th>") }
    [void]$sb.Append('</tr></thead><tbody>')
    foreach ($f in $Filas) {
        [void]$sb.Append('<tr>')
        foreach ($c in $Columnas) { [void]$sb.Append("<td>$([System.Net.WebUtility]::HtmlEncode([string]$f.$c))</td>") }
        [void]$sb.Append('</tr>')
    }
    [void]$sb.Append('</tbody></table>')
    return $sb.ToString()
}

function Get-DiagramaLogico {
    <#
    .SYNOPSIS
        Estructura lógica: bosque, dominio padre (cuentas) e hijo (recursos), y la cadena AGUDLP
        resumida, con un ejemplo concreto tomado de la escena 1 y 2 de la demostración.
        La matriz completa área x recurso va en tablas (un diagrama con todas las relaciones sería ilegible).
    #>
    param($Diseno)
    $r = $Diseno.Dominios.Raiz; $h = $Diseno.Dominios.Hijo
    $srvHijo = @($Diseno.Servidores | Where-Object { $_.Rol -eq 'DCHijo' })[0]
    $l = New-Object System.Collections.Generic.List[string]
    $l.Add('flowchart LR')
    $l.Add("  subgraph PADRE[""Dominio padre (raíz del bosque)<br/>$($r.FQDN) · NetBIOS $($r.NetBIOS)<br/>centraliza las CUENTAS""]")
    $l.Add("    A[""A · $(@($Diseno.Usuarios).Count) cuentas de usuario<br/>en $(@($Diseno.GruposGlobales).Count) OU, una por área""]")
    $l.Add("    G[""G · $(@($Diseno.GruposGlobales).Count) grupos globales<br/>GG-$($r.NetBIOS)-&lt;Área&gt;""]")
    $l.Add('    A -->|"miembro de"| G')
    $l.Add('  end')
    $l.Add("  subgraph HIJO[""Dominio hijo<br/>$($h.FQDN) · NetBIOS $($h.NetBIOS)<br/>aloja los RECURSOS""]")
    $l.Add("    DL[""DL · $(@($Diseno.GruposDL).Count) grupos de dominio local<br/>DL-&lt;Recurso&gt;-&lt;Nivel&gt;""]")
    $l.Add("    P[(""P · $(@($Diseno.Recursos).Count) recursos compartidos<br/>\\$($srvHijo.Nombre)\&lt;Recurso&gt;<br/>permisos de recurso compartido y NTFS"")]")
    $l.Add('    DL -->|"Lectura / Modificar"| P')
    $l.Add('  end')
    $l.Add('  G -->|"miembro de<br/>(entre dominios)"| DL')
    $l.Add('  PADRE <-.->|"confianza padre-hijo<br/>bidireccional y transitiva"| HIJO')

    $esc = @($Diseno.Demo.Escenas | Where-Object { $_.Nivel -ne 'SinAcceso' } | Select-Object -First 2)
    if ($esc.Count) {
        $l.Add('  subgraph EJ["Ejemplo (escenas de la demostración)"]')
        $l.Add('    direction LR')
        $i = 0
        foreach ($e in $esc) {
            $i++
            $l.Add("    EU$i[""$($e.Usuario)<br/>$($e.Nombre)""] --> EG$i[""$($r.NetBIOS)\$($e.Grupo)""] --> ED$i[""$($h.NetBIOS)\DL-$($e.Recurso)-$($e.Nivel)""] --> ER$i[(""$($e.Recurso)<br/>$($e.Nivel)"")]")
        }
        $l.Add('  end')
    }
    return ($l -join "`n")
}

function Get-DiagramaFisico {
    param($Diseno)
    $l = New-Object System.Collections.Generic.List[string]
    $l.Add('flowchart LR')
    $l.Add("  RED{{""Red $($Diseno.Red.Cidr)<br/>Gateway $($Diseno.Red.Gateway)""}}")
    foreach ($s in $Diseno.Servidores) {
        $l.Add("  $($s.Nombre -replace '-', '_')[""$($s.Nombre)<br/>$($s.IPFinal)<br/>$($s.Dominio)<br/>$($s.Roles -join ', ')""] --- RED")
    }
    if ($Diseno.Cliente) {
        $c = $Diseno.Cliente
        $l.Add("  $($c.Nombre -replace '-', '_')[/""$($c.Nombre) (cliente)<br/>$($c.IPFinal)<br/>miembro de $($c.Dominio)""/] --- RED")
    }
    return ($l -join "`n")
}

$script:EstiloHtml = @'
<style>
 body{font-family:Segoe UI,Arial,sans-serif;margin:24px;color:#222;background:#fff;max-width:1200px}
 h1{color:#1F4E79} h2{color:#1F4E79;border-bottom:2px solid #D9E2F3;padding-bottom:4px;margin-top:32px} h3{color:#2E5C8A;margin-bottom:4px}
 table{border-collapse:collapse;margin:8px 0 16px;font-size:13px} th,td{border:1px solid #A6A6A6;padding:4px 8px;text-align:left;vertical-align:top}
 th{background:#D9E2F3} .mermaid{background:#fafafa;border:1px solid #ddd;padding:8px;margin:8px 0}
 code{background:#f2f2f2;padding:1px 4px;border-radius:3px} pre.cmd{background:#1e1e1e;color:#eee;padding:10px;border-radius:4px;overflow-x:auto}
 .escena{border:1px solid #ccd;border-left:6px solid #1F4E79;border-radius:4px;padding:8px 14px;margin:12px 0;background:#fbfcff}
 .ok{color:#2E7D32;font-weight:bold} .no{color:#C62828;font-weight:bold} .lec{color:#B26A00;font-weight:bold}
 .nota{font-size:12px;color:#666}
</style>
'@

function Get-ClaseNivel { param([string]$Nivel) switch ($Nivel) { 'Modificar' { 'ok' } 'Lectura' { 'lec' } default { 'no' } } }

function Export-GuionDemo {
    <# Guion de la demostración: qué ejecutar, qué mostrar y qué debe pasar en el cliente. #>
    param($Diseno, [string]$Carpeta)
    $enc = { param($t) [System.Net.WebUtility]::HtmlEncode([string]$t) }
    $r = $Diseno.Dominios.Raiz; $h = $Diseno.Dominios.Hijo
    $srvHijo = @($Diseno.Servidores | Where-Object { $_.Rol -eq 'DCHijo' })[0]
    $cli = $Diseno.Cliente
    $pass = $Diseno.Parametros.ContrasenaDemo
    $textoPass = "<code>$(& $enc $pass)</code> (ContrasenaDemo de lab.psd1)"
    if (-not $pass) { $textoPass = 'la de <code>output\credenciales-iniciales.csv</code> (se pide cambiarla al iniciar sesión)' }
    $nombreCli = 'el cliente'; if ($cli) { $nombreCli = $cli.Nombre }

    $sb = New-Object System.Text.StringBuilder
    foreach ($e in $Diseno.Demo.Escenas) {
        $dl = "$($h.NetBIOS)\DL-$($e.Recurso)-$($e.Nivel)"
        $cadena = "$(& $enc $e.Usuario) &rarr; $(& $enc "$($r.NetBIOS)\$($e.Grupo)") (global, padre) &rarr; $(& $enc $dl) (dominio local, hijo) &rarr; $(& $enc $e.UNC)"
        if ($e.Nivel -eq 'SinAcceso') { $cadena = "$(& $enc "$($r.NetBIOS)\$($e.Grupo)") no es miembro de ningún grupo DL-$(& $enc $e.Recurso)-*: ni el recurso compartido ni NTFS le dan permisos." }
        [void]$sb.Append(@"
<div class="escena"><h3>Escena $($e.Numero) – $(& $enc $e.Titulo)</h3>
<p><b>Iniciar sesión en $(& $enc $nombreCli) como</b> <code>$(& $enc $e.Usuario)</code> ($(& $enc $e.Nombre), área $(& $enc $e.Area)) · contraseña: $textoPass</p>
<p><b>Hacer:</b> $(& $enc $e.Acciones)</p>
<p><b>Resultado esperado:</b> <span class="$(Get-ClaseNivel $e.Nivel)">$(& $enc $e.Resultado)</span></p>
<p><b>Por qué:</b> $cadena</p></div>
"@)
    }
    if (-not @($Diseno.Demo.Escenas).Count) { [void]$sb.Append('<p>No se encontró un recurso con un área con Modificar, otra con Lectura y otra sin acceso: revise accesos.csv.</p>') }

    # Tabla de acceso de los usuarios de la demostración
    $usuariosDemo = @($Diseno.Demo.Escenas | ForEach-Object { $_.Usuario } | Select-Object -Unique)
    $filas = New-Object System.Text.StringBuilder
    [void]$filas.Append('<table><thead><tr><th>Cuenta</th>')
    foreach ($rec in $Diseno.Recursos) { [void]$filas.Append("<th>$(& $enc $rec.Nombre)</th>") }
    [void]$filas.Append('</tr></thead><tbody>')
    foreach ($u in $usuariosDemo) {
        [void]$filas.Append("<tr><td><code>$(& $enc $u)</code></td>")
        foreach ($rec in $Diseno.Recursos) {
            $n = (@($Diseno.MatrizAcceso | Where-Object { $_.Usuario -eq $u -and $_.Recurso -eq $rec.Nombre })[0]).NivelEsperado
            $t = switch ($n) { 'Modificar' { 'Modificar' } 'Lectura' { 'Lectura' } default { '—' } }
            [void]$filas.Append("<td class='$(Get-ClaseNivel $n)'>$t</td>")
        }
        [void]$filas.Append('</tr>')
    }
    [void]$filas.Append('</tbody></table>')

    $carpetaDemo = 'C:\Demo'; if ($cli) { $carpetaDemo = $cli.CarpetaDemo }
    $html = @"
<!DOCTYPE html>
<html lang="es"><head><meta charset="utf-8"><title>Guion de la demostración – $($r.FQDN)</title>$($script:EstiloHtml)</head><body>
<h1>Guion de la demostración</h1>
<p><b>$(& $enc $Diseno.Parametros.Empresa)</b> · cuentas en <b>$($r.FQDN)</b> (padre) · recursos en <b>$($h.FQDN)</b> (hijo) · equipo de la demostración: <b>$(& $enc $nombreCli)</b></p>
<p>Objetivo: mostrar que usuarios con cuenta en el dominio padre acceden a recursos del dominio hijo con los permisos que les da su área, mediante la estrategia AGUDLP
(cuenta &rarr; grupo <b>G</b>lobal en el padre &rarr; grupo de <b>D</b>ominio <b>L</b>ocal en el hijo &rarr; <b>P</b>ermisos del recurso compartido y NTFS).</p>

<h2>Parte 1 – Creación automatizada de la estructura</h2>
<ol>
<li>En el equipo de administración (puede ser $(& $enc $nombreCli) antes de unirlo al dominio), abrir PowerShell como administrador en la carpeta del proyecto.</li>
<li>Mostrar la configuración: <code>config\lab.psd1</code> (dominios, red, servidores, áreas), <code>config\usuarios.csv</code> ($(@($Diseno.Usuarios).Count) empleados) y <code>config\accesos.csv</code> (qué área accede a qué recurso y con qué nivel).</li>
<li><code>.\Deploy.ps1 -SoloDiseno</code> y abrir <code>output\diseno\diseno.html</code>: diagramas lógico y físico, cuentas, grupos y permisos calculados.</li>
<li><code>.\Deploy.ps1</code>: se ingresa una sola contraseña y se ve cada paso en pantalla (log en <code>output\logs</code>):
 <ol><li>Diseño</li><li>Despliegue: bosque <b>$($r.FQDN)</b> en $(& $enc ($Diseno.Servidores[0].Nombre)) y dominio hijo <b>$($h.FQDN)</b> en $(& $enc $srvHijo.Nombre)</li>
 <li>DNS: zona inversa, delegación, reenviadores, verificación de registros SRV</li><li>Cuentas: OU por área y alta masiva desde el CSV</li>
 <li>Acceso: grupos globales en el padre, grupos de dominio local en el hijo, carpetas compartidas con permisos</li><li>Cliente: unión al dominio y accesos directos de la demostración</li><li>Validación automática con informe HTML</li></ol></li>
<li>Mostrar el resultado en las consolas de Windows:
 <ul><li><b>Usuarios y equipos de AD</b> en $(& $enc ($Diseno.Servidores[0].Nombre)): OU de cada área con sus cuentas y la OU <i>Grupos</i> con los grupos globales GG-$($r.NetBIOS)-*.</li>
 <li>En $(& $enc $srvHijo.Nombre): OU <i>Grupos</i> con los grupos DL-*; en la pestaña <i>Miembros</i> de uno de ellos aparecen grupos <b>$($r.NetBIOS)\GG-*</b> del otro dominio.</li>
 <li><b>Dominios y confianzas de AD</b>: confianza padre-hijo bidireccional y transitiva.</li>
 <li>Propiedades de una carpeta en <code>$(& $enc $Diseno.Parametros.RutaRecursos)</code> de $(& $enc $srvHijo.Nombre): pestañas <i>Compartir &rarr; Permisos</i> y <i>Seguridad</i> (solo grupos DL, sin <i>Todos</i>, herencia deshabilitada).</li></ul></li>
</ol>

<h2>Parte 2 – Demostración en $(& $enc $nombreCli)</h2>
<p>En el escritorio de cualquier usuario hay una carpeta <b>Recursos de $($h.FQDN)</b> con accesos directos a los $(@($Diseno.Recursos).Count) recursos, y el acceso directo <b>Probar mis permisos</b>, que ejecuta <code>$carpetaDemo\Probar-Permisos.ps1</code>: muestra la cuenta, sus grupos y una tabla con lo que puede hacer en cada recurso.</p>
$($sb.ToString())
<h3>Accesos de los usuarios de la demostración</h3>
$($filas.ToString())
<h3>Para explicar mientras se muestra</h3>
<ul>
<li><code>whoami /groups</code> en el cliente muestra los grupos <b>globales</b> del padre (GG-$($r.NetBIOS)-*). Los grupos de dominio local del hijo <b>no aparecen ahí</b>: se agregan al token cuando el usuario se autentica en $(& $enc $srvHijo.Nombre), porque un grupo de dominio local solo tiene validez en su propio dominio.</li>
<li>La cuenta nunca recibe permisos directos: alcanza con cambiarla de grupo global (o cambiar <code>accesos.csv</code> y ejecutar <code>.\Deploy.ps1 -Paso 5</code>) para cambiar lo que puede hacer. Los cambios de grupo se aplican al volver a iniciar sesión.</li>
<li>El permiso efectivo por red es el más restrictivo entre el del recurso compartido y el NTFS; en este diseño ambos se otorgan al mismo grupo con el mismo nivel (Lectura = Read / ReadAndExecute, Modificar = Change / Modify).</li>
<li>Con la enumeración basada en el acceso (ABE) cada usuario ve dentro del recurso solo los archivos y carpetas a los que tiene acceso.</li>
</ul>

<h2>Parte 3 – Cierre</h2>
<p>Abrir <code>output\validacion\informe-validacion.html</code>: el script comprobó por sí mismo la estructura, el DNS, los grupos, los permisos y el acceso real de una cuenta de prueba por área a cada recurso.</p>
<p class="nota">Generado el $($Diseno.Generado) a partir de la carpeta config.</p>
</body></html>
"@
    Set-Content -Path (Join-Path $Carpeta 'guion-demostracion.html') -Value $html -Encoding UTF8
}

function Export-Diseno {
    <#
    .SYNOPSIS
        Escribe en <RutaSalida>\diseno los artefactos del diseño.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Diseno, [Parameter(Mandatory)][string]$RutaSalida)

    $carpeta = Join-Path $RutaSalida 'diseno'
    if (-not (Test-Path $carpeta)) { New-Item -Path $carpeta -ItemType Directory -Force | Out-Null }

    # diseno.json (insumo de los pasos 2 a 7)
    ConvertTo-Json -InputObject $Diseno -Depth 10 | Set-Content -Path (Join-Path $RutaSalida 'diseno.json') -Encoding UTF8

    # Tablas para el documento
    $tablaServidores = @($Diseno.Servidores | ForEach-Object { [pscustomobject]@{ Equipo = $_.Nombre; Funcion = $_.Funcion; Dominio = $_.Dominio; 'IP actual' = $_.IPActual; 'IP final' = $_.IPFinal; DNS = ($_.DnsFinal -join ', '); 'Roles instalados' = ($_.Roles -join ', ') } })
    if ($Diseno.Cliente) {
        $c = $Diseno.Cliente
        $tablaServidores += [pscustomobject]@{ Equipo = $c.Nombre; Funcion = 'Cliente de la demostración'; Dominio = $c.Dominio; 'IP actual' = $c.IPActual; 'IP final' = $c.IPFinal; DNS = ($c.DnsFinal -join ', '); 'Roles instalados' = '' }
    }
    $tablaUsuarios   = $Diseno.Usuarios | ForEach-Object { [pscustomobject]@{ Usuario = $_.NombreCompleto; Cuenta = "$($_.NetBIOS)\$($_.Sam)"; UPN = $_.UPN; Area = $_.Area; Cargo = $_.Cargo; Oficina = $_.Oficina; OU = $_.OU } }
    $tablaGrupos     = @($Diseno.GruposGlobales | ForEach-Object { [pscustomobject]@{ Grupo = $_.Nombre; Ambito = 'Global'; Dominio = $_.DominioFQDN; Miembros = ($_.Miembros -join ', ') } }) +
                       @($Diseno.GruposDL      | ForEach-Object { [pscustomobject]@{ Grupo = $_.Nombre; Ambito = 'Dominio local'; Dominio = $_.DominioFQDN; Miembros = (($_.Miembros | ForEach-Object { $_.Referencia }) -join ', ') } })
    $tablaPermisos   = foreach ($r in $Diseno.Recursos) {
        foreach ($p in $r.PermisosCompartido) { [pscustomobject]@{ Recurso = $r.UNC; Tipo = 'Recurso compartido'; Cuenta = $p.Cuenta; Permiso = $p.Permiso } }
        foreach ($p in $r.PermisosNTFS)       { [pscustomobject]@{ Recurso = $r.RutaLocal; Tipo = 'NTFS'; Cuenta = $p.Cuenta; Permiso = $p.Permiso } }
    }
    $tablaMatriz     = $Diseno.MatrizAcceso | ForEach-Object { New-Object PSObject -Property $_ }
    # Matriz resumida área x recurso
    $tablaAreas = foreach ($g in $Diseno.NivelesPorGrupo) {
        $o = [ordered]@{ Area = $g.Area; Grupo = $g.Grupo }
        foreach ($n in $g.Niveles) { $o[$n.Recurso] = $(if ($n.Nivel -eq 'SinAcceso') { '—' } else { $n.Nivel }) }
        New-Object PSObject -Property $o
    }

    $tablaServidores | Export-Csv (Join-Path $carpeta 'equipos.csv') -NoTypeInformation -Encoding UTF8
    $tablaUsuarios   | Export-Csv (Join-Path $carpeta 'usuarios.csv')   -NoTypeInformation -Encoding UTF8
    $tablaGrupos     | Export-Csv (Join-Path $carpeta 'grupos.csv')     -NoTypeInformation -Encoding UTF8
    $tablaPermisos   | Export-Csv (Join-Path $carpeta 'permisos.csv')   -NoTypeInformation -Encoding UTF8
    $tablaMatriz     | Export-Csv (Join-Path $carpeta 'matriz-acceso.csv') -NoTypeInformation -Encoding UTF8
    $tablaAreas      | Export-Csv (Join-Path $carpeta 'matriz-areas.csv')  -NoTypeInformation -Encoding UTF8

    # Diagramas (Mermaid)
    $logico = Get-DiagramaLogico -Diseno $Diseno
    $fisico = Get-DiagramaFisico -Diseno $Diseno
    Set-Content -Path (Join-Path $carpeta 'diagrama-logico.mmd') -Value $logico -Encoding UTF8
    Set-Content -Path (Join-Path $carpeta 'diagrama-fisico.mmd') -Value $fisico -Encoding UTF8

    # Resumen HTML (diagramas + tablas). Mermaid se carga desde CDN para dibujar los diagramas.
    $r = $Diseno.Dominios.Raiz; $h = $Diseno.Dominios.Hijo
    $columnasAreas = @('Area') + @($Diseno.Recursos | ForEach-Object { $_.Nombre })
    $html = @"
<!DOCTYPE html>
<html lang="es"><head><meta charset="utf-8"><title>Diseño – $($r.FQDN)</title>
$($script:EstiloHtml)
<script src="https://cdn.jsdelivr.net/npm/mermaid@10.9.1/dist/mermaid.min.js"></script>
<script>mermaid.initialize({startOnLoad:true, flowchart:{useMaxWidth:true}});</script>
</head><body>
<h1>Diseño de la solución – $($r.FQDN) / $($h.FQDN)</h1>
<p><b>$([System.Net.WebUtility]::HtmlEncode($Diseno.Parametros.Empresa))</b> · cuentas centralizadas en <b>$($r.FQDN)</b>, recursos en <b>$($h.FQDN)</b></p>
<p>Generado: $($Diseno.Generado) · Enfoque de permisos: $($Diseno.Parametros.EnfoquePermisos) · Nivel funcional: $($Diseno.Parametros.NivelFuncional)</p>
<h2>Arquitectura lógica</h2><pre class="mermaid">
$([System.Net.WebUtility]::HtmlEncode($logico))
</pre>
<h2>Arquitectura física</h2><pre class="mermaid">
$([System.Net.WebUtility]::HtmlEncode($fisico))
</pre>
<p class="nota">Los diagramas se dibujan con Mermaid (requiere conexión a Internet). Sin conexión, pegar los archivos .mmd en https://mermaid.live.</p>
<h2>Red y DNS</h2>
<p>Red $($Diseno.Red.Cidr) (máscara $($Diseno.Red.Mascara)) · Gateway $($Diseno.Red.Gateway) · Zona inversa $($Diseno.Red.ZonaInversa) · Reenviadores: $(($Diseno.Red.Reenviadores) -join ', ')</p>
<h2>Equipos</h2>$(ConvertTo-TablaHtml $tablaServidores @('Equipo','Funcion','Dominio','IP actual','IP final','DNS','Roles instalados'))
<h2>Matriz de acceso por área</h2>$(ConvertTo-TablaHtml $tablaAreas $columnasAreas)
<h2>Usuarios ($(@($Diseno.Usuarios).Count))</h2>$(ConvertTo-TablaHtml $tablaUsuarios @('Usuario','Cuenta','UPN','Area','Cargo','Oficina'))
<h2>Grupos (AGUDLP)</h2>$(ConvertTo-TablaHtml $tablaGrupos @('Grupo','Ambito','Dominio','Miembros'))
<h2>Permisos</h2>$(ConvertTo-TablaHtml $tablaPermisos @('Recurso','Tipo','Cuenta','Permiso'))
</body></html>
"@
    Set-Content -Path (Join-Path $carpeta 'diseno.html') -Value $html -Encoding UTF8
    Export-GuionDemo -Diseno $Diseno -Carpeta $carpeta
    return $carpeta
}

Export-ModuleMember -Function Test-ConfigLab, Get-DisenoDerivado, Export-Diseno, Get-NivelArea
