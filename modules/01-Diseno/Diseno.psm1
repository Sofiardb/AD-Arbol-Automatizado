#Requires -Version 5.1
<#
.SYNOPSIS
    Módulo 01 – Diseño de la arquitectura lógica y física (objetivo específico 1).

.DESCRIPTION
    A partir de la configuración mínima del usuario:
      1. Test-ConfigLab        valida la configuración (frena antes de tocar nada si hay errores).
      2. Get-DisenoDerivado    calcula todos los valores derivados: nombres, IP finales, DNS,
                               OU, cuentas, grupos AGUDLP, recursos y permisos (red y NTFS).
      3. Export-Diseno         genera diseno.json (lo usan los módulos 02 a 06), tablas CSV,
                               diagramas Mermaid y un resumen HTML para el documento.
#>

Set-StrictMode -Version 2.0

# Valores por defecto de los servidores (rol -> nombre y desplazamiento de IP dentro de la red)
$script:DefectoServidores = @{
    DCRaiz   = @{ Nombre = 'DC-RAIZ';      Desplazamiento = 10; Orden = 1 }
    DCHijo   = @{ Nombre = 'DC-HIJO';      Desplazamiento = 11; Orden = 2 }
    Archivos = @{ Nombre = 'SRV-ARCHIVOS'; Desplazamiento = 20; Orden = 3 }
}
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
        $errores.Add("DominioHijo '$hijo' debe ser una sola etiqueta de hasta 15 caracteres, sin puntos (ej.: ventas).")
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
    if ($nivelFuncional -notin @('Win2012R2', 'WinThreshold', 'Default')) {
        $errores.Add("NivelFuncional '$nivelFuncional' no soportado (use Win2012R2 o WinThreshold).")
    }
    $usuarioAdmin = [string](Get-Valor $lab 'UsuarioAdministrador' 'Administrator')
    if ($usuarioAdmin -notmatch '^[^\\/@"\[\]:;|=,+*?<>]{1,20}$') { $errores.Add("UsuarioAdministrador '$usuarioAdmin' no es un nombre de cuenta válido.") }
    $zona = Get-Valor $lab 'ZonaHoraria'
    if ($zona -and $zona -notmatch '^[A-Za-z0-9 ()+.,_-]{3,64}$') { $errores.Add("ZonaHoraria '$zona' no parece un identificador de zona horaria de Windows (ej.: Argentina Standard Time).") }

    # --- Servidores ---
    $servidores = @($lab.Servidores)
    $roles = @($servidores | ForEach-Object { $_.Rol })
    foreach ($rol in $script:DefectoServidores.Keys) {
        $cant = @($roles | Where-Object { $_ -eq $rol }).Count
        if ($cant -ne 1) { $errores.Add("Servidores: debe haber exactamente un servidor con Rol = '$rol' (hay $cant).") }
    }
    foreach ($rol in $roles) {
        if ($rol -notin $script:DefectoServidores.Keys) { $errores.Add("Servidores: Rol '$rol' desconocido (válidos: DCRaiz, DCHijo, Archivos).") }
    }
    $ipsFinales = @()
    $nombres = @()
    foreach ($s in $servidores) {
        if (-not (Test-FormatoIPv4 (Get-Valor $s 'IPActual'))) { $errores.Add("Servidor $($s.Rol): IPActual '$(Get-Valor $s 'IPActual')' no es una IPv4 válida.") }
        $nombre = Get-Valor $s 'Nombre'
        if ($nombre) {
            if ($nombre -notmatch '^[A-Za-z0-9]([A-Za-z0-9-]{0,13}[A-Za-z0-9])?$') { $errores.Add("Servidor $($s.Rol): Nombre '$nombre' inválido (hasta 15 caracteres, letras, números y guiones).") }
            $nombres += $nombre.ToUpperInvariant()
        }
        elseif ($script:DefectoServidores.ContainsKey([string]$s.Rol)) { $nombres += $script:DefectoServidores[[string]$s.Rol].Nombre }
        $ipFinal = Get-Valor $s 'IPFinal'
        if ($ipFinal) {
            if ($infoRed -and -not (Test-IPEnRed -IP $ipFinal -InfoRed $infoRed)) { $errores.Add("Servidor $($s.Rol): IPFinal '$ipFinal' no pertenece a la red $($infoRed.Cidr).") }
            $ipsFinales += $ipFinal
        }
        elseif ($infoRed -and $script:DefectoServidores.ContainsKey([string]$s.Rol)) {
            $ipsFinales += Get-IPDesplazada -InfoRed $infoRed -Desplazamiento $script:DefectoServidores[[string]$s.Rol].Desplazamiento
        }
    }
    $dupIP = @($ipsFinales | Group-Object | Where-Object Count -gt 1 | ForEach-Object Name)
    foreach ($d in $dupIP) { $errores.Add("Servidores: la IP final $d está repetida.") }
    if ($lab.Gateway -in $ipsFinales) { $errores.Add("Servidores: una IP final coincide con el Gateway ($($lab.Gateway)).") }
    foreach ($d in @($nombres | Group-Object | Where-Object Count -gt 1 | ForEach-Object Name)) { $errores.Add("Servidores: el nombre $d está repetido.") }

    # --- Áreas ---
    $areas = $lab.Areas
    foreach ($dom in 'Raiz', 'Hijo') {
        $lista = @(Get-Valor $areas $dom @())
        if ($lista.Count -eq 0) { $errores.Add("Areas.$($dom): debe definir al menos un área."); continue }
        foreach ($a in $lista) {
            if ([string]::IsNullOrWhiteSpace($a) -or $a -match '[\\/,+"<>;=#]') { $errores.Add("Areas.$($dom): nombre de área inválido '$a'.") }
            if ($a -ieq 'Grupos') { $errores.Add("Areas.$($dom): 'Grupos' está reservado (OU donde se crean los grupos).") }
        }
        foreach ($d in @($lista | Group-Object | Where-Object Count -gt 1 | ForEach-Object Name)) { $errores.Add("Areas.$($dom): el área '$d' está repetida.") }
    }

    # --- usuarios.csv ---
    $usuarios = @($Config.Usuarios)
    if ($usuarios.Count -eq 0) { $advert.Add('usuarios.csv no tiene filas: no se darán de alta usuarios.') }
    else {
        $cols = $usuarios[0].PSObject.Properties.Name
        foreach ($c in 'Nombre', 'Apellido', 'Dominio', 'Area') { if ($c -notin $cols) { $errores.Add("usuarios.csv: falta la columna '$c'.") } }
    }
    if (-not ($errores | Where-Object { $_ -like 'usuarios.csv: falta*' })) {
        $fila = 1
        foreach ($u in $usuarios) {
            $fila++
            if ([string]::IsNullOrWhiteSpace($u.Nombre) -or [string]::IsNullOrWhiteSpace($u.Apellido)) { $errores.Add("usuarios.csv fila $($fila): Nombre y Apellido son obligatorios.") }
            if ($u.Dominio -notin 'Raiz', 'Hijo') { $errores.Add("usuarios.csv fila $($fila): Dominio '$($u.Dominio)' debe ser Raiz o Hijo."); continue }
            if ($u.Area -notin @(Get-Valor $areas $u.Dominio @())) { $errores.Add("usuarios.csv fila $($fila): el área '$($u.Area)' no está definida en Areas.$($u.Dominio).") }
        }
        $dups = $usuarios | Group-Object { "$($_.Dominio)|$($_.Nombre) $($_.Apellido)" } | Where-Object Count -gt 1
        foreach ($d in @($dups)) { $advert.Add("usuarios.csv: '$($d.Name.Split('|')[1])' aparece $($d.Count) veces en el dominio $($d.Name.Split('|')[0]) (se generarán cuentas distintas).") }
    }

    # --- accesos.csv ---
    $accesos = @($Config.Accesos)
    if ($accesos.Count -eq 0) { $advert.Add('accesos.csv no tiene filas: no se crearán recursos compartidos.') }
    else {
        $cols = $accesos[0].PSObject.Properties.Name
        foreach ($c in 'Recurso', 'Dominio', 'Area', 'Nivel') { if ($c -notin $cols) { $errores.Add("accesos.csv: falta la columna '$c'.") } }
    }
    if (-not ($errores | Where-Object { $_ -like 'accesos.csv: falta*' })) {
        $fila = 1
        foreach ($a in $accesos) {
            $fila++
            if ($a.Recurso -notmatch '^[A-Za-z0-9][A-Za-z0-9_-]{0,39}$') { $errores.Add("accesos.csv fila $($fila): Recurso '$($a.Recurso)' inválido (letras, números, '-' y '_', sin espacios, hasta 40).") }
            if ($a.Nivel -notin $script:NivelesValidos) { $errores.Add("accesos.csv fila $($fila): Nivel '$($a.Nivel)' inválido (válidos: $($script:NivelesValidos -join ', ')).") }
            if ($a.Dominio -notin 'Raiz', 'Hijo') { $errores.Add("accesos.csv fila $($fila): Dominio '$($a.Dominio)' debe ser Raiz o Hijo."); continue }
            if ($a.Area -notin @(Get-Valor $areas $a.Dominio @())) { $errores.Add("accesos.csv fila $($fila): el área '$($a.Area)' no está definida en Areas.$($a.Dominio).") }
            elseif (-not ($usuarios | Where-Object { $_.Dominio -eq $a.Dominio -and $_.Area -eq $a.Area })) {
                $advert.Add("accesos.csv fila $($fila): el área $($a.Dominio)/$($a.Area) no tiene usuarios (su grupo quedará vacío).")
            }
        }
        $conflictos = $accesos | Group-Object { "$($_.Recurso)|$($_.Dominio)|$($_.Area)" } | Where-Object Count -gt 1
        foreach ($c in @($conflictos)) { $errores.Add("accesos.csv: '$($c.Name.Replace('|', ' / '))' aparece $($c.Count) veces; defina un único nivel por recurso y área.") }
    }

    return [pscustomobject]@{ Errores = $errores.ToArray(); Advertencias = $advert.ToArray() }
}

# =====================================================================
#  2. Valores derivados
# =====================================================================
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

    # --- Dominios ---
    $fqdnRaiz = ([string]$lab.DominioRaiz).ToLowerInvariant()
    $etiquetaHijo = ([string]$lab.DominioHijo).ToLowerInvariant()
    $fqdnHijo = "$etiquetaHijo.$fqdnRaiz"
    $dnDe = { param($fqdn) ($fqdn.Split('.') | ForEach-Object { "DC=$_" }) -join ',' }
    $dominios = [ordered]@{
        Raiz = [ordered]@{ FQDN = $fqdnRaiz; NetBIOS = $fqdnRaiz.Split('.')[0].ToUpperInvariant(); DN = (& $dnDe $fqdnRaiz) }
        Hijo = [ordered]@{ FQDN = $fqdnHijo; Etiqueta = $etiquetaHijo; NetBIOS = $etiquetaHijo.ToUpperInvariant(); DN = (& $dnDe $fqdnHijo); Padre = $fqdnRaiz }
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
            'DCRaiz'   { $s.Dominio = $fqdnRaiz; $s.Roles = @('AD-Domain-Services', 'DNS'); $s.DnsInicial = @($s.IPFinal);       $s.DnsFinal = @($s.IPFinal, $srvHijo.IPFinal) }
            'DCHijo'   { $s.Dominio = $fqdnHijo; $s.Roles = @('AD-Domain-Services', 'DNS'); $s.DnsInicial = @($srvRaiz.IPFinal); $s.DnsFinal = @($s.IPFinal, $srvRaiz.IPFinal) }
            'Archivos' { $s.Dominio = $fqdnRaiz; $s.Roles = @('FS-FileServer');             $s.DnsInicial = @($srvRaiz.IPFinal); $s.DnsFinal = @($srvRaiz.IPFinal, $srvHijo.IPFinal) }
        }
        $s.FQDN = "$($s.Nombre).$($s.Dominio)".ToLowerInvariant()
        $s.NombrePTR = Get-NombrePTR -IP $s.IPFinal -ZonaInversa $infoRed.ZonaInversa
    }
    $srvArchivos = $servidores | Where-Object { $_.Rol -eq 'Archivos' }

    # --- OU (una por área + OU "Grupos" en cada dominio) ---
    $ous = foreach ($dom in 'Raiz', 'Hijo') {
        foreach ($area in @($lab.Areas[$dom]) + 'Grupos') {
            [ordered]@{ Dominio = $dom; DominioFQDN = $dominios[$dom].FQDN; Nombre = $area; DN = "OU=$area,$($dominios[$dom].DN)"; Padre = $dominios[$dom].DN }
        }
    }

    # --- Usuarios ---
    $samPorDominio = @{ Raiz = New-Object 'System.Collections.Generic.HashSet[string]'; Hijo = New-Object 'System.Collections.Generic.HashSet[string]' }
    $usuarios = foreach ($u in @($Config.Usuarios)) {
        $d = $dominios[$u.Dominio]
        $sam = Get-NombreSam -Nombre $u.Nombre.Trim() -Apellido $u.Apellido.Trim() -Existentes $samPorDominio[$u.Dominio]
        $opc = @{}
        foreach ($c in 'Cargo', 'Telefono', 'Oficina') {
            $opc[$c] = ''
            if ($u.PSObject.Properties.Name -contains $c -and $u.$c) { $opc[$c] = ([string]$u.$c).Trim() }
        }
        $completo = "$($u.Nombre.Trim()) $($u.Apellido.Trim())"
        [ordered]@{
            Nombre = $u.Nombre.Trim(); Apellido = $u.Apellido.Trim(); NombreCompleto = $completo
            CN = $completo   # nombre del objeto en AD; se desambigua más abajo si se repite en la misma OU
            Sam = $sam; UPN = "$sam@$($d.FQDN)"; Dominio = $u.Dominio; DominioFQDN = $d.FQDN; NetBIOS = $d.NetBIOS
            Area = $u.Area; OU = "OU=$($u.Area),$($d.DN)"
            Cargo = $opc.Cargo; Telefono = $opc.Telefono; Oficina = $opc.Oficina; Empresa = $empresa
            Descripcion = (@($opc.Cargo, $u.Area) | Where-Object { $_ }) -join ' - '
        }
    }
    # Dos personas con el mismo nombre en la misma OU tendrían el mismo CN: se agrega la cuenta entre paréntesis
    foreach ($g in @($usuarios | Group-Object { "$($_.OU)|$($_.CN)" } | Where-Object Count -gt 1)) {
        foreach ($u in $g.Group) { $u.CN = "$($u.NombreCompleto) ($($u.Sam))" }
    }

    # --- Grupos globales (uno por área y dominio) ---
    $gruposGlobales = foreach ($dom in 'Raiz', 'Hijo') {
        $d = $dominios[$dom]
        foreach ($area in @($lab.Areas[$dom])) {
            [ordered]@{
                Nombre = Get-NombreGrupoGlobal -NetBIOS $d.NetBIOS -Area $area; Ambito = 'Global'; Dominio = $dom; DominioFQDN = $d.FQDN
                OU = "OU=Grupos,$($d.DN)"; Area = $area; Descripcion = "Usuarios del área $area ($($d.FQDN))"
                Miembros = @($usuarios | Where-Object { $_.Dominio -eq $dom -and $_.Area -eq $area } | ForEach-Object { $_.Sam })
            }
        }
    }

    # --- Grupos de dominio local (uno por recurso y nivel, en el dominio raíz) ---
    $accesos = @($Config.Accesos)
    $gruposDL = foreach ($g in @($accesos | Group-Object { "$($_.Recurso)|$($_.Nivel)" })) {
        $recurso, $nivel = $g.Name.Split('|')
        [ordered]@{
            Nombre = Get-NombreGrupoDL -Recurso $recurso -Nivel $nivel; Ambito = 'DomainLocal'; Dominio = 'Raiz'; DominioFQDN = $fqdnRaiz
            OU = "OU=Grupos,$($dominios.Raiz.DN)"; Recurso = $recurso; Nivel = $nivel; Descripcion = "Permiso $nivel sobre el recurso compartido $recurso"
            Miembros = @($g.Group | ForEach-Object {
                    $d = $dominios[$_.Dominio]
                    [ordered]@{ Grupo = Get-NombreGrupoGlobal -NetBIOS $d.NetBIOS -Area $_.Area; DominioFQDN = $d.FQDN; Referencia = "$($d.NetBIOS)\$(Get-NombreGrupoGlobal -NetBIOS $d.NetBIOS -Area $_.Area)" }
                })
        }
    }

    # --- Recursos compartidos (enfoque 2: permisos por grupo en recurso compartido y en NTFS) ---
    $rutaBase = [string](Get-Valor $lab 'RutaRecursos' 'C:\Recursos')
    $nb = $dominios.Raiz.NetBIOS
    $recursos = foreach ($nombreRecurso in @($accesos | ForEach-Object { $_.Recurso } | Select-Object -Unique)) {
        $niveles = @($gruposDL | Where-Object { $_.Recurso -eq $nombreRecurso } | ForEach-Object { $_.Nivel })
        $compartido = @([ordered]@{ Cuenta = 'BUILTIN\Administrators'; Permiso = 'Full' })
        $ntfs = @(
            [ordered]@{ Cuenta = 'BUILTIN\Administrators'; Permiso = 'FullControl' }
            [ordered]@{ Cuenta = 'NT AUTHORITY\SYSTEM'; Permiso = 'FullControl' }
        )
        foreach ($nivel in $script:NivelesValidos) {
            if ($nivel -in $niveles) {
                $cuenta = "$nb\$(Get-NombreGrupoDL -Recurso $nombreRecurso -Nivel $nivel)"
                $compartido += [ordered]@{ Cuenta = $cuenta; Permiso = $script:MapeoPermisos[$nivel].Compartido }
                $ntfs       += [ordered]@{ Cuenta = $cuenta; Permiso = $script:MapeoPermisos[$nivel].NTFS }
            }
        }
        [ordered]@{
            Nombre = $nombreRecurso; Servidor = $srvArchivos.Nombre; RutaLocal = "$($rutaBase.TrimEnd('\'))\$nombreRecurso"   # ruta en el servidor remoto (no se usa Join-Path local)
            UNC = "\\$($srvArchivos.FQDN)\$nombreRecurso"; ABE = $true; HerenciaDeshabilitada = $true
            PermisosCompartido = $compartido; PermisosNTFS = $ntfs
        }
    }

    # --- Matriz de acceso esperado (para documentación y validación) ---
    $matriz = foreach ($u in $usuarios) {
        foreach ($r in $recursos) {
            $rangos = @($accesos | Where-Object { $_.Recurso -eq $r.Nombre -and $_.Dominio -eq $u.Dominio -and $_.Area -eq $u.Area } |
                    ForEach-Object { $script:MapeoPermisos[$_.Nivel].Rango })
            $nivel = 'SinAcceso'
            if ($rangos.Count) {
                $max = ($rangos | Measure-Object -Maximum).Maximum
                $nivel = ($script:MapeoPermisos.Keys | Where-Object { $script:MapeoPermisos[$_].Rango -eq $max })
            }
            $red = 'Denegado'; $local = 'Denegado'
            if ($nivel -ne 'SinAcceso') {
                # Enfoque 2: compartido y NTFS tienen el mismo nivel -> el más restrictivo coincide
                $red = "$nivel (compartido: $($script:MapeoPermisos[$nivel].Compartido) / NTFS: $($script:MapeoPermisos[$nivel].NTFS))"
                $local = "$nivel (NTFS: $($script:MapeoPermisos[$nivel].NTFS))"
            }
            [ordered]@{ Usuario = "$($u.NetBIOS)\$($u.Sam)"; Dominio = $u.Dominio; Area = $u.Area; Recurso = $r.Nombre; NivelEsperado = $nivel; AccesoRed = $red; AccesoLocal = $local }
        }
    }

    return [ordered]@{
        Generado       = (Get-Date -Format 's')
        Parametros     = [ordered]@{
            Empresa = $empresa; NivelFuncional = [string](Get-Valor $lab 'NivelFuncional' 'WinThreshold'); RutaRecursos = $rutaBase
            ZonaHoraria = [string](Get-Valor $lab 'ZonaHoraria' ''); UsuarioAdministrador = [string](Get-Valor $lab 'UsuarioAdministrador' 'Administrator')
            EnfoquePermisos = 'PorGrupo (recurso compartido + NTFS)'
        }
        Dominios       = $dominios
        Red            = [ordered]@{
            Cidr = $infoRed.Cidr; Mascara = $infoRed.Mascara; Prefijo = $infoRed.Prefijo; Gateway = [string]$lab.Gateway
            ZonaInversa = $infoRed.ZonaInversa; NetworkIdZona = $infoRed.NetworkIdZona; Reenviadores = @(Get-Valor $lab 'Reenviadores' @())
        }
        Servidores     = @($servidores)
        OUs            = @($ous)
        Usuarios       = @($usuarios)
        GruposGlobales = @($gruposGlobales)
        GruposDL       = @($gruposDL)
        Recursos       = @($recursos)
        MatrizAcceso   = @($matriz)
    }
}

# =====================================================================
#  3. Exportación (diseno.json, tablas, diagramas, resumen)
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
    param($Diseno)
    $r = $Diseno.Dominios.Raiz; $h = $Diseno.Dominios.Hijo
    $l = New-Object System.Collections.Generic.List[string]
    $l.Add('flowchart TB')
    $l.Add("  subgraph BOSQUE[""Bosque: $($r.FQDN)""]")
    $l.Add("    RAIZ[""Dominio raíz<br/>$($r.FQDN)<br/>NetBIOS: $($r.NetBIOS)""]")
    $l.Add("    HIJO[""Dominio hijo<br/>$($h.FQDN)<br/>NetBIOS: $($h.NetBIOS)""]")
    $l.Add('    RAIZ <-->|"Confianza padre-hijo<br/>bidireccional y transitiva"| HIJO')
    $i = 0
    foreach ($ou in $Diseno.OUs) {
        $i++; $id = "OU$i"; $padre = 'RAIZ'
        if ($ou.Dominio -eq 'Hijo') { $padre = 'HIJO' }
        $l.Add("    $padre --- $id[""OU $($ou.Nombre)""]")
    }
    $l.Add('  end')
    $l.Add('  subgraph ACCESO["Acceso entre dominios (AGUDLP)"]')
    $i = 0
    $idsGG = @{}
    foreach ($dl in $Diseno.GruposDL) {
        $i++; $idDL = "DL$i"
        $l.Add("    $idDL[""$($dl.Nombre)<br/>(dominio local)""]")
        $idRec = 'REC_' + ($dl.Recurso -replace '[^A-Za-z0-9_]', '_')
        $l.Add("    $idDL -->|""$($dl.Nivel)""| $idRec[(""\\$($dl.Recurso)"")]")
        foreach ($m in $dl.Miembros) {
            if (-not $idsGG.ContainsKey($m.Grupo)) { $idsGG[$m.Grupo] = "GG$($idsGG.Count + 1)"; $l.Add("    $($idsGG[$m.Grupo])[""$($m.Grupo)<br/>(global)""]") }
            $l.Add("    $($idsGG[$m.Grupo]) --> $idDL")
        }
    }
    $l.Add('  end')
    return ($l -join "`n")
}

function Get-DiagramaFisico {
    param($Diseno)
    $l = New-Object System.Collections.Generic.List[string]
    $l.Add('flowchart LR')
    $l.Add("  RED{{""Red $($Diseno.Red.Cidr)<br/>Gateway $($Diseno.Red.Gateway)""}}")
    foreach ($s in $Diseno.Servidores) {
        $id = $s.Nombre -replace '-', '_'
        $l.Add("  $id[""$($s.Nombre)<br/>$($s.IPFinal)<br/>$($s.Dominio)<br/>$($s.Roles -join ', ')""] --- RED")
    }
    return ($l -join "`n")
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

    # diseno.json (insumo de los módulos 02 a 06)
    ConvertTo-Json -InputObject $Diseno -Depth 10 | Set-Content -Path (Join-Path $RutaSalida 'diseno.json') -Encoding UTF8

    # Tablas para el documento
    $tablaServidores = $Diseno.Servidores | ForEach-Object { [pscustomobject]@{ Servidor = $_.Nombre; Rol = $_.Rol; Dominio = $_.Dominio; 'IP actual' = $_.IPActual; 'IP final' = $_.IPFinal; DNS = ($_.DnsFinal -join ', '); 'Roles instalados' = ($_.Roles -join ', ') } }
    $tablaUsuarios   = $Diseno.Usuarios   | ForEach-Object { [pscustomobject]@{ Usuario = $_.NombreCompleto; Cuenta = "$($_.NetBIOS)\$($_.Sam)"; UPN = $_.UPN; Area = $_.Area; Cargo = $_.Cargo; Oficina = $_.Oficina; OU = $_.OU } }
    $tablaGrupos     = @($Diseno.GruposGlobales | ForEach-Object { [pscustomobject]@{ Grupo = $_.Nombre; Ambito = 'Global'; Dominio = $_.DominioFQDN; Miembros = ($_.Miembros -join ', ') } }) +
                       @($Diseno.GruposDL      | ForEach-Object { [pscustomobject]@{ Grupo = $_.Nombre; Ambito = 'Dominio local'; Dominio = $_.DominioFQDN; Miembros = (($_.Miembros | ForEach-Object { $_.Referencia }) -join ', ') } })
    $tablaPermisos   = foreach ($r in $Diseno.Recursos) {
        foreach ($p in $r.PermisosCompartido) { [pscustomobject]@{ Recurso = $r.UNC; Tipo = 'Recurso compartido'; Cuenta = $p.Cuenta; Permiso = $p.Permiso } }
        foreach ($p in $r.PermisosNTFS)       { [pscustomobject]@{ Recurso = $r.RutaLocal; Tipo = 'NTFS'; Cuenta = $p.Cuenta; Permiso = $p.Permiso } }
    }
    $tablaMatriz     = $Diseno.MatrizAcceso | ForEach-Object { [pscustomobject]$_ }

    $tablaServidores | Export-Csv (Join-Path $carpeta 'servidores.csv') -NoTypeInformation -Encoding UTF8
    $tablaUsuarios   | Export-Csv (Join-Path $carpeta 'usuarios.csv')   -NoTypeInformation -Encoding UTF8
    $tablaGrupos     | Export-Csv (Join-Path $carpeta 'grupos.csv')     -NoTypeInformation -Encoding UTF8
    $tablaPermisos   | Export-Csv (Join-Path $carpeta 'permisos.csv')   -NoTypeInformation -Encoding UTF8
    $tablaMatriz     | Export-Csv (Join-Path $carpeta 'matriz-acceso.csv') -NoTypeInformation -Encoding UTF8

    # Diagramas (Mermaid)
    $logico = Get-DiagramaLogico -Diseno $Diseno
    $fisico = Get-DiagramaFisico -Diseno $Diseno
    Set-Content -Path (Join-Path $carpeta 'diagrama-logico.mmd') -Value $logico -Encoding UTF8
    Set-Content -Path (Join-Path $carpeta 'diagrama-fisico.mmd') -Value $fisico -Encoding UTF8

    # Resumen HTML (diagramas + tablas). Mermaid se carga desde CDN para dibujar los diagramas.
    $r = $Diseno.Dominios.Raiz; $h = $Diseno.Dominios.Hijo
    $html = @"
<!DOCTYPE html>
<html lang="es"><head><meta charset="utf-8"><title>Diseño – $($r.FQDN)</title>
<style>
 body{font-family:Segoe UI,Arial,sans-serif;margin:24px;color:#222;background:#fff}
 h1{color:#1F4E79} h2{color:#1F4E79;border-bottom:2px solid #D9E2F3;padding-bottom:4px;margin-top:32px}
 table{border-collapse:collapse;margin:8px 0 16px;font-size:13px} th,td{border:1px solid #A6A6A6;padding:4px 8px;text-align:left}
 th{background:#D9E2F3} .mermaid{background:#fafafa;border:1px solid #ddd;padding:8px;margin:8px 0}
</style>
<script src="https://cdn.jsdelivr.net/npm/mermaid@10.9.1/dist/mermaid.min.js"></script>
<script>mermaid.initialize({startOnLoad:true});</script>
</head><body>
<h1>Diseño de la solución – $($r.FQDN) / $($h.FQDN)</h1>
<p><b>$([System.Net.WebUtility]::HtmlEncode($Diseno.Parametros.Empresa))</b></p>
<p>Generado: $($Diseno.Generado) · Enfoque de permisos: $($Diseno.Parametros.EnfoquePermisos) · Nivel funcional: $($Diseno.Parametros.NivelFuncional)</p>
<h2>Arquitectura lógica</h2><pre class="mermaid">
$([System.Net.WebUtility]::HtmlEncode($logico))
</pre>
<h2>Arquitectura física</h2><pre class="mermaid">
$([System.Net.WebUtility]::HtmlEncode($fisico))
</pre>
<p style="font-size:12px;color:#666">Los diagramas se dibujan con Mermaid (requiere conexión a Internet). Sin conexión, pegar los archivos .mmd en https://mermaid.live.</p>
<h2>Red y DNS</h2>
<p>Red $($Diseno.Red.Cidr) (máscara $($Diseno.Red.Mascara)) · Gateway $($Diseno.Red.Gateway) · Zona inversa $($Diseno.Red.ZonaInversa) · Reenviadores: $(($Diseno.Red.Reenviadores) -join ', ')</p>
<h2>Servidores</h2>$(ConvertTo-TablaHtml $tablaServidores @('Servidor','Rol','Dominio','IP actual','IP final','DNS','Roles instalados'))
<h2>Usuarios ($(@($Diseno.Usuarios).Count))</h2>$(ConvertTo-TablaHtml $tablaUsuarios @('Usuario','Cuenta','UPN','Area','Cargo','Oficina'))
<h2>Grupos (AGUDLP)</h2>$(ConvertTo-TablaHtml $tablaGrupos @('Grupo','Ambito','Dominio','Miembros'))
<h2>Permisos</h2>$(ConvertTo-TablaHtml $tablaPermisos @('Recurso','Tipo','Cuenta','Permiso'))
<h2>Matriz de acceso esperado</h2>$(ConvertTo-TablaHtml $tablaMatriz @('Usuario','Area','Recurso','NivelEsperado','AccesoRed','AccesoLocal'))
</body></html>
"@
    Set-Content -Path (Join-Path $carpeta 'diseno.html') -Value $html -Encoding UTF8
    return $carpeta
}

Export-ModuleMember -Function Test-ConfigLab, Get-DisenoDerivado, Export-Diseno
