#Requires -Version 5.1
<#
.SYNOPSIS
    Módulo 06 – Lógica de validación (objetivo específico 6).

.DESCRIPTION
    Funciones PURAS: comparan el diseño (diseno.json) con el estado real que devuelven los
    servidores y producen filas de resultado (OK / FALLA / ADVERTENCIA). No se conectan a nada,
    por eso se pueden probar sin un laboratorio (ver tests\Test-Offline.ps1).

      Test-Bosque           bosque, dominios, confianza padre-hijo, catálogo global, nivel funcional
      Test-Dns              zonas, delegación, reenviadores, scavenging y consultas SRV/A/PTR
      Test-Estructura       OU y cuentas de un dominio
      Test-Grupos           grupos globales y de dominio local (ámbito y pertenencia exacta)
      Test-Recursos         recursos compartidos, ABE, permisos del recurso compartido y NTFS
      Get-CasosPrueba       cuentas temporales y nivel esperado por recurso (pruebas de acceso reales)
      Test-ResultadoAcceso  compara lo que pudo hacer cada cuenta con lo esperado
      Export-InformeValidacion   informe HTML y CSV
#>

Set-StrictMode -Version 2.0

# Derechos NTFS con el bit Synchronize, como los devuelve Windows
$script:DerechosNTFS = @{ FullControl = 2032127; Modify = 1245631; ReadAndExecute = 1179817 }
$script:RangoNivel   = @{ SinAcceso = 0; Lectura = 1; Modificar = 2 }
$script:ModoFuncional = @{ WinThreshold = 'Windows2016'; Win2012R2 = 'Windows2012R2' }

function New-Resultado {
    param(
        [Parameter(Mandatory)][string]$Categoria,
        [Parameter(Mandatory)][string]$Prueba,
        [AllowEmptyString()][string]$Esperado = '',
        [AllowEmptyString()][string]$Obtenido = '',
        [Parameter(Mandatory)][ValidateSet('OK', 'FALLA', 'ADVERTENCIA')][string]$Resultado
    )
    [pscustomobject]@{ Categoria = $Categoria; Prueba = $Prueba; Esperado = $Esperado; Obtenido = $Obtenido; Resultado = $Resultado }
}

function Get-ResultadoBool {
    param([bool]$Condicion, [switch]$SoloAdvertencia)
    if ($Condicion) { return 'OK' }
    if ($SoloAdvertencia) { return 'ADVERTENCIA' }
    return 'FALLA'
}

function Compare-Conjunto {
    <# Devuelve faltantes y sobrantes entre dos listas (sin distinguir mayúsculas). #>
    param([string[]]$Esperado, [string[]]$Obtenido)
    $e = @($Esperado | Where-Object { $_ } | ForEach-Object { $_.ToLowerInvariant() })
    $o = @($Obtenido | Where-Object { $_ } | ForEach-Object { $_.ToLowerInvariant() })
    [pscustomobject]@{
        Faltan  = @($e | Where-Object { $_ -notin $o })
        Sobran  = @($o | Where-Object { $_ -notin $e })
        Iguales = (@($e | Where-Object { $_ -notin $o }).Count -eq 0 -and @($o | Where-Object { $_ -notin $e }).Count -eq 0)
    }
}

function Get-TextoDiferencia {
    param($Comparacion, [scriptblock]$Formato = { param($x) $x })
    $partes = @()
    if (@($Comparacion.Faltan).Count) { $partes += "faltan: $(@($Comparacion.Faltan | ForEach-Object { & $Formato $_ }) -join ', ')" }
    if (@($Comparacion.Sobran).Count) { $partes += "sobran: $(@($Comparacion.Sobran | ForEach-Object { & $Formato $_ }) -join ', ')" }
    if (-not $partes) { return 'coincide' }
    return ($partes -join ' · ')
}

function Get-CN { param([string]$DN) return (($DN -split '(?<!\\),')[0] -replace '^(?i)cn=', '') }

# =====================================================================
#  Bosque y dominios
# =====================================================================
function Test-Bosque {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Diseno, [Parameter(Mandatory)]$EstadoRaiz, [Parameter(Mandatory)]$EstadoHijo)
    $cat = 'Bosque y dominios'
    $r = $Diseno.Dominios.Raiz; $h = $Diseno.Dominios.Hijo

    New-Resultado $cat 'Dominio raíz del bosque' $r.FQDN $EstadoRaiz.Bosque.RootDomain (Get-ResultadoBool ($EstadoRaiz.Bosque.RootDomain -eq $r.FQDN))
    $cmp = Compare-Conjunto @($r.FQDN, $h.FQDN) @($EstadoRaiz.Bosque.Domains)
    New-Resultado $cat 'Dominios del bosque (árbol padre-hijo)' "$($r.FQDN), $($h.FQDN)" (@($EstadoRaiz.Bosque.Domains) -join ', ') (Get-ResultadoBool $cmp.Iguales)
    New-Resultado $cat "Nombre NetBIOS de $($r.FQDN)" $r.NetBIOS $EstadoRaiz.Dominio.NetBIOSName (Get-ResultadoBool ($EstadoRaiz.Dominio.NetBIOSName -eq $r.NetBIOS))
    New-Resultado $cat "Nombre NetBIOS de $($h.FQDN)" $h.NetBIOS $EstadoHijo.Dominio.NetBIOSName (Get-ResultadoBool ($EstadoHijo.Dominio.NetBIOSName -eq $h.NetBIOS))
    New-Resultado $cat "Dominio padre de $($h.FQDN)" $r.FQDN ([string]$EstadoHijo.Dominio.ParentDomain) (Get-ResultadoBool ($EstadoHijo.Dominio.ParentDomain -eq $r.FQDN))

    foreach ($par in @(@($EstadoRaiz, $h.FQDN, $r.FQDN), @($EstadoHijo, $r.FQDN, $h.FQDN))) {
        $estado, $destino, $origen = $par
        $t = @($estado.Confianzas | Where-Object { $_.Target -eq $destino }) | Select-Object -First 1
        $obt = 'no existe'
        if ($t) { $obt = "$($t.Direction), intra-bosque: $($t.IntraForest)" }
        New-Resultado $cat "Confianza $origen -> $destino" 'BiDirectional, intra-bosque: True' $obt (Get-ResultadoBool ($t -and $t.Direction -eq 'BiDirectional' -and [bool]$t.IntraForest))
    }

    $dcRaiz = Get-ServidorDiseno -Diseno $Diseno -Rol DCRaiz
    $esGC = @($EstadoRaiz.Bosque.GlobalCatalogs | Where-Object { $_ -eq $dcRaiz.FQDN }).Count -gt 0
    New-Resultado $cat "$($dcRaiz.Nombre) es catálogo global" 'Sí' (@($EstadoRaiz.Bosque.GlobalCatalogs) -join ', ') (Get-ResultadoBool $esGC)

    $nivel = [string]$Diseno.Parametros.NivelFuncional
    if ($script:ModoFuncional.ContainsKey($nivel)) {
        $pref = $script:ModoFuncional[$nivel]
        New-Resultado $cat 'Nivel funcional del bosque' "$pref*" ([string]$EstadoRaiz.Bosque.ForestMode) (Get-ResultadoBool ([string]$EstadoRaiz.Bosque.ForestMode -like "$pref*"))
        foreach ($e in $EstadoRaiz, $EstadoHijo) {
            New-Resultado $cat "Nivel funcional de $($e.Dominio.DNSRoot)" "$pref*" ([string]$e.Dominio.DomainMode) (Get-ResultadoBool ([string]$e.Dominio.DomainMode -like "$pref*"))
        }
    }
    New-Resultado $cat 'Maestros de operaciones del bosque' 'informativo' "Esquema: $($EstadoRaiz.Bosque.SchemaMaster) · Nombres: $($EstadoRaiz.Bosque.DomainNamingMaster)" 'OK'
    foreach ($e in $EstadoRaiz, $EstadoHijo) {
        New-Resultado $cat "Maestros de operaciones de $($e.Dominio.DNSRoot)" 'informativo' "PDC: $($e.Dominio.PDCEmulator) · RID: $($e.Dominio.RIDMaster) · Infraestructura: $($e.Dominio.InfrastructureMaster)" 'OK'
    }
}

# =====================================================================
#  DNS
# =====================================================================
function Test-Dns {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Diseno, [Parameter(Mandatory)]$EstadoRaiz, [Parameter(Mandatory)]$EstadoHijo)
    $cat = 'DNS'
    $r = $Diseno.Dominios.Raiz; $h = $Diseno.Dominios.Hijo
    $dcRaiz = Get-ServidorDiseno -Diseno $Diseno -Rol DCRaiz

    $zonasEsperadas = @(
        @{ Estado = $EstadoRaiz; Zona = $r.FQDN;                  Desc = "Zona $($r.FQDN) integrada en AD" }
        @{ Estado = $EstadoRaiz; Zona = "_msdcs.$($r.FQDN)";      Desc = "Zona _msdcs.$($r.FQDN) integrada en AD" }
        @{ Estado = $EstadoRaiz; Zona = $Diseno.Red.ZonaInversa;  Desc = "Zona inversa $($Diseno.Red.ZonaInversa)" }
        @{ Estado = $EstadoHijo; Zona = $h.FQDN;                  Desc = "Zona $($h.FQDN) integrada en AD (en el DC hijo)" }
        @{ Estado = $EstadoHijo; Zona = $Diseno.Red.ZonaInversa;  Desc = "Zona inversa replicada al DC hijo" }
    )
    foreach ($z in $zonasEsperadas) {
        $zona = @($z.Estado.Dns.Zonas | Where-Object { $_.Nombre -eq $z.Zona }) | Select-Object -First 1
        $obt = 'no existe'
        if ($zona) { $obt = "integrada en AD: $($zona.IntegradaAD) · replicación: $($zona.Replicacion)" }
        New-Resultado $cat $z.Desc 'integrada en AD: True' $obt (Get-ResultadoBool ($zona -and [bool]$zona.IntegradaAD))
    }
    $inv = @($EstadoRaiz.Dns.Zonas | Where-Object { $_.Nombre -eq $Diseno.Red.ZonaInversa }) | Select-Object -First 1
    if ($inv) { New-Resultado $cat 'Replicación de la zona inversa' 'Forest' ([string]$inv.Replicacion) (Get-ResultadoBool ($inv.Replicacion -eq 'Forest') -SoloAdvertencia) }

    $deleg = @($EstadoRaiz.Dns.Delegaciones | Where-Object { $_.Hijo -eq $h.FQDN -or $_.Hijo -eq $h.Etiqueta }) | Select-Object -First 1
    $obt = 'no existe'
    if ($deleg) { $obt = "NS: $(@($deleg.NS) -join ', ')" }
    New-Resultado $cat "Delegación de $($h.FQDN) en la zona $($r.FQDN)" 'existe' $obt (Get-ResultadoBool ([bool]$deleg))

    $reenv = @($Diseno.Red.Reenviadores)
    if ($reenv.Count) {
        $cmp = Compare-Conjunto $reenv @($EstadoRaiz.Dns.Reenviadores)
        New-Resultado $cat "Reenviadores de $($dcRaiz.Nombre)" ($reenv -join ', ') (@($EstadoRaiz.Dns.Reenviadores) -join ', ') (Get-ResultadoBool $cmp.Iguales -SoloAdvertencia)
    }
    $okH = $dcRaiz.IPFinal -in @($EstadoHijo.Dns.Reenviadores)
    New-Resultado $cat 'Reenviador del DC hijo hacia el DC raíz' $dcRaiz.IPFinal (@($EstadoHijo.Dns.Reenviadores) -join ', ') (Get-ResultadoBool $okH -SoloAdvertencia)
    foreach ($e in $EstadoRaiz, $EstadoHijo) {
        New-Resultado $cat "Scavenging en $($e.DC.HostName)" 'habilitado' ([string]$e.Dns.Scavenging) (Get-ResultadoBool ([bool]$e.Dns.Scavenging) -SoloAdvertencia)
    }
    foreach ($q in @($EstadoRaiz.Consultas) + @($EstadoHijo.Consultas)) {
        if (-not $q) { continue }
        $res = 'OK'
        if (-not $q.OK) { $res = 'ADVERTENCIA'; if ($q.Critica) { $res = 'FALLA' } }
        $esp = $q.Esperado; if (-not $esp) { $esp = 'al menos un registro' }
        New-Resultado $cat "[$($q.Servidor)] $($q.Tipo) $($q.Consulta)" $esp $q.Obtenido $res
    }
}

# =====================================================================
#  Estructura lógica y cuentas
# =====================================================================
function Test-Estructura {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Diseno, [Parameter(Mandatory)][ValidateSet('Raiz', 'Hijo')][string]$Clave, [Parameter(Mandatory)]$Estado)
    $d = $Diseno.Dominios.$Clave
    $cat = "Estructura y cuentas ($($d.FQDN))"
    $ous = @{}
    foreach ($o in @($Estado.OUs)) { $ous[$o.DN.ToLowerInvariant()] = $o }
    foreach ($ou in @($Diseno.OUs | Where-Object { $_.Dominio -eq $Clave })) {
        $o = $ous[$ou.DN.ToLowerInvariant()]
        if (-not $o) { New-Resultado $cat "OU $($ou.Nombre)" 'existe' 'no existe' 'FALLA'; continue }
        New-Resultado $cat "OU $($ou.Nombre)" 'existe, protegida contra borrado' "existe, protegida: $($o.Protegida)" (Get-ResultadoBool ([bool]$o.Protegida) -SoloAdvertencia)
    }
    $usuarios = @{}
    foreach ($u in @($Estado.Usuarios)) { $usuarios[$u.Sam.ToLowerInvariant()] = $u }
    $previstos = @($Diseno.Usuarios | Where-Object { $_.Dominio -eq $Clave })
    foreach ($u in $previstos) {
        $real = $usuarios[$u.Sam.ToLowerInvariant()]
        $prueba = "Cuenta $($u.NetBIOS)\$($u.Sam) ($($u.NombreCompleto))"
        if (-not $real) { New-Resultado $cat $prueba 'existe' 'no existe' 'FALLA'; continue }
        $dnEsperado = "CN=$($u.CN),$($u.OU)"
        $problemas = @()
        if ($real.UPN -ne $u.UPN) { $problemas += "UPN $($real.UPN)" }
        if (-not $real.Habilitado) { $problemas += 'deshabilitada' }
        if ($real.DN -ne $dnEsperado) { $problemas += "ubicada en $($real.DN)" }
        $obt = 'correcta'; if ($problemas) { $obt = $problemas -join ' · ' }
        New-Resultado $cat $prueba "UPN $($u.UPN) · habilitada · OU $($u.Area)" $obt (Get-ResultadoBool (-not $problemas))
    }
    $creadas = @($previstos | Where-Object { $usuarios.ContainsKey($_.Sam.ToLowerInvariant()) }).Count
    New-Resultado $cat 'Total de cuentas del diseño presentes' "$($previstos.Count)" "$creadas" (Get-ResultadoBool ($creadas -eq $previstos.Count))
}

# =====================================================================
#  Grupos (AGUDLP)
# =====================================================================
function Get-DNUsuario { param($Diseno, [string]$Clave, [string]$Sam)
    $u = @($Diseno.Usuarios | Where-Object { $_.Dominio -eq $Clave -and $_.Sam -eq $Sam }) | Select-Object -First 1
    return "CN=$($u.CN),$($u.OU)"
}

function Test-Grupos {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Diseno, [Parameter(Mandatory)]$EstadoRaiz, [Parameter(Mandatory)]$EstadoHijo)
    $cat = 'Grupos (AGUDLP)'
    $estados = @{ Raiz = $EstadoRaiz; Hijo = $EstadoHijo }
    $dnGG = @{}

    foreach ($g in @($Diseno.GruposGlobales)) {
        $dnGG[$g.Nombre] = "CN=$($g.Nombre),$($g.OU)"
        $real = @($estados[$g.Dominio].Grupos | Where-Object { $_.Nombre -eq $g.Nombre }) | Select-Object -First 1
        $prueba = "$($g.Nombre) ($($g.DominioFQDN))"
        if (-not $real) { New-Resultado $cat $prueba 'existe' 'no existe' 'FALLA'; continue }
        New-Resultado $cat "$prueba – ámbito" 'Global / Security' "$($real.Ambito) / $($real.Categoria)" (Get-ResultadoBool ($real.Ambito -eq 'Global' -and $real.Categoria -eq 'Security'))
        $esperados = @($g.Miembros | ForEach-Object { Get-DNUsuario $Diseno $g.Dominio $_ })
        $cmp = Compare-Conjunto $esperados @($real.Miembros)
        New-Resultado $cat "$prueba – miembros" "$($esperados.Count) cuentas del área $($g.Area)" "$(@($real.Miembros).Count) miembros · $(Get-TextoDiferencia $cmp { param($x) Get-CN $x })" (Get-ResultadoBool $cmp.Iguales)
    }

    $entreDominios = 0
    foreach ($g in @($Diseno.GruposDL)) {
        $real = @($EstadoRaiz.Grupos | Where-Object { $_.Nombre -eq $g.Nombre }) | Select-Object -First 1
        $prueba = "$($g.Nombre) ($($g.DominioFQDN))"
        if (-not $real) { New-Resultado $cat $prueba 'existe' 'no existe' 'FALLA'; continue }
        New-Resultado $cat "$prueba – ámbito" 'DomainLocal / Security' "$($real.Ambito) / $($real.Categoria)" (Get-ResultadoBool ($real.Ambito -eq 'DomainLocal' -and $real.Categoria -eq 'Security'))
        $esperados = @($g.Miembros | ForEach-Object { $dnGG[$_.Grupo] })
        $cmp = Compare-Conjunto $esperados @($real.Miembros)
        $nombres = @($g.Miembros | ForEach-Object { $_.Referencia }) -join ', '
        New-Resultado $cat "$prueba – miembros" $nombres (Get-TextoDiferencia $cmp { param($x) Get-CN $x }) (Get-ResultadoBool $cmp.Iguales)
        $entreDominios += @($g.Miembros | Where-Object { $_.DominioFQDN -ne $g.DominioFQDN }).Count
    }
    New-Resultado $cat 'Anidamientos entre dominios (GG del hijo dentro de DL del raíz)' 'informativo' "$entreDominios" 'OK'
}

# =====================================================================
#  Recursos compartidos y NTFS
# =====================================================================
function Test-Recursos {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Diseno, [Parameter(Mandatory)]$EstadoArchivos)
    $cat = 'Recursos y permisos'
    $srv = Get-ServidorDiseno -Diseno $Diseno -Rol Archivos
    New-Resultado $cat "$($srv.Nombre) miembro del dominio" $Diseno.Dominios.Raiz.FQDN ([string]$EstadoArchivos.Dominio) (Get-ResultadoBool ($EstadoArchivos.ParteDominio -and $EstadoArchivos.Dominio -eq $Diseno.Dominios.Raiz.FQDN))

    foreach ($r in @($Diseno.Recursos)) {
        $e = @($EstadoArchivos.Recursos | Where-Object { $_.Nombre -eq $r.Nombre }) | Select-Object -First 1
        $p = "\\$($srv.Nombre)\$($r.Nombre)"
        if (-not $e -or -not $e.Compartido) { New-Resultado $cat "$p – recurso compartido" 'existe' 'no existe' 'FALLA'; continue }
        $sid = @{}
        foreach ($m in @($e.SidDiseno)) { $sid[$m.Cuenta] = $m.Sid }

        New-Resultado $cat "$p – carpeta" $r.RutaLocal "$($e.Ruta) (existe: $($e.CarpetaExiste))" (Get-ResultadoBool ($e.CarpetaExiste -and $e.Ruta.TrimEnd('\') -eq $r.RutaLocal.TrimEnd('\')))
        $abe = 'Unrestricted'; if ($r.ABE) { $abe = 'AccessBased' }
        New-Resultado $cat "$p – enumeración basada en el acceso" $abe ([string]$e.ABE) (Get-ResultadoBool ($e.ABE -eq $abe))

        # Permisos del recurso compartido (exactos, sin Todos)
        $espComp = @($r.PermisosCompartido | ForEach-Object { "$($sid[$_.Cuenta])=$($_.Permiso)" })
        $obtComp = @($e.AccesoCompartido | Where-Object { $_.Tipo -eq 'Allow' } | ForEach-Object { "$($_.Sid)=$($_.Derecho)" })
        $cmp = Compare-Conjunto $espComp $obtComp
        $nombresSid = @{}
        foreach ($a in @($e.AccesoCompartido)) { $nombresSid[$a.Sid.ToLowerInvariant()] = $a.Cuenta }
        foreach ($k in $sid.Keys) { $nombresSid[$sid[$k].ToLowerInvariant()] = $k }
        $fmt = { param($x) $s, $d = $x -split '='; $n = $nombresSid[$s]; if (-not $n) { $n = $s }; "$n=$d" }.GetNewClosure()
        New-Resultado $cat "$p – permisos del recurso compartido" (@($r.PermisosCompartido | ForEach-Object { "$($_.Cuenta)=$($_.Permiso)" }) -join '; ') (Get-TextoDiferencia $cmp $fmt) (Get-ResultadoBool $cmp.Iguales)
        $todos = @($e.AccesoCompartido | Where-Object { $_.Sid -eq 'S-1-1-0' }).Count -gt 0
        New-Resultado $cat "$p – sin 'Todos' (Everyone)" 'ausente' $(if ($todos) { 'presente' } else { 'ausente' }) (Get-ResultadoBool (-not $todos))

        # NTFS
        New-Resultado $cat "$p – herencia NTFS deshabilitada" 'True' ([string]$e.NTFSProtegido) (Get-ResultadoBool ([bool]$e.NTFSProtegido))
        $espNTFS = @($r.PermisosNTFS | ForEach-Object { "$($sid[$_.Cuenta])=$($script:DerechosNTFS[$_.Permiso])" })
        $obtNTFS = @($e.NTFS | Where-Object { $_.Tipo -eq 'Allow' -and -not $_.Heredada } | ForEach-Object { "$($_.Sid)=$($_.Derechos)" })
        foreach ($a in @($e.NTFS)) { $nombresSid[$a.Sid.ToLowerInvariant()] = $a.Cuenta }
        $inv = @{}; foreach ($k in $script:DerechosNTFS.Keys) { $inv[[string]$script:DerechosNTFS[$k]] = $k }
        $fmtN = { param($x) $s, $d = $x -split '='; $n = $nombresSid[$s]; if (-not $n) { $n = $s }; $dd = $inv[$d]; if (-not $dd) { $dd = $d }; "$n=$dd" }.GetNewClosure()
        $cmp = Compare-Conjunto $espNTFS $obtNTFS
        New-Resultado $cat "$p – permisos NTFS" (@($r.PermisosNTFS | ForEach-Object { "$($_.Cuenta)=$($_.Permiso)" }) -join '; ') (Get-TextoDiferencia $cmp $fmtN) (Get-ResultadoBool $cmp.Iguales)
        $sinHerencia = @($e.NTFS | Where-Object { -not $_.Heredada -and -not ($_.Herencia -match 'ContainerInherit' -and $_.Herencia -match 'ObjectInherit') }).Count
        New-Resultado $cat "$p – reglas NTFS se propagan a subcarpetas y archivos" 'ContainerInherit, ObjectInherit' "$sinHerencia regla(s) sin propagación" (Get-ResultadoBool ($sinHerencia -eq 0) -SoloAdvertencia)
    }
}

# =====================================================================
#  Pruebas de acceso reales
# =====================================================================
function Get-NivelEsperado {
    <# Nivel efectivo de un grupo global sobre un recurso: el mayor entre los DL que lo contienen. #>
    param([Parameter(Mandatory)]$Diseno, [AllowEmptyString()][string]$Grupo, [Parameter(Mandatory)][string]$Recurso)
    $nivel = 'SinAcceso'
    if (-not $Grupo) { return $nivel }
    foreach ($dl in @($Diseno.GruposDL | Where-Object { $_.Recurso -eq $Recurso })) {
        if (@($dl.Miembros | Where-Object { $_.Grupo -eq $Grupo }).Count -and $script:RangoNivel[$dl.Nivel] -gt $script:RangoNivel[$nivel]) { $nivel = $dl.Nivel }
    }
    return $nivel
}

function Get-CasosPrueba {
    <#
    .SYNOPSIS
        Una cuenta temporal por grupo global (representa a cualquier usuario del área) y una cuenta
        sin grupos en cada dominio (control negativo). Para cada una, el nivel esperado por recurso.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Diseno)
    $casos = New-Object System.Collections.Generic.List[object]
    $n = 0
    $definiciones = @($Diseno.GruposGlobales | ForEach-Object { [pscustomobject]@{ Dominio = $_.Dominio; Grupo = $_.Nombre; Area = $_.Area } })
    $definiciones += [pscustomobject]@{ Dominio = 'Hijo'; Grupo = ''; Area = '(sin grupo)' }
    $definiciones += [pscustomobject]@{ Dominio = 'Raiz'; Grupo = ''; Area = '(sin grupo)' }
    foreach ($def in $definiciones) {
        $n++
        $d = $Diseno.Dominios.($def.Dominio)
        $esperado = @($Diseno.Recursos | ForEach-Object { [pscustomobject]@{ Recurso = $_.Nombre; Nivel = (Get-NivelEsperado -Diseno $Diseno -Grupo $def.Grupo -Recurso $_.Nombre) } })
        $casos.Add([pscustomobject]@{
                Sam = 'zzprueba{0:D2}' -f $n; Dominio = $def.Dominio; DominioFQDN = $d.FQDN; NetBIOS = $d.NetBIOS
                Grupo = $def.Grupo; Area = $def.Area; Esperado = $esperado
            })
    }
    return $casos.ToArray()
}

function Test-ResultadoAcceso {
    <#
    .SYNOPSIS
        Compara lo que pudo hacer una cuenta en un recurso con su nivel esperado.
        Lectura: listar y leer sí, escribir no.  Modificar: todo.  SinAcceso: nada.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Caso, [Parameter(Mandatory)][string]$Recurso, [Parameter(Mandatory)]$Operaciones, [string]$Servidor = '')
    $nivel = (@($Caso.Esperado | Where-Object { $_.Recurso -eq $Recurso }) | Select-Object -First 1).Nivel
    $rango = $script:RangoNivel[$nivel]
    $espera = [ordered]@{ Lista = ($rango -ge 1); Lee = ($rango -ge 1); Escribe = ($rango -ge 2) }
    $simbolo = { param($b) if ($null -eq $b) { '–' } elseif ($b) { 'sí' } else { 'no' } }
    $obt = "lista: $(& $simbolo $Operaciones.Lista) · lee: $(& $simbolo $Operaciones.Lee) · escribe: $(& $simbolo $Operaciones.Escribe) · borra: $(& $simbolo $Operaciones.Borra)"
    $ok = ($Operaciones.Lista -eq $espera.Lista) -and ($Operaciones.Lee -eq $espera.Lee) -and ($Operaciones.Escribe -eq $espera.Escribe)
    if ($espera.Escribe) { $ok = $ok -and [bool]$Operaciones.Borra }
    $esp = switch ($nivel) { 'Modificar' { 'Modificar (lista, lee, escribe, borra)' } 'Lectura' { 'Lectura (lista y lee; no escribe)' } default { 'Sin acceso' } }
    if ($Operaciones.Error -and -not $ok) { $obt += " · $($Operaciones.Error)" }
    $quien = "$($Caso.NetBIOS)\$($Caso.Sam) [$(if ($Caso.Grupo) { $Caso.Grupo } else { 'sin grupo' })]"
    New-Resultado 'Acceso real entre dominios' "$quien -> \\$Servidor\$Recurso" $esp $obt (Get-ResultadoBool $ok)
}

# =====================================================================
#  Informe
# =====================================================================
function Export-InformeValidacion {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object[]]$Resultados, [Parameter(Mandatory)]$Diseno, [Parameter(Mandatory)][string]$RutaSalida)
    $carpeta = Join-Path $RutaSalida 'validacion'
    if (-not (Test-Path $carpeta)) { New-Item -Path $carpeta -ItemType Directory -Force | Out-Null }
    $Resultados | Export-Csv -Path (Join-Path $carpeta 'resultados.csv') -NoTypeInformation -Encoding UTF8

    $enc = { param($t) [System.Net.WebUtility]::HtmlEncode([string]$t) }
    $total = $Resultados.Count
    $ok = @($Resultados | Where-Object Resultado -eq 'OK').Count
    $fa = @($Resultados | Where-Object Resultado -eq 'FALLA').Count
    $ad = @($Resultados | Where-Object Resultado -eq 'ADVERTENCIA').Count
    $sb = New-Object System.Text.StringBuilder
    foreach ($g in @($Resultados | Group-Object Categoria)) {
        $gf = @($g.Group | Where-Object Resultado -eq 'FALLA').Count
        $ga = @($g.Group | Where-Object Resultado -eq 'ADVERTENCIA').Count
        [void]$sb.Append("<h2>$(& $enc $g.Name) <span class='cnt'>$($g.Count) pruebas · $gf fallas · $ga advertencias</span></h2>")
        [void]$sb.Append('<table><thead><tr><th>Resultado</th><th>Prueba</th><th>Esperado</th><th>Obtenido</th></tr></thead><tbody>')
        foreach ($r in $g.Group) {
            $cls = $r.Resultado.ToLowerInvariant()
            [void]$sb.Append("<tr class='$cls'><td><span class='b $cls'>$($r.Resultado)</span></td><td>$(& $enc $r.Prueba)</td><td>$(& $enc $r.Esperado)</td><td>$(& $enc $r.Obtenido)</td></tr>")
        }
        [void]$sb.Append('</tbody></table>')
    }
    $estadoGeneral = 'APROBADA'; $claseGeneral = 'ok'
    if ($fa) { $estadoGeneral = 'CON FALLAS'; $claseGeneral = 'falla' }
    $html = @"
<!DOCTYPE html>
<html lang="es"><head><meta charset="utf-8"><title>Validación – $($Diseno.Dominios.Raiz.FQDN)</title>
<style>
 body{font-family:Segoe UI,Arial,sans-serif;margin:24px;color:#222;background:#fff}
 h1{color:#1F4E79;margin-bottom:4px} h2{color:#1F4E79;border-bottom:2px solid #D9E2F3;padding-bottom:4px;margin-top:28px;font-size:18px}
 .cnt{font-size:12px;color:#666;font-weight:normal;margin-left:8px}
 .resumen{display:flex;gap:12px;margin:16px 0} .tarjeta{border:1px solid #ddd;border-radius:6px;padding:10px 16px;min-width:110px}
 .tarjeta b{display:block;font-size:24px}
 table{border-collapse:collapse;width:100%;font-size:13px;margin:6px 0} th,td{border:1px solid #ccc;padding:4px 8px;text-align:left;vertical-align:top} th{background:#D9E2F3}
 .b{display:inline-block;padding:1px 8px;border-radius:10px;font-size:11px;font-weight:bold;color:#fff}
 .b.ok{background:#2E7D32} .b.falla{background:#C62828} .b.advertencia{background:#EF8F00}
 tr.falla td{background:#FDECEA} tr.advertencia td{background:#FFF6E5}
 .general.ok{color:#2E7D32} .general.falla{color:#C62828}
</style></head><body>
<h1>Informe de validación</h1>
<p>$(& $enc $Diseno.Parametros.Empresa) · $($Diseno.Dominios.Raiz.FQDN) / $($Diseno.Dominios.Hijo.FQDN) · $(Get-Date -Format 'dd/MM/yyyy HH:mm')</p>
<h2 class="general $claseGeneral">Resultado general: $estadoGeneral</h2>
<div class="resumen">
 <div class="tarjeta">Pruebas<b>$total</b></div><div class="tarjeta">Correctas<b style="color:#2E7D32">$ok</b></div>
 <div class="tarjeta">Fallas<b style="color:#C62828">$fa</b></div><div class="tarjeta">Advertencias<b style="color:#EF8F00">$ad</b></div>
</div>
$($sb.ToString())
</body></html>
"@
    $archivo = Join-Path $carpeta 'informe-validacion.html'
    Set-Content -Path $archivo -Value $html -Encoding UTF8
    return $archivo
}

Export-ModuleMember -Function Test-Bosque, Test-Dns, Test-Estructura, Test-Grupos, Test-Recursos, Get-NivelEsperado, Get-CasosPrueba, Test-ResultadoAcceso, Export-InformeValidacion, New-Resultado, Compare-Conjunto
