#Requires -Version 5.1
<#
.SYNOPSIS
    Paso 6 – Validación automática y documentación de resultados (objetivo específico 6).

.DESCRIPTION
    1. Recolecta el estado real de DC-RAIZ, DC-HIJO y SRV-ARCHIVOS (solo lectura).
    2. Lo compara con el diseño (Validacion.psm1):
         bosque y dominios · confianza · catálogo global · nivel funcional · FSMO
         DNS (zonas, delegación, reenviadores, scavenging, SRV/A/PTR desde ambos DC)
         OU y cuentas · grupos globales y de dominio local (ámbito y pertenencia exacta)
         recursos compartidos, ABE, permisos del recurso compartido y NTFS
    3. Diagnóstico de AD: dcdiag /q en ambos DC y repadmin /replsummary.
    4. Pruebas de acceso REALES: crea una cuenta temporal por grupo global (más una sin grupos en cada
       dominio), se conecta a cada recurso con esa cuenta e intenta listar, leer, escribir y borrar,
       y compara con el nivel esperado. Al terminar elimina las cuentas y archivos de prueba.
    5. Genera output\validacion\informe-validacion.html y resultados.csv.

    Devuelve 'Completado' si no hay fallas, o 'Fallido' si hay al menos una.

.PARAMETER SinPruebasDeAcceso
    Omite el punto 4 (por ejemplo, si el equipo de administración no llega por SMB al servidor de archivos).
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    $Diseno,
    [pscredential]$Credencial,
    [Parameter(Mandatory)][string]$RutaSalida,
    [switch]$SinPruebasDeAcceso
)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot '../00-Comun/Comun.psm1') -DisableNameChecking
Import-Module (Join-Path $PSScriptRoot 'Validacion.psm1') -Force -DisableNameChecking
$Diseno = Get-DisenoParaPaso -Diseno $Diseno -RutaSalida $RutaSalida

$srvRaiz     = Get-ServidorDiseno -Diseno $Diseno -Rol DCRaiz
$srvHijo     = Get-ServidorDiseno -Diseno $Diseno -Rol DCHijo
$srvArchivos = Get-ServidorDiseno -Diseno $Diseno -Rol Archivos
$domRaiz     = $Diseno.Dominios.Raiz
$domHijo     = $Diseno.Dominios.Hijo
$casos       = @(Get-CasosPrueba -Diseno $Diseno)

# Consultas DNS (las mismas que verifica el paso 3)
$consultas = New-Object System.Collections.Generic.List[object]
foreach ($d in $domRaiz, $domHijo) {
    $consultas.Add([pscustomobject]@{ Nombre = "_ldap._tcp.dc._msdcs.$($d.FQDN)"; Tipo = 'SRV'; Esperado = ''; Critica = $true })
    $consultas.Add([pscustomobject]@{ Nombre = "_kerberos._tcp.$($d.FQDN)"; Tipo = 'SRV'; Esperado = ''; Critica = $true })
}
$consultas.Add([pscustomobject]@{ Nombre = "_gc._tcp.$($domRaiz.FQDN)"; Tipo = 'SRV'; Esperado = ''; Critica = $true })
foreach ($s in $Diseno.Servidores) {
    $consultas.Add([pscustomobject]@{ Nombre = $s.FQDN; Tipo = 'A'; Esperado = $s.IPFinal; Critica = $true })
    $consultas.Add([pscustomobject]@{ Nombre = $s.IPFinal; Tipo = 'PTR'; Esperado = $s.FQDN; Critica = $true })
}

$recursos = @($Diseno.Recursos | ForEach-Object {
        [pscustomobject]@{
            Nombre = $_.Nombre; RutaLocal = $_.RutaLocal
            Cuentas = @(@($_.PermisosCompartido) + @($_.PermisosNTFS) | ForEach-Object { $_.Cuenta } | Select-Object -Unique)
        }
    })

# =====================================================================
#  Simulación
# =====================================================================
if ($WhatIfPreference) {
    Write-Plan "leer el estado de $($srvRaiz.Nombre), $($srvHijo.Nombre) y $($srvArchivos.Nombre) (solo lectura)"
    Write-Plan "comparar con el diseño: 2 dominios, $(@($Diseno.OUs).Count) OU, $(@($Diseno.Usuarios).Count) cuentas, $(@($Diseno.GruposGlobales).Count + @($Diseno.GruposDL).Count) grupos, $(@($Diseno.Recursos).Count) recursos, $($consultas.Count * 2) consultas DNS"
    Write-Plan 'dcdiag /q en ambos DC y repadmin /replsummary'
    Write-Plan "pruebas de acceso reales: $($casos.Count) cuentas temporales x $(@($Diseno.Recursos).Count) recursos = $($casos.Count * @($Diseno.Recursos).Count) combinaciones"
    foreach ($c in $casos) {
        $resumen = @($c.Esperado | Where-Object { $_.Nivel -ne 'SinAcceso' } | ForEach-Object { "$($_.Recurso)=$($_.Nivel)" }) -join ', '
        if (-not $resumen) { $resumen = 'ningún recurso (control negativo)' }
        Write-Plan "    $($c.NetBIOS)\$($c.Sam) [$(if ($c.Grupo) { $c.Grupo } else { 'sin grupo' })]: $resumen"
    }
    Write-Plan 'informe: output\validacion\informe-validacion.html y resultados.csv'
    return 'Simulado'
}

if (-not $Credencial) { throw 'Se requiere la credencial del despliegue.' }
$cred = Get-CredencialesLab -Credencial $Credencial -Diseno $Diseno

# =====================================================================
#  Bloques remotos de recolección (solo lectura)
# =====================================================================
$bloqueEstadoAD = {
    param([object[]]$Consultas, [string]$IPPropia, [bool]$EsRaiz)
    $ErrorActionPreference = 'Stop'
    Import-Module ActiveDirectory
    $dom = Get-ADDomain
    $bos = Get-ADForest
    $grupos = @()
    try {
        $grupos = @(Get-ADGroup -SearchBase "OU=Grupos,$($dom.DistinguishedName)" -Filter * -Properties member | ForEach-Object {
                [pscustomobject]@{ Nombre = $_.Name; Ambito = [string]$_.GroupScope; Categoria = [string]$_.GroupCategory; DN = $_.DistinguishedName; Miembros = @($_.member) }
            })
    }
    catch { $grupos = @() }

    $delegaciones = @()
    if ($EsRaiz) {
        $delegaciones = @(Get-DnsServerZoneDelegation -Name $dom.DNSRoot -ErrorAction SilentlyContinue | ForEach-Object {
                [pscustomobject]@{ Hijo = [string]$_.ChildZoneName; NS = @($_.NameServer | ForEach-Object { $_.RecordData.NameServer }) }
            })
    }
    $consultasRes = foreach ($q in $Consultas) {
        $obt = ''; $ok = $false
        try {
            $r = @(Resolve-DnsName -Name $q.Nombre -Type $q.Tipo -Server $IPPropia -DnsOnly -QuickTimeout -ErrorAction Stop | Where-Object { $_.Type -eq $q.Tipo })
            switch ($q.Tipo) {
                'SRV' { $v = @($r | ForEach-Object { "$($_.NameTarget):$($_.Port)" }); $ok = $v.Count -gt 0 }
                'A'   { $v = @($r | ForEach-Object { $_.IPAddress }); $ok = $v.Count -gt 0 -and (-not $q.Esperado -or $q.Esperado -in $v) }
                'PTR' { $v = @($r | ForEach-Object { $_.NameHost.TrimEnd('.').ToLowerInvariant() }); $ok = $q.Esperado.ToLowerInvariant() -in $v }
            }
            $obt = $v -join ', '
        }
        catch { $obt = "sin respuesta: $($_.Exception.Message)" }
        [pscustomobject]@{ Servidor = $env:COMPUTERNAME; Tipo = $q.Tipo; Consulta = $q.Nombre; Esperado = $q.Esperado; Obtenido = $obt; OK = $ok; Critica = [bool]$q.Critica }
    }

    $dcdiag = (& dcdiag.exe /q 2>&1 | Out-String).Trim()
    $repadmin = ''
    if ($EsRaiz) { $repadmin = (& repadmin.exe /replsummary 2>&1 | Out-String).Trim() }

    [pscustomobject]@{
        Dominio = [pscustomobject]@{
            DNSRoot = $dom.DNSRoot; NetBIOSName = $dom.NetBIOSName; ParentDomain = [string]$dom.ParentDomain; DomainMode = [string]$dom.DomainMode
            PDCEmulator = $dom.PDCEmulator; RIDMaster = $dom.RIDMaster; InfrastructureMaster = $dom.InfrastructureMaster
        }
        Bosque = [pscustomobject]@{
            RootDomain = $bos.RootDomain; Domains = @($bos.Domains); GlobalCatalogs = @($bos.GlobalCatalogs); ForestMode = [string]$bos.ForestMode
            SchemaMaster = $bos.SchemaMaster; DomainNamingMaster = $bos.DomainNamingMaster
        }
        DC         = [pscustomobject]@{ HostName = $env:COMPUTERNAME }
        Confianzas = @(Get-ADTrust -Filter * | ForEach-Object { [pscustomobject]@{ Target = $_.Target; Direction = [string]$_.Direction; IntraForest = [bool]$_.IntraForest } })
        OUs        = @(Get-ADOrganizationalUnit -Filter * -Properties ProtectedFromAccidentalDeletion | ForEach-Object { [pscustomobject]@{ DN = $_.DistinguishedName; Protegida = [bool]$_.ProtectedFromAccidentalDeletion } })
        Usuarios   = @(Get-ADUser -Filter * | ForEach-Object { [pscustomobject]@{ Sam = $_.SamAccountName; UPN = $_.UserPrincipalName; Habilitado = [bool]$_.Enabled; DN = $_.DistinguishedName } })
        Grupos     = $grupos
        Dns        = [pscustomobject]@{
            Zonas        = @(Get-DnsServerZone | ForEach-Object { [pscustomobject]@{ Nombre = $_.ZoneName; IntegradaAD = [bool]$_.IsDsIntegrated; Replicacion = [string]$_.ReplicationScope; Inversa = [bool]$_.IsReverseLookupZone } })
            Reenviadores = @((Get-DnsServerForwarder).IPAddress | ForEach-Object { $_.IPAddressToString })
            Scavenging   = [bool](Get-DnsServerScavenging).ScavengingState
            Delegaciones = $delegaciones
        }
        Consultas   = @($consultasRes)
        Diagnostico = [pscustomobject]@{ Dcdiag = $dcdiag; Repadmin = $repadmin }
    }
}

$bloqueEstadoArchivos = {
    param([object[]]$Recursos)
    $ErrorActionPreference = 'Stop'
    $conocidos = @{ 'BUILTIN\Administrators' = 'S-1-5-32-544'; 'NT AUTHORITY\SYSTEM' = 'S-1-5-18'; 'Everyone' = 'S-1-1-0' }
    function Get-Sid([string]$Cuenta) {
        if ($conocidos.ContainsKey($Cuenta)) { return $conocidos[$Cuenta] }
        try { return (New-Object System.Security.Principal.NTAccount($Cuenta)).Translate([System.Security.Principal.SecurityIdentifier]).Value } catch { return "(no resuelve: $Cuenta)" }
    }
    function Get-Nombre([string]$Sid) {
        try { return (New-Object System.Security.Principal.SecurityIdentifier($Sid)).Translate([System.Security.Principal.NTAccount]).Value } catch { return $Sid }
    }
    $sync = 0x100000
    $cs = Get-CimInstance Win32_ComputerSystem
    $lista = foreach ($r in $Recursos) {
        $share = Get-SmbShare -Name $r.Nombre -ErrorAction SilentlyContinue
        $existe = Test-Path -LiteralPath $r.RutaLocal
        $acceso = @(); $ntfs = @(); $protegido = $false
        if ($share) {
            $acceso = @(Get-SmbShareAccess -Name $r.Nombre | ForEach-Object { [pscustomobject]@{ Sid = (Get-Sid $_.AccountName); Cuenta = $_.AccountName; Derecho = [string]$_.AccessRight; Tipo = [string]$_.AccessControlType } })
        }
        if ($existe) {
            $acl = Get-Acl -LiteralPath $r.RutaLocal
            $protegido = $acl.AreAccessRulesProtected
            $ntfs = @($acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]) | ForEach-Object {
                    [pscustomobject]@{ Sid = $_.IdentityReference.Value; Cuenta = (Get-Nombre $_.IdentityReference.Value); Derechos = ([int]$_.FileSystemRights -bor $sync); Heredada = $_.IsInherited; Tipo = [string]$_.AccessControlType; Herencia = [string]$_.InheritanceFlags }
                })
        }
        [pscustomobject]@{
            Nombre = $r.Nombre; CarpetaExiste = $existe; Compartido = [bool]$share; Ruta = $(if ($share) { $share.Path } else { '' })
            ABE = $(if ($share) { [string]$share.FolderEnumerationMode } else { '' })
            AccesoCompartido = $acceso; NTFSProtegido = $protegido; NTFS = $ntfs
            SidDiseno = @($r.Cuentas | ForEach-Object { [pscustomobject]@{ Cuenta = $_; Sid = (Get-Sid $_) } })
        }
    }
    [pscustomobject]@{ Equipo = $env:COMPUTERNAME; ParteDominio = [bool]$cs.PartOfDomain; Dominio = ([string]$cs.Domain).ToLowerInvariant(); Recursos = @($lista) }
}

$bloqueCuentasPrueba = {
    param([string]$Accion, [object[]]$Casos)
    $ErrorActionPreference = 'Stop'
    Import-Module ActiveDirectory
    $marca = 'Cuenta temporal de validacion'
    # Siempre se eliminan restos de ejecuciones anteriores
    Get-ADUser -Filter "Description -like '$marca*'" | Remove-ADUser -Confirm:$false
    if ($Accion -ne 'Crear') { return }
    $dom = Get-ADDomain
    foreach ($c in $Casos) {
        $desc = "$marca ($(if ($c.Grupo) { $c.Grupo } else { 'sin grupo' }))"
        New-ADUser -Name $c.Sam -SamAccountName $c.Sam -UserPrincipalName "$($c.Sam)@$($dom.DNSRoot)" -AccountPassword $c.Password `
            -Enabled $true -ChangePasswordAtLogon $false -PasswordNeverExpires $true -Description $desc
        if ($c.Grupo) { Add-ADGroupMember -Identity $c.Grupo -Members $c.Sam }
    }
}

$bloqueLimpiarArchivos = {
    param([string[]]$Rutas)
    foreach ($r in $Rutas) { Get-ChildItem -LiteralPath $r -Filter 'validacion-*.txt' -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue }
}

# =====================================================================
#  Prueba de acceso desde el equipo de administración
# =====================================================================
function Invoke-PruebaAcceso {
    param([string]$UNC, [pscredential]$CredencialPrueba, [string]$Sam)
    $op = [ordered]@{ Lista = $false; Lee = $false; Escribe = $false; Borra = $null; Error = '' }
    $unidad = 'VAL' + (Get-Random -Minimum 1000 -Maximum 9999)
    $conectado = $false
    for ($i = 1; $i -le 3 -and -not $conectado; $i++) {
        try { New-PSDrive -Name $unidad -PSProvider FileSystem -Root $UNC -Credential $CredencialPrueba -ErrorAction Stop | Out-Null; $conectado = $true }
        catch {
            $op.Error = $_.Exception.Message
            # 1219: queda abierta una conexión al mismo servidor con otra cuenta -> se cierra y se reintenta
            if ($op.Error -match '1219|multiple connections|varias conexiones') {
                Get-SmbMapping -ErrorAction SilentlyContinue | Where-Object { $_.RemotePath -like "$(($UNC -split '\\')[0..2] -join '\')\*" } | Remove-SmbMapping -Force -ErrorAction SilentlyContinue
                Start-Sleep -Seconds 5
            }
            else { break }
        }
    }
    if (-not $conectado) { return [pscustomobject]$op }
    $op.Error = ''
    try {
        try { $null = Get-ChildItem -LiteralPath "${unidad}:\" -ErrorAction Stop; $op.Lista = $true } catch { }
        try { $null = Get-Content -LiteralPath "${unidad}:\LEEME.txt" -ErrorAction Stop; $op.Lee = $true } catch { }
        $archivo = "${unidad}:\validacion-$Sam.txt"
        try { Set-Content -LiteralPath $archivo -Value "Prueba de escritura $(Get-Date -Format s)" -ErrorAction Stop; $op.Escribe = $true } catch { }
        if ($op.Escribe) { try { Remove-Item -LiteralPath $archivo -Force -ErrorAction Stop; $op.Borra = $true } catch { $op.Borra = $false } }
    }
    finally {
        Remove-PSDrive -Name $unidad -Force -ErrorAction SilentlyContinue
        Get-SmbMapping -ErrorAction SilentlyContinue | Where-Object { $_.RemotePath -eq $UNC } | Remove-SmbMapping -Force -ErrorAction SilentlyContinue
    }
    return [pscustomobject]$op
}

# =====================================================================
#  1-2. Recolección y comparación
# =====================================================================
$resultados = New-Object System.Collections.Generic.List[object]
function Add-R($x) { foreach ($i in @($x)) { if ($i) { $resultados.Add($i) } } }

Write-Log 'Recolectando el estado de los servidores' -Nivel Paso
$estados = @{}
foreach ($par in @(@('Raiz', $srvRaiz, $cred.Raiz, $true), @('Hijo', $srvHijo, $cred.Hijo, $false))) {
    $clave, $srv, $c, $esRaiz = $par
    try {
        $estados[$clave] = Invoke-EnServidor -Equipo $srv.IPFinal -Credencial $c -Bloque $bloqueEstadoAD -Argumentos @($consultas.ToArray(), $srv.IPFinal, $esRaiz) -Descripcion 'estado de AD y DNS'
        Add-R (New-Resultado 'Conectividad' "PowerShell Remoting a $($srv.Nombre) ($($srv.IPFinal))" 'conecta' 'conecta' 'OK')
    }
    catch { Add-R (New-Resultado 'Conectividad' "PowerShell Remoting a $($srv.Nombre) ($($srv.IPFinal))" 'conecta' $_.Exception.Message 'FALLA') }
}
$estadoArchivos = $null
try {
    $estadoArchivos = Invoke-EnServidor -Equipo $srvArchivos.IPFinal -Credencial $cred.Raiz -Bloque $bloqueEstadoArchivos -Argumentos @(, $recursos) -Descripcion 'recursos compartidos y NTFS'
    Add-R (New-Resultado 'Conectividad' "PowerShell Remoting a $($srvArchivos.Nombre) ($($srvArchivos.IPFinal))" 'conecta' 'conecta' 'OK')
}
catch { Add-R (New-Resultado 'Conectividad' "PowerShell Remoting a $($srvArchivos.Nombre) ($($srvArchivos.IPFinal))" 'conecta' $_.Exception.Message 'FALLA') }

Write-Log 'Comparando con el diseño' -Nivel Paso
if ($estados.Raiz -and $estados.Hijo) {
    Add-R (Test-Bosque -Diseno $Diseno -EstadoRaiz $estados.Raiz -EstadoHijo $estados.Hijo)
    Add-R (Test-Dns    -Diseno $Diseno -EstadoRaiz $estados.Raiz -EstadoHijo $estados.Hijo)
    Add-R (Test-Grupos -Diseno $Diseno -EstadoRaiz $estados.Raiz -EstadoHijo $estados.Hijo)
}
foreach ($clave in 'Raiz', 'Hijo') { if ($estados[$clave]) { Add-R (Test-Estructura -Diseno $Diseno -Clave $clave -Estado $estados[$clave]) } }
if ($estadoArchivos) { Add-R (Test-Recursos -Diseno $Diseno -EstadoArchivos $estadoArchivos) }

# =====================================================================
#  3. Diagnóstico de AD
# =====================================================================
foreach ($clave in 'Raiz', 'Hijo') {
    $e = $estados[$clave]
    if (-not $e) { continue }
    $txt = [string]$e.Diagnostico.Dcdiag
    $res = 'OK'; $obt = 'sin errores'
    if ($txt) { $res = 'ADVERTENCIA'; $obt = ($txt -split "`r?`n" | Where-Object { $_ -match '\S' } | Select-Object -First 6) -join ' | ' }
    Add-R (New-Resultado 'Diagnóstico de AD' "dcdiag /q en $($e.DC.HostName)" 'sin errores' $obt $res)
}
if ($estados.Raiz -and $estados.Raiz.Diagnostico.Repadmin) {
    $txt = [string]$estados.Raiz.Diagnostico.Repadmin
    $fallas = @([regex]::Matches($txt, '(?m)^\s*\S+\s+\S+\s+(\d+)\s*/\s*(\d+)') | Where-Object { [int]$_.Groups[1].Value -gt 0 }).Count
    $res = 'OK'; if ($fallas -or $txt -match '(?i)error') { $res = 'ADVERTENCIA' }
    Add-R (New-Resultado 'Diagnóstico de AD' 'repadmin /replsummary (replicación entre DC del bosque)' '0 fallas' "$fallas línea(s) con fallas" $res)
}

# =====================================================================
#  4. Pruebas de acceso reales
# =====================================================================
$esWindows = [System.Environment]::OSVersion.Platform -eq 'Win32NT'
if ($SinPruebasDeAcceso) {
    Add-R (New-Resultado 'Acceso real entre dominios' 'Pruebas de acceso' 'ejecutar' 'omitidas por parámetro -SinPruebasDeAcceso' 'ADVERTENCIA')
}
elseif (-not $esWindows) {
    Add-R (New-Resultado 'Acceso real entre dominios' 'Pruebas de acceso' 'ejecutar' 'el equipo de administración no es Windows' 'ADVERTENCIA')
}
elseif (-not $estadoArchivos -or -not $estados.Raiz -or -not $estados.Hijo) {
    Add-R (New-Resultado 'Acceso real entre dominios' 'Pruebas de acceso' 'ejecutar' 'no se pudo leer el estado de los servidores' 'FALLA')
}
else {
    Write-Log "Pruebas de acceso reales: $($casos.Count) cuentas temporales x $(@($Diseno.Recursos).Count) recursos" -Nivel Paso
    $claves = @{}
    $porDominio = @{ Raiz = @(); Hijo = @() }
    foreach ($c in $casos) {
        $claves[$c.Sam] = New-ContrasenaAleatoria -Longitud 20
        $porDominio[$c.Dominio] += [pscustomobject]@{ Sam = $c.Sam; Grupo = $c.Grupo; Password = (ConvertTo-SecureString $claves[$c.Sam] -AsPlainText -Force) }
    }
    $dcs = @{ Raiz = @($srvRaiz.IPFinal, $cred.Raiz); Hijo = @($srvHijo.IPFinal, $cred.Hijo) }
    try {
        foreach ($k in 'Raiz', 'Hijo') {
            Invoke-EnServidor -Equipo $dcs[$k][0] -Credencial $dcs[$k][1] -Bloque $bloqueCuentasPrueba -Argumentos @('Crear', $porDominio[$k]) -Descripcion "crear $($porDominio[$k].Count) cuentas temporales"
        }
        Write-Log 'Esperando 30 s para que las cuentas y la pertenencia a grupos estén disponibles...'
        Start-Sleep -Seconds 30
        foreach ($c in $casos) {
            $credPrueba = New-Object System.Management.Automation.PSCredential("$($c.NetBIOS)\$($c.Sam)", (ConvertTo-SecureString $claves[$c.Sam] -AsPlainText -Force))
            $okCaso = 0
            foreach ($r in $Diseno.Recursos) {
                $op = Invoke-PruebaAcceso -UNC "\\$($srvArchivos.IPFinal)\$($r.Nombre)" -CredencialPrueba $credPrueba -Sam $c.Sam
                $fila = Test-ResultadoAcceso -Caso $c -Recurso $r.Nombre -Operaciones $op -Servidor $srvArchivos.Nombre
                Add-R $fila
                if ($fila.Resultado -eq 'OK') { $okCaso++ }
            }
            $nivelLog = 'Ok'; if ($okCaso -ne @($Diseno.Recursos).Count) { $nivelLog = 'Error' }
            Write-Log ("{0}\{1,-11} [{2,-24}] {3}/{4} recursos con el acceso esperado" -f $c.NetBIOS, $c.Sam, $(if ($c.Grupo) { $c.Grupo } else { 'sin grupo' }), $okCaso, @($Diseno.Recursos).Count) -Nivel $nivelLog
        }
    }
    finally {
        foreach ($k in 'Raiz', 'Hijo') {
            try { Invoke-EnServidor -Equipo $dcs[$k][0] -Credencial $dcs[$k][1] -Bloque $bloqueCuentasPrueba -Argumentos @('Eliminar', @()) -Descripcion 'eliminar cuentas temporales' } catch { Write-Log "No se pudieron eliminar las cuentas temporales en $k." -Nivel Advertencia }
        }
        try { Invoke-EnServidor -Equipo $srvArchivos.IPFinal -Credencial $cred.Raiz -Bloque $bloqueLimpiarArchivos -Argumentos @(, @($Diseno.Recursos | ForEach-Object { $_.RutaLocal })) -Descripcion 'eliminar archivos de prueba' } catch { }
    }
}

# =====================================================================
#  5. Informe
# =====================================================================
$informe = Export-InformeValidacion -Resultados $resultados.ToArray() -Diseno $Diseno -RutaSalida $RutaSalida
$total = $resultados.Count
$fallas = @($resultados | Where-Object Resultado -eq 'FALLA')
$advert = @($resultados | Where-Object Resultado -eq 'ADVERTENCIA').Count
foreach ($g in @($resultados | Group-Object Categoria)) {
    $gf = @($g.Group | Where-Object Resultado -eq 'FALLA').Count
    $nivelLog = 'Ok'; if ($gf) { $nivelLog = 'Error' }
    Write-Log ("{0,-40} {1,4} pruebas · {2} fallas" -f $g.Name, $g.Count, $gf) -Nivel $nivelLog
}
foreach ($f in $fallas | Select-Object -First 15) { Write-Log "FALLA: $($f.Prueba) -> esperado: $($f.Esperado) · obtenido: $($f.Obtenido)" -Nivel Error }
Write-Log "Validación: $total pruebas · $($total - $fallas.Count - $advert) correctas · $($fallas.Count) fallas · $advert advertencias. Informe: $informe" -Nivel $(if ($fallas.Count) { 'Error' } else { 'Ok' })

if ($fallas.Count) { return 'Fallido' }
return 'Completado'
