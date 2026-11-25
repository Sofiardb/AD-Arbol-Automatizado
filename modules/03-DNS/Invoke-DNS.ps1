#Requires -Version 3.0
<#
.SYNOPSIS
    Paso 3 – DNS: configura y verifica el DNS integrado en AD de ambos dominios (objetivo específico 3).

.DESCRIPTION
    En DC-RAIZ (servidor DNS del dominio raíz):
      - Zona inversa integrada en AD (replicación a todo el bosque) y registros PTR de ambos servidores.
      - Registro A del servidor de archivos (si no se registró dinámicamente).
      - Reenviadores hacia los DNS externos de lab.psd1.
      - Delegación de la zona del dominio hijo (la crea Install-ADDSDomain; acá se verifica y se repara).
      - Envejecimiento y borrado de registros obsoletos (scavenging).
    En DC-HIJO (servidor DNS del dominio hijo):
      - Reenviador hacia DC-RAIZ (resuelve el dominio padre e Internet a través de él).
      - Envejecimiento y scavenging.
    Verificación desde cada DC: registros SRV de localización de DC, Kerberos y catálogo global,
    registros A y PTR de los servidores y, si hay reenviadores, un nombre externo.
    Si faltan registros SRV, fuerza su registro (nltest /dsregdns) y vuelve a verificar.
    Resultado: output\dns-verificacion.csv.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    $Diseno,
    [pscredential]$Credencial,
    [Parameter(Mandatory)][string]$RutaSalida
)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot '../00-Comun/Comun.psm1') -DisableNameChecking
$Diseno = Get-DisenoParaPaso -Diseno $Diseno -RutaSalida $RutaSalida

$srvRaiz = Get-ServidorDiseno -Diseno $Diseno -Rol DCRaiz
$srvHijo = Get-ServidorDiseno -Diseno $Diseno -Rol DCHijo
$domRaiz = $Diseno.Dominios.Raiz
$domHijo = $Diseno.Dominios.Hijo
$red     = $Diseno.Red
$reenviadores = @($red.Reenviadores)

# Datos de los servidores que viajan a los bloques remotos (tipos simples)
$servidores = @($Diseno.Servidores | ForEach-Object {
        [pscustomobject]@{ Nombre = $_.Nombre; FQDN = $_.FQDN; IP = $_.IPFinal; PTR = $_.NombrePTR; Dominio = $_.Dominio }
    })

# Consultas de verificación
$consultas = New-Object System.Collections.Generic.List[object]
foreach ($d in $domRaiz, $domHijo) {
    $consultas.Add([pscustomobject]@{ Nombre = "_ldap._tcp.dc._msdcs.$($d.FQDN)"; Tipo = 'SRV'; Esperado = ''; Critica = $true; Descripcion = "Localización de DC de $($d.FQDN)" })
    $consultas.Add([pscustomobject]@{ Nombre = "_ldap._tcp.pdc._msdcs.$($d.FQDN)"; Tipo = 'SRV'; Esperado = ''; Critica = $true; Descripcion = "Emulador de PDC de $($d.FQDN)" })
    $consultas.Add([pscustomobject]@{ Nombre = "_kerberos._tcp.$($d.FQDN)"; Tipo = 'SRV'; Esperado = ''; Critica = $true; Descripcion = "KDC (Kerberos) de $($d.FQDN)" })
}
$consultas.Add([pscustomobject]@{ Nombre = "_gc._tcp.$($domRaiz.FQDN)"; Tipo = 'SRV'; Esperado = ''; Critica = $true; Descripcion = 'Catálogo global del bosque' })
foreach ($s in $servidores) {
    $consultas.Add([pscustomobject]@{ Nombre = $s.FQDN; Tipo = 'A'; Esperado = $s.IP; Critica = $true; Descripcion = "Registro A de $($s.Nombre)" })
    $consultas.Add([pscustomobject]@{ Nombre = $s.IP; Tipo = 'PTR'; Esperado = $s.FQDN; Critica = $true; Descripcion = "Registro PTR de $($s.Nombre)" })
}
if ($reenviadores.Count) {
    $consultas.Add([pscustomobject]@{ Nombre = 'www.microsoft.com'; Tipo = 'A'; Esperado = ''; Critica = $false; Descripcion = 'Resolución externa (reenviadores)' })
}

# =====================================================================
#  Simulación
# =====================================================================
if ($WhatIfPreference) {
    Write-Log "[$($srvRaiz.Nombre)] DNS del dominio raíz"
    Write-Plan "zona inversa $($red.ZonaInversa) (NetworkId $($red.NetworkIdZona), replicación: bosque, actualizaciones seguras)"
    foreach ($s in $servidores) { Write-Plan "PTR $($s.PTR).$($red.ZonaInversa) -> $($s.FQDN)" }
    Write-Plan "registros A de los servidores del dominio raíz si no se registraron dinámicamente"
    Write-Plan "reenviadores: $(if ($reenviadores.Count) { $reenviadores -join ', ' } else { '(ninguno)' })"
    Write-Plan "delegación $($domHijo.Etiqueta).$($domRaiz.FQDN) -> $($srvHijo.FQDN) ($($srvHijo.IPFinal))"
    Write-Plan 'scavenging cada 7 días y envejecimiento en las zonas del dominio y la inversa'
    Write-Log "[$($srvHijo.Nombre)] DNS del dominio hijo"
    Write-Plan "reenviador -> $($srvRaiz.IPFinal) ($($srvRaiz.Nombre))"
    Write-Plan 'scavenging cada 7 días y envejecimiento en la zona del dominio hijo'
    Write-Log "Verificación desde ambos DC: $($consultas.Count) consultas (SRV, A, PTR, externa)"
    foreach ($q in $consultas) { Write-Plan "$($q.Tipo) $($q.Nombre)$(if ($q.Esperado) { " = $($q.Esperado)" })" }
    return 'Simulado'
}

if (-not $Credencial) { throw 'Se requiere la credencial del despliegue.' }
$cred = Get-CredencialesLab -Credencial $Credencial -Diseno $Diseno

# =====================================================================
#  Bloques remotos
# =====================================================================
$bloqueDnsRaiz = {
    param([string]$Zona, [string]$NetworkId, [object[]]$Servidores, [string[]]$Reenviadores, [string]$Raiz, [string]$Etiqueta, [string]$DcHijoFQDN, [string]$DcHijoIP)
    $ErrorActionPreference = 'Stop'
    $acciones = New-Object System.Collections.Generic.List[string]

    # Zona inversa
    if (-not (Get-DnsServerZone -Name $Zona -ErrorAction SilentlyContinue)) {
        Add-DnsServerPrimaryZone -NetworkId $NetworkId -ReplicationScope Forest -DynamicUpdate Secure
        $acciones.Add("Zona inversa $Zona creada (integrada en AD, replicación al bosque).")
    }
    else { $acciones.Add("Zona inversa $Zona ya existía.") }

    # PTR de cada servidor
    foreach ($s in $Servidores) {
        $destino = "$($s.FQDN)."
        $existentes = @(Get-DnsServerResourceRecord -ZoneName $Zona -Name $s.PTR -RRType Ptr -ErrorAction SilentlyContinue)
        $correcto = @($existentes | Where-Object { $_.RecordData.PtrDomainName -eq $destino })
        if ($correcto.Count -eq 0) {
            foreach ($e in $existentes) { Remove-DnsServerResourceRecord -ZoneName $Zona -InputObject $e -Force }
            Add-DnsServerResourceRecordPtr -ZoneName $Zona -Name $s.PTR -PtrDomainName $destino
            $acciones.Add("PTR $($s.PTR) -> $destino creado.")
        }
    }

    # Registro A de los servidores del dominio raíz (los DC se registran solos; el miembro puede demorar)
    foreach ($s in @($Servidores | Where-Object { $_.Dominio -eq $Raiz })) {
        $hostname = $s.FQDN.Substring(0, $s.FQDN.Length - $Raiz.Length - 1)
        $a = @(Get-DnsServerResourceRecord -ZoneName $Raiz -Name $hostname -RRType A -ErrorAction SilentlyContinue | Where-Object { $_.RecordData.IPv4Address.IPAddressToString -eq $s.IP })
        if ($a.Count -eq 0) {
            Add-DnsServerResourceRecordA -ZoneName $Raiz -Name $hostname -IPv4Address $s.IP
            $acciones.Add("A $hostname.$Raiz -> $($s.IP) creado.")
        }
    }

    # Reenviadores
    if ($Reenviadores.Count) {
        Set-DnsServerForwarder -IPAddress $Reenviadores -UseRootHint $true
        $acciones.Add("Reenviadores: $($Reenviadores -join ', ').")
    }

    # Delegación del dominio hijo
    $deleg = Get-DnsServerZoneDelegation -Name $Raiz -ChildZoneName $Etiqueta -ErrorAction SilentlyContinue
    if (-not $deleg) {
        Add-DnsServerZoneDelegation -Name $Raiz -ChildZoneName $Etiqueta -NameServer $DcHijoFQDN -IPAddress $DcHijoIP
        $acciones.Add("Delegación $Etiqueta.$Raiz -> $DcHijoFQDN creada.")
    }
    else { $acciones.Add("Delegación $Etiqueta.$Raiz verificada (NS: $(@($deleg | ForEach-Object { $_.NameServer.RecordData.NameServer }) -join ', ')).") }

    # Scavenging y envejecimiento
    Set-DnsServerScavenging -ScavengingState $true -ScavengingInterval 7.00:00:00 -RefreshInterval 7.00:00:00 -NoRefreshInterval 7.00:00:00 -ApplyOnAllZones
    foreach ($z in $Raiz, $Zona) { Set-DnsServerZoneAging -Name $z -Aging $true }
    $acciones.Add('Scavenging habilitado (7 días) y envejecimiento en las zonas.')
    $acciones.ToArray()
}

$bloqueDnsHijo = {
    param([string]$Hijo, [string]$IPRaiz)
    $ErrorActionPreference = 'Stop'
    Set-DnsServerForwarder -IPAddress $IPRaiz -UseRootHint $true
    Set-DnsServerScavenging -ScavengingState $true -ScavengingInterval 7.00:00:00 -RefreshInterval 7.00:00:00 -NoRefreshInterval 7.00:00:00 -ApplyOnAllZones
    Set-DnsServerZoneAging -Name $Hijo -Aging $true
    @("Reenviador -> $IPRaiz.", 'Scavenging habilitado (7 días) y envejecimiento en la zona.')
}

$bloqueVerificar = {
    param([object[]]$Consultas, [string]$ServidorDns)
    foreach ($q in $Consultas) {
        $obtenido = ''; $ok = $false
        try {
            $r = @(Resolve-DnsName -Name $q.Nombre -Type $q.Tipo -Server $ServidorDns -DnsOnly -QuickTimeout -ErrorAction Stop | Where-Object { $_.Type -eq $q.Tipo })
            switch ($q.Tipo) {
                'SRV' { $valores = @($r | ForEach-Object { "$($_.NameTarget):$($_.Port)" }); $ok = $valores.Count -gt 0 }
                'A'   { $valores = @($r | ForEach-Object { $_.IPAddress }); $ok = $valores.Count -gt 0 -and (-not $q.Esperado -or $q.Esperado -in $valores) }
                'PTR' { $valores = @($r | ForEach-Object { $_.NameHost.TrimEnd('.').ToLowerInvariant() }); $ok = $q.Esperado.ToLowerInvariant() -in $valores }
            }
            $obtenido = $valores -join ', '
        }
        catch { $obtenido = "sin respuesta: $($_.Exception.Message)" }
        [pscustomobject]@{ Servidor = $env:COMPUTERNAME; Tipo = $q.Tipo; Consulta = $q.Nombre; Esperado = $q.Esperado; Obtenido = $obtenido; OK = $ok; Critica = [bool]$q.Critica; Descripcion = $q.Descripcion }
    }
}

$bloqueReregistrar = {
    & nltest.exe /dsregdns | Out-Null
    & ipconfig.exe /registerdns | Out-Null
    Restart-Service -Name Netlogon -Force
}

# =====================================================================
#  Configuración
# =====================================================================
Write-Log "[$($srvRaiz.Nombre)] Configurando DNS del dominio raíz" -Nivel Paso
$acc = Invoke-EnServidor -Equipo $srvRaiz.IPFinal -Credencial $cred.Raiz -Bloque $bloqueDnsRaiz -Descripcion 'zona inversa, PTR, reenviadores, delegación y scavenging' `
    -Argumentos @($red.ZonaInversa, $red.NetworkIdZona, $servidores, $reenviadores, $domRaiz.FQDN, $domHijo.Etiqueta, $srvHijo.FQDN, $srvHijo.IPFinal)
foreach ($a in @($acc)) { Write-Log "  $a" -Nivel Ok }

Write-Log "[$($srvHijo.Nombre)] Configurando DNS del dominio hijo" -Nivel Paso
$acc = Invoke-EnServidor -Equipo $srvHijo.IPFinal -Credencial $cred.Hijo -Bloque $bloqueDnsHijo -Argumentos @($domHijo.FQDN, $srvRaiz.IPFinal) -Descripcion 'reenviador y scavenging'
foreach ($a in @($acc)) { Write-Log "  $a" -Nivel Ok }

# =====================================================================
#  Verificación (con reintentos: el registro dinámico puede demorar)
# =====================================================================
Write-Log 'Verificando la resolución desde ambos controladores de dominio' -Nivel Paso
$dcs = @(
    [pscustomobject]@{ Servidor = $srvRaiz; Credencial = $cred.Raiz }
    [pscustomobject]@{ Servidor = $srvHijo; Credencial = $cred.Hijo }
)
$intentosMax = 3
for ($intento = 1; $intento -le $intentosMax; $intento++) {
    $resultados = @(foreach ($dc in $dcs) {
            Invoke-EnServidor -Equipo $dc.Servidor.IPFinal -Credencial $dc.Credencial -Bloque $bloqueVerificar -Argumentos @($consultas.ToArray(), $dc.Servidor.IPFinal) -Descripcion "$($consultas.Count) consultas DNS"
        })
    $fallasCriticas = @($resultados | Where-Object { -not $_.OK -and $_.Critica })
    if ($fallasCriticas.Count -eq 0 -or $intento -eq $intentosMax) { break }
    Write-Log "$($fallasCriticas.Count) consulta(s) crítica(s) sin respuesta correcta; se fuerza el registro DNS de los DC y se reintenta ($intento/$intentosMax)..." -Nivel Advertencia
    foreach ($dc in $dcs) { Invoke-EnServidor -Equipo $dc.Servidor.IPFinal -Credencial $dc.Credencial -Bloque $bloqueReregistrar -Descripcion 'nltest /dsregdns' }
    Start-Sleep -Seconds 60
}

$resultados | Select-Object Servidor, Tipo, Consulta, Esperado, Obtenido, OK, Critica, Descripcion |
    Export-Csv -Path (Join-Path $RutaSalida 'dns-verificacion.csv') -NoTypeInformation -Encoding UTF8
foreach ($r in $resultados) {
    $nivelLog = 'Ok'
    if (-not $r.OK) { $nivelLog = 'Advertencia'; if ($r.Critica) { $nivelLog = 'Error' } }
    Write-Log ("[{0}] {1,-3} {2} -> {3}" -f $r.Servidor, $r.Tipo, $r.Consulta, $r.Obtenido) -Nivel $nivelLog
}
$fallasCriticas = @($resultados | Where-Object { -not $_.OK -and $_.Critica })
if ($fallasCriticas.Count) { throw "DNS: $($fallasCriticas.Count) verificación(es) crítica(s) fallaron. Ver output\dns-verificacion.csv." }
Write-Log "DNS verificado: $(@($resultados | Where-Object OK).Count)/$($resultados.Count) consultas correctas." -Nivel Ok
return 'Completado'
