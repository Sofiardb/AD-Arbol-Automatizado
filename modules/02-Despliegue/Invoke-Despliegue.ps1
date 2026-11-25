#Requires -Version 3.0
<#
.SYNOPSIS
    Paso 2 – Despliegue: prepara los dos servidores y crea el dominio raíz (bosque, cuentas)
    y el dominio hijo (recursos) (objetivo específico 2).

.DESCRIPTION
    Se ejecuta desde el equipo de administración; todo el trabajo en los servidores se hace
    por PowerShell Remoting (Invoke-Command contra la IP de cada VM).

    Fase A  Preparación de DC-RAIZ y DC-HIJO
            roles y características (DC-HIJO incluye el servidor de archivos) · zona horaria ·
            nombre · IP fija · DNS inicial · reinicio
    Fase B  DC-RAIZ: Install-ADDSForest  (bosque + dominio raíz + DNS integrado)
    Fase C  DC-HIJO: Install-ADDSDomain  (dominio hijo + DNS + delegación en el padre)
    Fase D  DNS de cliente definitivo en ambos servidores y verificación de la confianza

    El equipo cliente de la demostración se prepara en el paso 6.

    Es idempotente: cada fase comprueba el estado real del servidor y se omite si ya está hecha,
    por lo que se puede volver a ejecutar después de un corte.

    Requisitos de las VM recién instaladas: WinRM habilitado (Enable-PSRemoting -Force) y la
    contraseña del Administrador local igual a la contraseña del despliegue.
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

$srvRaiz     = Get-ServidorDiseno -Diseno $Diseno -Rol DCRaiz
$srvHijo     = Get-ServidorDiseno -Diseno $Diseno -Rol DCHijo
$domRaiz     = $Diseno.Dominios.Raiz
$domHijo     = $Diseno.Dominios.Hijo
$nivel       = [string]$Diseno.Parametros.NivelFuncional
$zonaHoraria = [string]$Diseno.Parametros.ZonaHoraria

# =====================================================================
#  Simulación (-WhatIf)
# =====================================================================
if ($WhatIfPreference) {
    Write-Log 'Fase A – Preparación de servidores'
    foreach ($s in $Diseno.Servidores) {
        Write-Plan "[$($s.IPActual)] instalar $($s.Roles -join ', ') · zona horaria '$zonaHoraria' · renombrar a $($s.Nombre) · IP $($s.IPActual) -> $($s.IPFinal)/$($Diseno.Red.Prefijo) gw $($Diseno.Red.Gateway) · DNS $($s.DnsInicial -join ', ') · reiniciar"
    }
    Write-Log 'Fase B – Bosque y dominio raíz'
    Write-Plan "[$($srvRaiz.IPFinal)] Install-ADDSForest -DomainName $($domRaiz.FQDN) -DomainNetbiosName $($domRaiz.NetBIOS) -ForestMode/-DomainMode $nivel -InstallDns · reiniciar · esperar AD"
    Write-Log 'Fase C – Dominio hijo'
    Write-Plan "[$($srvHijo.IPFinal)] Install-ADDSDomain -NewDomainName $($domHijo.Etiqueta) -ParentDomainName $($domRaiz.FQDN) -DomainType ChildDomain -InstallDns -CreateDnsDelegation · reiniciar · esperar AD"
    Write-Log 'Fase D – DNS definitivo y verificación'
    foreach ($s in $Diseno.Servidores) { Write-Plan "[$($s.IPFinal)] DNS de cliente: $($s.DnsFinal -join ', ')" }
    Write-Plan "[$($srvRaiz.IPFinal)] verificar confianza $($domRaiz.FQDN) <-> $($domHijo.FQDN) (bidireccional, transitiva)"
    return 'Simulado'
}

if (-not $Credencial) { throw 'Se requiere la credencial del despliegue.' }
$cred = Get-CredencialesLab -Credencial $Credencial -Diseno $Diseno
$todas = @(@($cred.Local) + @($cred.LocalAlternativas) + @($cred.Raiz, $cred.Hijo))
Set-HostsConfiables -IPs @($Diseno.Servidores | ForEach-Object { $_.IPActual, $_.IPFinal })

# =====================================================================
#  Bloques remotos
# =====================================================================
$bloqueEstado = {
    $cs = Get-CimInstance Win32_ComputerSystem
    $os = Get-CimInstance Win32_OperatingSystem
    [pscustomobject]@{
        Nombre      = $env:COMPUTERNAME
        ParteDominio = [bool]$cs.PartOfDomain
        Dominio     = ([string]$cs.Domain).ToLowerInvariant()
        RolDominio  = [int]$cs.DomainRole          # 4 = DC de respaldo, 5 = DC principal
        IPs         = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike '169.254.*' } | ForEach-Object { $_.IPAddress })
        Ahora       = Get-Date
        Arranque    = $os.LastBootUpTime
        SO          = $os.Caption
    }
}

$bloquePreparar = {
    param([string[]]$Roles, [string]$Nombre, [string]$ZonaHoraria)
    $ErrorActionPreference = 'Stop'
    $res = [ordered]@{ Instaladas = @(); ReinicioPorRoles = $false; Renombrado = $false; ZonaHoraria = '' }
    $faltan = @($Roles | Where-Object { -not (Get-WindowsFeature -Name $_).Installed })
    if ($faltan.Count) {
        $r = Install-WindowsFeature -Name $faltan -IncludeManagementTools
        if (-not $r.Success) { throw "No se pudieron instalar: $($faltan -join ', ')" }
        $res.Instaladas = $faltan
        $res.ReinicioPorRoles = ([string]$r.RestartNeeded -eq 'Yes')
    }
    if ($ZonaHoraria) {
        # tzutil funciona en todas las versiones (Set-TimeZone requiere PowerShell 5.1)
        if ((& tzutil.exe /g) -ne $ZonaHoraria) { & tzutil.exe /s $ZonaHoraria }
        $res.ZonaHoraria = (& tzutil.exe /g)
    }
    if ($env:COMPUTERNAME -ne $Nombre) {
        Rename-Computer -NewName $Nombre -Force -WarningAction SilentlyContinue
        $res.Renombrado = $true
    }
    New-Object PSObject -Property $res
}

$bloqueProgramarCambioIP = {
    # Cambiar la IP corta la sesión remota: se delega en una tarea programada que corre como SYSTEM,
    # cambia la IP y el DNS y reinicia el equipo. El resultado queda en C:\Windows\Temp\ad-cambio-ip.log.
    param([string]$IPActual, [string]$IPFinal, [int]$Prefijo, [string]$Gateway, [string[]]$Dns)
    $ErrorActionPreference = 'Stop'
    $ruta = 'C:\Windows\Temp\ad-cambio-ip.ps1'
    $contenido = @'
param([string]$IPActual, [string]$IPFinal, [int]$Prefijo, [string]$Gateway, [string]$Dns)
$log = 'C:\Windows\Temp\ad-cambio-ip.log'
Start-Sleep -Seconds 5
try {
    $idx = (Get-NetIPAddress -AddressFamily IPv4 -IPAddress $IPActual -ErrorAction Stop).InterfaceIndex
    Set-NetIPInterface -InterfaceIndex $idx -Dhcp Disabled -ErrorAction SilentlyContinue
    Get-NetRoute -InterfaceIndex $idx -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue
    Remove-NetIPAddress -InterfaceIndex $idx -AddressFamily IPv4 -Confirm:$false -ErrorAction SilentlyContinue
    New-NetIPAddress -InterfaceIndex $idx -IPAddress $IPFinal -PrefixLength $Prefijo -DefaultGateway $Gateway -ErrorAction Stop | Out-Null
    Set-DnsClientServerAddress -InterfaceIndex $idx -ServerAddresses ($Dns -split ',')
    "$(Get-Date -Format s) OK $IPActual -> $IPFinal/$Prefijo gw $Gateway dns $Dns" | Out-File $log -Append
}
catch { "$(Get-Date -Format s) ERROR $($_.Exception.Message)" | Out-File $log -Append }
Unregister-ScheduledTask -TaskName 'AD-CambioIP' -Confirm:$false -ErrorAction SilentlyContinue
Restart-Computer -Force
'@
    Set-Content -Path $ruta -Value $contenido -Encoding UTF8
    $argumentos = "-NoProfile -ExecutionPolicy Bypass -File `"$ruta`" -IPActual $IPActual -IPFinal $IPFinal -Prefijo $Prefijo -Gateway $Gateway -Dns $($Dns -join ',')"
    $accion = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $argumentos
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    Register-ScheduledTask -TaskName 'AD-CambioIP' -Action $accion -Principal $principal -Force | Out-Null
    Start-ScheduledTask -TaskName 'AD-CambioIP'
}

$bloqueDnsCliente = {
    param([string]$IP, [string[]]$Dns)
    $ErrorActionPreference = 'Stop'
    $idx = (Get-NetIPAddress -AddressFamily IPv4 -IPAddress $IP).InterfaceIndex
    Set-DnsClientServerAddress -InterfaceIndex $idx -ServerAddresses $Dns
    Clear-DnsClientCache
    & ipconfig.exe /registerdns | Out-Null
    @((Get-DnsClientServerAddress -InterfaceIndex $idx -AddressFamily IPv4).ServerAddresses)
}

$bloqueReiniciar = { & shutdown.exe /r /t 5 /f /d p:4:2 /c 'Despliegue AD automatizado' | Out-Null }

$bloqueForest = {
    param([string]$FQDN, [string]$NetBIOS, [string]$Nivel, [securestring]$Dsrm)
    $ErrorActionPreference = 'Stop'
    Import-Module ADDSDeployment
    $p = @{
        DomainName = $FQDN; DomainNetbiosName = $NetBIOS; InstallDns = $true
        SafeModeAdministratorPassword = $Dsrm; NoRebootOnCompletion = $true; Force = $true; WarningAction = 'SilentlyContinue'
    }
    if ($Nivel -and $Nivel -ne 'Default') { $p.ForestMode = $Nivel; $p.DomainMode = $Nivel }
    $r = Install-ADDSForest @p
    # Tras la promoción el servidor ya no acepta la cuenta local hasta reiniciarse:
    # el reinicio se programa en esta misma sesión, que ya está autenticada.
    if ([string]$r.Status -eq 'Success') { & shutdown.exe /r /t 15 /f /d p:4:2 /c 'Promocion a controlador de dominio' | Out-Null }
    [pscustomobject]@{ Estado = [string]$r.Status; Mensaje = [string]$r.Message }
}

$bloqueHijo = {
    param([string]$Etiqueta, [string]$Padre, [string]$NetBIOS, [string]$Nivel, [pscredential]$CredRaiz, [securestring]$Dsrm)
    $ErrorActionPreference = 'Stop'
    # El DC hijo debe poder localizar un DC del dominio padre por DNS
    try { $null = Resolve-DnsName -Name "_ldap._tcp.dc._msdcs.$Padre" -Type SRV -DnsOnly }
    catch { throw "Este servidor no resuelve los registros SRV de $Padre. Verifique que su DNS apunte al DC raíz. ($($_.Exception.Message))" }
    Import-Module ADDSDeployment
    $p = @{
        NewDomainName = $Etiqueta; ParentDomainName = $Padre; NewDomainNetbiosName = $NetBIOS; DomainType = 'ChildDomain'
        InstallDns = $true; CreateDnsDelegation = $true; DnsDelegationCredential = $CredRaiz; Credential = $CredRaiz
        SafeModeAdministratorPassword = $Dsrm; NoRebootOnCompletion = $true; Force = $true; WarningAction = 'SilentlyContinue'
    }
    if ($Nivel -and $Nivel -ne 'Default') { $p.DomainMode = $Nivel }
    $r = Install-ADDSDomain @p
    # Tras la promoción el servidor ya no acepta la cuenta local hasta reiniciarse:
    # el reinicio se programa en esta misma sesión, que ya está autenticada.
    if ([string]$r.Status -eq 'Success') { & shutdown.exe /r /t 15 /f /d p:4:2 /c 'Promocion a controlador de dominio' | Out-Null }
    [pscustomobject]@{ Estado = [string]$r.Status; Mensaje = [string]$r.Message }
}

$bloqueVerificar = {
    param([string]$Hijo)
    $ErrorActionPreference = 'Stop'
    Import-Module ActiveDirectory
    $bosque = Get-ADForest
    $dominio = Get-ADDomain
    $confianza = Get-ADTrust -Filter * | Where-Object { $_.Target -eq $Hijo }
    [pscustomobject]@{
        Dominios          = @($bosque.Domains)
        MaestroEsquema    = $bosque.SchemaMaster
        MaestroNombres    = $bosque.DomainNamingMaster
        PDC               = $dominio.PDCEmulator
        RID               = $dominio.RIDMaster
        Infraestructura   = $dominio.InfrastructureMaster
        CatalogosGlobales = @($bosque.GlobalCatalogs)
        Confianza         = [bool]$confianza
        Direccion         = [string]$(if ($confianza) { $confianza.Direction } else { '' })
        IntraBosque       = [bool]$(if ($confianza) { $confianza.IntraForest } else { $false })
    }
}

# =====================================================================
#  Funciones de apoyo
# =====================================================================
function Get-Estado {
    param($Conexion)
    Invoke-EnServidor -Equipo $Conexion.Equipo -Credencial $Conexion.Credencial -Bloque $bloqueEstado -Descripcion 'leer estado'
}

function Restart-YEsperar {
    <# Reinicia (si se pide), espera a que el equipo vuelva con un arranque posterior a la marca y devuelve la nueva conexión. #>
    param($Servidor, $Conexion, [switch]$YaProgramado, $Marca, [int]$TiempoMaximoSeg = 1500)
    # Marca = hora del servidor antes del reinicio: el equipo "volvió" cuando su último arranque es posterior
    $marca = $Marca
    if (-not $marca) { $marca = (Get-Estado $Conexion).Ahora }
    if (-not $YaProgramado) {
        Invoke-EnServidor -Equipo $Conexion.Equipo -Credencial $Conexion.Credencial -Bloque $bloqueReiniciar -Descripcion 'reiniciar'
    }
    Write-Log "Esperando el reinicio de $($Servidor.Nombre)..."
    Start-Sleep -Seconds 45
    $limite = (Get-Date).AddSeconds($TiempoMaximoSeg)
    while ((Get-Date) -lt $limite) {
        try {
            $c = Connect-Servidor -Servidor $Servidor -Credenciales $todas
            $e = Get-Estado $c
            if ($e.Arranque -gt $marca) { Write-Log "$($Servidor.Nombre) reiniciado y disponible en $($c.Equipo)." -Nivel Ok; return $c }
        }
        catch { Write-Verbose $_.Exception.Message }
        Start-Sleep -Seconds 20
    }
    throw "Tiempo agotado esperando el reinicio de $($Servidor.Nombre)."
}

# =====================================================================
#  Fase A – Preparación
# =====================================================================
Write-Log 'Fase A – Preparación de los servidores' -Nivel Paso
foreach ($s in $Diseno.Servidores) {
    $con = Connect-Servidor -Servidor $s -Credenciales $todas -Intentos 3
    $estado = Get-Estado $con
    Write-Log "[$($con.Equipo)] $($estado.Nombre) · $($estado.SO) · dominio: $(if ($estado.ParteDominio) { $estado.Dominio } else { 'ninguno (grupo de trabajo)' })"
    # El nivel funcional no puede superar la versión de Windows Server de los DC
    $maximo = 'WinThreshold'
    if ($estado.SO -match '2012 R2') { $maximo = 'Win2012R2' }
    elseif ($estado.SO -match '2012') { $maximo = 'Win2012' }
    $orden = @{ Win2012 = 1; Win2012R2 = 2; WinThreshold = 3 }
    if ($nivel -ne 'Default' -and $orden[$nivel] -gt $orden[$maximo]) {
        throw "$($s.Nombre) tiene $($estado.SO): el nivel funcional '$nivel' no está disponible. Ponga NivelFuncional = '$maximo' en config\lab.psd1 y vuelva a ejecutar."
    }

    $prep = Invoke-EnServidor -Equipo $con.Equipo -Credencial $con.Credencial -Bloque $bloquePreparar `
        -Argumentos @(@($s.Roles), $s.Nombre, $zonaHoraria) -Descripcion "roles $($s.Roles -join ', '), zona horaria y nombre $($s.Nombre)"
    if (@($prep.Instaladas).Count) { Write-Log "[$($con.Equipo)] Instalado: $($prep.Instaladas -join ', ')" -Nivel Ok }
    if ($prep.Renombrado) { Write-Log "[$($con.Equipo)] Renombrado $($estado.Nombre) -> $($s.Nombre) (efectivo tras el reinicio)" -Nivel Ok }

    $cambiaIP = ($s.IPFinal -notin @($estado.IPs))
    if ($cambiaIP) {
        if ($estado.ParteDominio) { throw "$($s.Nombre) ya pertenece a un dominio y no tiene la IP final $($s.IPFinal). Cambie la IP a mano o ajuste IPFinal en lab.psd1." }
        Write-Log "[$($con.Equipo)] Programando cambio de IP $($con.Equipo) -> $($s.IPFinal) y reinicio..."
        $marca = (Get-Estado $con).Ahora
        Invoke-EnServidor -Equipo $con.Equipo -Credencial $con.Credencial -Bloque $bloqueProgramarCambioIP `
            -Argumentos @($con.Equipo, $s.IPFinal, [int]$Diseno.Red.Prefijo, $Diseno.Red.Gateway, @($s.DnsInicial)) -Descripcion 'programar cambio de IP'
        $con = Restart-YEsperar -Servidor $s -Conexion $con -YaProgramado -Marca $marca
        if (-not $con.EnIPFinal) { throw "$($s.Nombre) volvió con la IP $($con.Equipo) y no con $($s.IPFinal). Revise C:\Windows\Temp\ad-cambio-ip.log en el servidor." }
    }
    elseif (-not $estado.ParteDominio) {
        # Sin cambio de IP: solo se fija el DNS inicial
        $null = Invoke-EnServidor -Equipo $con.Equipo -Credencial $con.Credencial -Bloque $bloqueDnsCliente -Argumentos @($s.IPFinal, @($s.DnsInicial)) -Descripcion "DNS inicial $($s.DnsInicial -join ', ')"
        if ($prep.Renombrado -or $prep.ReinicioPorRoles) { $con = Restart-YEsperar -Servidor $s -Conexion $con }
    }
    elseif ($prep.ReinicioPorRoles) { $con = Restart-YEsperar -Servidor $s -Conexion $con }

    $final = Get-Estado $con
    if ($final.Nombre -ne $s.Nombre) { throw "$($s.Nombre): el nombre del equipo es '$($final.Nombre)' después del reinicio." }
    Write-Log "$($s.Nombre) preparado ($($s.IPFinal))." -Nivel Ok
}

# =====================================================================
#  Fase B – Bosque y dominio raíz
# =====================================================================
Write-Log "Fase B – Bosque y dominio raíz $($domRaiz.FQDN)" -Nivel Paso
$con = Connect-Servidor -Servidor $srvRaiz -Credenciales $todas
$estado = Get-Estado $con
if ($estado.RolDominio -ge 4 -and $estado.Dominio -eq $domRaiz.FQDN) {
    Write-Log "$($srvRaiz.Nombre) ya es controlador de dominio de $($domRaiz.FQDN); se omite." -Nivel Ok
}
else {
    if ($estado.ParteDominio) { throw "$($srvRaiz.Nombre) pertenece a otro dominio ($($estado.Dominio))." }
    $r = Invoke-EnServidor -Equipo $con.Equipo -Credencial $con.Credencial -Bloque $bloqueForest `
        -Argumentos @($domRaiz.FQDN, $domRaiz.NetBIOS, $nivel, $Credencial.Password) -Descripcion "Install-ADDSForest $($domRaiz.FQDN) (puede demorar varios minutos)"
    if ($r.Estado -ne 'Success') { throw "Install-ADDSForest terminó con estado '$($r.Estado)': $($r.Mensaje)" }
    Write-Log "Bosque $($domRaiz.FQDN) creado. Reiniciando $($srvRaiz.Nombre)..." -Nivel Ok
    $null = Restart-YEsperar -Servidor $srvRaiz -Conexion $con -YaProgramado -Marca $estado.Ahora
}
Wait-ADDisponible -Equipo $srvRaiz.IPFinal -Credencial $cred.Raiz -Dominio $domRaiz.FQDN

# =====================================================================
#  Fase C – Dominio hijo
# =====================================================================
Write-Log "Fase C – Dominio hijo $($domHijo.FQDN)" -Nivel Paso
$con = Connect-Servidor -Servidor $srvHijo -Credenciales $todas
$estado = Get-Estado $con
if ($estado.RolDominio -ge 4 -and $estado.Dominio -eq $domHijo.FQDN) {
    Write-Log "$($srvHijo.Nombre) ya es controlador de dominio de $($domHijo.FQDN); se omite." -Nivel Ok
}
else {
    if ($estado.ParteDominio) { throw "$($srvHijo.Nombre) pertenece a otro dominio ($($estado.Dominio))." }
    $null = Invoke-EnServidor -Equipo $con.Equipo -Credencial $con.Credencial -Bloque $bloqueDnsCliente -Argumentos @($srvHijo.IPFinal, @($srvHijo.DnsInicial)) -Descripcion "DNS -> DC raíz ($($srvHijo.DnsInicial -join ', '))"
    $r = Invoke-EnServidor -Equipo $con.Equipo -Credencial $con.Credencial -Bloque $bloqueHijo `
        -Argumentos @($domHijo.Etiqueta, $domRaiz.FQDN, $domHijo.NetBIOS, $nivel, $cred.Raiz, $Credencial.Password) -Descripcion "Install-ADDSDomain $($domHijo.FQDN) (puede demorar varios minutos)"
    if ($r.Estado -ne 'Success') { throw "Install-ADDSDomain terminó con estado '$($r.Estado)': $($r.Mensaje)" }
    Write-Log "Dominio hijo $($domHijo.FQDN) creado. Reiniciando $($srvHijo.Nombre)..." -Nivel Ok
    $null = Restart-YEsperar -Servidor $srvHijo -Conexion $con -YaProgramado -Marca $estado.Ahora
}
Wait-ADDisponible -Equipo $srvHijo.IPFinal -Credencial $cred.Hijo -Dominio $domHijo.FQDN

# =====================================================================
#  Fase D – DNS definitivo y verificación
# =====================================================================
Write-Log 'Fase D – DNS de cliente definitivo y verificación' -Nivel Paso
foreach ($s in $Diseno.Servidores) {
    $c = $cred.Raiz
    if ($s.Rol -eq 'DCHijo') { $c = $cred.Hijo }
    $dns = Invoke-EnServidor -Equipo $s.IPFinal -Credencial $c -Bloque $bloqueDnsCliente -Argumentos @($s.IPFinal, @($s.DnsFinal)) -Descripcion "DNS de cliente $($s.DnsFinal -join ', ')"
    Write-Log "$($s.Nombre): DNS $(@($dns) -join ', ')" -Nivel Ok
}

$v = Invoke-EnServidor -Equipo $srvRaiz.IPFinal -Credencial $cred.Raiz -Bloque $bloqueVerificar -Argumentos @($domHijo.FQDN) -Descripcion 'verificar bosque, roles FSMO y confianza'
Write-Log "Dominios del bosque: $(@($v.Dominios) -join ', ')"
Write-Log "Maestro de esquema: $($v.MaestroEsquema) · Maestro de nombres de dominio: $($v.MaestroNombres)"
Write-Log "PDC: $($v.PDC) · RID: $($v.RID) · Infraestructura: $($v.Infraestructura)"
Write-Log "Catálogos globales: $(@($v.CatalogosGlobales) -join ', ')"
if (-not $v.Confianza) { throw "No se encontró la confianza entre $($domRaiz.FQDN) y $($domHijo.FQDN)." }
if ($v.Direccion -ne 'BiDirectional') { throw "La confianza con $($domHijo.FQDN) no es bidireccional (Direction = $($v.Direccion))." }
Write-Log "Confianza padre-hijo $($domRaiz.FQDN) <-> $($domHijo.FQDN): bidireccional, transitiva, intra-bosque = $($v.IntraBosque)." -Nivel Ok

[pscustomobject]@{
    Fecha = (Get-Date -Format 's'); Bosque = $domRaiz.FQDN; Dominios = @($v.Dominios)
    FSMO = [ordered]@{ Esquema = $v.MaestroEsquema; Nombres = $v.MaestroNombres; PDC = $v.PDC; RID = $v.RID; Infraestructura = $v.Infraestructura }
    CatalogosGlobales = @($v.CatalogosGlobales); Confianza = $v.Direccion
} | ConvertTo-Json -Depth 4 | Set-Content -Path (Join-Path $RutaSalida 'despliegue.json') -Encoding UTF8

return 'Completado'
