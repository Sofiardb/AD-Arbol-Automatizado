#Requires -Version 3.0
<#
.SYNOPSIS
    Paso 6 – Cliente de la demostración: une el equipo cliente al dominio y le instala el kit de demostración.

.DESCRIPTION
    El cliente (Windows 10/11 Pro, Enterprise o Education) es el equipo donde se inicia sesión con
    cuentas del dominio padre para acceder a los recursos del dominio hijo.

      1. DNS apuntando a los DC (primero el de su dominio) · zona horaria · IP fija si se pidió.
      2. Une el equipo al dominio (por defecto el padre) en la OU "Equipos", con el nombre del diseño.
      3. Kit de demostración en C:\Demo:
           Probar-Permisos.ps1      lo ejecuta el usuario logueado: muestra sus grupos y prueba
                                    listar, leer, escribir y borrar en cada recurso
           permisos-demo.json       recursos y nivel de cada grupo global (generado de accesos.csv)
           guion-demostracion.html  guion de la presentación
         y en el escritorio público (lo ven todos los usuarios): carpeta "Recursos de <dominio hijo>" con un acceso
         directo a cada recurso compartido y el acceso directo "Probar mis permisos".

    Funciona de dos maneras, que detecta solo:
      - LOCAL: Deploy.ps1 se ejecuta en el mismo cliente (recomendado). Al terminar hay que reiniciar
        el equipo y volver a ejecutar .\Deploy.ps1, que sigue con el paso 7.
      - REMOTA: Deploy.ps1 se ejecuta en otro equipo; requiere WinRM habilitado en el cliente
        (Enable-PSRemoting -Force). El cliente se reinicia y se espera a que vuelva.
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

$cli = $Diseno.Cliente
if (-not $cli) {
    Write-Log 'lab.psd1 no define un Cliente: se omite este paso.' -Nivel Advertencia
    return 'Completado'
}
$dom     = $Diseno.Dominios.($cli.DominioClave)
$domHijo = $Diseno.Dominios.Hijo
$srvHijo = Get-ServidorDiseno -Diseno $Diseno -Rol DCHijo
$carpetaEscritorio = "Recursos de $($domHijo.FQDN)"
$raizProyecto = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent

# =====================================================================
#  Kit de demostración (se arma localmente en output\demo y se copia al cliente)
# =====================================================================
$carpetaKit = Join-Path $RutaSalida 'demo'
if (-not (Test-Path $carpetaKit)) { New-Item -Path $carpetaKit -ItemType Directory -Force -WhatIf:$false | Out-Null }
$configDemo = [ordered]@{
    Empresa = $Diseno.Parametros.Empresa
    DominioCuentas = $Diseno.Dominios.Raiz.FQDN; NetBIOSCuentas = $Diseno.Dominios.Raiz.NetBIOS
    DominioRecursos = $domHijo.FQDN; NetBIOSRecursos = $domHijo.NetBIOS; Servidor = $srvHijo.FQDN
    Recursos = @($Diseno.Recursos | ForEach-Object { [ordered]@{ Nombre = $_.Nombre; UNC = $_.UNC } })
    Grupos   = @($Diseno.NivelesPorGrupo | ForEach-Object { [ordered]@{ Grupo = $_.Grupo; Niveles = @($_.Niveles | ForEach-Object { [ordered]@{ Recurso = $_.Recurso; Nivel = $_.Nivel } }) } })
}
$archivos = [ordered]@{
    'Probar-Permisos.ps1' = (Get-Content -Path (Join-Path $raizProyecto 'demo/Probar-Permisos.ps1') -Raw -Encoding UTF8)
    'permisos-demo.json'  = (ConvertTo-Json -InputObject $configDemo -Depth 6)
}
$guion = Join-Path $RutaSalida 'diseno/guion-demostracion.html'
if (Test-Path $guion) { $archivos['guion-demostracion.html'] = Get-Content -Path $guion -Raw -Encoding UTF8 }
foreach ($k in $archivos.Keys) { Set-ContenidoUtf8 -Ruta (Join-Path $carpetaKit $k) -Texto $archivos[$k] }
$accesosDirectos = @($Diseno.Recursos | ForEach-Object { [pscustomobject]@{ Nombre = $_.Nombre; UNC = $_.UNC } })

# =====================================================================
#  Simulación
# =====================================================================
if ($WhatIfPreference) {
    Write-Log "Cliente $($cli.Nombre) ($($cli.IPActual))"
    if ($cli.IPFinal -ne $cli.IPActual) { Write-Plan "IP $($cli.IPActual) -> $($cli.IPFinal)/$($Diseno.Red.Prefijo) gw $($Diseno.Red.Gateway)" }
    Write-Plan "DNS de cliente: $($cli.DnsFinal -join ', ') · zona horaria '$($Diseno.Parametros.ZonaHoraria)'"
    Write-Plan "Add-Computer -DomainName $($dom.FQDN) -NewName $($cli.Nombre) -OUPath '$($cli.OU)'"
    Write-Plan "kit en $($cli.CarpetaDemo): $($archivos.Keys -join ', ')"
    Write-Plan "escritorio público: carpeta '$carpetaEscritorio' con $($accesosDirectos.Count) accesos directos (\\$($srvHijo.FQDN)\...) y 'Probar mis permisos'"
    Write-Plan 'reiniciar el cliente'
    return 'Simulado'
}

if (-not $Credencial) { throw 'Se requiere la credencial del despliegue.' }
$cred = Get-CredencialesLab -Credencial $Credencial -Diseno $Diseno
$credDominio = $cred.($cli.DominioClave)

# =====================================================================
#  Bloques (se ejecutan en el cliente: localmente con & o remotamente con Invoke-Command)
# =====================================================================
$bloqueCliente = {
    param([string]$IPActual, [string]$IPFinal, [int]$Prefijo, [string]$Gateway, [string[]]$Dns, [string]$Nombre,
        [string]$Dominio, [string]$OU, [pscredential]$CredDominio, [string]$ZonaHoraria, [bool]$PermitirCambioIP)
    $ErrorActionPreference = 'Stop'
    $res = [ordered]@{ SO = ''; EsCliente = $true; IPCambiada = $false; Unido = $false; Renombrado = $false; YaMiembro = $false; NombreAnterior = $env:COMPUTERNAME }
    $os = Get-CimInstance Win32_OperatingSystem
    $res.SO = $os.Caption
    $res.EsCliente = ([int]$os.ProductType -eq 1)

    $ip = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -in @($IPActual, $IPFinal) }) | Select-Object -First 1
    if (-not $ip) { throw "No se encontró una interfaz con la IP $IPActual ni $IPFinal." }
    $idx = $ip.InterfaceIndex
    if ($IPFinal -ne $IPActual -and $ip.IPAddress -ne $IPFinal) {
        if (-not $PermitirCambioIP) { throw "El cliente tiene la IP $($ip.IPAddress) y el diseño indica ${IPFinal}: cambie la IP a mano o ejecute Deploy.ps1 en el propio cliente." }
        Set-NetIPInterface -InterfaceIndex $idx -Dhcp Disabled -ErrorAction SilentlyContinue
        Get-NetRoute -InterfaceIndex $idx -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue
        Remove-NetIPAddress -InterfaceIndex $idx -AddressFamily IPv4 -Confirm:$false -ErrorAction SilentlyContinue
        New-NetIPAddress -InterfaceIndex $idx -IPAddress $IPFinal -PrefixLength $Prefijo -DefaultGateway $Gateway | Out-Null
        $res.IPCambiada = $true
    }
    Set-DnsClientServerAddress -InterfaceIndex $idx -ServerAddresses $Dns
    Clear-DnsClientCache
    if ($ZonaHoraria -and (& tzutil.exe /g) -ne $ZonaHoraria) { & tzutil.exe /s $ZonaHoraria }   # tzutil: también en Windows 8

    try { $null = Resolve-DnsName -Name "_ldap._tcp.dc._msdcs.$Dominio" -Type SRV -DnsOnly }
    catch { throw "El cliente no encuentra un DC de $Dominio por DNS ($($_.Exception.Message)). Verifique la red y los DNS $($Dns -join ', ')." }

    $cs = Get-CimInstance Win32_ComputerSystem
    if ($cs.PartOfDomain -and ([string]$cs.Domain).ToLowerInvariant() -eq $Dominio) {
        $res.YaMiembro = $true
        if ($env:COMPUTERNAME -ne $Nombre) { Rename-Computer -NewName $Nombre -DomainCredential $CredDominio -Force -WarningAction SilentlyContinue; $res.Renombrado = $true }
    }
    elseif ($cs.PartOfDomain) { throw "El cliente pertenece a otro dominio ($($cs.Domain))." }
    else {
        if (Get-Command Add-Computer -ErrorAction SilentlyContinue) {
            $p = @{ DomainName = $Dominio; Credential = $CredDominio; OUPath = $OU; Force = $true; WarningAction = 'SilentlyContinue' }
            if ($env:COMPUTERNAME -ne $Nombre) { $p.NewName = $Nombre; $res.Renombrado = $true }
            Add-Computer @p
        }
        else {
            # PowerShell 7 no tiene Add-Computer: se usa el método WMI que hay en todas las versiones de Windows
            $red = $CredDominio.GetNetworkCredential()
            $usuario = $CredDominio.UserName
            $r = Invoke-CimMethod -InputObject $cs -MethodName JoinDomainOrWorkgroup -Arguments @{ Name = $Dominio; UserName = $usuario; Password = $red.Password; AccountOU = $OU; FJoinOptions = [uint32]3 }
            if ($r.ReturnValue -ne 0) { throw "No se pudo unir al dominio $Dominio (código $($r.ReturnValue))." }
            if ($env:COMPUTERNAME -ne $Nombre) { Rename-Computer -NewName $Nombre -DomainCredential $CredDominio -Force -WarningAction SilentlyContinue; $res.Renombrado = $true }
        }
        $res.Unido = $true
    }
    New-Object PSObject -Property $res
}

$bloqueKit = {
    param([string]$Carpeta, [System.Collections.IDictionary]$Archivos, [object[]]$Recursos, [string]$NombreCarpetaEscritorio)
    $ErrorActionPreference = 'Stop'
    if (-not (Test-Path -LiteralPath $Carpeta)) { New-Item -Path $Carpeta -ItemType Directory -Force | Out-Null }
    # UTF-8 con BOM: Windows PowerShell 3.0-5.1 del cliente lo necesita para leer los acentos
    foreach ($k in $Archivos.Keys) { [System.IO.File]::WriteAllText((Join-Path $Carpeta $k), [string]$Archivos[$k], (New-Object System.Text.UTF8Encoding($true))) }

    $escritorio = Join-Path $env:PUBLIC 'Desktop'
    $dirRec = Join-Path $escritorio $NombreCarpetaEscritorio
    if (-not (Test-Path -LiteralPath $dirRec)) { New-Item -Path $dirRec -ItemType Directory -Force | Out-Null }
    $shell = New-Object -ComObject WScript.Shell
    foreach ($r in $Recursos) {
        $lnk = $shell.CreateShortcut((Join-Path $dirRec "$($r.Nombre).lnk"))
        $lnk.TargetPath = $r.UNC
        $lnk.Description = "Recurso compartido $($r.UNC)"
        $lnk.Save()
    }
    $lnk = $shell.CreateShortcut((Join-Path $escritorio 'Probar mis permisos.lnk'))
    $lnk.TargetPath = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
    $lnk.Arguments = "-NoProfile -ExecutionPolicy Bypass -NoExit -File `"$(Join-Path $Carpeta 'Probar-Permisos.ps1')`""
    $lnk.WorkingDirectory = $Carpeta
    $lnk.Description = 'Muestra la cuenta, sus grupos y lo que puede hacer en cada recurso'
    $lnk.Save()
    @(Get-ChildItem -LiteralPath $Carpeta | ForEach-Object { $_.Name })
}

$bloqueVerificar = {
    $cs = Get-CimInstance Win32_ComputerSystem
    $canal = $false
    try {
        # Test-ComputerSecureChannel no existe en PowerShell 7: en ese caso se usa nltest
        if (Get-Command Test-ComputerSecureChannel -ErrorAction SilentlyContinue) { $canal = Test-ComputerSecureChannel }
        elseif ($cs.PartOfDomain) { $null = & nltest.exe "/sc_query:$($cs.Domain)" 2>&1; $canal = ($LASTEXITCODE -eq 0) }
    }
    catch { $canal = $false }
    [pscustomobject]@{ Nombre = $env:COMPUTERNAME; Dominio = ([string]$cs.Domain).ToLowerInvariant(); ParteDominio = [bool]$cs.PartOfDomain; CanalSeguro = $canal; Arranque = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime }
}

$argsCliente = @($cli.IPActual, $cli.IPFinal, [int]$Diseno.Red.Prefijo, $Diseno.Red.Gateway, @($cli.DnsFinal), $cli.Nombre,
    $dom.FQDN, $cli.OU, $credDominio, [string]$Diseno.Parametros.ZonaHoraria)
$argsKit = @($cli.CarpetaDemo, $archivos, $accesosDirectos, $carpetaEscritorio)

function Write-ResultadoCliente($r) {
    Write-Log "Sistema operativo: $($r.SO)"
    if (-not $r.EsCliente) { Write-Log 'El equipo no es una edición cliente de Windows; se continúa igual.' -Nivel Advertencia }
    if ($r.IPCambiada) { Write-Log "IP cambiada a $($cli.IPFinal)." -Nivel Ok }
    Write-Log "DNS de cliente: $($cli.DnsFinal -join ', ')." -Nivel Ok
    if ($r.YaMiembro) { Write-Log "Ya era miembro de $($dom.FQDN)." -Nivel Ok }
    if ($r.Unido) { Write-Log "Unido a $($dom.FQDN) en $($cli.OU)$(if ($r.Renombrado) { " con el nombre $($cli.Nombre) (antes $($r.NombreAnterior))" })." -Nivel Ok }
    elseif ($r.Renombrado) { Write-Log "Renombrado $($r.NombreAnterior) -> $($cli.Nombre)." -Nivel Ok }
}

# =====================================================================
#  ¿Se ejecuta en el propio cliente?
# =====================================================================
$ipsLocales = @()
try { $ipsLocales = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop | ForEach-Object { $_.IPAddress }) } catch { $ipsLocales = @() }
$esLocal = ($cli.IPActual -in $ipsLocales) -or ($cli.IPFinal -in $ipsLocales)

if ($esLocal) {
    Write-Log "Deploy.ps1 se está ejecutando en el cliente ($($cli.IPActual)): se configura localmente." -Nivel Paso
    $r = & $bloqueCliente @argsCliente $true
    Write-ResultadoCliente $r
    $kit = & $bloqueKit @argsKit
    Write-Log "Kit de demostración en $($cli.CarpetaDemo): $(@($kit) -join ', '). Accesos directos en el escritorio público." -Nivel Ok
    if ($r.Unido -or $r.Renombrado -or $r.IPCambiada) {
        Write-Log "REINICIE ESTE EQUIPO y vuelva a ejecutar .\Deploy.ps1 (como administrador local o $($dom.NetBIOS)\$($Diseno.Parametros.UsuarioAdministrador)) para la validación." -Nivel Advertencia
        Write-Log "Para la demostración, inicie sesión con una cuenta del dominio, por ejemplo $(@($Diseno.Demo.Escenas)[0].Usuario) (ver el guion)." -Nivel Advertencia
        return 'ReinicioPendiente'
    }
    return 'Completado'
}

# =====================================================================
#  Modo remoto
# =====================================================================
Write-Log "Configurando el cliente $($cli.Nombre) por PowerShell Remoting" -Nivel Paso
$todas = @(@($cred.Local) + @($cred.LocalAlternativas) + @($credDominio))
try { $con = Connect-Servidor -Servidor $cli -Credenciales $todas -Intentos 2 }
catch { throw "No se pudo conectar al cliente $($cli.IPActual). En el cliente ejecute 'Enable-PSRemoting -Force' (y 'Set-NetConnectionProfile -NetworkCategory Private' si la red es pública), o ejecute Deploy.ps1 directamente en el cliente. Detalle: $($_.Exception.Message)" }

$antes = Invoke-EnServidor -Equipo $con.Equipo -Credencial $con.Credencial -Bloque $bloqueVerificar -Descripcion 'estado del cliente'
$r = Invoke-EnServidor -Equipo $con.Equipo -Credencial $con.Credencial -Bloque $bloqueCliente -Argumentos (@($argsCliente) + $false) -Descripcion "unir a $($dom.FQDN)"
Write-ResultadoCliente $r
$kit = Invoke-EnServidor -Equipo $con.Equipo -Credencial $con.Credencial -Bloque $bloqueKit -Argumentos $argsKit -Descripcion 'kit de demostración'
Write-Log "Kit de demostración en $($cli.CarpetaDemo): $(@($kit) -join ', ')." -Nivel Ok

if ($r.Unido -or $r.Renombrado) {
    Write-Log "Reiniciando $($cli.Nombre)..."
    Invoke-EnServidor -Equipo $con.Equipo -Credencial $con.Credencial -Bloque { & shutdown.exe /r /t 5 /f /d p:4:2 /c 'Union al dominio' | Out-Null } -Descripcion 'reiniciar'
    Start-Sleep -Seconds 45
    $limite = (Get-Date).AddMinutes(15)
    $listo = $null
    while ((Get-Date) -lt $limite -and -not $listo) {
        try {
            $c = Connect-Servidor -Servidor $cli -Credenciales @(@($credDominio, $cred.Local) + @($cred.LocalAlternativas))
            $e = Invoke-EnServidor -Equipo $c.Equipo -Credencial $c.Credencial -Bloque $bloqueVerificar -Descripcion 'estado tras el reinicio'
            if ($e.Arranque -gt $antes.Arranque) { $listo = $e }
        }
        catch { Write-Verbose $_.Exception.Message }
        if (-not $listo) { Start-Sleep -Seconds 20 }
    }
    if (-not $listo) { throw "Tiempo agotado esperando el reinicio de $($cli.Nombre)." }
    $antes = $listo
}
else { $antes = Invoke-EnServidor -Equipo $con.Equipo -Credencial $con.Credencial -Bloque $bloqueVerificar -Descripcion 'estado del cliente' }

if (-not $antes.ParteDominio -or $antes.Dominio -ne $dom.FQDN) { throw "El cliente no quedó unido a $($dom.FQDN) (dominio actual: $($antes.Dominio))." }
Write-Log "$($antes.Nombre) es miembro de $($antes.Dominio) · canal seguro con el dominio: $($antes.CanalSeguro)." -Nivel Ok
return 'Completado'
