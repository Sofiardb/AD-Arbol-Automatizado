#Requires -Version 3.0
<#
.SYNOPSIS
    Preparación ÚNICA de cada VM del laboratorio antes del despliegue.

.DESCRIPTION
    Se ejecuta una vez en cada una de las cuatro VM recién instaladas, indicando su rol.
    Toma los datos de config\lab.psd1 (red, puerta de enlace e IP inicial de cada equipo),
    así que no hay que configurar nada a mano en Windows.

    En todas las VM:
      1. Dirección IP fija según el rol (máscara y puerta de enlace calculadas desde lab.psd1).
      2. Red "no identificada" (red solo anfitrión sin Internet) como PRIVADA, de forma permanente.
      3. Servicio WinRM con inicio automático y PowerShell Remoting habilitado.
      4. Reglas de firewall para WinRM (TCP 5985) y ping, en todos los perfiles de red.

    Además, en DCRaiz, DCHijo y Cliente (los equipos que administra Deploy.ps1):
      5. Cuenta Administrador integrada activa y con la contraseña del despliegue.
      6. Administración remota con cuentas locales permitida (LocalAccountTokenFilterPolicy = 1).

    Y en Admin (el equipo que ejecuta Deploy.ps1):
      5. Red del laboratorio en TrustedHosts (PowerShell Remoting por IP con equipos fuera del dominio).
      6. Prueba de conexión WinRM con los otros tres equipos.

    Uso, en PowerShell COMO ADMINISTRADOR, desde la carpeta del proyecto:
        Set-ExecutionPolicy -Scope Process Bypass -Force
        .\tools\Preparar-Equipo.ps1 -Rol DCRaiz      # en el servidor del dominio padre
        .\tools\Preparar-Equipo.ps1 -Rol DCHijo      # en el servidor del dominio hijo
        .\tools\Preparar-Equipo.ps1 -Rol Cliente     # en el cliente de la demostración
        .\tools\Preparar-Equipo.ps1 -Rol Admin       # en el equipo de administración (al final)
    Sin -Rol, el script muestra un menú.

    Se puede volver a ejecutar: lo que ya está configurado no se modifica. Si el equipo ya es
    controlador de dominio o ya está unido al dominio, no se cambia su IP.

    SOLO PARA EL LABORATORIO: relaja controles de seguridad de Windows para la administración remota.
#>
[CmdletBinding()]
param(
    [ValidateSet('DCRaiz', 'DCHijo', 'Cliente', 'Admin')]
    [string]$Rol,

    # Contraseña del Administrador integrado (la MISMA en todas las VM). Si se omite, se pide por pantalla.
    [securestring]$Contrasena,

    # IP a asignar. Por defecto se toma de lab.psd1 según el rol.
    [string]$IP,

    # No modificar la configuración IP del equipo.
    [switch]$SinCambiarIP,

    [string]$RutaConfig    # por defecto: ..\config
)

$ErrorActionPreference = 'Stop'
# En PowerShell 3.0 y 4.0, $PSScriptRoot puede llegar vacío a los valores por defecto de los parámetros
# (por ejemplo, al ejecutar con powershell.exe -File desde un acceso directo): se calcula acá.
$raiz = $PSScriptRoot
if (-not $raiz) { $raiz = Split-Path -Parent $MyInvocation.MyCommand.Path }
if (-not $RutaConfig) { $RutaConfig = Join-Path $raiz '..\config' }
function Paso([string]$t) { Write-Host "`n>> $t" -ForegroundColor Cyan }
function Ok([string]$t) { Write-Host "   OK  $t" -ForegroundColor Green }
function Aviso([string]$t) { Write-Host "   !!  $t" -ForegroundColor Yellow }

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Abra PowerShell con "Ejecutar como administrador" y vuelva a ejecutar el script.'
}

# --- Configuración del laboratorio --------------------------------------------------------
Import-Module (Join-Path $raiz '..\modules\00-Comun\Comun.psm1') -Force -DisableNameChecking
$archivoLab = Join-Path $RutaConfig 'lab.psd1'
if (-not (Test-Path $archivoLab)) { throw "No se encontró $archivoLab. Ejecute el script desde la carpeta completa del proyecto." }
$lab = Import-DatosPsd1 -Ruta $archivoLab
$red = Get-InfoRed -Cidr ([string]$lab.Red)

function Get-IPServidor([string]$RolServidor) {
    $s = @($lab.Servidores | Where-Object { $_.Rol -eq $RolServidor })[0]
    if (-not $s) { throw "lab.psd1 no tiene un servidor con Rol = '$RolServidor'." }
    return [string]$s.IPActual
}
function Get-IPFinalServidor([string]$RolServidor, [int]$Desplazamiento) {
    $s = @($lab.Servidores | Where-Object { $_.Rol -eq $RolServidor })[0]
    if ($s -and $s.IPFinal) { return [string]$s.IPFinal }
    return Get-IPDesplazada -InfoRed $red -Desplazamiento $Desplazamiento
}
$ipAdmin = if ($lab.EquipoAdmin -and $lab.EquipoAdmin.IP) { [string]$lab.EquipoAdmin.IP } else { Get-IPDesplazada -InfoRed $red -Desplazamiento 200 }
$ipsPorRol = [ordered]@{
    DCRaiz  = Get-IPServidor 'DCRaiz'
    DCHijo  = Get-IPServidor 'DCHijo'
    Cliente = [string]$lab.Cliente.IPActual
    Admin   = $ipAdmin
}
$descripcion = @{
    DCRaiz  = "servidor del dominio padre $($lab.DominioRaiz)"
    DCHijo  = "servidor del dominio hijo $($lab.DominioHijo).$($lab.DominioRaiz)"
    Cliente = 'cliente de la demostración'
    Admin   = 'equipo de administración (ejecuta Deploy.ps1)'
}

if (-not $Rol) {
    Write-Host "`n¿Qué equipo es este?" -ForegroundColor White
    $roles = @($ipsPorRol.Keys)
    for ($i = 0; $i -lt $roles.Count; $i++) {
        Write-Host ("  {0}) {1,-8} {2,-16} {3}" -f ($i + 1), $roles[$i], $ipsPorRol[$roles[$i]], $descripcion[$roles[$i]])
    }
    $opcion = Read-Host 'Número'
    if ($opcion -notmatch '^[1-4]$') { throw 'Opción inválida.' }
    $Rol = $roles[[int]$opcion - 1]
}
if (-not $IP) { $IP = $ipsPorRol[$Rol] }
if (-not (Test-IPEnRed -IP $IP -InfoRed $red)) { throw "La IP $IP no pertenece a la red $($red.Cidr)." }

$os = Get-CimInstance Win32_OperatingSystem
$cs = Get-CimInstance Win32_ComputerSystem
Write-Host "`nEquipo: $env:COMPUTERNAME · $($os.Caption) · PowerShell $($PSVersionTable.PSVersion)" -ForegroundColor White
Write-Host "Rol:    $Rol ($($descripcion[$Rol])) · IP $IP/$($red.Prefijo)" -ForegroundColor White

# --- 1. Dirección IP ------------------------------------------------------------------------
Paso 'Dirección IP'
if ($SinCambiarIP) {
    Ok 'Se omite (-SinCambiarIP)'
}
elseif ([int]$cs.DomainRole -ge 4) {
    Ok 'El equipo ya es controlador de dominio: conserva la IP que le asignó el despliegue.'
}
elseif ($Rol -eq 'Cliente' -and $cs.PartOfDomain) {
    Ok "El equipo ya está unido al dominio $($cs.Domain): conserva su IP."
}
else {
    $adaptadores = @(Get-NetAdapter -Physical -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Up' })
    if ($adaptadores.Count -gt 1) {
        # Con varios adaptadores, se usa el que ya tiene una IP de la red del laboratorio
        $enRed = @($adaptadores | Where-Object {
                $idx = $_.ifIndex
                @(Get-NetIPAddress -InterfaceIndex $idx -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { Test-IPEnRed -IP $_.IPAddress -InfoRed $red }).Count
            })
        if ($enRed.Count -eq 1) { $adaptadores = $enRed }
    }
    if ($adaptadores.Count -ne 1) {
        $lista = @(Get-NetAdapter -ErrorAction SilentlyContinue | ForEach-Object { "$($_.Name) [$($_.Status)]" }) -join ', '
        throw "Se esperaba un único adaptador de red conectado y se encontraron $($adaptadores.Count) ($lista). Deje un solo adaptador (red solo anfitrión) o configure la IP a mano y use -SinCambiarIP."
    }
    $nic = $adaptadores[0]
    $actuales = @(Get-NetIPAddress -InterfaceIndex $nic.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -notlike '169.254.*' })
    $ruta = @(Get-NetRoute -InterfaceIndex $nic.ifIndex -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue)
    $gatewayOk = (-not $lab.Gateway) -or (@($ruta | Where-Object { $_.NextHop -eq $lab.Gateway }).Count -eq 1 -and $ruta.Count -eq 1)
    $ipOk = ($actuales.Count -eq 1) -and ($actuales[0].IPAddress -eq $IP) -and ($actuales[0].PrefixLength -eq $red.Prefijo) -and ([string]$actuales[0].PrefixOrigin -eq 'Manual')
    if ($ipOk -and $gatewayOk) {
        Ok "$($nic.Name): $IP/$($red.Prefijo), puerta de enlace $($lab.Gateway) (ya configurada)"
    }
    else {
        Set-NetIPInterface -InterfaceIndex $nic.ifIndex -AddressFamily IPv4 -Dhcp Disabled
        foreach ($a in $actuales) { Remove-NetIPAddress -InterfaceIndex $nic.ifIndex -IPAddress $a.IPAddress -Confirm:$false -ErrorAction SilentlyContinue }
        foreach ($r in $ruta) { Remove-NetRoute -InterfaceIndex $nic.ifIndex -DestinationPrefix '0.0.0.0/0' -NextHop $r.NextHop -Confirm:$false -ErrorAction SilentlyContinue }
        $parametros = @{ InterfaceIndex = $nic.ifIndex; AddressFamily = 'IPv4'; IPAddress = $IP; PrefixLength = $red.Prefijo }
        if ($lab.Gateway) { $parametros.DefaultGateway = [string]$lab.Gateway }
        New-NetIPAddress @parametros | Out-Null
        Ok "$($nic.Name): $IP/$($red.Prefijo) (máscara $($red.Mascara)), puerta de enlace $($lab.Gateway)"
        Start-Sleep -Seconds 3   # la red se vuelve a identificar
    }
}

# --- 2. Red privada ---------------------------------------------------------------------
Paso 'Red como privada'
# Directiva "Redes no identificadas -> Tipo de ubicación: Privada" (la misma que secpol.msc)
$clave = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\010103000F0000F0010000000F0000F0C967A3643C3AD745950DA7859209176EF5B87C875FA20DF21951640E807D7C24'
try {
    if (-not (Test-Path $clave)) { New-Item -Path $clave -Force | Out-Null }
    New-ItemProperty -Path $clave -Name Category -Value 1 -PropertyType DWord -Force | Out-Null
    Ok 'Redes no identificadas = Privada (permanente)'
}
catch { Aviso "No se pudo fijar la directiva de redes no identificadas: $($_.Exception.Message)" }
foreach ($perfil in @(Get-NetConnectionProfile -ErrorAction SilentlyContinue)) {
    if ([string]$perfil.NetworkCategory -eq 'DomainAuthenticated') { Ok "$($perfil.InterfaceAlias): red de dominio"; continue }
    try { Set-NetConnectionProfile -InterfaceIndex $perfil.InterfaceIndex -NetworkCategory Private -ErrorAction Stop; Ok "$($perfil.InterfaceAlias): Privada" }
    catch { Aviso "$($perfil.InterfaceAlias): no se pudo cambiar ahora ($($_.Exception.Message)); la directiva lo aplica al reiniciar." }
}

# --- 3. WinRM ----------------------------------------------------------------------------
Paso 'PowerShell Remoting (WinRM)'
Set-Service -Name WinRM -StartupType Automatic
# En Windows 8/8.1/10 WinRM queda en "Automático (inicio retrasado)" y tarda 1-2 minutos en responder
# después de arrancar: se deja en inicio automático normal.
& sc.exe config WinRM start= auto | Out-Null
Start-Service -Name WinRM
Enable-PSRemoting -Force -SkipNetworkProfileCheck | Out-Null
Ok 'WinRM automático y PowerShell Remoting habilitado'

# --- 4. Firewall -------------------------------------------------------------------------
Paso 'Firewall'
& netsh.exe advfirewall firewall delete rule name="WinRM 5985 (laboratorio)" | Out-Null
& netsh.exe advfirewall firewall add rule name="WinRM 5985 (laboratorio)" dir=in action=allow protocol=TCP localport=5985 profile=any | Out-Null
Ok 'WinRM (TCP 5985) permitido en todos los perfiles'
& netsh.exe advfirewall firewall delete rule name="Ping (laboratorio)" | Out-Null
& netsh.exe advfirewall firewall add rule name="Ping (laboratorio)" dir=in action=allow protocol=icmpv4:8,any profile=any | Out-Null
Ok 'Ping permitido'

if ($Rol -ne 'Admin') {
    # --- 5. Administrador integrado ------------------------------------------------------
    Paso 'Cuenta Administrador integrada'
    if ([int]$cs.DomainRole -ge 4) {
        Ok 'El equipo ya es controlador de dominio: se omite (las cuentas son del dominio).'
    }
    else {
        # La cuenta integrada se identifica por su RID 500: se llama Administrator o Administrador según el idioma
        $admin = @(Get-CimInstance Win32_UserAccount -Filter "LocalAccount=True" | Where-Object { $_.SID -like 'S-1-5-21-*-500' })[0]
        if (-not $admin) { throw 'No se encontró la cuenta Administrador integrada.' }
        if (-not $Contrasena) {
            $p1 = Read-Host "Contraseña para '$($admin.Name)' (la MISMA en todas las VM)" -AsSecureString
            $p2 = Read-Host 'Repita la contraseña' -AsSecureString
            $t1 = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($p1))
            $t2 = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($p2))
            if ($t1 -ne $t2) { throw 'Las contraseñas no coinciden.' }
        }
        else { $t1 = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($Contrasena)) }
        $usuario = [ADSI]"WinNT://$env:COMPUTERNAME/$($admin.Name),user"
        $usuario.SetPassword($t1)
        $usuario.UserFlags = [int]$usuario.UserFlags.Value -band (-bnot 0x2)   # 0x2 = cuenta deshabilitada
        $usuario.SetInfo()
        Ok "'$($admin.Name)' activa y con la contraseña indicada"
        if ($Rol -ne 'Cliente' -and $admin.Name -ne [string]$lab.UsuarioAdministrador) {
            Aviso "En lab.psd1, UsuarioAdministrador = '$($lab.UsuarioAdministrador)', pero en este servidor la cuenta se llama '$($admin.Name)'. Ajústelo en ADMIN antes del despliegue."
        }
    }

    # --- 6. Cuentas locales por red ------------------------------------------------------
    Paso 'Administración remota con cuentas locales'
    New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name LocalAccountTokenFilterPolicy -Value 1 -PropertyType DWord -Force | Out-Null
    Ok 'LocalAccountTokenFilterPolicy = 1'
}
else {
    # --- 5. TrustedHosts -----------------------------------------------------------------
    Paso 'Equipos de confianza para PowerShell Remoting (TrustedHosts)'
    Import-Module Microsoft.WSMan.Management -ErrorAction SilentlyContinue
    if ($red.Prefijo % 8 -eq 0) {
        # Red con octetos completos: un comodín cubre las IP iniciales y las finales (ej.: 192.168.10.*)
        $n = [int]($red.Prefijo / 8)
        $octetos = @($red.Direccion.Split('.')[0..($n - 1)])
        $entradas = @((($octetos + @(@('*') * (4 - $n))) -join '.'))
    }
    else {
        $entradas = @($ipsPorRol.DCRaiz, $ipsPorRol.DCHijo, $ipsPorRol.Cliente,
            (Get-IPFinalServidor 'DCRaiz' 10), (Get-IPFinalServidor 'DCHijo' 11)) | Select-Object -Unique
    }
    $actual = [string](Get-Item WSMan:\localhost\Client\TrustedHosts).Value
    $lista = @($actual.Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    if ($lista -contains '*') {
        Ok 'TrustedHosts = * (ya admite todos los equipos)'
    }
    else {
        $faltan = @($entradas | Where-Object { $lista -notcontains $_ })
        if ($faltan.Count) { Set-Item WSMan:\localhost\Client\TrustedHosts -Value ((@($lista) + $faltan) -join ',') -Force }
        Ok "TrustedHosts: $((@($lista) + $faltan) -join ', ')"
    }

    # --- 6. Conexión con los otros equipos -----------------------------------------------
    Paso 'Conexión WinRM con los equipos del laboratorio'
    $faltanEquipos = 0
    foreach ($r in 'DCRaiz', 'DCHijo', 'Cliente') {
        $destino = $ipsPorRol[$r]
        if (Test-PuertoAbierto -Equipo $destino -Puerto 5985) { Ok ("{0,-8} {1}  responde" -f $r, $destino) }
        else { Aviso ("{0,-8} {1}  no responde (¿está encendido y preparado con -Rol {0}?)" -f $r, $destino); $faltanEquipos++ }
    }
}

# --- Verificación ------------------------------------------------------------------------
Paso 'Verificación'
try { $null = Test-WSMan -ComputerName localhost -ErrorAction Stop; Ok 'WinRM responde en este equipo' } catch { Aviso "WinRM no responde: $($_.Exception.Message)" }
$ips = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike '169.254.*' } | ForEach-Object { $_.IPAddress })
Write-Host "`nListo. IP de este equipo: $($ips -join ', ')" -ForegroundColor White
if ($Rol -eq 'Admin') {
    if ($faltanEquipos -eq 0) { Write-Host 'Todos los equipos responden. Tome una instantánea de las cuatro VM y ejecute:  .\Deploy.ps1' -ForegroundColor White }
    else { Write-Host 'Prepare los equipos que no responden y vuelva a ejecutar este script en ADMIN para comprobarlo.' -ForegroundColor White }
}
else {
    Write-Host 'Siguiente: preparar las demás VM y, al final, ADMIN con -Rol Admin.' -ForegroundColor White
}
