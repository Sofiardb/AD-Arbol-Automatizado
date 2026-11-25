#Requires -Version 3.0
<#
.SYNOPSIS
    Preparación ÚNICA de cada VM antes del despliegue (servidores y cliente).

.DESCRIPTION
    Deja el equipo listo para que Deploy.ps1 lo administre de forma remota, y que siga así después de
    reiniciar o de restaurar una instantánea tomada después de ejecutarlo:

      1. Red "no identificada" (red solo anfitrión sin Internet) como PRIVADA, de forma permanente.
      2. Servicio WinRM con inicio automático y PowerShell Remoting habilitado.
      3. Regla de firewall para WinRM (TCP 5985) en todos los perfiles de red.
      4. Cuenta Administrador integrada activa y con la contraseña del despliegue.
      5. Administración remota con cuentas locales permitida (LocalAccountTokenFilterPolicy = 1).
      6. Respuesta a ping (útil para diagnosticar).

    Ejecutar en PowerShell COMO ADMINISTRADOR en cada VM (DC-RAIZ, DC-HIJO y CLIENTE01):
        Set-ExecutionPolicy -Scope Process Bypass -Force
        .\Preparar-Equipo.ps1

    SOLO PARA EL LABORATORIO: relaja controles de seguridad de Windows para la administración remota.
#>
[CmdletBinding()]
param(
    # Si se omite, se pide por pantalla (dos veces).
    [securestring]$Contrasena
)

$ErrorActionPreference = 'Stop'
function Paso([string]$t) { Write-Host "`n>> $t" -ForegroundColor Cyan }
function Ok([string]$t) { Write-Host "   OK  $t" -ForegroundColor Green }
function Aviso([string]$t) { Write-Host "   !!  $t" -ForegroundColor Yellow }

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Abra PowerShell con "Ejecutar como administrador" y vuelva a ejecutar el script.'
}
$os = Get-CimInstance Win32_OperatingSystem
Write-Host "Equipo: $env:COMPUTERNAME · $($os.Caption)" -ForegroundColor White

# --- 1. Red privada ---------------------------------------------------------------------
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

# --- 2. WinRM ----------------------------------------------------------------------------
Paso 'PowerShell Remoting (WinRM)'
Set-Service -Name WinRM -StartupType Automatic
Start-Service -Name WinRM
Enable-PSRemoting -Force -SkipNetworkProfileCheck | Out-Null
Ok 'WinRM automático y PowerShell Remoting habilitado'

# --- 3. Firewall -------------------------------------------------------------------------
Paso 'Firewall'
& netsh.exe advfirewall firewall delete rule name="WinRM 5985 (laboratorio)" | Out-Null
& netsh.exe advfirewall firewall add rule name="WinRM 5985 (laboratorio)" dir=in action=allow protocol=TCP localport=5985 profile=any | Out-Null
Ok 'WinRM (TCP 5985) permitido en todos los perfiles'
& netsh.exe advfirewall firewall delete rule name="Ping (laboratorio)" | Out-Null
& netsh.exe advfirewall firewall add rule name="Ping (laboratorio)" dir=in action=allow protocol=icmpv4:8,any profile=any | Out-Null
Ok 'Ping permitido'

# --- 4. Administrador integrado ----------------------------------------------------------
Paso 'Cuenta Administrador integrada'
$cs = Get-CimInstance Win32_ComputerSystem
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
}

# --- 5. Cuentas locales por red ----------------------------------------------------------
Paso 'Administración remota con cuentas locales'
New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name LocalAccountTokenFilterPolicy -Value 1 -PropertyType DWord -Force | Out-Null
Ok 'LocalAccountTokenFilterPolicy = 1'

# --- Verificación ------------------------------------------------------------------------
Paso 'Verificación'
try { $null = Test-WSMan -ComputerName localhost -ErrorAction Stop; Ok 'WinRM responde en este equipo' } catch { Aviso "WinRM no responde: $($_.Exception.Message)" }
$ips = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike '169.254.*' } | ForEach-Object { $_.IPAddress })
Write-Host "`nListo. IP de este equipo: $($ips -join ', ')" -ForegroundColor White
Write-Host 'Desde ADMIN, probar:  Test-WSMan <IP>' -ForegroundColor White
Write-Host 'Cuando todas las VM estén preparadas, tomar una instantánea.' -ForegroundColor White
