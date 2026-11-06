#Requires -Version 5.1
<#
.SYNOPSIS
    Funciones compartidas por todos los módulos del proyecto.

.DESCRIPTION
    - Registro (log en consola y archivo, transcripción).
    - Carga de la configuración (lab.psd1, usuarios.csv, accesos.csv).
    - Archivo de estado para retomar el despliegue.
    - Credencial de despliegue (se pide una sola vez y se guarda cifrada con DPAPI).
    - Convenciones de nombres (cuentas, grupos, contraseñas).
    - Cálculos de red (CIDR, IP derivadas, zona inversa).
    - Espera de servidores (reinicios) y ejecución remota.

    Compatible con Windows PowerShell 5.1 y PowerShell 7.
#>

Set-StrictMode -Version 2.0

# =====================================================================
#  Registro
# =====================================================================
$script:ArchivoLog = $null

function Start-Registro {
    <# Crea la carpeta de logs, define el archivo de log y arranca la transcripción. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$RutaSalida)

    $carpeta = Join-Path $RutaSalida 'logs'
    if (-not (Test-Path $carpeta)) { New-Item -Path $carpeta -ItemType Directory -Force | Out-Null }
    $marca = Get-Date -Format 'yyyyMMdd-HHmmss'
    $script:ArchivoLog = Join-Path $carpeta "despliegue-$marca.log"
    try { Start-Transcript -Path (Join-Path $carpeta "transcripcion-$marca.txt") -Append | Out-Null } catch { }
    Write-Log "Registro iniciado: $($script:ArchivoLog)"
}

function Stop-Registro {
    [CmdletBinding()] param()
    try { Stop-Transcript | Out-Null } catch { }
}

function Write-Log {
    <# Escribe un mensaje con nivel en la consola (con color) y en el archivo de log. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)][AllowEmptyString()][string]$Mensaje,
        [ValidateSet('Info', 'Ok', 'Advertencia', 'Error', 'Paso')][string]$Nivel = 'Info'
    )
    $hora = Get-Date -Format 'HH:mm:ss'
    $prefijos = @{ Info = '[INFO]'; Ok = '[ OK ]'; Advertencia = '[ADV ]'; Error = '[ERR ]'; Paso = '[====]' }
    $colores  = @{ Info = 'Gray';   Ok = 'Green'; Advertencia = 'Yellow'; Error = 'Red';  Paso = 'Cyan' }
    $linea = "$hora $($prefijos[$Nivel]) $Mensaje"
    Write-Host $linea -ForegroundColor $colores[$Nivel]
    if ($script:ArchivoLog) { Add-Content -Path $script:ArchivoLog -Value $linea -Encoding UTF8 }
}

# =====================================================================
#  Configuración
# =====================================================================
function Import-ConfigLab {
    <#
    .SYNOPSIS
        Lee lab.psd1, usuarios.csv y accesos.csv de la carpeta de configuración.
    .OUTPUTS
        Hashtable con las claves Lab, Usuarios y Accesos.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$RutaConfig)

    $archivos = @{
        Lab      = Join-Path $RutaConfig 'lab.psd1'
        Usuarios = Join-Path $RutaConfig 'usuarios.csv'
        Accesos  = Join-Path $RutaConfig 'accesos.csv'
    }
    foreach ($a in $archivos.Values) {
        if (-not (Test-Path $a)) { throw "No se encontró el archivo de configuración: $a" }
    }
    return @{
        Lab      = Import-PowerShellDataFile -Path $archivos.Lab
        Usuarios = @(Import-Csv -Path $archivos.Usuarios -Encoding UTF8)
        Accesos  = @(Import-Csv -Path $archivos.Accesos  -Encoding UTF8)
    }
}

# =====================================================================
#  Estado del despliegue (para retomar)
# =====================================================================
function Get-EstadoDespliegue {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$RutaSalida)
    $archivo = Join-Path $RutaSalida 'estado.json'
    if (-not (Test-Path $archivo)) { return @() }
    $contenido = Get-Content -Path $archivo -Raw -Encoding UTF8
    if ([string]::IsNullOrWhiteSpace($contenido)) { return @() }
    return @($contenido | ConvertFrom-Json)
}

function Test-PasoCompletado {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$RutaSalida, [Parameter(Mandatory)][int]$Paso)
    return [bool](@(Get-EstadoDespliegue -RutaSalida $RutaSalida | Where-Object { $_.Paso -eq $Paso }).Count)
}

function Set-PasoCompletado {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$RutaSalida, [Parameter(Mandatory)][int]$Paso, [string]$Nombre = '')
    $estado = @(Get-EstadoDespliegue -RutaSalida $RutaSalida | Where-Object { $_.Paso -ne $Paso })
    $estado += [pscustomobject]@{ Paso = $Paso; Nombre = $Nombre; Fecha = (Get-Date -Format 's') }
    $estado = @($estado | Sort-Object Paso)
    ConvertTo-Json -InputObject $estado -Depth 3 | Set-Content -Path (Join-Path $RutaSalida 'estado.json') -Encoding UTF8
}

function Reset-EstadoDespliegue {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$RutaSalida)
    $archivo = Join-Path $RutaSalida 'estado.json'
    if (Test-Path $archivo) { Remove-Item $archivo -Force }
}

# =====================================================================
#  Credencial de despliegue
# =====================================================================
function Get-CredencialDespliegue {
    <#
    .SYNOPSIS
        Devuelve la contraseña de administrador del despliegue.
    .DESCRIPTION
        Se pide UNA sola vez (con confirmación) y se guarda cifrada con DPAPI
        (Export-Clixml: solo la puede leer el mismo usuario en el mismo equipo).
        Se usa como contraseña del Administrador local inicial y como contraseña DSRM.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$RutaSalida)

    $archivo = Join-Path $RutaSalida 'credencial.xml'
    if (Test-Path $archivo) {
        Write-Log 'Usando la credencial guardada de una ejecución anterior.'
        return Import-Clixml -Path $archivo
    }
    do {
        $c1 = Read-Host 'Contraseña de administrador del despliegue' -AsSecureString
        $c2 = Read-Host 'Confirmar contraseña' -AsSecureString
        $iguales = (ConvertFrom-SecureStringTexto $c1) -ceq (ConvertFrom-SecureStringTexto $c2)
        if (-not $iguales) { Write-Log 'Las contraseñas no coinciden. Intente nuevamente.' -Nivel Advertencia }
    } until ($iguales)

    $cred = New-Object System.Management.Automation.PSCredential('Administrator', $c1)
    $cred | Export-Clixml -Path $archivo
    return $cred
}

function Remove-CredencialDespliegue {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$RutaSalida)
    $archivo = Join-Path $RutaSalida 'credencial.xml'
    if (Test-Path $archivo) { Remove-Item $archivo -Force; Write-Log 'Credencial temporal eliminada.' }
}

function ConvertFrom-SecureStringTexto {
    <# Uso interno: compara contraseñas. No se registra nunca en el log. #>
    param([Parameter(Mandatory)][securestring]$Valor)
    $ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Valor)
    try { return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr) }
}

function New-CredencialDominio {
    <# Construye la credencial de administrador de un dominio a partir de la del despliegue. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][pscredential]$Credencial,
        [Parameter(Mandatory)][string]$NetBIOS
    )
    return New-Object System.Management.Automation.PSCredential("$NetBIOS\Administrator", $Credencial.Password)
}

# =====================================================================
#  Convenciones de nombres
# =====================================================================
function ConvertTo-TextoSimple {
    <# Quita acentos y caracteres no alfanuméricos ("Núñez" -> "Nunez"). #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Texto, [switch]$PermitirGuion)

    $normalizado = $Texto.Normalize([Text.NormalizationForm]::FormD)
    $sb = New-Object System.Text.StringBuilder
    foreach ($ch in $normalizado.ToCharArray()) {
        if ([Globalization.CharUnicodeInfo]::GetUnicodeCategory($ch) -ne [Globalization.UnicodeCategory]::NonSpacingMark) {
            [void]$sb.Append($ch)
        }
    }
    $patron = '[^A-Za-z0-9]'
    if ($PermitirGuion) { $patron = '[^A-Za-z0-9-]' }
    return ($sb.ToString() -replace $patron, '')
}

function Get-NombreSam {
    <#
    .SYNOPSIS
        Genera el sAMAccountName: inicial del nombre + apellido, en minúsculas, sin acentos,
        máximo 20 caracteres. Si ya existe, agrega un número (jperez, jperez2, ...).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Nombre,
        [Parameter(Mandatory)][string]$Apellido,
        [System.Collections.Generic.HashSet[string]]$Existentes
    )
    $base = (ConvertTo-TextoSimple ($Nombre.Substring(0, 1) + $Apellido)).ToLowerInvariant()
    if ($base.Length -gt 18) { $base = $base.Substring(0, 18) }
    $candidato = $base
    $n = 2
    while ($Existentes -and $Existentes.Contains($candidato)) { $candidato = "$base$n"; $n++ }
    if ($Existentes) { [void]$Existentes.Add($candidato) }
    return $candidato
}

function Get-NombreGrupoGlobal {
    <# GG-<NETBIOS>-<Area>   ej.: GG-VENTAS-Comerciales #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$NetBIOS, [Parameter(Mandatory)][string]$Area)
    return "GG-$($NetBIOS.ToUpperInvariant())-$(ConvertTo-TextoSimple $Area)"
}

function Get-NombreGrupoDL {
    <# DL-<Recurso>-<Nivel>   ej.: DL-Proyectos-Lectura #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Recurso, [Parameter(Mandatory)][string]$Nivel)
    return "DL-$(ConvertTo-TextoSimple $Recurso -PermitirGuion)-$Nivel"
}

function New-ContrasenaAleatoria {
    <#
    .SYNOPSIS
        Genera una contraseña aleatoria que cumple la complejidad de Windows
        (mayúsculas, minúsculas, números y símbolos).
    #>
    [CmdletBinding()]
    param([ValidateRange(12, 64)][int]$Longitud = 14)

    $grupos = @('ABCDEFGHJKLMNPQRSTUVWXYZ', 'abcdefghijkmnopqrstuvwxyz', '23456789', '!@#$%*-_+=?')
    $todos = -join $grupos
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $byte = New-Object byte[] 1
    $siguiente = {
        param([string]$conjunto)
        $rng.GetBytes($byte)
        return $conjunto[$byte[0] % $conjunto.Length]
    }
    $chars = New-Object System.Collections.Generic.List[char]
    foreach ($g in $grupos) { $chars.Add((& $siguiente $g)) }
    while ($chars.Count -lt $Longitud) { $chars.Add((& $siguiente $todos)) }
    # mezcla (Fisher-Yates)
    for ($i = $chars.Count - 1; $i -gt 0; $i--) {
        $rng.GetBytes($byte); $j = $byte[0] % ($i + 1)
        $tmp = $chars[$i]; $chars[$i] = $chars[$j]; $chars[$j] = $tmp
    }
    $rng.Dispose()
    return -join $chars
}

# =====================================================================
#  Cálculos de red
# =====================================================================
function ConvertTo-EnteroIP {
    param([Parameter(Mandatory)][string]$IP)
    $bytes = [System.Net.IPAddress]::Parse($IP).GetAddressBytes()
    [Array]::Reverse($bytes)
    return [BitConverter]::ToUInt32($bytes, 0)
}

function ConvertFrom-EnteroIP {
    param([Parameter(Mandatory)][uint32]$Valor)
    $bytes = [BitConverter]::GetBytes($Valor)
    [Array]::Reverse($bytes)
    return ([System.Net.IPAddress]::new($bytes)).ToString()
}

function Test-FormatoIPv4 {
    [CmdletBinding()]
    param([AllowEmptyString()][string]$IP)
    if ([string]::IsNullOrWhiteSpace($IP)) { return $false }
    return $IP -match '^((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$'
}

function Get-InfoRed {
    <#
    .SYNOPSIS
        A partir de una red en notación CIDR calcula dirección de red, máscara,
        primer y último host, broadcast, y los datos de la zona DNS inversa.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Cidr)

    if ($Cidr -notmatch '^(?<ip>[\d\.]+)/(?<pref>\d{1,2})$') { throw "Formato de red inválido: '$Cidr' (se espera p. ej. 192.168.10.0/24)" }
    $ip = $Matches.ip; $prefijo = [int]$Matches.pref
    if (-not (Test-FormatoIPv4 $ip)) { throw "Dirección de red inválida: '$ip'" }
    if ($prefijo -lt 8 -or $prefijo -gt 30) { throw "Prefijo fuera de rango (8 a 30): /$prefijo" }

    $mascara = [uint32]([math]::Pow(2, 32) - [math]::Pow(2, 32 - $prefijo))
    $red     = (ConvertTo-EnteroIP $ip) -band $mascara
    $bcast   = $red + [uint32]([math]::Pow(2, 32 - $prefijo) - 1)

    # Zona inversa: se usan los octetos completos de la parte de red (/24 -> 3 octetos, /16 -> 2, ...)
    $octetosRed = [math]::Floor($prefijo / 8)
    [string[]]$partes = @((ConvertFrom-EnteroIP $red).Split('.')[0..($octetosRed - 1)])
    [Array]::Reverse($partes)
    $zona = ($partes -join '.') + '.in-addr.arpa'
    $networkIdZona = "$(ConvertFrom-EnteroIP $red)/$($octetosRed * 8)"

    return [pscustomobject]@{
        Cidr          = "$(ConvertFrom-EnteroIP $red)/$prefijo"
        Direccion     = ConvertFrom-EnteroIP $red
        Prefijo       = $prefijo
        Mascara       = ConvertFrom-EnteroIP $mascara
        PrimerHost    = ConvertFrom-EnteroIP ($red + 1)
        UltimoHost    = ConvertFrom-EnteroIP ($bcast - 1)
        Broadcast     = ConvertFrom-EnteroIP $bcast
        ZonaInversa   = $zona
        NetworkIdZona = $networkIdZona   # para Add-DnsServerPrimaryZone -NetworkId
    }
}

function Get-NombrePTR {
    <# Nombre del registro PTR relativo a la zona inversa (192.168.10.20 en 10.168.192.in-addr.arpa -> '20'). #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$IP, [Parameter(Mandatory)][string]$ZonaInversa)
    $partes = $IP.Split('.'); [Array]::Reverse($partes)
    $completo = ($partes -join '.') + '.in-addr.arpa'
    $sufijo = '.' + $ZonaInversa
    if (-not $completo.EndsWith($sufijo)) { throw "La IP $IP no pertenece a la zona $ZonaInversa." }
    return $completo.Substring(0, $completo.Length - $sufijo.Length)
}

function Test-IPEnRed {
    <# Verdadero si la IP es un host válido de la red (no es la dirección de red ni el broadcast). #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$IP, [Parameter(Mandatory)]$InfoRed)
    if (-not (Test-FormatoIPv4 $IP)) { return $false }
    $v = ConvertTo-EnteroIP $IP
    return ($v -ge (ConvertTo-EnteroIP $InfoRed.PrimerHost)) -and ($v -le (ConvertTo-EnteroIP $InfoRed.UltimoHost))
}

function Get-IPDesplazada {
    <# Devuelve la IP = dirección de red + desplazamiento (ej.: 192.168.10.0 + 10 = 192.168.10.10). #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$InfoRed, [Parameter(Mandatory)][int]$Desplazamiento)
    return ConvertFrom-EnteroIP ((ConvertTo-EnteroIP $InfoRed.Direccion) + [uint32]$Desplazamiento)
}

# =====================================================================
#  Servidores remotos
# =====================================================================
function Wait-ServidorDisponible {
    <#
    .SYNOPSIS
        Espera a que un servidor responda por WinRM. Con -EsperarReinicio, primero
        espera a que deje de responder (se está reiniciando) y luego a que vuelva.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Equipo,
        [int]$TiempoMaximoSeg = 1200,
        [switch]$EsperarReinicio
    )
    $limite = (Get-Date).AddSeconds($TiempoMaximoSeg)
    if ($EsperarReinicio) {
        Write-Log "Esperando que $Equipo se reinicie..."
        $limiteBaja = (Get-Date).AddMinutes(5)
        while ((Get-Date) -lt $limiteBaja -and (Test-WSMan -ComputerName $Equipo -ErrorAction SilentlyContinue)) { Start-Sleep -Seconds 5 }
    }
    Write-Log "Esperando que $Equipo esté disponible..."
    while ((Get-Date) -lt $limite) {
        if (Test-WSMan -ComputerName $Equipo -ErrorAction SilentlyContinue) {
            Write-Log "$Equipo disponible." -Nivel Ok
            return
        }
        Start-Sleep -Seconds 10
    }
    throw "Tiempo agotado esperando a $Equipo ($TiempoMaximoSeg s)."
}

function Invoke-EnServidor {
    <# Ejecuta un bloque de código en un servidor remoto, con registro y manejo de errores. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Equipo,
        [Parameter(Mandatory)][pscredential]$Credencial,
        [Parameter(Mandatory)][scriptblock]$Bloque,
        [object[]]$Argumentos = @(),
        [string]$Descripcion = 'operación remota'
    )
    Write-Log "[$Equipo] $Descripcion"
    try {
        return Invoke-Command -ComputerName $Equipo -Credential $Credencial -ScriptBlock $Bloque -ArgumentList $Argumentos -ErrorAction Stop
    }
    catch {
        Write-Log "[$Equipo] Falló: $Descripcion -> $($_.Exception.Message)" -Nivel Error
        throw
    }
}

# =====================================================================
#  Apoyo a los pasos 2 a 6
# =====================================================================
function Get-DisenoParaPaso {
    <#
    .SYNOPSIS
        Devuelve el diseño recibido o, si el paso se ejecuta solo, lo lee de output\diseno.json.
    #>
    [CmdletBinding()]
    param($Diseno, [Parameter(Mandatory)][string]$RutaSalida)
    if ($Diseno) { return $Diseno }
    $archivo = Join-Path $RutaSalida 'diseno.json'
    if (-not (Test-Path $archivo)) { throw "No se encontró $archivo. Ejecute primero el paso 1 (.\Deploy.ps1 -SoloDiseno)." }
    return (Get-Content -Path $archivo -Raw -Encoding UTF8 | ConvertFrom-Json)
}

function Get-ServidorDiseno {
    <# Devuelve el servidor del diseño con el rol indicado (DCRaiz, DCHijo o Archivos). #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Diseno, [Parameter(Mandatory)][ValidateSet('DCRaiz', 'DCHijo', 'Archivos')][string]$Rol)
    return @($Diseno.Servidores | Where-Object { $_.Rol -eq $Rol })[0]
}

function Get-CredencialesLab {
    <#
    .SYNOPSIS
        A partir de la contraseña del despliegue arma las tres credenciales que se usan:
          Local -> Administrador local de las VM recién instaladas (antes de unirse a un dominio)
          Raiz  -> ANDINA\Administrador (pasa a ser Administrador de empresa del bosque)
          Hijo  -> VENTAS\Administrador (administrador del dominio hijo)
        Las tres comparten la contraseña: el Administrador local del primer DC de cada dominio
        se convierte en el Administrador de ese dominio.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][pscredential]$Credencial, [Parameter(Mandatory)]$Diseno)
    $usuario = 'Administrator'
    if ($Diseno.Parametros.UsuarioAdministrador) { $usuario = [string]$Diseno.Parametros.UsuarioAdministrador }
    return [pscustomobject]@{
        Local = New-Object System.Management.Automation.PSCredential($usuario, $Credencial.Password)
        Raiz  = New-Object System.Management.Automation.PSCredential("$($Diseno.Dominios.Raiz.NetBIOS)\$usuario", $Credencial.Password)
        Hijo  = New-Object System.Management.Automation.PSCredential("$($Diseno.Dominios.Hijo.NetBIOS)\$usuario", $Credencial.Password)
    }
}

function Connect-Servidor {
    <#
    .SYNOPSIS
        Encuentra cómo conectarse a un servidor: prueba primero la IP final y luego la actual,
        con cada credencial candidata, y devuelve la primera combinación que funciona.
    .OUTPUTS
        Objeto con Equipo (IP), Credencial y EnIPFinal.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Servidor,
        [Parameter(Mandatory)][pscredential[]]$Credenciales,
        [int]$Intentos = 1
    )
    for ($i = 1; $i -le $Intentos; $i++) {
        foreach ($ip in @($Servidor.IPFinal, $Servidor.IPActual) | Select-Object -Unique) {
            if (-not (Test-WSMan -ComputerName $ip -ErrorAction SilentlyContinue)) { continue }
            foreach ($c in $Credenciales) {
                try {
                    $null = Invoke-Command -ComputerName $ip -Credential $c -ScriptBlock { $env:COMPUTERNAME } -ErrorAction Stop
                    return [pscustomobject]@{ Equipo = $ip; Credencial = $c; EnIPFinal = ($ip -eq $Servidor.IPFinal) }
                }
                catch { Write-Verbose "[$ip] $($c.UserName): $($_.Exception.Message)" }
            }
        }
        if ($i -lt $Intentos) { Start-Sleep -Seconds 15 }
    }
    throw "No se pudo conectar a $($Servidor.Nombre) (IP $($Servidor.IPFinal) / $($Servidor.IPActual)) con las credenciales disponibles. Verifique que la VM esté encendida, que WinRM esté habilitado (Enable-PSRemoting) y que la contraseña del Administrador sea la del despliegue."
}

function Wait-ADDisponible {
    <#
    .SYNOPSIS
        Después de promover un DC espera a que Active Directory Web Services responda
        (Get-ADDomain), lo que puede demorar varios minutos tras el reinicio.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Equipo,
        [Parameter(Mandatory)][pscredential]$Credencial,
        [Parameter(Mandatory)][string]$Dominio,
        [int]$TiempoMaximoSeg = 900
    )
    $limite = (Get-Date).AddSeconds($TiempoMaximoSeg)
    Write-Log "Esperando que Active Directory ($Dominio) responda en $Equipo..."
    while ((Get-Date) -lt $limite) {
        try {
            $dns = Invoke-Command -ComputerName $Equipo -Credential $Credencial -ErrorAction Stop -ScriptBlock {
                Import-Module ActiveDirectory -ErrorAction Stop
                (Get-ADDomain -ErrorAction Stop).DNSRoot
            }
            if ($dns -eq $Dominio) { Write-Log "Active Directory $Dominio operativo." -Nivel Ok; return }
        }
        catch { Write-Verbose $_.Exception.Message }
        Start-Sleep -Seconds 20
    }
    throw "Tiempo agotado esperando a que Active Directory $Dominio responda en $Equipo."
}

function Set-HostsConfiables {
    <#
    .SYNOPSIS
        Agrega las IP de los servidores a TrustedHosts del equipo de administración
        (necesario para PowerShell Remoting por IP con equipos fuera del dominio).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string[]]$IPs)
    if ([System.Environment]::OSVersion.Platform -ne 'Win32NT') { return }
    try {
        $actual = [string](Get-Item WSMan:\localhost\Client\TrustedHosts -ErrorAction Stop).Value
        if ($actual -eq '*') { return }
        $lista = @($actual.Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ })
        $faltan = @($IPs | Where-Object { $_ -notin $lista } | Select-Object -Unique)
        if ($faltan.Count -eq 0) { return }
        Set-Item WSMan:\localhost\Client\TrustedHosts -Value ((@($lista) + $faltan) -join ',') -Force
        Write-Log "TrustedHosts: se agregaron $($faltan -join ', ')."
    }
    catch {
        Write-Log "No se pudo actualizar TrustedHosts ($($_.Exception.Message)). Ejecute como administrador o agréguelas a mano: Set-Item WSMan:\localhost\Client\TrustedHosts -Value '$($IPs -join ',')' -Force" -Nivel Advertencia
    }
}

function Write-Plan {
    <# En modo simulación (-WhatIf) muestra una acción que se haría. #>
    [CmdletBinding()]
    param([Parameter(Mandatory, Position = 0)][string]$Mensaje)
    Write-Log "  [SIMULACIÓN] $Mensaje"
}

Export-ModuleMember -Function *
