#Requires -Version 3.0
<#
.SYNOPSIS
    Paso 4 – Estructura lógica y alta masiva de cuentas (objetivo específico 4).

.DESCRIPTION
    Dominio PADRE (cuentas), en DC-RAIZ:
      - Crea una OU por área, la OU "Grupos" y la OU "Equipos" (protegidas contra borrado accidental).
      - Da de alta las cuentas de usuarios.csv en la OU de su área, con nombre, UPN, cargo,
        área, empresa, teléfono y oficina. Contraseña: la ContrasenaDemo de lab.psd1 (sin cambio
        obligatorio, para la demostración) o una aleatoria con cambio en el primer inicio de sesión.
    Dominio HIJO (recursos), en DC-HIJO:
      - Crea la OU "Grupos" para los grupos de dominio local. No tiene cuentas de usuario.
      - Si la cuenta ya existe: actualiza los atributos que cambiaron y la mueve de OU si cambió de área.
      - Informa las cuentas que están en las OU de área pero no figuran en usuarios.csv (no las borra).

    Con contraseñas aleatorias, las de las cuentas NUEVAS se guardan en output\credenciales-iniciales.csv
    para entregarlas a los usuarios. Ese archivo debe resguardarse y eliminarse luego.
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

$dominios = @(
    [pscustomobject]@{ Clave = 'Raiz'; Info = $Diseno.Dominios.Raiz; Servidor = (Get-ServidorDiseno -Diseno $Diseno -Rol DCRaiz) }
    [pscustomobject]@{ Clave = 'Hijo'; Info = $Diseno.Dominios.Hijo; Servidor = (Get-ServidorDiseno -Diseno $Diseno -Rol DCHijo) }
)

# =====================================================================
#  Simulación
# =====================================================================
if ($WhatIfPreference) {
    foreach ($d in $dominios) {
        $ous = @($Diseno.OUs | Where-Object { $_.Dominio -eq $d.Clave })
        $usuarios = @($Diseno.Usuarios | Where-Object { $_.Dominio -eq $d.Clave })
        Write-Log "[$($d.Servidor.Nombre)] $($d.Info.FQDN): $($ous.Count) OU y $($usuarios.Count) cuentas"
        foreach ($ou in $ous) {
            $n = @($usuarios | Where-Object { $_.Area -eq $ou.Nombre }).Count
            Write-Plan "OU $($ou.DN)$(if ($ou.Nombre -notin 'Grupos', 'Equipos') { " ($n cuentas)" })"
        }
        foreach ($u in $usuarios | Select-Object -First 3) { Write-Plan "cuenta $($u.NetBIOS)\$($u.Sam) ($($u.UPN)) · $($u.NombreCompleto) · $($u.Cargo) · $($u.OU)" }
        if ($usuarios.Count -gt 3) { Write-Plan "... y $($usuarios.Count - 3) cuentas más (ver output\diseno\usuarios.csv)" }
    }
    return 'Simulado'
}

if (-not $Credencial) { throw 'Se requiere la credencial del despliegue.' }
$cred = Get-CredencialesLab -Credencial $Credencial -Diseno $Diseno

# =====================================================================
#  Bloque remoto (se ejecuta en el DC de cada dominio)
# =====================================================================
$bloqueEstructura = {
    param([object[]]$OUs, [object[]]$Usuarios, [bool]$CambiarAlIniciar = $true)
    $ErrorActionPreference = 'Stop'
    Import-Module ActiveDirectory

    # --- OU ---
    foreach ($ou in $OUs) {
        $existe = $true
        try { $null = Get-ADOrganizationalUnit -Identity $ou.DN } catch { $existe = $false }
        if (-not $existe) {
            $desc = [string]$ou.Descripcion
            if (-not $desc) { $desc = "Área $($ou.Nombre)" }
            New-ADOrganizationalUnit -Name $ou.Nombre -Path $ou.Padre -Description $desc -ProtectedFromAccidentalDeletion $true
        }
        [pscustomobject]@{ Tipo = 'OU'; Objeto = $ou.DN; Accion = $(if ($existe) { 'Existente' } else { 'Creada' }); Detalle = '' }
    }

    # --- Usuarios ---
    $mapa = [ordered]@{ GivenName = 'Nombre'; Surname = 'Apellido'; DisplayName = 'NombreCompleto'; UserPrincipalName = 'UPN'
                        Title = 'Cargo'; Department = 'Area'; Company = 'Empresa'; OfficePhone = 'Telefono'; Office = 'Oficina'; Description = 'Descripcion' }
    foreach ($u in $Usuarios) {
        $actual = $null
        try { $actual = Get-ADUser -Identity $u.Sam -Properties @($mapa.Keys) } catch { $actual = $null }

        if (-not $actual) {
            $p = @{
                Name = $u.CN; SamAccountName = $u.Sam; Path = $u.OU; AccountPassword = $u.Password
                ChangePasswordAtLogon = $CambiarAlIniciar; Enabled = $true
            }
            foreach ($atr in $mapa.Keys) { if ($u.($mapa[$atr])) { $p[$atr] = [string]$u.($mapa[$atr]) } }
            New-ADUser @p
            [pscustomobject]@{ Tipo = 'Usuario'; Objeto = $u.Sam; Accion = 'Creado'; Detalle = $u.OU }
            continue
        }

        $cambios = @{}
        foreach ($atr in $mapa.Keys) {
            $deseado = [string]$u.($mapa[$atr])
            if ([string]$actual.$atr -cne $deseado) { if ($deseado) { $cambios[$atr] = $deseado } else { $cambios[$atr] = $null } }
        }
        $detalle = @()
        if ($cambios.Count) { Set-ADUser -Identity $actual @cambios; $detalle += "atributos: $($cambios.Keys -join ', ')" }

        $ouActual = $actual.DistinguishedName.Substring($actual.DistinguishedName.IndexOf(',') + 1)
        if ($ouActual -ne $u.OU) {
            Move-ADObject -Identity $actual.DistinguishedName -TargetPath $u.OU
            $detalle += "movido de $ouActual"
            $actual = Get-ADUser -Identity $u.Sam
        }
        if ($actual.Name -cne $u.CN) { Rename-ADObject -Identity $actual.DistinguishedName -NewName $u.CN; $detalle += "renombrado a '$($u.CN)'" }

        $accion = 'Sin cambios'
        if ($detalle.Count) { $accion = 'Actualizado' }
        [pscustomobject]@{ Tipo = 'Usuario'; Objeto = $u.Sam; Accion = $accion; Detalle = ($detalle -join '; ') }
    }

    # --- Cuentas en las OU de área que no están en el diseño (solo se informan) ---
    $previstas = @($Usuarios | ForEach-Object { $_.Sam })
    foreach ($ou in @($OUs | Where-Object { $_.Nombre -notin 'Grupos', 'Equipos' })) {
        foreach ($x in @(Get-ADUser -SearchBase $ou.DN -SearchScope OneLevel -Filter *)) {
            if ($x.SamAccountName -notin $previstas) { [pscustomobject]@{ Tipo = 'Usuario'; Objeto = $x.SamAccountName; Accion = 'NoEnDiseno'; Detalle = $ou.DN } }
        }
    }
}

# =====================================================================
#  Ejecución por dominio
# =====================================================================
$archivoCred = Join-Path $RutaSalida 'credenciales-iniciales.csv'
$contrasenaDemo = [string]$Diseno.Parametros.ContrasenaDemo
if ($contrasenaDemo) { Write-Log 'Se usa la ContrasenaDemo de lab.psd1 para las cuentas nuevas, sin cambio obligatorio al iniciar sesión (solo laboratorio).' -Nivel Advertencia }
$todos = New-Object System.Collections.Generic.List[object]

foreach ($d in $dominios) {
    Write-Log "Dominio $($d.Info.FQDN) (en $($d.Servidor.Nombre))" -Nivel Paso
    $credDom = $cred.($d.Clave)
    $ous = @($Diseno.OUs | Where-Object { $_.Dominio -eq $d.Clave } | ForEach-Object { [pscustomobject]@{ Nombre = $_.Nombre; DN = $_.DN; Padre = $_.Padre; Descripcion = $_.Descripcion } })

    # Contraseña inicial de cada cuenta (solo se usa si la cuenta se crea)
    $contrasenas = @{}
    $usuarios = @($Diseno.Usuarios | Where-Object { $_.Dominio -eq $d.Clave } | ForEach-Object {
            $texto = $contrasenaDemo
            if (-not $texto) { $texto = New-ContrasenaAleatoria }
            $contrasenas[$_.Sam] = $texto
            [pscustomobject]@{
                Sam = $_.Sam; CN = $_.CN; Nombre = $_.Nombre; Apellido = $_.Apellido; NombreCompleto = $_.NombreCompleto; UPN = $_.UPN
                OU = $_.OU; Area = $_.Area; Cargo = $_.Cargo; Telefono = $_.Telefono; Oficina = $_.Oficina; Empresa = $_.Empresa; Descripcion = $_.Descripcion
                Password = (ConvertTo-SecureString $texto -AsPlainText -Force)
            }
        })

    $res = @(Invoke-EnServidor -Equipo $d.Servidor.IPFinal -Credencial $credDom -Bloque $bloqueEstructura -Argumentos @($ous, $usuarios, (-not $contrasenaDemo)) `
            -Descripcion "$($ous.Count) OU y $($usuarios.Count) cuentas")

    $creados = @($res | Where-Object { $_.Tipo -eq 'Usuario' -and $_.Accion -eq 'Creado' })
    if ($creados.Count -and -not $contrasenaDemo) {
        $fecha = Get-Date -Format 's'
        $filas = foreach ($c in $creados) {
            $u = $Diseno.Usuarios | Where-Object { $_.Dominio -eq $d.Clave -and $_.Sam -eq $c.Objeto } | Select-Object -First 1
            [pscustomobject]@{ Dominio = $d.Info.FQDN; Cuenta = "$($d.Info.NetBIOS)\$($c.Objeto)"; UPN = $u.UPN; Nombre = $u.NombreCompleto; Area = $u.Area; ContrasenaInicial = $contrasenas[$c.Objeto]; Fecha = $fecha }
        }
        $filas | Export-Csv -Path $archivoCred -NoTypeInformation -Encoding UTF8 -Append
    }

    $ouCreadas = @($res | Where-Object { $_.Tipo -eq 'OU' -and $_.Accion -eq 'Creada' }).Count
    $ouExist   = @($res | Where-Object { $_.Tipo -eq 'OU' -and $_.Accion -eq 'Existente' }).Count
    $act       = @($res | Where-Object { $_.Accion -eq 'Actualizado' })
    $sinCambio = @($res | Where-Object { $_.Accion -eq 'Sin cambios' }).Count
    Write-Log "OU: $ouCreadas creadas, $ouExist existentes." -Nivel Ok
    Write-Log "Cuentas: $($creados.Count) creadas, $($act.Count) actualizadas, $sinCambio sin cambios." -Nivel Ok
    foreach ($a in $act) { Write-Log "  $($a.Objeto): $($a.Detalle)" }
    foreach ($x in @($res | Where-Object { $_.Accion -eq 'NoEnDiseno' })) { Write-Log "  $($x.Objeto) está en $($x.Detalle) pero no figura en usuarios.csv (no se modifica)." -Nivel Advertencia }
    foreach ($r in $res) { $todos.Add(($r | Select-Object @{ n = 'Dominio'; e = { $d.Info.FQDN } }, Tipo, Objeto, Accion, Detalle)) }
}

$todos | Export-Csv -Path (Join-Path $RutaSalida 'estructura-resultado.csv') -NoTypeInformation -Encoding UTF8
if (Test-Path $archivoCred) {
    Write-Log "Contraseñas iniciales de las cuentas nuevas en $archivoCred. Entréguelas por un canal seguro y elimine el archivo." -Nivel Advertencia
}
return 'Completado'
