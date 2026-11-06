#Requires -Version 5.1
<#
.SYNOPSIS
    Orquestador: despliega el árbol de Active Directory (dominio padre e hijo), DNS
    y el acceso entre dominios, a partir de la carpeta config.

.DESCRIPTION
    Pasos:
      1  Diseño                    valida la configuración y calcula el diseño (no toca servidores)
      2  Despliegue                prepara servidores, crea el dominio raíz y el dominio hijo
      3  DNS                       zonas inversas, PTR, reenviadores, delegación y verificación SRV
      4  Estructura                OU y alta masiva de usuarios
      5  Acceso entre dominios     grupos AGUDLP, recursos compartidos y permisos NTFS
      6  Validación                pruebas automáticas e informe HTML

    El paso 1 se ejecuta siempre (genera output\diseno.json, que usan los demás).
    Los pasos 2 a 6 se registran en output\estado.json: si la ejecución se corta,
    al volver a ejecutar se retoma desde el primer paso pendiente.

.PARAMETER Paso
    Ejecuta solo los pasos indicados (ej.: -Paso 3 o -Paso 4,5).

.PARAMETER SoloDiseno
    Ejecuta solo el paso 1 (útil para revisar el diseño antes de desplegar).

.PARAMETER SoloValidar
    Ejecuta solo el paso 6.

.PARAMETER Reiniciar
    Ignora el estado guardado y vuelve a ejecutar los pasos aunque figuren como completados.

.EXAMPLE
    .\Deploy.ps1                  # despliegue completo
.EXAMPLE
    .\Deploy.ps1 -SoloDiseno      # solo valida la configuración y genera el diseño
.EXAMPLE
    .\Deploy.ps1 -Paso 5 -WhatIf  # muestra qué haría el paso 5 sin cambiar nada
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [ValidateRange(1, 6)][int[]]$Paso,
    [switch]$SoloDiseno,
    [switch]$SoloValidar,
    [switch]$Reiniciar,
    [string]$RutaConfig = (Join-Path $PSScriptRoot 'config'),
    [string]$RutaSalida = (Join-Path $PSScriptRoot 'output')
)

$ErrorActionPreference = 'Stop'
# Con -WhatIf igual se escriben los archivos locales (log, diseño); solo se simulan los pasos 2 a 6.
$simular = [bool]$WhatIfPreference
$WhatIfPreference = $false
$modulos = Join-Path $PSScriptRoot 'modules'
Import-Module (Join-Path $modulos '00-Comun/Comun.psm1') -Force -DisableNameChecking

if (-not (Test-Path $RutaSalida)) { New-Item -Path $RutaSalida -ItemType Directory -Force | Out-Null }
Start-Registro -RutaSalida $RutaSalida

$pasos = @(
    [pscustomobject]@{ Numero = 1; Nombre = 'Diseño';                Script = '01-Diseno/Invoke-Diseno.ps1' }
    [pscustomobject]@{ Numero = 2; Nombre = 'Despliegue';            Script = '02-Despliegue/Invoke-Despliegue.ps1' }
    [pscustomobject]@{ Numero = 3; Nombre = 'DNS';                   Script = '03-DNS/Invoke-DNS.ps1' }
    [pscustomobject]@{ Numero = 4; Nombre = 'Estructura y cuentas';  Script = '04-Estructura/Invoke-Estructura.ps1' }
    [pscustomobject]@{ Numero = 5; Nombre = 'Acceso entre dominios'; Script = '05-AccesoEntreDominios/Invoke-Acceso.ps1' }
    [pscustomobject]@{ Numero = 6; Nombre = 'Validación';            Script = '06-Validacion/Invoke-Validacion.ps1' }
)

# --- Pasos a ejecutar ---
if ($SoloDiseno)      { $seleccion = @(1) }
elseif ($SoloValidar) { $seleccion = @(1, 6) }
elseif ($Paso)        { $seleccion = @(@(1) + $Paso | Select-Object -Unique | Sort-Object) }
else                  { $seleccion = 1..6 }
$explicitos = [bool]($Paso -or $SoloValidar)   # los pasos pedidos explícitamente se ejecutan aunque estén completados

if ($Reiniciar -and -not $simular) { Reset-EstadoDespliegue -RutaSalida $RutaSalida }

$resumen = New-Object System.Collections.Generic.List[object]
$credencial = $null
$diseno = $null
$codigoSalida = 0

try {
    foreach ($p in $pasos | Where-Object { $_.Numero -in $seleccion }) {
        Write-Log "PASO $($p.Numero) – $($p.Nombre)" -Nivel Paso

        # Paso 1: siempre (solo lectura de config y escritura en output)
        if ($p.Numero -eq 1) {
            $null = & (Join-Path $modulos $p.Script) -RutaConfig $RutaConfig -RutaSalida $RutaSalida
            # Los pasos 2 a 6 reciben el diseño tal como quedó en diseno.json (misma forma que si se ejecutan solos)
            $diseno = Get-DisenoParaPaso -Diseno $null -RutaSalida $RutaSalida
            $resumen.Add([pscustomobject]@{ Paso = 1; Nombre = $p.Nombre; Resultado = 'Completado' })
            continue
        }

        if (-not $explicitos -and (Test-PasoCompletado -RutaSalida $RutaSalida -Paso $p.Numero)) {
            Write-Log "Paso $($p.Numero) ya completado en una ejecución anterior; se omite (use -Reiniciar o -Paso $($p.Numero) para repetirlo)."
            $resumen.Add([pscustomobject]@{ Paso = $p.Numero; Nombre = $p.Nombre; Resultado = 'Omitido (ya completado)' })
            continue
        }

        if ($simular) {
            Write-Log "SIMULACIÓN (-WhatIf): se muestra lo que haría el paso $($p.Numero), sin cambiar nada." -Nivel Advertencia
            # En modo simulación se invoca el script con -WhatIf para que muestre lo que haría
            $null = & (Join-Path $modulos $p.Script) -Diseno $diseno -Credencial $null -RutaSalida $RutaSalida -WhatIf
            $resumen.Add([pscustomobject]@{ Paso = $p.Numero; Nombre = $p.Nombre; Resultado = 'Simulado (-WhatIf)' })
            continue
        }

        if (-not $credencial) {
            $credencial = Get-CredencialDespliegue -RutaSalida $RutaSalida
            Set-HostsConfiables -IPs @($diseno.Servidores | ForEach-Object { $_.IPActual, $_.IPFinal })
        }
        $resultado = @(& (Join-Path $modulos $p.Script) -Diseno $diseno -Credencial $credencial -RutaSalida $RutaSalida)[-1]

        if ($resultado -eq 'Pendiente') {
            $resumen.Add([pscustomobject]@{ Paso = $p.Numero; Nombre = $p.Nombre; Resultado = 'Pendiente de implementación' })
        }
        elseif ($resultado -eq 'Fallido') {
            # La validación encontró diferencias: no se marca como completado y el script termina con código 1
            $resumen.Add([pscustomobject]@{ Paso = $p.Numero; Nombre = $p.Nombre; Resultado = 'Con fallas (ver output\validacion\informe-validacion.html)' })
            $codigoSalida = 1
        }
        else {
            Set-PasoCompletado -RutaSalida $RutaSalida -Paso $p.Numero -Nombre $p.Nombre
            $resumen.Add([pscustomobject]@{ Paso = $p.Numero; Nombre = $p.Nombre; Resultado = 'Completado' })
        }
    }
}
catch {
    Write-Log "El despliegue se detuvo: $($_.Exception.Message)" -Nivel Error
    Write-Log 'Corrija el problema y vuelva a ejecutar .\Deploy.ps1: se retomará desde el paso pendiente.' -Nivel Advertencia
    $codigoSalida = 1
}
finally {
    Write-Log 'RESUMEN' -Nivel Paso
    foreach ($r in $resumen) { Write-Log ("Paso {0} – {1,-22} {2}" -f $r.Paso, $r.Nombre, $r.Resultado) }

    # Si se completaron todos los pasos que modifican servidores, se borra la credencial temporal
    if (@(2..6 | Where-Object { -not (Test-PasoCompletado -RutaSalida $RutaSalida -Paso $_) }).Count -eq 0) {
        Remove-CredencialDespliegue -RutaSalida $RutaSalida
    }
    Stop-Registro
}
exit $codigoSalida
