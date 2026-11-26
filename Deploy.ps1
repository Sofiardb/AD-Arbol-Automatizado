#Requires -Version 3.0
<#
.SYNOPSIS
    Orquestador: despliega el árbol de Active Directory (dominio padre con las cuentas, dominio hijo
    con los recursos), el DNS, el acceso entre dominios y el cliente de la demostración,
    a partir de la carpeta config.

.DESCRIPTION
    Pasos:
      1  Diseño                    valida la configuración y calcula el diseño (no toca servidores)
      2  Despliegue                prepara DC-RAIZ y DC-HIJO, crea el dominio raíz y el dominio hijo
      3  DNS                       zona inversa, PTR, reenviadores, delegación y verificación SRV
      4  Estructura y cuentas      OU y alta masiva de cuentas en el dominio padre
      5  Acceso entre dominios     GG en el padre, DL en el hijo, recursos compartidos y NTFS en DC-HIJO
      6  Cliente                   une el cliente al dominio e instala el kit de demostración
      7  Validación                pruebas automáticas (incluye acceso real) e informe HTML

    El paso 1 se ejecuta siempre (genera output\diseno.json, que usan los demás).
    Si el paso 6 se ejecuta en el propio cliente, al terminar pide reiniciar el equipo; al volver a
    ejecutar .\Deploy.ps1 se continúa con el paso 7.
    Los pasos 2 a 7 se registran en output\estado.json: si la ejecución se corta,
    al volver a ejecutar se retoma desde el primer paso pendiente.

.PARAMETER Paso
    Ejecuta solo los pasos indicados (ej.: -Paso 3 o -Paso 4,5).

.PARAMETER SoloDiseno
    Ejecuta solo el paso 1 (útil para revisar el diseño antes de desplegar).

.PARAMETER SoloValidar
    Ejecuta solo el paso 7.

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
    [ValidateRange(1, 7)][int[]]$Paso,
    [switch]$SoloDiseno,
    [switch]$SoloValidar,
    [switch]$Reiniciar,
    [string]$RutaConfig,   # por defecto: .\config
    [string]$RutaSalida    # por defecto: .\output
)

$ErrorActionPreference = 'Stop'
# En PowerShell 3.0 y 4.0, $PSScriptRoot puede llegar vacío a los valores por defecto de los parámetros
# (por ejemplo, al ejecutar con powershell.exe -File desde un acceso directo): se calcula acá.
$raiz = $PSScriptRoot
if (-not $raiz) { $raiz = Split-Path -Parent $MyInvocation.MyCommand.Path }
if (-not $RutaConfig) { $RutaConfig = Join-Path $raiz 'config' }
if (-not $RutaSalida) { $RutaSalida = Join-Path $raiz 'output' }
# Funciona con Windows PowerShell 3.0, 4.0, 5.1 y PowerShell 7 en Windows.
$esWindows = [System.Environment]::OSVersion.Platform -eq 'Win32NT'
if (-not $esWindows -and -not ($SoloDiseno -or [bool]$WhatIfPreference)) {
    throw 'Los pasos 2 a 7 administran los servidores por PowerShell Remoting (WinRM) y requieren Windows. En Linux o macOS solo se puede usar -SoloDiseno o -WhatIf.'
}
# Con -WhatIf igual se escriben los archivos locales (log, diseño); solo se simulan los pasos 2 a 7.
$simular = [bool]$WhatIfPreference
$WhatIfPreference = $false
$modulos = Join-Path $raiz 'modules'
Import-Module (Join-Path $modulos '00-Comun/Comun.psm1') -Force -DisableNameChecking

if (-not (Test-Path $RutaSalida)) { New-Item -Path $RutaSalida -ItemType Directory -Force | Out-Null }
Start-Registro -RutaSalida $RutaSalida

$pasos = @(
    [pscustomobject]@{ Numero = 1; Nombre = 'Diseño';                Script = '01-Diseno/Invoke-Diseno.ps1' }
    [pscustomobject]@{ Numero = 2; Nombre = 'Despliegue';            Script = '02-Despliegue/Invoke-Despliegue.ps1' }
    [pscustomobject]@{ Numero = 3; Nombre = 'DNS';                   Script = '03-DNS/Invoke-DNS.ps1' }
    [pscustomobject]@{ Numero = 4; Nombre = 'Estructura y cuentas';  Script = '04-Estructura/Invoke-Estructura.ps1' }
    [pscustomobject]@{ Numero = 5; Nombre = 'Acceso entre dominios'; Script = '05-AccesoEntreDominios/Invoke-Acceso.ps1' }
    [pscustomobject]@{ Numero = 6; Nombre = 'Cliente';               Script = '06-Cliente/Invoke-Cliente.ps1' }
    [pscustomobject]@{ Numero = 7; Nombre = 'Validación';            Script = '07-Validacion/Invoke-Validacion.ps1' }
)

# --- Pasos a ejecutar ---
if ($SoloDiseno)      { $seleccion = @(1) }
elseif ($SoloValidar) { $seleccion = @(1, 7) }
elseif ($Paso)        { $seleccion = @(@(1) + $Paso | Select-Object -Unique | Sort-Object) }
else                  { $seleccion = 1..7 }
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
            # Los pasos 2 a 7 reciben el diseño tal como quedó en diseno.json (misma forma que si se ejecutan solos)
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
            Set-HostsConfiables -IPs @(@($diseno.Servidores) + @($diseno.Cliente | Where-Object { $_ }) | ForEach-Object { $_.IPActual, $_.IPFinal })
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
        elseif ($resultado -eq 'ReinicioPendiente') {
            # El paso 6 se ejecutó en el propio cliente: hay que reiniciarlo antes de seguir
            Set-PasoCompletado -RutaSalida $RutaSalida -Paso $p.Numero -Nombre $p.Nombre
            $resumen.Add([pscustomobject]@{ Paso = $p.Numero; Nombre = $p.Nombre; Resultado = 'Completado – REINICIAR este equipo y ejecutar de nuevo .\Deploy.ps1' })
            break
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
    if (@(2..7 | Where-Object { -not (Test-PasoCompletado -RutaSalida $RutaSalida -Paso $_) }).Count -eq 0) {
        Remove-CredencialDespliegue -RutaSalida $RutaSalida
    }
    Stop-Registro
}
exit $codigoSalida
