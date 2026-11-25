#Requires -Version 3.0
<#
.SYNOPSIS
    Paso 1 – Diseño: valida la configuración y genera el diseño derivado.

.DESCRIPTION
    No modifica ningún servidor. Lee config\, valida, calcula los valores derivados
    y escribe output\diseno.json (insumo de los pasos 2 a 7), las tablas CSV,
    los diagramas Mermaid y output\diseno\diseno.html.

.EXAMPLE
    .\modules\01-Diseno\Invoke-Diseno.ps1 -RutaConfig .\config -RutaSalida .\output
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$RutaConfig,
    [Parameter(Mandatory)][string]$RutaSalida
)

Import-Module (Join-Path $PSScriptRoot '../00-Comun/Comun.psm1') -DisableNameChecking   # sin -Force: conserva el archivo de log abierto por Deploy.ps1
Import-Module (Join-Path $PSScriptRoot 'Diseno.psm1') -Force -DisableNameChecking

if (-not (Test-Path $RutaSalida)) { New-Item -Path $RutaSalida -ItemType Directory -Force | Out-Null }

Write-Log 'Leyendo la configuración...'
$config = Import-ConfigLab -RutaConfig $RutaConfig

Write-Log 'Validando la configuración...'
$resultado = Test-ConfigLab -Config $config
foreach ($a in $resultado.Advertencias) { Write-Log $a -Nivel Advertencia }
if ($resultado.Errores.Count -gt 0) {
    foreach ($e in $resultado.Errores) { Write-Log $e -Nivel Error }
    throw "La configuración tiene $($resultado.Errores.Count) error(es). Corríjalos en la carpeta config y vuelva a ejecutar."
}
Write-Log 'Configuración válida.' -Nivel Ok

Write-Log 'Calculando el diseño derivado...'
$diseno = Get-DisenoDerivado -Config $config
$carpeta = Export-Diseno -Diseno $diseno -RutaSalida $RutaSalida

Write-Log ("Dominios: {0} (NetBIOS {1}) / {2} (NetBIOS {3})" -f $diseno.Dominios.Raiz.FQDN, $diseno.Dominios.Raiz.NetBIOS, $diseno.Dominios.Hijo.FQDN, $diseno.Dominios.Hijo.NetBIOS)
foreach ($s in @($diseno.Servidores) + @($diseno.Cliente | Where-Object { $_ })) { Write-Log ("Equipo {0,-10} {1,-15} -> {2,-15} {3}" -f $s.Nombre, $s.IPActual, $s.IPFinal, $s.Dominio) }
Write-Log ("{0} OU · {1} cuentas (padre) · {2} grupos globales (padre) · {3} grupos de dominio local (hijo) · {4} recursos compartidos (hijo) · {5} escenas de demostración" -f `
        $diseno.OUs.Count, $diseno.Usuarios.Count, $diseno.GruposGlobales.Count, $diseno.GruposDL.Count, $diseno.Recursos.Count, @($diseno.Demo.Escenas).Count)
Write-Log "Diseño exportado en $carpeta (diseno.html: diagramas y tablas · guion-demostracion.html: guion de la demo)." -Nivel Ok

return $diseno
