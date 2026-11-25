#Requires -Version 3.0   # corre también en Windows 8 (PowerShell 3.0)
<#
.SYNOPSIS
    Demostración en el cliente: muestra con qué cuenta y grupos inició sesión el usuario y qué puede
    hacer realmente en cada recurso compartido del dominio de recursos.

.DESCRIPTION
    Lo ejecuta el USUARIO que inició sesión en el cliente (acceso directo "Probar mis permisos" del
    escritorio). No necesita permisos de administrador. Para cada recurso intenta:
        listar la carpeta · leer LEEME.txt · crear un archivo · borrarlo
    y compara el resultado con el nivel que le corresponde según su área (permisos-demo.json,
    generado por el despliegue a partir de accesos.csv).

.PARAMETER Recurso
    Prueba solo los recursos indicados.

.PARAMETER DejarArchivo
    No borra el archivo de prueba (para mostrarlo luego en el Explorador).

.EXAMPLE
    C:\Demo\Probar-Permisos.ps1
.EXAMPLE
    C:\Demo\Probar-Permisos.ps1 -Recurso Lista-Precios -DejarArchivo
#>
[CmdletBinding()]
param(
    [string[]]$Recurso,
    [switch]$DejarArchivo,
    [string]$Configuracion = (Join-Path $PSScriptRoot 'permisos-demo.json')
)

$ErrorActionPreference = 'Stop'
$cfg = Get-Content -Path $Configuracion -Raw -Encoding UTF8 | ConvertFrom-Json
$rango = @{ SinAcceso = 0; Lectura = 1; Modificar = 2 }

function Write-Linea([string]$Texto = '', [string]$Color = 'Gray') { Write-Host $Texto -ForegroundColor $Color }
function Write-Celda([string]$Texto, [int]$Ancho, [string]$Color = 'Gray') { Write-Host ($Texto.PadRight($Ancho).Substring(0, $Ancho)) -ForegroundColor $Color -NoNewline }

# --- Quién soy ---
$cuenta = (& whoami.exe).Trim()
$upn = ''
try { $upn = (& whoami.exe /upn 2>$null).Trim() } catch { }
# Primera columna de whoami /groups = nombre del grupo (el encabezado cambia según el idioma de Windows)
$grupos = @(& whoami.exe /groups /fo csv | ConvertFrom-Csv | ForEach-Object { ($_.PSObject.Properties | Select-Object -First 1).Value })
$globales = @($grupos | Where-Object { $_ -like "$($cfg.NetBIOSCuentas)\GG-*" } | ForEach-Object { ($_ -split '\\')[1] })

Write-Linea ''
Write-Linea ('=' * 96) 'DarkCyan'
Write-Linea "  $($cfg.Empresa) – Prueba de permisos entre dominios" 'Cyan'
Write-Linea ('=' * 96) 'DarkCyan'
Write-Linea "  Cuenta:          $cuenta   $upn"
Write-Linea "  Equipo:          $env:COMPUTERNAME ($env:USERDNSDOMAIN)"
Write-Linea "  Cuentas en:      $($cfg.DominioCuentas)  ·  recursos en: $($cfg.DominioRecursos) (\\$($cfg.Servidor))"
if ($globales.Count) { Write-Linea "  Grupos globales: $($globales -join ', ')" 'White' }
else { Write-Linea "  Grupos globales: ninguno GG-* (esta cuenta no pertenece a ningún área con permisos)" 'Yellow' }
Write-Linea ''

# --- Nivel esperado por recurso: el mayor entre los grupos globales de la cuenta ---
$recursos = @($cfg.Recursos)
if ($Recurso) { $recursos = @($recursos | Where-Object { $_.Nombre -in $Recurso }) }
$esperado = @{}
$via = @{}
foreach ($r in $recursos) {
    $esperado[$r.Nombre] = 'SinAcceso'; $via[$r.Nombre] = ''
    foreach ($g in @($cfg.Grupos | Where-Object { $_.Grupo -in $globales })) {
        $n = (@($g.Niveles | Where-Object { $_.Recurso -eq $r.Nombre })[0]).Nivel
        if ($n -and $rango[$n] -gt $rango[$esperado[$r.Nombre]]) { $esperado[$r.Nombre] = $n; $via[$r.Nombre] = "$($cfg.NetBIOSCuentas)\$($g.Grupo) -> $($cfg.NetBIOSRecursos)\DL-$($r.Nombre)-$n" }
    }
}

# --- Pruebas reales ---
$sello = Get-Date -Format 'yyyyMMdd-HHmmss'
$usuario = ($cuenta -split '\\')[-1]
$filas = foreach ($r in $recursos) {
    $op = [ordered]@{ Listar = $false; Leer = $false; Escribir = $false; Borrar = $null; Error = '' }
    try { $null = Get-ChildItem -LiteralPath $r.UNC -ErrorAction Stop; $op.Listar = $true } catch { $op.Error = $_.Exception.Message }
    try { $null = Get-Content -LiteralPath (Join-Path $r.UNC 'LEEME.txt') -TotalCount 1 -ErrorAction Stop; $op.Leer = $true } catch { }
    $archivo = Join-Path $r.UNC "prueba-$usuario-$sello.txt"
    try { Set-Content -LiteralPath $archivo -Value "Archivo creado por $cuenta desde $env:COMPUTERNAME el $(Get-Date)" -ErrorAction Stop; $op.Escribir = $true } catch { }
    if ($op.Escribir -and -not $DejarArchivo) { try { Remove-Item -LiteralPath $archivo -Force -ErrorAction Stop; $op.Borrar = $true } catch { $op.Borrar = $false } }
    $n = $esperado[$r.Nombre]
    $ok = ($op.Listar -eq ($rango[$n] -ge 1)) -and ($op.Leer -eq ($rango[$n] -ge 1)) -and ($op.Escribir -eq ($rango[$n] -ge 2))
    if ($rango[$n] -ge 2 -and -not $DejarArchivo) { $ok = $ok -and [bool]$op.Borrar }
    [pscustomobject]@{ Recurso = $r.Nombre; UNC = $r.UNC; Esperado = $n; Via = $via[$r.Nombre]; Op = $op; Coincide = $ok }
}

# --- Tabla ---
$anchos = @(20, 12, 8, 7, 10, 8, 12)
$titulos = @('Recurso', 'Nivel', 'Listar', 'Leer', 'Escribir', 'Borrar', 'Resultado')
for ($i = 0; $i -lt $titulos.Count; $i++) { Write-Celda $titulos[$i] $anchos[$i] 'White' }
Write-Host ''
Write-Linea ('-' * 96) 'DarkGray'
$si = { param($b) if ($null -eq $b) { '-' } elseif ($b) { 'SI' } else { 'NO' } }
$colorSi = { param($b) if ($null -eq $b) { 'DarkGray' } elseif ($b) { 'Green' } else { 'Red' } }
foreach ($f in $filas) {
    $colorNivel = switch ($f.Esperado) { 'Modificar' { 'Green' } 'Lectura' { 'Yellow' } default { 'DarkGray' } }
    $textoNivel = $f.Esperado; if ($textoNivel -eq 'SinAcceso') { $textoNivel = 'Sin acceso' }
    Write-Celda $f.Recurso $anchos[0] 'White'
    Write-Celda $textoNivel $anchos[1] $colorNivel
    Write-Celda (& $si $f.Op.Listar) $anchos[2] (& $colorSi $f.Op.Listar)
    Write-Celda (& $si $f.Op.Leer) $anchos[3] (& $colorSi $f.Op.Leer)
    Write-Celda (& $si $f.Op.Escribir) $anchos[4] (& $colorSi $f.Op.Escribir)
    Write-Celda (& $si $f.Op.Borrar) $anchos[5] (& $colorSi $f.Op.Borrar)
    if ($f.Coincide) { Write-Celda 'esperado' $anchos[6] 'Green' } else { Write-Celda 'DISTINTO' $anchos[6] 'Red' }
    Write-Host ''
}
Write-Linea ('-' * 96) 'DarkGray'

# --- Explicación ---
Write-Linea ''
Write-Linea '  Por qué (AGUDLP: cuenta -> grupo global del padre -> grupo de dominio local del hijo -> permisos):' 'Cyan'
foreach ($f in $filas | Where-Object { $_.Via }) { Write-Linea ("    {0,-20} {1} -> {2}" -f $f.Recurso, $cuenta, $f.Via) }
if (-not @($filas | Where-Object { $_.Via }).Count) { Write-Linea '    Ningún grupo global de esta cuenta es miembro de un grupo DL-*: no tiene acceso a ningún recurso.' 'Yellow' }
Write-Linea ''
Write-Linea "  Los grupos DL-* son de dominio local de $($cfg.DominioRecursos): no aparecen en 'whoami /groups'" 'DarkGray'
Write-Linea "  porque se agregan al token recién cuando la cuenta se autentica en \\$($cfg.Servidor)." 'DarkGray'
if ($DejarArchivo) { Write-Linea "  Se dejaron los archivos prueba-$usuario-$sello.txt en los recursos donde se pudo escribir." 'DarkGray' }
$distintos = @($filas | Where-Object { -not $_.Coincide })
Write-Linea ''
if ($distintos.Count) {
    Write-Linea "  $($distintos.Count) recurso(s) con un resultado distinto del esperado. Si se cambió de grupo a la cuenta, cerrar sesión y volver a iniciarla." 'Red'
    foreach ($d in $distintos | Where-Object { $_.Op.Error }) { Write-Linea "    $($d.Recurso): $($d.Op.Error)" 'DarkGray' }
}
else { Write-Linea "  Todos los resultados coinciden con los permisos asignados a las áreas de la cuenta." 'Green' }
Write-Linea ''
