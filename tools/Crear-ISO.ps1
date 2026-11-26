#Requires -Version 3.0
<#
.SYNOPSIS
    Empaqueta el proyecto en una imagen ISO para copiarlo a las VM.

.DESCRIPTION
    Las VM de la red "solo anfitrión" no tienen carpetas compartidas ni Internet, y las Guest Additions
    no siempre se pueden instalar (por ejemplo, en Windows 8.1 de 32 bits). La forma más simple de pasar
    el proyecto es montarlo como CD en cada VM.

    Se ejecuta en el equipo ANFITRIÓN (Windows), no en las VM:
        Set-ExecutionPolicy -Scope Process Bypass -Force
        .\tools\Crear-ISO.ps1                               # crea ..\AD-Arbol-Automatizado.iso
        .\tools\Crear-ISO.ps1 -Destino D:\VMs\proyecto.iso

    La ISO contiene la carpeta AD-Arbol-Automatizado sin .git ni output. En cada VM:
      1. VirtualBox > Dispositivos > Unidades ópticas > elegir la ISO.
      2. Copiar la carpeta AD-Arbol-Automatizado del CD a C:\.
      3. En PowerShell como administrador (los archivos de un CD quedan de solo lectura y bloqueados):
             attrib -r C:\AD-Arbol-Automatizado\* /s /d
             Get-ChildItem C:\AD-Arbol-Automatizado -Recurse | Unblock-File
#>
[CmdletBinding()]
param(
    [string]$Origen,      # por defecto: la carpeta del proyecto
    [string]$Destino,
    [string]$Etiqueta = 'PROYECTO'
)

$ErrorActionPreference = 'Stop'
# En PowerShell 3.0 y 4.0, $PSScriptRoot puede llegar vacío a los valores por defecto de los parámetros
# (por ejemplo, al ejecutar con powershell.exe -File desde un acceso directo): se calcula acá.
$raiz = $PSScriptRoot
if (-not $raiz) { $raiz = Split-Path -Parent $MyInvocation.MyCommand.Path }
if (-not $Origen) { $Origen = Split-Path $raiz -Parent }
$Origen = (Resolve-Path $Origen).ProviderPath
if (-not $Destino) { $Destino = Join-Path (Split-Path $Origen -Parent) 'AD-Arbol-Automatizado.iso' }
$Destino = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Destino)

# Copia temporal sin el historial de git ni los resultados de ejecuciones anteriores
$raizTmp = Join-Path $env:TEMP ('iso-proyecto-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
$carpeta = Join-Path $raizTmp 'AD-Arbol-Automatizado'
& robocopy.exe $Origen $carpeta /E /XD .git output /XF *.iso /NFL /NDL /NJH /NJS /NP | Out-Null
if ($LASTEXITCODE -ge 8) { throw "robocopy no pudo copiar el proyecto (código $LASTEXITCODE)." }

if (-not ('GuardarIso2' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Runtime.InteropServices;
using ComTypes = System.Runtime.InteropServices.ComTypes;
public static class GuardarIso2 {
    public static void Guardar(object flujo, string ruta) {
        ComTypes.IStream s = (ComTypes.IStream)flujo;
        ComTypes.STATSTG st; s.Stat(out st, 1);
        byte[] buf = new byte[65536];
        IntPtr leidos = Marshal.AllocHGlobal(4);
        try {
            using (FileStream fs = File.Create(ruta)) {
                long resta = st.cbSize;
                while (resta > 0) {
                    s.Read(buf, buf.Length, leidos);
                    int n = Marshal.ReadInt32(leidos);
                    if (n <= 0) break;
                    fs.Write(buf, 0, n);
                    resta -= n;
                }
            }
        }
        finally { Marshal.FreeHGlobal(leidos); }
    }
}
'@
}

try {
    $imagen = New-Object -ComObject IMAPI2FS.MsftFileSystemImage
    $imagen.FileSystemsToCreate = 3      # ISO 9660 + Joliet (nombres largos y acentos)
    $imagen.VolumeName = $Etiqueta
    $imagen.Root.AddTree($raizTmp, $false)
    if (Test-Path $Destino) { Remove-Item $Destino -Force }
    [GuardarIso2]::Guardar($imagen.CreateResultImage().ImageStream, $Destino)
    $mb = [math]::Round((Get-Item $Destino).Length / 1MB, 1)
    Write-Host "ISO creada: $Destino ($mb MB)" -ForegroundColor Green
}
finally {
    Remove-Item $raizTmp -Recurse -Force -ErrorAction SilentlyContinue
}
