#Requires -Version 5.1
<#
.SYNOPSIS
    Pruebas sin laboratorio: verifican la lógica del proyecto en cualquier equipo con PowerShell
    (Windows PowerShell 5.1 o PowerShell 7, también en Linux/macOS).

.DESCRIPTION
    1. Diseño: cálculos de red, nombres de cuenta, validación de configuraciones incorrectas
       y diseño derivado de la configuración de ejemplo.
    2. Validación: un estado "perfecto" construido a partir del diseño debe dar 0 fallas, y cada
       defecto inyectado (cuenta faltante, miembro de más, "Todos" en el recurso, NTFS heredado...)
       debe detectarse.
    3. Bloques remotos de los pasos 4 y 5 ejecutados contra un Active Directory simulado en memoria:
       alta inicial, idempotencia (segunda ejecución sin cambios) y reconciliación de cambios.

.EXAMPLE
    pwsh -File .\tests\Test-Offline.ps1
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$raiz = Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $raiz 'modules/00-Comun/Comun.psm1') -Force -DisableNameChecking
Import-Module (Join-Path $raiz 'modules/01-Diseno/Diseno.psm1') -Force -DisableNameChecking
Import-Module (Join-Path $raiz 'modules/06-Validacion/Validacion.psm1') -Force -DisableNameChecking

$script:Total = 0; $script:Fallidas = 0
function Assert {
    param([bool]$Condicion, [string]$Descripcion)
    $script:Total++
    if ($Condicion) { Write-Host "  [ OK ] $Descripcion" -ForegroundColor Green }
    else { $script:Fallidas++; Write-Host "  [FALLA] $Descripcion" -ForegroundColor Red }
}
function Seccion([string]$t) { Write-Host "`n== $t ==" -ForegroundColor Cyan }

# =====================================================================
Seccion '1. Diseño'
# =====================================================================
$red = Get-InfoRed -Cidr '192.168.10.0/24'
Assert ($red.Mascara -eq '255.255.255.0' -and $red.ZonaInversa -eq '10.168.192.in-addr.arpa') 'Get-InfoRed /24: máscara y zona inversa'
$red16 = Get-InfoRed -Cidr '172.16.5.9/16'
Assert ($red16.Cidr -eq '172.16.0.0/16' -and $red16.ZonaInversa -eq '16.172.in-addr.arpa') 'Get-InfoRed /16: normaliza la red y calcula la zona'
Assert ((Get-NombrePTR -IP '172.16.5.9' -ZonaInversa '16.172.in-addr.arpa') -eq '9.5') 'Get-NombrePTR en una zona /16'
$set = New-Object 'System.Collections.Generic.HashSet[string]'
$s1 = Get-NombreSam -Nombre 'Juan' -Apellido 'Pérez' -Existentes $set
$s2 = Get-NombreSam -Nombre 'Julieta' -Apellido 'Pérez' -Existentes $set
Assert ($s1 -eq 'jperez' -and $s2 -eq 'jperez2') 'Get-NombreSam quita acentos y desambigua (jperez, jperez2)'
$pw = New-ContrasenaAleatoria
Assert ($pw.Length -eq 14 -and $pw -cmatch '[A-Z]' -and $pw -cmatch '[a-z]' -and $pw -match '\d' -and $pw -match '[^A-Za-z0-9]') 'New-ContrasenaAleatoria cumple la complejidad'

$config = Import-ConfigLab -RutaConfig (Join-Path $raiz 'config')
$val = Test-ConfigLab -Config $config
Assert ($val.Errores.Count -eq 0) "La configuración de ejemplo es válida ($($val.Advertencias.Count) advertencias)"

$malo = @{ Lab = $config.Lab.Clone(); Usuarios = @($config.Usuarios); Accesos = @($config.Accesos) }
$malo.Lab.Gateway = '10.0.0.1'
$malo.Lab.DominioHijo = 'ventas.norte'
$malo.Accesos = @($config.Accesos) + [pscustomobject]@{ Recurso = 'Ventas 2024'; Dominio = 'Hijo'; Area = 'Inexistente'; Nivel = 'Total' }
$val = Test-ConfigLab -Config $malo
Assert ($val.Errores.Count -ge 5) "Una configuración con 5 errores se rechaza ($($val.Errores.Count) errores detectados)"

$diseno = Get-DisenoDerivado -Config $config
Assert (@($diseno.Usuarios).Count -eq @($config.Usuarios).Count) "Diseño: $(@($diseno.Usuarios).Count) cuentas"
Assert (@($diseno.GruposGlobales).Count -eq 11 -and @($diseno.GruposDL).Count -eq 20 -and @($diseno.Recursos).Count -eq 10) 'Diseño: 11 grupos globales, 20 de dominio local, 10 recursos'
$jp = @($diseno.Usuarios | Where-Object { $_.Sam -like 'jperez*' })
Assert ($jp.Count -eq 2 -and $jp[0].UPN -eq 'jperez@ventas.andina.local') 'Diseño: UPN en el dominio hijo'
$cruzados = @($diseno.GruposDL | ForEach-Object { $_.Miembros } | Where-Object { $_.DominioFQDN -eq 'ventas.andina.local' }).Count
Assert ($cruzados -gt 0) "Diseño: $cruzados anidamientos de grupos globales del hijo en DL del raíz"

# El diseño usado por los pasos 2 a 6 se lee de JSON: se prueba con la misma forma
$diseno = ($diseno | ConvertTo-Json -Depth 10 | ConvertFrom-Json)

# =====================================================================
Seccion '2. Validación con un estado simulado'
# =====================================================================
$r = $diseno.Dominios.Raiz; $h = $diseno.Dominios.Hijo
$srvRaiz = Get-ServidorDiseno -Diseno $diseno -Rol DCRaiz
$srvHijo = Get-ServidorDiseno -Diseno $diseno -Rol DCHijo

function New-EstadoAD([string]$Clave) {
    $d = $diseno.Dominios.$Clave
    $grupos = @()
    foreach ($g in @($diseno.GruposGlobales | Where-Object { $_.Dominio -eq $Clave })) {
        $miembros = @($g.Miembros | ForEach-Object { $s = $_; $u = @($diseno.Usuarios | Where-Object { $_.Dominio -eq $Clave -and $_.Sam -eq $s })[0]; "CN=$($u.CN),$($u.OU)" })
        $grupos += [pscustomobject]@{ Nombre = $g.Nombre; Ambito = 'Global'; Categoria = 'Security'; DN = "CN=$($g.Nombre),$($g.OU)"; Miembros = $miembros }
    }
    if ($Clave -eq 'Raiz') {
        foreach ($g in @($diseno.GruposDL)) {
            $miembros = @($g.Miembros | ForEach-Object { $n = $_.Grupo; $gg = @($diseno.GruposGlobales | Where-Object { $_.Nombre -eq $n })[0]; "CN=$($gg.Nombre),$($gg.OU)" })
            $grupos += [pscustomobject]@{ Nombre = $g.Nombre; Ambito = 'DomainLocal'; Categoria = 'Security'; DN = "CN=$($g.Nombre),$($g.OU)"; Miembros = $miembros }
        }
    }
    $consultas = @(
        [pscustomobject]@{ Servidor = 'DC'; Tipo = 'SRV'; Consulta = "_ldap._tcp.dc._msdcs.$($d.FQDN)"; Esperado = ''; Obtenido = 'dc:389'; OK = $true; Critica = $true }
    )
    [pscustomobject]@{
        Dominio = [pscustomobject]@{ DNSRoot = $d.FQDN; NetBIOSName = $d.NetBIOS; ParentDomain = $(if ($Clave -eq 'Hijo') { $r.FQDN } else { '' }); DomainMode = 'Windows2016Domain'; PDCEmulator = 'x'; RIDMaster = 'x'; InfrastructureMaster = 'x' }
        Bosque  = [pscustomobject]@{ RootDomain = $r.FQDN; Domains = @($r.FQDN, $h.FQDN); GlobalCatalogs = @($srvRaiz.FQDN.ToUpper()); ForestMode = 'Windows2016Forest'; SchemaMaster = 'x'; DomainNamingMaster = 'x' }
        DC      = [pscustomobject]@{ HostName = "DC-$Clave" }
        Confianzas = @([pscustomobject]@{ Target = $(if ($Clave -eq 'Raiz') { $h.FQDN } else { $r.FQDN }); Direction = 'BiDirectional'; IntraForest = $true })
        OUs     = @($diseno.OUs | Where-Object { $_.Dominio -eq $Clave } | ForEach-Object { [pscustomobject]@{ DN = $_.DN; Protegida = $true } })
        Usuarios = @($diseno.Usuarios | Where-Object { $_.Dominio -eq $Clave } | ForEach-Object { [pscustomobject]@{ Sam = $_.Sam; UPN = $_.UPN; Habilitado = $true; DN = "CN=$($_.CN),$($_.OU)" } })
        Grupos  = $grupos
        Dns     = [pscustomobject]@{
            Zonas = @(
                [pscustomobject]@{ Nombre = $d.FQDN; IntegradaAD = $true; Replicacion = 'Domain'; Inversa = $false }
                [pscustomobject]@{ Nombre = "_msdcs.$($r.FQDN)"; IntegradaAD = $true; Replicacion = 'Forest'; Inversa = $false }
                [pscustomobject]@{ Nombre = $diseno.Red.ZonaInversa; IntegradaAD = $true; Replicacion = 'Forest'; Inversa = $true }
            )
            Reenviadores = $(if ($Clave -eq 'Raiz') { @($diseno.Red.Reenviadores) } else { @($srvRaiz.IPFinal) })
            Scavenging = $true
            Delegaciones = $(if ($Clave -eq 'Raiz') { @([pscustomobject]@{ Hijo = $h.FQDN; NS = @($srvHijo.FQDN) }) } else { @() })
        }
        Consultas = $consultas
    }
}

function New-EstadoArchivos {
    $sids = @{ 'BUILTIN\Administrators' = 'S-1-5-32-544'; 'NT AUTHORITY\SYSTEM' = 'S-1-5-18' }
    $n = 1000
    foreach ($g in $diseno.GruposDL) { $n++; $sids["$($r.NetBIOS)\$($g.Nombre)"] = "S-1-5-21-1-2-3-$n" }
    $ntfsVal = @{ FullControl = 2032127; Modify = 1245631; ReadAndExecute = 1179817 }
    [pscustomobject]@{
        Equipo = 'SRV-ARCHIVOS'; ParteDominio = $true; Dominio = $r.FQDN
        Recursos = @($diseno.Recursos | ForEach-Object {
                $rec = $_
                [pscustomobject]@{
                    Nombre = $rec.Nombre; CarpetaExiste = $true; Compartido = $true; Ruta = $rec.RutaLocal; ABE = 'AccessBased'
                    AccesoCompartido = @($rec.PermisosCompartido | ForEach-Object { [pscustomobject]@{ Sid = $sids[$_.Cuenta]; Cuenta = $_.Cuenta; Derecho = $_.Permiso; Tipo = 'Allow' } })
                    NTFSProtegido = $true
                    NTFS = @($rec.PermisosNTFS | ForEach-Object { [pscustomobject]@{ Sid = $sids[$_.Cuenta]; Cuenta = $_.Cuenta; Derechos = $ntfsVal[$_.Permiso]; Heredada = $false; Tipo = 'Allow'; Herencia = 'ContainerInherit, ObjectInherit' } })
                    SidDiseno = @(@($rec.PermisosCompartido) + @($rec.PermisosNTFS) | ForEach-Object { $_.Cuenta } | Select-Object -Unique | ForEach-Object { [pscustomobject]@{ Cuenta = $_; Sid = $sids[$_] } })
                }
            })
    }
}

function Invoke-Todas($er, $eh, $ea) {
    @(Test-Bosque -Diseno $diseno -EstadoRaiz $er -EstadoHijo $eh) +
    @(Test-Dns -Diseno $diseno -EstadoRaiz $er -EstadoHijo $eh) +
    @(Test-Grupos -Diseno $diseno -EstadoRaiz $er -EstadoHijo $eh) +
    @(Test-Estructura -Diseno $diseno -Clave Raiz -Estado $er) +
    @(Test-Estructura -Diseno $diseno -Clave Hijo -Estado $eh) +
    @(Test-Recursos -Diseno $diseno -EstadoArchivos $ea)
}

$er = New-EstadoAD Raiz; $eh = New-EstadoAD Hijo; $ea = New-EstadoArchivos
$res = Invoke-Todas $er $eh $ea
$fallas = @($res | Where-Object Resultado -ne 'OK')
Assert ($fallas.Count -eq 0) "Estado perfecto: $($res.Count) pruebas, $($fallas.Count) con observaciones"
foreach ($f in $fallas) { Write-Host "         $($f.Resultado) $($f.Prueba) | esp: $($f.Esperado) | obt: $($f.Obtenido)" -ForegroundColor DarkGray }

function Test-Defecto([string]$Descripcion, [scriptblock]$Romper, [string]$Patron) {
    $er = New-EstadoAD Raiz; $eh = New-EstadoAD Hijo; $ea = New-EstadoArchivos
    & $Romper $er $eh $ea
    $f = @(Invoke-Todas $er $eh $ea | Where-Object { $_.Resultado -eq 'FALLA' })
    $match = @($f | Where-Object { $_.Prueba -like $Patron })
    Assert ($match.Count -ge 1) "Detecta: $Descripcion ($($f.Count) falla(s): $(@($f | ForEach-Object Prueba | Select-Object -First 2) -join ' / '))"
}
Test-Defecto 'cuenta del hijo faltante' { param($er, $eh, $ea) $eh.Usuarios = @($eh.Usuarios | Where-Object { $_.Sam -ne 'jperez2' }) } '*jperez2*'
Test-Defecto 'cuenta en otra OU' { param($er, $eh, $ea) ($er.Usuarios | Where-Object Sam -eq 'cnunez').DN = 'CN=Carlos Núñez,CN=Users,DC=andina,DC=local' } '*cnunez*'
Test-Defecto 'miembro de más en un grupo global' { param($er, $eh, $ea) $g = $eh.Grupos | Where-Object Nombre -eq 'GG-VENTAS-Comerciales'; $g.Miembros = @($g.Miembros) + 'CN=Intruso,CN=Users,DC=ventas,DC=andina,DC=local' } 'GG-VENTAS-Comerciales*miembros'
Test-Defecto 'grupo global del hijo ausente de un DL' { param($er, $eh, $ea) $g = $er.Grupos | Where-Object Nombre -eq 'DL-Lista-Precios-Lectura'; $g.Miembros = @($g.Miembros | Where-Object { $_ -notlike '*GG-VENTAS-Comerciales*' }) } 'DL-Lista-Precios-Lectura*miembros'
Test-Defecto 'DL creado con ámbito Global' { param($er, $eh, $ea) ($er.Grupos | Where-Object Nombre -eq 'DL-Stock-Modificar').Ambito = 'Global' } 'DL-Stock-Modificar*ámbito'
Test-Defecto 'confianza unidireccional' { param($er, $eh, $ea) $er.Confianzas[0].Direction = 'Outbound' } 'Confianza*'
Test-Defecto 'delegación DNS faltante' { param($er, $eh, $ea) $er.Dns.Delegaciones = @() } 'Delegación*'
Test-Defecto "'Todos' en un recurso compartido" { param($er, $eh, $ea) $x = $ea.Recursos | Where-Object Nombre -eq 'Legajos'; $x.AccesoCompartido = @($x.AccesoCompartido) + [pscustomobject]@{ Sid = 'S-1-1-0'; Cuenta = 'Everyone'; Derecho = 'Read'; Tipo = 'Allow' } } "*Legajos*Todos*"
Test-Defecto 'herencia NTFS habilitada' { param($er, $eh, $ea) ($ea.Recursos | Where-Object Nombre -eq 'Contratos').NTFSProtegido = $false } '*Contratos*herencia*'
Test-Defecto 'NTFS con Modificar en lugar de Lectura' { param($er, $eh, $ea) $x = $ea.Recursos | Where-Object Nombre -eq 'Manuales'; ($x.NTFS | Where-Object Derechos -eq 1179817).Derechos = 1245631 } '*Manuales*NTFS'
Test-Defecto 'ABE deshabilitado' { param($er, $eh, $ea) ($ea.Recursos | Where-Object Nombre -eq 'Stock').ABE = 'Unrestricted' } '*Stock*enumeración*'

$casos = @(Get-CasosPrueba -Diseno $diseno)
Assert ($casos.Count -eq 13) "Casos de prueba de acceso: $($casos.Count) cuentas (11 grupos + 2 sin grupo)"
$com = $casos | Where-Object Grupo -eq 'GG-VENTAS-Comerciales'
Assert ((@($com.Esperado | Where-Object Recurso -eq 'Lista-Precios')[0].Nivel) -eq 'Lectura') 'Comerciales (hijo) -> Lista-Precios: Lectura'
$sup = $casos | Where-Object Grupo -eq 'GG-VENTAS-Supervisores'
Assert ((@($sup.Esperado | Where-Object Recurso -eq 'Lista-Precios')[0].Nivel) -eq 'Modificar') 'Supervisores (hijo) -> Lista-Precios: Modificar'
$op = { param($l, $le, $e, $b) [pscustomobject]@{ Lista = $l; Lee = $le; Escribe = $e; Borra = $b; Error = '' } }
Assert ((Test-ResultadoAcceso -Caso $com -Recurso 'Lista-Precios' -Operaciones (& $op $true $true $false $null)).Resultado -eq 'OK') 'Acceso: Lectura que no puede escribir -> OK'
Assert ((Test-ResultadoAcceso -Caso $com -Recurso 'Lista-Precios' -Operaciones (& $op $true $true $true $true)).Resultado -eq 'FALLA') 'Acceso: Lectura que PUEDE escribir -> FALLA'
Assert ((Test-ResultadoAcceso -Caso $com -Recurso 'Legajos' -Operaciones (& $op $false $false $false $null)).Resultado -eq 'OK') 'Acceso: sin permiso y sin acceso -> OK'
Assert ((Test-ResultadoAcceso -Caso $sup -Recurso 'Reportes-Ventas' -Operaciones (& $op $true $true $true $false)).Resultado -eq 'FALLA') 'Acceso: Modificar que no puede borrar -> FALLA'

$tmp = Join-Path ([System.IO.Path]::GetTempPath()) "ad-test-$(Get-Random)"
New-Item $tmp -ItemType Directory | Out-Null
$inf = Export-InformeValidacion -Resultados $res -Diseno $diseno -RutaSalida $tmp
Assert ((Test-Path $inf) -and ((Get-Content $inf -Raw) -match 'APROBADA')) 'Informe HTML generado'

# =====================================================================
Seccion '3. Bloques remotos de los pasos 4 y 5 contra un AD simulado'
# =====================================================================
function Get-Bloque([string]$Script, [string]$Variable) {
    $ast = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $raiz $Script), [ref]$null, [ref]$null)
    $asig = $ast.Find({ param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and $n.Left.Extent.Text -eq "`$$Variable" }, $true)
    return [scriptblock]::Create($asig.Right.Extent.Text.Trim().TrimStart('{').TrimEnd('}'))
}

# --- AD simulado: un almacén por dominio ---
$script:AD = @{ 'andina.local' = New-Object System.Collections.ArrayList; 'ventas.andina.local' = New-Object System.Collections.ArrayList }
$script:DominioActual = 'andina.local'
function Get-Almacen([string]$Server) { if ($Server) { return , $script:AD[$Server] } return , $script:AD[$script:DominioActual] }
function Find-Objeto([string]$Id, [string]$Clase, [string]$Server) {
    $id = $Id; if ($Id -isnot [string] -and $Id.DistinguishedName) { $id = $Id.DistinguishedName }
    @((Get-Almacen $Server) | Where-Object { $_.Clase -eq $Clase -and ($_.DistinguishedName -eq $id -or $_.SamAccountName -eq $id) })[0]
}
function Import-Module { param([Parameter(Position = 0)]$Name) }
function Get-ADOrganizationalUnit { param($Identity) $o = Find-Objeto $Identity 'ou'; if (-not $o) { throw "OU no encontrada: $Identity" }; $o }
function New-ADOrganizationalUnit { param($Name, $Path, $Description, $ProtectedFromAccidentalDeletion)
    [void](Get-Almacen).Add([pscustomobject]@{ Clase = 'ou'; Name = $Name; DistinguishedName = "OU=$Name,$Path"; SamAccountName = $null }) }
$atributos = 'GivenName', 'Surname', 'DisplayName', 'UserPrincipalName', 'Title', 'Department', 'Company', 'OfficePhone', 'Office', 'Description'
function Get-ADUser { param($Identity, $Properties, $SearchBase, $SearchScope, $Filter)
    if ($SearchBase) { return @((Get-Almacen) | Where-Object { $_.Clase -eq 'user' -and $_.DistinguishedName.EndsWith(",$SearchBase") }) }
    $o = Find-Objeto ([string]$Identity) 'user'; if (-not $o) { throw "Usuario no encontrado: $Identity" }; $o }
function New-ADUser { param($Name, $SamAccountName, $Path, $AccountPassword, $ChangePasswordAtLogon, $Enabled, $GivenName, $Surname, $DisplayName, $UserPrincipalName, $Title, $Department, $Company, $OfficePhone, $Office, $Description)
    $o = [pscustomobject]@{ Clase = 'user'; Name = $Name; SamAccountName = $SamAccountName; DistinguishedName = "CN=$Name,$Path"; Enabled = $Enabled }
    foreach ($a in $atributos) { $o | Add-Member -NotePropertyName $a -NotePropertyValue (Get-Variable $a -ValueOnly) }
    [void](Get-Almacen).Add($o) }
function Set-ADUser { param($Identity, $GivenName, $Surname, $DisplayName, $UserPrincipalName, $Title, $Department, $Company, $OfficePhone, $Office, $Description)
    $o = Find-Objeto $Identity.DistinguishedName 'user'
    foreach ($k in $PSBoundParameters.Keys) { if ($k -ne 'Identity') { $o.$k = $PSBoundParameters[$k] } } }
function Move-ADObject { param($Identity, $TargetPath) $o = @((Get-Almacen) | Where-Object DistinguishedName -eq $Identity)[0]; $o.DistinguishedName = "CN=$($o.Name),$TargetPath" }
function Rename-ADObject { param($Identity, $NewName) $o = @((Get-Almacen) | Where-Object DistinguishedName -eq $Identity)[0]; $o.DistinguishedName = $o.DistinguishedName -replace '^CN=[^,]+', "CN=$NewName"; $o.Name = $NewName }
function Get-ADGroup { param($Identity, $Server, $Credential, $Properties)
    $o = Find-Objeto ([string]$Identity) 'group' $Server; if (-not $o) { throw "Grupo no encontrado: $Identity" }
    $o | Add-Member -NotePropertyName member -NotePropertyValue @($o.Miembros) -Force; $o }
function New-ADGroup { param($Name, $SamAccountName, $GroupScope, $GroupCategory, $Path, $Description)
    [void](Get-Almacen).Add([pscustomobject]@{ Clase = 'group'; Name = $Name; SamAccountName = $SamAccountName; DistinguishedName = "CN=$Name,$Path"; GroupScope = $GroupScope; Miembros = (New-Object System.Collections.ArrayList) }) }
function Get-ADGroupMember { param($Identity) $g = Find-Objeto $Identity.DistinguishedName 'group'; @($g.Miembros | ForEach-Object { $dn = $_; @((Get-Almacen) | Where-Object DistinguishedName -eq $dn)[0] }) }
function Add-ADGroupMember { param($Identity, $Members) $g = Find-Objeto $Identity.DistinguishedName 'group'; foreach ($m in $Members) { [void]$g.Miembros.Add((Find-Objeto $m 'user').DistinguishedName) } }
function Remove-ADGroupMember { param($Identity, $Members, $Confirm) $g = Find-Objeto $Identity.DistinguishedName 'group'; foreach ($m in $Members) { $g.Miembros.Remove((Find-Objeto $m 'user').DistinguishedName) } }
function Set-ADGroup { param($Identity, $Add, $Remove) $g = Find-Objeto $Identity 'group'
    if ($Add) { foreach ($dn in @($Add.member)) { [void]$g.Miembros.Add($dn) } }
    if ($Remove) { foreach ($dn in @($Remove.member)) { $x = @($g.Miembros | Where-Object { $_ -eq $dn })[0]; $g.Miembros.Remove($x) } } }

# --- Paso 4 ---
$bloque4 = Get-Bloque 'modules/04-Estructura/Invoke-Estructura.ps1' 'bloqueEstructura'
function Get-EntradaPaso4([string]$Clave) {
    $ous = @($diseno.OUs | Where-Object { $_.Dominio -eq $Clave } | ForEach-Object { [pscustomobject]@{ Nombre = $_.Nombre; DN = $_.DN; Padre = $_.Padre } })
    $usu = @($diseno.Usuarios | Where-Object { $_.Dominio -eq $Clave } | ForEach-Object {
            [pscustomobject]@{ Sam = $_.Sam; CN = $_.CN; Nombre = $_.Nombre; Apellido = $_.Apellido; NombreCompleto = $_.NombreCompleto; UPN = $_.UPN; OU = $_.OU; Area = $_.Area
                Cargo = $_.Cargo; Telefono = $_.Telefono; Oficina = $_.Oficina; Empresa = $_.Empresa; Descripcion = $_.Descripcion; Password = 'x' } })
    , @($ous, $usu)
}
foreach ($par in @(@('Raiz', 'andina.local'), @('Hijo', 'ventas.andina.local'))) {
    $script:DominioActual = $par[1]
    $ent = Get-EntradaPaso4 $par[0]
    $r1 = @(& $bloque4 $ent[0] $ent[1])
    $creados = @($r1 | Where-Object Accion -eq 'Creado').Count
    Assert ($creados -eq $ent[1].Count -and @($r1 | Where-Object Accion -eq 'Creada').Count -eq $ent[0].Count) "Paso 4 ($($par[1])): primera ejecución crea $($ent[0].Count) OU y $creados cuentas"
    $r2 = @(& $bloque4 $ent[0] $ent[1])
    Assert (@($r2 | Where-Object { $_.Accion -notin 'Existente', 'Sin cambios' }).Count -eq 0) "Paso 4 ($($par[1])): segunda ejecución sin cambios (idempotente)"
}
$script:DominioActual = 'ventas.andina.local'
$ent = Get-EntradaPaso4 'Hijo'
$u = $ent[1] | Where-Object Sam -eq 'mfernandez'
$u.Cargo = 'Supervisora Sucursal Tucumán'; $u.Area = 'Supervisores'; $u.OU = 'OU=Supervisores,DC=ventas,DC=andina,DC=local'
$r3 = @(& $bloque4 $ent[0] $ent[1])
$act = @($r3 | Where-Object { $_.Objeto -eq 'mfernandez' })[0]
Assert ($act.Accion -eq 'Actualizado' -and $act.Detalle -match 'Title' -and $act.Detalle -match 'movido') "Paso 4: un cambio de área actualiza atributos y mueve la cuenta ($($act.Detalle))"
[void]$script:AD['ventas.andina.local'].Add([pscustomobject]@{ Clase = 'user'; Name = 'Viejo Usuario'; SamAccountName = 'vusuario'; DistinguishedName = 'CN=Viejo Usuario,OU=Comerciales,DC=ventas,DC=andina,DC=local' })
$r4 = @(& $bloque4 $ent[0] $ent[1])
Assert (@($r4 | Where-Object { $_.Accion -eq 'NoEnDiseno' -and $_.Objeto -eq 'vusuario' }).Count -eq 1) 'Paso 4: informa (sin borrar) una cuenta que no está en usuarios.csv'

# Se restablece el área original para el paso 5
$u.Cargo = 'Vendedora'; $u.Area = 'Comerciales'; $u.OU = 'OU=Comerciales,DC=ventas,DC=andina,DC=local'
$null = & $bloque4 $ent[0] $ent[1]
$script:AD['ventas.andina.local'].Remove(@($script:AD['ventas.andina.local'] | Where-Object SamAccountName -eq 'vusuario')[0])

# --- Paso 5: grupos globales y de dominio local ---
$bloqueGG = Get-Bloque 'modules/05-AccesoEntreDominios/Invoke-Acceso.ps1' 'bloqueGruposGlobales'
$bloqueDL = Get-Bloque 'modules/05-AccesoEntreDominios/Invoke-Acceso.ps1' 'bloqueGruposDL'
$ggs = @{}
foreach ($k in 'Raiz', 'Hijo') { $ggs[$k] = @($diseno.GruposGlobales | Where-Object Dominio -eq $k | ForEach-Object { [pscustomobject]@{ Nombre = $_.Nombre; OU = $_.OU; Descripcion = $_.Descripcion; Miembros = @($_.Miembros) } }) }
$dls = @($diseno.GruposDL | ForEach-Object { [pscustomobject]@{ Nombre = $_.Nombre; OU = $_.OU; Descripcion = $_.Descripcion; Miembros = @($_.Miembros | ForEach-Object { [pscustomobject]@{ Grupo = $_.Grupo; DominioFQDN = $_.DominioFQDN } }) } })

$script:DominioActual = 'andina.local';        $g1 = @(& $bloqueGG $ggs.Raiz)
$script:DominioActual = 'ventas.andina.local'; $g2 = @(& $bloqueGG $ggs.Hijo)
Assert (@($g1 + $g2 | Where-Object Accion -eq 'Creado').Count -eq 11) 'Paso 5: crea 11 grupos globales'
$com = Find-Objeto 'GG-VENTAS-Comerciales' 'group'
Assert (@($com.Miembros).Count -eq 12) "Paso 5: GG-VENTAS-Comerciales con 12 miembros ($(@($com.Miembros).Count))"

$script:DominioActual = 'andina.local'
$d1 = @(& $bloqueDL $dls 'andina.local' $null)
Assert (@($d1 | Where-Object Accion -eq 'Creado').Count -eq 20) 'Paso 5: crea 20 grupos de dominio local en el raíz'
$dlp = Find-Objeto 'DL-Lista-Precios-Lectura' 'group'
Assert (@($dlp.Miembros | Where-Object { $_ -like 'CN=GG-VENTAS-Comerciales,*DC=ventas*' }).Count -eq 1) 'Paso 5: el DL del raíz contiene el grupo global del hijo (anidamiento entre dominios)'
$d2 = @(& $bloqueDL $dls 'andina.local' $null)
Assert (@($d2 | Where-Object { $_.Agregados -or $_.Quitados -or $_.Accion -ne 'Existente' }).Count -eq 0) 'Paso 5: segunda ejecución sin cambios (idempotente)'
[void]$dlp.Miembros.Add('CN=GG-ANDINA-Legales,OU=Grupos,DC=andina,DC=local')
$d3 = @(& $bloqueDL $dls 'andina.local' $null)
Assert (@($d3 | Where-Object { $_.Objeto -eq 'DL-Lista-Precios-Lectura' -and $_.Quitados -match 'gg-andina-legales' }).Count -eq 1) 'Paso 5: quita un miembro agregado a mano que no está en accesos.csv'

# --- Validación sobre el AD simulado (cierra el circuito: lo que crean los pasos 4 y 5 valida OK) ---
function Get-EstadoDesdeSimulado([string]$Dominio, [string]$Clave) {
    $base = New-EstadoAD $Clave
    $alm = $script:AD[$Dominio]
    $base.Usuarios = @($alm | Where-Object Clase -eq 'user' | ForEach-Object { [pscustomobject]@{ Sam = $_.SamAccountName; UPN = $_.UserPrincipalName; Habilitado = [bool]$_.Enabled; DN = $_.DistinguishedName } })
    $base.Grupos = @($alm | Where-Object Clase -eq 'group' | ForEach-Object { [pscustomobject]@{ Nombre = $_.Name; Ambito = $_.GroupScope; Categoria = 'Security'; DN = $_.DistinguishedName; Miembros = @($_.Miembros) } })
    $base
}
$esR = Get-EstadoDesdeSimulado 'andina.local' 'Raiz'; $esH = Get-EstadoDesdeSimulado 'ventas.andina.local' 'Hijo'
$v = @(Test-Grupos -Diseno $diseno -EstadoRaiz $esR -EstadoHijo $esH) + @(Test-Estructura -Diseno $diseno -Clave Raiz -Estado $esR) + @(Test-Estructura -Diseno $diseno -Clave Hijo -Estado $esH)
$vf = @($v | Where-Object Resultado -eq 'FALLA')
Assert ($vf.Count -eq 0) "La validación del AD que dejaron los pasos 4 y 5 da $($v.Count) pruebas y $($vf.Count) fallas"
foreach ($f in $vf | Select-Object -First 5) { Write-Host "         $($f.Prueba) | $($f.Obtenido)" -ForegroundColor DarkGray }

Remove-Item $tmp -Recurse -Force
Write-Host "`nResultado: $($script:Total - $script:Fallidas)/$($script:Total) pruebas correctas." -ForegroundColor $(if ($script:Fallidas) { 'Red' } else { 'Green' })
if ($script:Fallidas) { exit 1 }
