#Requires -Version 3.0
<#
.SYNOPSIS
    Paso 5 – Acceso de cuentas del dominio padre a recursos del dominio hijo con AGUDLP (objetivo específico 5).

.DESCRIPTION
    Las cuentas están centralizadas en el dominio PADRE y los recursos en el dominio HIJO;
    los permisos se asignan en ese único sentido.

    A -> G   en el PADRE (DC-RAIZ): un grupo global por área (GG-ANDINA-Finanzas, ...) con
             exactamente las cuentas del área.
    G -> DL  en el HIJO (DC-HIJO): un grupo de dominio local por recurso y nivel
             (DL-Lista-Precios-Lectura, DL-Lista-Precios-Modificar, ...). Sus miembros son grupos
             globales del padre: un grupo de dominio local admite grupos globales de cualquier
             dominio del bosque, y la confianza padre-hijo permite resolverlos.
    DL -> P  en DC-HIJO: cada carpeta compartida y su NTFS reciben permisos SOLO para los DL del
             recurso (enfoque 2: Lectura -> Read / ReadAndExecute; Modificar -> Change / Modify),
             más Administradores y SYSTEM. Se quita "Todos" (Everyone), se deshabilita la herencia
             NTFS y se activa la enumeración basada en el acceso (ABE).

    La pertenencia y los permisos se reconcilian: lo que sobra se quita y lo que falta se agrega,
    de modo que el resultado coincide exactamente con accesos.csv.
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

$srvRaiz     = Get-ServidorDiseno -Diseno $Diseno -Rol DCRaiz
$srvHijo     = Get-ServidorDiseno -Diseno $Diseno -Rol DCHijo
$domRaiz     = $Diseno.Dominios.Raiz
$domHijo     = $Diseno.Dominios.Hijo

# Datos simples para los bloques remotos
$ggs = @($Diseno.GruposGlobales | ForEach-Object {
        [pscustomobject]@{ Nombre = $_.Nombre; OU = $_.OU; Descripcion = $_.Descripcion; Miembros = @($_.Miembros) }
    })
$dls = @($Diseno.GruposDL | ForEach-Object {
        [pscustomobject]@{
            Nombre = $_.Nombre; OU = $_.OU; Descripcion = $_.Descripcion
            Miembros = @($_.Miembros | ForEach-Object { [pscustomobject]@{ Grupo = $_.Grupo; DominioFQDN = $_.DominioFQDN } })
        }
    })
$recursos = @($Diseno.Recursos | ForEach-Object {
        [pscustomobject]@{
            Nombre = $_.Nombre; RutaLocal = $_.RutaLocal; ABE = [bool]$_.ABE
            Compartido = @($_.PermisosCompartido | ForEach-Object { [pscustomobject]@{ Cuenta = $_.Cuenta; Permiso = $_.Permiso } })
            NTFS       = @($_.PermisosNTFS | ForEach-Object { [pscustomobject]@{ Cuenta = $_.Cuenta; Permiso = $_.Permiso } })
        }
    })

# =====================================================================
#  Simulación
# =====================================================================
if ($WhatIfPreference) {
    Write-Log "A -> G: grupos globales en $($domRaiz.FQDN) (padre, cuentas)"
    foreach ($g in $ggs) { Write-Plan "$($g.Nombre) (Global) en $($g.OU): $(@($g.Miembros).Count) miembros" }
    Write-Log "G -> DL: grupos de dominio local en $($domHijo.FQDN) (hijo, recursos)"
    foreach ($g in $dls) { Write-Plan "$($g.Nombre) (DomainLocal) <- $(@($g.Miembros | ForEach-Object { "$($domRaiz.NetBIOS)\$($_.Grupo)" }) -join ', ')" }
    Write-Log "DL -> P: recursos en $($srvHijo.Nombre)"
    foreach ($r in $recursos) {
        Write-Plan "\\$($srvHijo.Nombre)\$($r.Nombre) ($($r.RutaLocal)) · ABE · sin 'Todos' · herencia NTFS deshabilitada"
        Write-Plan "    compartido: $(@($r.Compartido | ForEach-Object { "$($_.Cuenta)=$($_.Permiso)" }) -join '; ')"
        Write-Plan "    NTFS:       $(@($r.NTFS | ForEach-Object { "$($_.Cuenta)=$($_.Permiso)" }) -join '; ')"
    }
    return 'Simulado'
}

if (-not $Credencial) { throw 'Se requiere la credencial del despliegue.' }
$cred = Get-CredencialesLab -Credencial $Credencial -Diseno $Diseno

# =====================================================================
#  Bloques remotos
# =====================================================================
$bloqueGruposGlobales = {
    param([object[]]$Grupos)
    $ErrorActionPreference = 'Stop'
    Import-Module ActiveDirectory
    foreach ($g in $Grupos) {
        $accion = 'Existente'
        $grupo = $null
        try { $grupo = Get-ADGroup -Identity $g.Nombre } catch { $grupo = $null }
        if (-not $grupo) {
            New-ADGroup -Name $g.Nombre -SamAccountName $g.Nombre -GroupScope Global -GroupCategory Security -Path $g.OU -Description $g.Descripcion
            $grupo = Get-ADGroup -Identity $g.Nombre
            $accion = 'Creado'
        }
        elseif ([string]$grupo.GroupScope -ne 'Global') { throw "El grupo $($g.Nombre) existe con ámbito $($grupo.GroupScope) (se esperaba Global)." }

        $actuales = @(Get-ADGroupMember -Identity $grupo | ForEach-Object { $_.SamAccountName })
        $deseados = @($g.Miembros)
        $agregar = @($deseados | Where-Object { $_ -notin $actuales })
        $quitar  = @($actuales | Where-Object { $_ -notin $deseados })
        if ($agregar.Count) { Add-ADGroupMember -Identity $grupo -Members $agregar }
        if ($quitar.Count)  { Remove-ADGroupMember -Identity $grupo -Members $quitar -Confirm:$false }
        [pscustomobject]@{ Tipo = 'GrupoGlobal'; Objeto = $g.Nombre; Accion = $accion; Agregados = ($agregar -join ', '); Quitados = ($quitar -join ', '); Miembros = $deseados.Count }
    }
}

$bloqueGruposDL = {
    param([object[]]$Grupos, [string]$DominioLocal, [pscredential]$CredBosque)
    $ErrorActionPreference = 'Stop'
    Import-Module ActiveDirectory
    $cache = @{}
    foreach ($g in $Grupos) {
        $accion = 'Existente'
        $grupo = $null
        try { $grupo = Get-ADGroup -Identity $g.Nombre } catch { $grupo = $null }
        if (-not $grupo) {
            New-ADGroup -Name $g.Nombre -SamAccountName $g.Nombre -GroupScope DomainLocal -GroupCategory Security -Path $g.OU -Description $g.Descripcion
            $accion = 'Creado'
        }
        elseif ([string]$grupo.GroupScope -ne 'DomainLocal') { throw "El grupo $($g.Nombre) existe con ámbito $($grupo.GroupScope) (se esperaba DomainLocal)." }

        # Grupos globales miembros: los del otro dominio (padre) se buscan en SU dominio (credencial explícita: segundo salto)
        $deseados = @{}
        foreach ($m in $g.Miembros) {
            $clave = "$($m.DominioFQDN)|$($m.Grupo)"
            if (-not $cache.ContainsKey($clave)) {
                if ($m.DominioFQDN -eq $DominioLocal) { $cache[$clave] = Get-ADGroup -Identity $m.Grupo }
                else { $cache[$clave] = Get-ADGroup -Identity $m.Grupo -Server $m.DominioFQDN -Credential $CredBosque }
            }
            $deseados[$cache[$clave].DistinguishedName.ToLowerInvariant()] = $cache[$clave]
        }
        $actuales = @((Get-ADGroup -Identity $g.Nombre -Properties member).member | ForEach-Object { $_.ToLowerInvariant() })
        $agregar = @($deseados.Keys | Where-Object { $_ -notin $actuales })
        $quitar  = @($actuales | Where-Object { -not $deseados.ContainsKey($_) })

        foreach ($dn in $agregar) {
            # Un grupo recién creado en el otro dominio puede tardar en llegar al catálogo global: se reintenta
            $ok = $false
            for ($i = 1; $i -le 10 -and -not $ok; $i++) {
                try { Set-ADGroup -Identity $g.Nombre -Add @{ member = $deseados[$dn].DistinguishedName }; $ok = $true }
                catch { if ($i -eq 10) { throw "No se pudo agregar $dn a $($g.Nombre): $($_.Exception.Message)" }; Start-Sleep -Seconds 30 }
            }
        }
        foreach ($dn in $quitar) { Set-ADGroup -Identity $g.Nombre -Remove @{ member = $dn } }
        $nombres = { param($lista) @($lista | ForEach-Object { ($_ -split ',')[0] -replace '^cn=', '' }) -join ', ' }
        [pscustomobject]@{ Tipo = 'GrupoDL'; Objeto = $g.Nombre; Accion = $accion; Agregados = (& $nombres $agregar); Quitados = (& $nombres $quitar); Miembros = $deseados.Count }
    }
}

$bloqueRecursos = {
    param([object[]]$Recursos, [string]$Empresa)
    $ErrorActionPreference = 'Stop'
    # En Windows Server 2012 la política de ejecución puede impedir que se cargue el módulo SmbShare
    # en una sesión remota: se habilita solo para esta sesión y se carga explícitamente.
    try { Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force -ErrorAction Stop } catch { }
    try { Import-Module SmbShare -ErrorAction Stop }
    catch { throw "No se pudo cargar el módulo SmbShare en $env:COMPUTERNAME ($($_.Exception.Message)). Política de ejecución: $(Get-ExecutionPolicy -List | Out-String)" }

    # Cuentas integradas por SID: funciona aunque Windows esté en otro idioma (Administradores, Todos, ...)
    $sidConocidos = @{ 'BUILTIN\Administrators' = 'S-1-5-32-544'; 'NT AUTHORITY\SYSTEM' = 'S-1-5-18'; 'Everyone' = 'S-1-1-0' }
    function Get-Sid([string]$Cuenta) {
        if ($sidConocidos.ContainsKey($Cuenta)) { return $sidConocidos[$Cuenta] }
        return (New-Object System.Security.Principal.NTAccount($Cuenta)).Translate([System.Security.Principal.SecurityIdentifier]).Value
    }
    function Get-NombreCuenta([string]$Cuenta) {
        $sid = New-Object System.Security.Principal.SecurityIdentifier((Get-Sid $Cuenta))
        return $sid.Translate([System.Security.Principal.NTAccount]).Value
    }
    $sync = [int][System.Security.AccessControl.FileSystemRights]::Synchronize

    foreach ($r in $Recursos) {
        $detalle = New-Object System.Collections.Generic.List[string]

        # --- Carpeta y archivo de ejemplo ---
        if (-not (Test-Path -LiteralPath $r.RutaLocal)) { New-Item -Path $r.RutaLocal -ItemType Directory -Force | Out-Null; $detalle.Add('carpeta creada') }
        $leeme = Join-Path $r.RutaLocal 'LEEME.txt'
        if (-not (Test-Path -LiteralPath $leeme)) {
            Set-Content -LiteralPath $leeme -Encoding UTF8 -Value @("$Empresa", "Recurso compartido: $($r.Nombre)", "Creado por el despliegue automatizado el $(Get-Date -Format 'dd/MM/yyyy HH:mm').", "Los permisos se administran con los grupos DL-$($r.Nombre)-*. No otorgar permisos a usuarios individuales.")
        }

        # --- NTFS: herencia deshabilitada y solo las reglas del diseño ---
        $deseadoNTFS = @($r.NTFS | ForEach-Object {
                $derechos = [System.Security.AccessControl.FileSystemRights]$_.Permiso
                [pscustomobject]@{ Sid = (Get-Sid $_.Cuenta); Derechos = $derechos; Firma = "$(Get-Sid $_.Cuenta)|$([int]$derechos -bor $sync)" }
            })
        $acl = Get-Acl -LiteralPath $r.RutaLocal
        $explicitas = @($acl.GetAccessRules($true, $false, [System.Security.Principal.SecurityIdentifier]))
        $firmaActual = @($explicitas | Where-Object { $_.AccessControlType -eq 'Allow' } | ForEach-Object { "$($_.IdentityReference.Value)|$([int]$_.FileSystemRights -bor $sync)" } | Sort-Object)
        $firmaDeseada = @($deseadoNTFS | ForEach-Object { $_.Firma } | Sort-Object)
        $iguales = $acl.AreAccessRulesProtected -and $explicitas.Count -eq $deseadoNTFS.Count -and (($firmaActual -join ';') -eq ($firmaDeseada -join ';'))
        if (-not $iguales) {
            $acl.SetAccessRuleProtection($true, $false)
            foreach ($regla in $explicitas) { [void]$acl.RemoveAccessRuleSpecific($regla) }
            foreach ($d in $deseadoNTFS) {
                $id = New-Object System.Security.Principal.SecurityIdentifier($d.Sid)
                $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($id, $d.Derechos, 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
            }
            Set-Acl -LiteralPath $r.RutaLocal -AclObject $acl
            $detalle.Add('NTFS aplicado')
        }

        # --- Recurso compartido ---
        $admins = Get-NombreCuenta 'BUILTIN\Administrators'
        $share = Get-SmbShare -Name $r.Nombre -ErrorAction SilentlyContinue
        $desc = "$Empresa - $($r.Nombre)"
        $abe = 'Unrestricted'; if ($r.ABE) { $abe = 'AccessBased' }
        if (-not $share) {
            New-SmbShare -Name $r.Nombre -Path $r.RutaLocal -Description $desc -FullAccess $admins -FolderEnumerationMode $abe | Out-Null
            $detalle.Add('recurso compartido creado')
        }
        else {
            if ($share.Path.TrimEnd('\') -ne $r.RutaLocal.TrimEnd('\')) { throw "El recurso compartido $($r.Nombre) ya existe apuntando a $($share.Path)." }
            if ([string]$share.FolderEnumerationMode -ne $abe -or $share.Description -ne $desc) { Set-SmbShare -Name $r.Nombre -FolderEnumerationMode $abe -Description $desc -Force; $detalle.Add('ABE/descripción actualizados') }
        }

        $deseadoComp = @{}
        foreach ($p in $r.Compartido) { $deseadoComp[(Get-Sid $p.Cuenta)] = [pscustomobject]@{ Nombre = (Get-NombreCuenta $p.Cuenta); Permiso = $p.Permiso } }
        foreach ($a in @(Get-SmbShareAccess -Name $r.Nombre)) {
            $sid = $null
            try { $sid = Get-Sid $a.AccountName } catch { $sid = $null }
            $quitar = (-not $sid) -or (-not $deseadoComp.ContainsKey($sid)) -or ([string]$a.AccessRight -ne $deseadoComp[$sid].Permiso) -or ([string]$a.AccessControlType -ne 'Allow')
            if ($quitar) { Revoke-SmbShareAccess -Name $r.Nombre -AccountName $a.AccountName -Force | Out-Null; $detalle.Add("compartido: quitado $($a.AccountName) ($($a.AccessRight))") }
        }
        $presentes = @(Get-SmbShareAccess -Name $r.Nombre | ForEach-Object { try { Get-Sid $_.AccountName } catch { '' } })
        foreach ($sid in $deseadoComp.Keys) {
            if ($sid -notin $presentes) {
                Grant-SmbShareAccess -Name $r.Nombre -AccountName $deseadoComp[$sid].Nombre -AccessRight $deseadoComp[$sid].Permiso -Force | Out-Null
                $detalle.Add("compartido: $($deseadoComp[$sid].Nombre) = $($deseadoComp[$sid].Permiso)")
            }
        }

        $accion = 'Sin cambios'; if ($detalle.Count) { $accion = 'Actualizado' }
        [pscustomobject]@{ Tipo = 'Recurso'; Objeto = "\\$env:COMPUTERNAME\$($r.Nombre)"; Accion = $accion; Agregados = ($detalle -join '; '); Quitados = ''; Miembros = '' }
    }
}

# =====================================================================
#  Ejecución
# =====================================================================
$resultados = New-Object System.Collections.Generic.List[object]
function Add-Resultados($lista) { foreach ($x in @($lista)) { $resultados.Add(($x | Select-Object Tipo, Objeto, Accion, Agregados, Quitados, Miembros)) } }

Write-Log "A -> G: grupos globales en $($domRaiz.FQDN) (padre, cuentas)" -Nivel Paso
Add-Resultados (Invoke-EnServidor -Equipo $srvRaiz.IPFinal -Credencial $cred.Raiz -Bloque $bloqueGruposGlobales -Argumentos @(, $ggs) -Descripcion "$($ggs.Count) grupos globales")

Write-Log "G -> DL: grupos de dominio local en $($domHijo.FQDN) (hijo, recursos) con grupos globales del padre como miembros" -Nivel Paso
Add-Resultados (Invoke-EnServidor -Equipo $srvHijo.IPFinal -Credencial $cred.Hijo -Bloque $bloqueGruposDL -Argumentos @($dls, $domHijo.FQDN, $cred.Raiz) -Descripcion "$($dls.Count) grupos de dominio local")

Write-Log "DL -> P: recursos compartidos y NTFS en $($srvHijo.Nombre)" -Nivel Paso
Add-Resultados (Invoke-EnServidor -Equipo $srvHijo.IPFinal -Credencial $cred.Hijo -Bloque $bloqueRecursos -Argumentos @($recursos, [string]$Diseno.Parametros.Empresa) -Descripcion "$($recursos.Count) recursos")

foreach ($r in $resultados) {
    $texto = "$($r.Tipo) $($r.Objeto): $($r.Accion)"
    if ($r.Agregados) { $texto += " · + $($r.Agregados)" }
    if ($r.Quitados)  { $texto += " · - $($r.Quitados)" }
    $nivelLog = 'Info'; if ($r.Accion -ne 'Sin cambios' -and $r.Accion -ne 'Existente') { $nivelLog = 'Ok' }
    Write-Log $texto -Nivel $nivelLog
}
$resultados | Export-Csv -Path (Join-Path $RutaSalida 'acceso-resultado.csv') -NoTypeInformation -Encoding UTF8
Write-Log 'Los usuarios deben cerrar e iniciar sesión para que su token incluya los grupos nuevos.' -Nivel Advertencia
return 'Completado'
