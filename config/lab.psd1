# =====================================================================
#  Configuración del laboratorio
#  ÚNICO archivo (junto con usuarios.csv y accesos.csv) que completa el usuario.
#  Todo lo demás (nombres, IP finales, grupos, permisos) se deriva de acá.
#
#  Escenario de ejemplo: "Distribuidora Andina S.A."
#    - andina.local          dominio raíz: casa central (gerencia y áreas de soporte)
#    - ventas.andina.local   dominio hijo: red comercial (vendedores, sucursales, logística)
#    - SRV-ARCHIVOS (raíz)   aloja los recursos compartidos que usan ambos dominios
# =====================================================================
@{
    # --- Organización -------------------------------------------------
    Empresa      = 'Distribuidora Andina S.A.'   # se carga en el atributo Company de los usuarios

    # --- Dominios -----------------------------------------------------
    DominioRaiz  = 'andina.local'       # FQDN del dominio padre (raíz del bosque)
    DominioHijo  = 'ventas'             # solo la etiqueta -> ventas.andina.local

    # --- Red ----------------------------------------------------------
    Red          = '192.168.10.0/24'    # subred del laboratorio (notación CIDR)
    Gateway      = '192.168.10.1'
    Reenviadores = @('8.8.8.8', '1.1.1.1')   # DNS externos (opcional; @() para ninguno)

    # --- Servidores (IP que tiene cada VM recién instalada) -----------
    # Rol: DCRaiz | DCHijo | Archivos
    # Opcional por servidor: Nombre = '...'  e  IPFinal = '...'
    # Por defecto: DC-RAIZ .10 · DC-HIJO .11 · SRV-ARCHIVOS .20
    Servidores = @(
        @{ IPActual = '192.168.10.101'; Rol = 'DCRaiz'   }
        @{ IPActual = '192.168.10.102'; Rol = 'DCHijo'   }
        @{ IPActual = '192.168.10.103'; Rol = 'Archivos' }
    )

    # --- Áreas (se crea una OU y un grupo global por área en cada dominio) ---
    Areas = @{
        Raiz = @('Gerencia', 'Administracion', 'Finanzas', 'RRHH', 'IT', 'Legales')
        Hijo = @('Comerciales', 'Supervisores', 'Postventa', 'Marketing', 'Logistica')
    }

    # --- Opcionales (si se omiten se usan estos valores) ---------------
    ZonaHoraria  = 'Argentina Standard Time'   # se aplica a los tres servidores (Get-TimeZone -ListAvailable)
    # RutaRecursos         = 'C:\Recursos'     # carpeta base de los recursos compartidos en SRV-ARCHIVOS
    # NivelFuncional       = 'WinThreshold'    # WinThreshold = 2016+ ; Win2012R2 para Windows Server 2012 R2
    # UsuarioAdministrador = 'Administrator'   # 'Administrador' si las VM se instalaron en español
}
