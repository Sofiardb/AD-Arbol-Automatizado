# =====================================================================
#  Configuración del laboratorio
#  ÚNICO archivo (junto con usuarios.csv y accesos.csv) que completa el usuario.
#  Todo lo demás (nombres, IP finales, grupos, permisos) se deriva de acá.
#
#  Escenario de ejemplo: "Distribuidora Andina S.A."
#    - andina.local             dominio PADRE (raíz del bosque): CUENTAS de todos los empleados
#    - recursos.andina.local    dominio HIJO: RECURSOS compartidos (carpetas en DC-HIJO)
#    - CLIENTE01                equipo de la demostración: se inicia sesión con una cuenta
#                               del padre y se accede a los recursos del hijo
# =====================================================================
@{
    # --- Organización -------------------------------------------------
    Empresa      = 'Distribuidora Andina S.A.'   # se carga en el atributo Company de los usuarios

    # --- Dominios -----------------------------------------------------
    DominioRaiz  = 'andina.local'       # FQDN del dominio padre (cuentas)
    DominioHijo  = 'recursos'           # solo la etiqueta -> recursos.andina.local (recursos)

    # --- Red ----------------------------------------------------------
    Red          = '192.168.10.0/24'    # subred del laboratorio (notación CIDR)
    Gateway      = '192.168.10.1'
    Reenviadores = @()                       # DNS externos; vacío porque la red solo anfitrión no tiene Internet (ej.: @('8.8.8.8'))

    # --- Servidores (IP que tiene cada VM recién instalada) -----------
    # Rol: DCRaiz | DCHijo      Opcional: Nombre = '...' e IPFinal = '...'
    # Por defecto: DC-RAIZ .10 · DC-HIJO .11
    Servidores = @(
        @{ IPActual = '192.168.10.101'; Rol = 'DCRaiz' }
        @{ IPActual = '192.168.10.102'; Rol = 'DCHijo' }
    )

    # --- Cliente de la demostración (Windows 8/8.1/10/11 Pro, Enterprise o Education) ---
    # Por defecto se llama CLIENTE01, conserva su IP y se une al dominio padre.
    # Opcional: Nombre = '...', IPFinal = '...', Dominio = 'Raiz' | 'Hijo'
    Cliente = @{ IPActual = '192.168.10.150' }

    # --- Equipo de administración (ejecuta Deploy.ps1; no se une al dominio) ---
    # Solo lo usa tools\Preparar-Equipo.ps1 -Rol Admin para fijarle la IP.
    EquipoAdmin = @{ IP = '192.168.10.200' }

    # --- Áreas de la empresa (una OU y un grupo global por área, en el dominio padre) ---
    Areas = @(
        'Gerencia', 'Administracion', 'Finanzas', 'RRHH', 'IT', 'Legales',
        'Comerciales', 'Supervisores', 'Postventa', 'Marketing', 'Logistica'
    )

    # --- Contraseña de la demostración ----------------------------------
    # Con ContrasenaDemo todas las cuentas reciben esta contraseña y NO se pide cambiarla
    # al iniciar sesión, para poder mostrar en vivo el inicio de sesión en el cliente.
    # SOLO PARA EL LABORATORIO. Si se comenta, cada cuenta recibe una contraseña aleatoria
    # (output\credenciales-iniciales.csv) que debe cambiarse en el primer inicio de sesión.
    ContrasenaDemo = 'Andina.2026'

    # --- Opcionales (si se omiten se usan estos valores) ---------------
    ZonaHoraria  = 'Argentina Standard Time'   # se aplica a los servidores y al cliente
    # RutaRecursos         = 'C:\Recursos'     # carpeta base de los recursos compartidos en DC-HIJO
    NivelFuncional       = 'Win2012'           # Win2012 = Windows Server 2012 ; Win2012R2 = 2012 R2 ; WinThreshold = 2016+
    UsuarioAdministrador = 'Administrator'     # nombre del Administrador de los SERVIDORES ('Administrador' si están en español)
}
