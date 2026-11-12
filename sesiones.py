"""EnVivo · fase 3 · usuarios y sesiones.

De cada usuario se guarda: nombre completo, nombre de usuario, contraseña
(puede estar en plano), privilegios (entero positivo) y el token de sesión si
tiene una activa. Las sesiones duran **un mes** y al caducar desaparecen solas.

Las firmas y los valores de retorno **no deben cambiarse**.
"""

import redis
import secrets

DURACION_SESION = 30 * 24 * 60 * 60      # un mes
SIN_ACCESO = -1

_CREAR= """
if redis.call('EXISTS', KEYS[1]) == 1 then return 0 end
redis.call('HSET', KEYS[1], 'usuario', ARGV[1], 'nombre', ARGV[2], 'password', ARGV[3], 'privilegios', ARGV[4])
return 1
"""

_ACTUALIZAR = """
if redis.call('EXISTS', KEYS[1]) == 0 then return 0 end
for i = 1, #ARGV, 2 do
    redis.call('HSET', KEYS[1], ARGV[i], ARGV[i+1])
end
"""

# Borra el usuario y la sesion que el mismo tuviera abierta
_BORRAR = """
local token = redis.call('HGET', KEYS[1], 'token')
if token then redis.call('DEL', ARGV[1] .. token) end
return redis.call('DEL', KEYS[1])
"""

# Comprueba las credenciales, invalida la sesion anterior y abre una nueva
_LOGIN = """
local password = redis.call('HGET', KEYS[1], 'password')
if not password or password ~= ARGV[1] then return -1 end
local anterior = redis.call('HGET', KEYS[1], 'token')
if anterior then redis.call('DEL', ARGV[4] .. anterior) end
redis.call('SET', ARGV[4] .. ARGV[2], ARGV[5], 'EX', ARGV[3])
redis.call('HSET', KEYS[1], 'token', ARGV[2])
return tonumber(redis.call('HGET', KEYS[1], 'privilegios'))
"""

_LOGOUT = """
local usuario = redis.call('GET', KEYS[1])
if not usuario then return 0 end
redis.call('DEL', KEYS[1])
local clave_usuario = ARGV[2] .. usuario
if redis.call('HGET', clave_usuario, 'token') == ARGV[1] then
    redis.call('HDEL', clave_usuario, 'token')
end
return 1
"""
def clave_usuario(usuario: str) -> str:
    """Formato: envivo:usuario:<usuario>"""
    return f"envivo:usuario:{usuario}"


def clave_sesion(token: str) -> str:
    """Formato: envivo:sesion:<token>"""
    return f"envivo:sesion:{token}"


# ── Gestión de usuarios (CRUD) ──────────────────────────────────────────────

def crear_usuario(r: redis.Redis, usuario: str, nombre: str,
                  password: str, privilegios: int) -> bool:
    """Crea el usuario si no existe. Devuelve si se ha creado."""
    return bool(r.eval(_CREAR, 1, clave_usuario(usuario), usuario, nombre, password, str(privilegios)))


def obtener_usuario(r: redis.Redis, usuario: str) -> dict | None:
    """Todos los campos del usuario, o None si no existe.

    `privilegios` debe venir como **entero**, no como cadena.
    """
    datos = r.hgetall(clave_usuario(usuario))
    if not datos:
        return None
    datos["privilegios"] = int(datos["privilegios"])
    # si ha caducado la sesion, el token guardado en el hash ya no es activo
    token = datos.get("token")
    if token and not r.exists(clave_sesion(token)):
        del datos["token"]
    return datos


def actualizar_usuario(r: redis.Redis, usuario: str, **campos) -> bool:
    """Modifica los campos indicados y **solo** esos.

    Devuelve False si el usuario no existe.
    """
    argumentos = []
    for campo,valor in campo.items():
        argumentos.append(campo)
        argumentos.append(str(valor))
    return bool(r.eval(_ACTUALIZAR, 1, clave_usuario(usuario), *argumentos))


def borrar_usuario(r: redis.Redis, usuario: str) -> bool:
    """Borra el usuario. Si tenía sesión abierta, debe quedar cerrada."""
    return bool(r.eval(_BORRAR, 1, clave_usuario(usuario), clave_sesion("")))
    


# ── Sesiones ────────────────────────────────────────────────────────────────

def login(r: redis.Redis, usuario: str, password: str) -> tuple[int, str | None]:
    """Comprueba las credenciales y abre una sesión.

    Devuelve `(privilegios, token)` si son correctas y `(-1, None)` si no.
    Un login nuevo debe invalidar la sesión anterior del mismo usuario.
    """
    token = secrets.token_urlsafe(32)
    privilegios = r.eval(_LOGIN, 1, clave_usuario(usuario), password, token, DURACION_SESION, clave_sesion(""), usuario)
    if privilegios == SIN_ACCESO:
        return SIN_ACCESO, None
    return int(privilegios), token


def login_por_token(r: redis.Redis, token: str) -> int:
    """Privilegios asociados al token, o -1 si no vale.

    Un token cuya sesión ha caducado devuelve -1, igual que uno inventado.
    """
    if not token:
        return SIN_ACCESO
    usuario = r.get(clave_sesion(token))
    if usuario is None:
        return SIN_ACCESO
    privilegios = r.hget(clave_usuario(usuario), "privilegios")
    return SIN_ACCESO if privilegios is None else int(privilegios)


def logout(r: redis.Redis, token: str) -> bool:
    """Cierra la sesión. Devuelve si había una sesión que cerrar."""
    return bool(r.eval(_LOGOUT, 1, clave_sesion(token), token, clave_usuario("")))


def segundos_de_sesion(r: redis.Redis, token: str) -> int:
    """Segundos que le quedan a la sesión. -2 si no existe."""
    return r.ttl(clave_sesion(token))
