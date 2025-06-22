import os, io, csv
from flask import Blueprint, render_template, request, redirect, url_for, flash, current_app, jsonify, make_response, session
from flask_jwt_extended import (
    current_user,
    create_access_token,
    set_access_cookies,
    jwt_required,
    get_jwt_identity,
    unset_jwt_cookies,
    verify_jwt_in_request
)
from wtforms.validators import DataRequired

import app
from app import jwt, db, bcrypt
from app.models import Usuario, AccessLog, Configuracion, PasswordResetToken, SolicitudBaja

from app.forms import ConfiguracionForm, UsuarioForm, SolicitudRecuperacionForm, VerificarCodigoForm, NuevaContrasenaForm
from .utils.decorators import role_required
from .utils.logger import log_event
from datetime import datetime, timedelta
from app import db
from werkzeug.utils import secure_filename
from sqlalchemy.exc import IntegrityError

#para el EMAIL Y PASS DE USER
from app.utils.security import generar_contrasena_temporal
from app.utils.email import enviar_correo_bienvenida, enviar_correo_codigo_recuperacion, enviar_notificacion_baja

#CAMBIO DE CONTRASEÑAS
from app.forms import CambioContrasenaForm
from app.utils.email import enviar_correo_contrasena_cambiada

from sqlalchemy import text
from sqlalchemy.orm import joinedload

# Blueprints
routes_bp = Blueprint('main', __name__)
admin_bp = Blueprint('admin', __name__, url_prefix='/admin')

# CONFIGURACION DEL LOADER
@jwt.user_lookup_loader
def user_lookup_callback(_jwt_header, jwt_data):
    identity = jwt_data["sub"]
    return Usuario.query.get(identity)

#LOGIN DE USAURION
@routes_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        usuario = request.form.get('usuario')
        password = request.form.get('password')

        user = Usuario.query.filter_by(usuario=usuario).first()


        if user is None:
            log_event(
                user=None,
                event_type='login_failed',
                endpoint='main.login',
                details=f'Usuario no encontrado: {usuario}'
            )
            flash('Usuario no encontrado', 'danger')
            return redirect(url_for('main.login'))

        if user.check_password(password):
            # REGISTRAR ACCESO EXITOSO
            log_event(
                user=user,
                event_type='login_success',
                endpoint='main.login',
                details=f'Inicio de sesión exitoso - IP: {request.remote_addr}'
            )

            # Si es nuevo usuario, redirigir a cambio de contraseña
            if user.nuevo_user:
                access_token = create_access_token(identity=str(user.id))
                response = redirect(url_for('main.cambiar_contrasena_primera_vez'))
                set_access_cookies(response, access_token)
                return response

            additional_claims = {"rol": user.rol}
            access_token = create_access_token(identity=str(user.id), additional_claims=additional_claims)

            response = redirect(
                url_for('admin.admin_dashboard') if user.rol == 'admin'
                else url_for('main.user_dashboard')  # Nueva ruta para usuarios
            )
            set_access_cookies(response, access_token)
            return response
        else:
            # REGISTRAR INTENTO FALLIDO
            log_event(
                user=user,
                event_type='login_failed',
                endpoint='main.login',
                details=f'Contraseña incorrecta para usuario: {usuario} - IP: {request.remote_addr}'
            )
            flash('Credenciales inválidas', 'danger')

            # Registrar acceso a la página de login
        log_event(
            user=None,
            event_type='page_access',
            endpoint='main.login',
            details='Acceso a página de login'
        )

    return render_template('auth/login.html')

#CAMBIO DE CONTRASEÑA
@routes_bp.route('/cambiar-contrasena', methods=['GET', 'POST'])
@jwt_required()
def cambiar_contrasena_primera_vez():
    user_id = get_jwt_identity()
    user = Usuario.query.get(user_id)

    # Si no es nuevo usuario, redirigir al dashboard
    if not user.nuevo_user:
        return redirect(url_for('main.user_dashboard' if user.rol == 'user' else 'admin.admin_dashboard'))

    form = CambioContrasenaForm()

    if form.validate_on_submit():
        # Cambiar la contraseña
        user.set_password(form.nueva_contrasena.data)
        user.nuevo_user = False  # Ya no es nuevo usuario
        db.session.commit()

        # Enviar correo de notificación
        enviar_correo_contrasena_cambiada(user)

        flash('Contraseña cambiada exitosamente. Ahora puede utilizar el sistema.', 'success')
        return redirect(url_for('main.user_dashboard' if user.rol == 'user' else 'admin.admin_dashboard'))

    return render_template('cambiar_contrasena_primera_vez.html', form=form)

#RECUPERAR CONTRASEÑA
@routes_bp.route('/recuperar-contrasena', methods=['GET', 'POST'])
def solicitar_recuperacion_contrasena():
    form = SolicitudRecuperacionForm()
    intentos = session.get('recovery_attempts', 0)

    # Si hay más de 2 intentos, requerir captcha
    if intentos > 2:
        form.captcha.validators = [DataRequired()]

    if form.validate_on_submit():
        usuario_o_email = form.usuario_o_email.data
        user = Usuario.query.filter((Usuario.usuario == usuario_o_email) | (Usuario.email == usuario_o_email)).first()

        if user:
            # Generar token de recuperación
            token = PasswordResetToken.generate_token(user)
            db.session.add(token)
            db.session.commit()

            # Enviar correo con código
            enviar_correo_codigo_recuperacion(user, token.token[:6])

            flash('Se ha enviado un código de verificación a su correo electrónico.', 'info')
            return redirect(url_for('main.verificar_codigo_recuperacion', token_id=token.id))

        # Incrementar contador de intentos fallidos
        session['recovery_attempts'] = intentos + 1
        flash('No se encontró una cuenta con ese usuario o correo.', 'danger')

    return render_template('auth/solicitar_recuperacion.html', form=form, intentos=intentos)


@routes_bp.route('/verificar-codigo/<int:token_id>', methods=['GET', 'POST'])
def verificar_codigo_recuperacion(token_id):
    token = PasswordResetToken.query.get(token_id)

    if not token or not token.is_valid():
        flash('El enlace de recuperación es inválido o ha expirado.', 'danger')
        return redirect(url_for('main.solicitar_recuperacion_contrasena'))

    form = VerificarCodigoForm()

    if form.validate_on_submit():
        # Verificar el código (primeros 6 caracteres del token)
        if form.codigo.data == token.token[:6]:
            # Crear token de acceso temporal para establecer nueva contraseña
            access_token = create_access_token(identity=str(token.user_id))
            response = redirect(url_for('main.establecer_nueva_contrasena'))
            set_access_cookies(response, access_token)
            return response

        flash('Código incorrecto. Intente nuevamente.', 'danger')

    return render_template('auth/verificar_codigo.html', form=form, token=token)


@routes_bp.route('/establecer-nueva-contrasena', methods=['GET', 'POST'])
@jwt_required()
def establecer_nueva_contrasena():
    user_id = get_jwt_identity()
    user = Usuario.query.get(user_id)
    form = NuevaContrasenaForm()

    if form.validate_on_submit():
        # Cambiar la contraseña
        user.set_password(form.nueva_contrasena.data)
        db.session.commit()

        # Enviar correo de notificación
        enviar_correo_contrasena_cambiada(user)

        flash('Su contraseña ha sido cambiada exitosamente. Por favor inicie sesión.', 'success')
        return redirect(url_for('main.login'))

    return render_template('auth/establecer_nueva_contrasena.html', form=form)

#DASHBOARD DEL USUARIO
@routes_bp.route('/user/dashboard')
@jwt_required()
@role_required(['user', 'admin'])  # Admin también puede acceder
def user_dashboard():
    config = Configuracion.obtener_config()  # Obtener configuración
    log_event(
        user=current_user,
        event_type='user_dashboard_access',
        endpoint='main.user_dashboard',
        details=f'Acceso al dashboard de usuario'
    )
    return render_template('user/dashboard.html', current_user=current_user, config=config)

#DASHBOARD PRINCIPAL
@admin_bp.route('/dashboard')
@jwt_required()
@role_required(['admin'])
def admin_dashboard():
    # REGISTRAR ACCESO AL DASHBOARD
    log_event(
        user=current_user,
        event_type='admin_dashboard_access',
        endpoint='admin.admin_dashboard',
        details=f'Acceso al dashboard de administrador'
    )
    return render_template('admin/dashboard.html', current_user=current_user)

#AGREGAR EN EL LOG
@admin_bp.route('/access-logs')
@jwt_required()
@role_required(['admin'])
def access_logs():
    log_event(
        user=current_user,
        event_type='access_logs_view',
        endpoint='admin.access_logs',
        details='Visualización de bitácora de accesos'
    )

    # Obtener parámetros de búsqueda
    page = request.args.get('page', 1, type=int)
    per_page = 20
    fecha_inicio = request.args.get('fecha_inicio', '')
    fecha_fin = request.args.get('fecha_fin', '')
    busqueda = request.args.get('busqueda', '', type=str)

    # Construir consulta base
    query = AccessLog.query.join(Usuario).order_by(AccessLog.timestamp.desc())
    #query = AccessLog.query.options(db.joinedload(AccessLog.user))
    #query = AccessLog.query.join(Usuario).order_by(AccessLog.timestamp.desc())
    #query = AccessLog.query.options(db.joinedload(AccessLog.user)).order_by(AccessLog.timestamp.desc())

    # Aplicar filtro de fechas
    if fecha_inicio:
        try:
            fecha_inicio_dt = datetime.strptime(fecha_inicio, '%Y-%m-%d')
            query = query.filter(AccessLog.timestamp >= fecha_inicio_dt)
        except ValueError:
            flash('Formato de fecha inicial inválido', 'warning')
    if fecha_fin:
        try:
            fecha_fin_dt = datetime.strptime(fecha_fin, '%Y-%m-%d') + timedelta(days=1)
            query = query.filter(AccessLog.timestamp < fecha_fin_dt)
        except ValueError:
            flash('Formato de fecha final inválido', 'warning')

    # Aplicar filtro de búsqueda por nombre de usuario
    if busqueda:
        busqueda_pattern = f'%{busqueda}%'
        query = query.filter(Usuario.usuario.ilike(busqueda_pattern))

    # Paginar resultados
    #logs = query.order_by(AccessLog.timestamp.desc()).paginate(page=page, per_page=per_page)
    logs = query.paginate(page=page, per_page=per_page)

    return render_template('admin/access_logs.html',
                           logs=logs,
                           current_user=current_user,
                           fecha_inicio=fecha_inicio,
                           fecha_fin=fecha_fin,
                           busqueda=busqueda)


#EXPORTAR A CSV
@admin_bp.route('/access-logs/exportar')
@jwt_required()
@role_required(['admin'])
def exportar_access_logs():
    # Obtener parámetros de búsqueda
    fecha_inicio = request.args.get('fecha_inicio', '')
    fecha_fin = request.args.get('fecha_fin', '')
    busqueda = request.args.get('busqueda', '', type=str)

    # Construir consulta base
    #query = AccessLog.query.options(db.joinedload(AccessLog.user))
    #query = AccessLog.query.options(db.joinedload(AccessLog.user)).order_by(AccessLog.timestamp.desc())
    #query = AccessLog.query.join(Usuario).order_by(AccessLog.timestamp.desc())
    query = AccessLog.query.join(Usuario).order_by(AccessLog.timestamp.desc())

    # Aplicar filtro de fechas
    if fecha_inicio:
        fecha_inicio_dt = datetime.strptime(fecha_inicio, '%Y-%m-%d')
        query = query.filter(AccessLog.timestamp >= fecha_inicio_dt)
    if fecha_fin:
        fecha_fin_dt = datetime.strptime(fecha_fin, '%Y-%m-%d') + timedelta(days=1)
        query = query.filter(AccessLog.timestamp < fecha_fin_dt)

    # Aplicar filtro de búsqueda por nombre de usuario
    if busqueda:
        busqueda_pattern = f'%{busqueda}%'
        query = query.filter(Usuario.usuario.ilike(busqueda_pattern))

    # Obtener todos los registros
    logs = query.all()

    # Crear un buffer en memoria para el CSV
    buffer = io.StringIO()
    writer = csv.writer(buffer, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)

    # Escribir encabezado del reporte
    writer.writerow(["Sistema de Cobros Municipales - Bitácora de Usuario"])
    writer.writerow([])  # Línea vacía

    # Escribir filtros aplicados
    if fecha_inicio:
        writer.writerow([f"Fecha Inicial: {fecha_inicio}"])
    if fecha_fin:
        writer.writerow([f"Fecha Final: {fecha_fin}"])
    if busqueda:
        writer.writerow([f"Usuario: {busqueda}"])
    writer.writerow([f"Fecha de exportación: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"])
    writer.writerow([])  # Línea vacía

    # Escribir encabezados de columnas
    writer.writerow([
        'Fecha/Hora',
        'Usuario',
        'Evento',
        'IP',
        'Ubicación',
        'Dispositivo',
        'Detalles',
        'Método HTTP',
        'Ruta'
    ])

    # Escribir cada registro
    for log in logs:
        writer.writerow([
            log.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            log.user.usuario if log.user else 'N/A',
            log.event_type,
            log.ip_address,
            log.location or 'N/A',
            log.device_info,
            log.details or '',
            log.request_method or '',
            log.request_path or ''
        ])

    # Preparar respuesta con BOM para UTF-8
    data = buffer.getvalue()
    output = io.BytesIO()
    output.write(b'\xEF\xBB\xBF')  # BOM para UTF-8
    output.write(data.encode('utf-8'))
    output.seek(0)

    filename = f"bitacora_accesos_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    response = make_response(output.getvalue())
    response.headers['Content-Disposition'] = f'attachment; filename={filename}'
    response.headers['Content-type'] = 'text/csv; charset=utf-8'
    return response

#CERRAR SESIÓN
@routes_bp.route('/logout')
def logout():
    # Verificar manualmente si hay un token válido
    try:
        verify_jwt_in_request(optional=True)
        user_id = get_jwt_identity()
        if user_id:
            user = Usuario.query.get(user_id)
            # REGISTRAR CIERRE DE SESIÓN
            log_event(
                user=user,
                event_type='logout',
                endpoint='main.logout',
                details='Cierre de sesión exitoso'
            )
    except Exception:
        log_event(
            user=None,
            event_type='logout_error',
            endpoint='main.logout',
            details=f'Error en cierre de sesión: {str(e)}'
        )
        pass

    # Siempre limpiar las cookies y redirigir
    response = redirect(url_for('main.login'))
    unset_jwt_cookies(response)
    flash('Sesión cerrada exitosamente', 'success')
    return response

#GRID DE LOS USUARIOS
@admin_bp.route('/usuarios', methods=['GET'])
@jwt_required()
@role_required(['admin'])
def gestion_usuarios():
    try:
        # Registrar acceso al listado
        log_event(
            user=current_user,
            event_type='user_list_access',
            endpoint='admin.gestion_usuarios',
            details=f'Acceso a gestión de usuarios. Filtros: {request.args}'
        )
        # Obtener parámetros de paginación
        page = request.args.get('page', 1, type=int)
        per_page = 10

        # Obtener parámetros de búsqueda
        busqueda = request.args.get('busqueda', '')
        estado = request.args.get('estado', 'todos')
        rol = request.args.get('rol', 'todos')

        # Construir la consulta base
        query = Usuario.query

        # Aplicar filtros de búsqueda
        if busqueda:
            busqueda_pattern = f'%{busqueda}%'
            query = query.filter(
                db.or_(
                    Usuario.usuario.ilike(busqueda_pattern),
                    Usuario.nombre.ilike(busqueda_pattern),
                    Usuario.apellido_paterno.ilike(busqueda_pattern),
                    Usuario.apellido_materno.ilike(busqueda_pattern),
                    Usuario.email.ilike(busqueda_pattern)
                )
            )

        # Filtrar por estado
        if estado != 'todos':
            estado_bool = estado == 'activos'
            query = query.filter(Usuario.activo == estado_bool)

        # Filtrar por rol
        if rol != 'todos':
            query = query.filter(Usuario.rol == rol)

        # Ordenar y paginar
        usuarios = query.order_by(Usuario.creado_en.desc()).paginate(
            page=page, per_page=per_page, error_out=False
        )


        return render_template(
            'admin/gestion_usuarios.html',
            usuarios=usuarios,
            busqueda=busqueda,
            estado=estado,
            rol=rol,
            current_user=current_user,
            roles_disponibles=['admin', 'user']  # Para el dropdown de filtros
        )

    except Exception as e:
        log_event(
            user=current_user,
            event_type='user_list_error',
            endpoint='admin.gestion_usuarios',
            details=f'Error en gestión de usuarios: {str(e)}'
        )
        current_app.logger.error(f"Error en gestión de usuarios: {str(e)}")
        flash('Ocurrió un error al cargar la lista de usuarios', 'danger')
        return redirect(url_for('admin.admin_dashboard'))

#GESTIÓN DE LOS USUARIOS
@admin_bp.route('/usuarios/crear', methods=['GET', 'POST'])
@jwt_required()
@role_required(['admin'])
def crear_usuario():
    if request.method == 'GET':
        log_event(
            user=current_user,
            event_type='user_create_form_access',
            endpoint='admin.crear_usuario',
            details='Acceso a formulario de creación de usuario'
        )

    form = UsuarioForm()

    if form.validate_on_submit():
        try:
            # Verificar si el correo ya existe
            if Usuario.query.filter_by(email=form.email.data).first():
                flash('El correo electrónico ya está en uso por otro usuario', 'danger')
                return render_template('admin/editar_usuario.html',
                                       form=form,
                                       accion='Crear',
                                       current_user=current_user)

            # Generar contraseña temporal segura
            contrasena_temporal = generar_contrasena_temporal()

            # Crear nuevo usuario
            nuevo_usuario = Usuario(
                usuario=form.usuario.data,
                email=form.email.data,
                nombre=form.nombre.data,
                apellido_paterno=form.apellido_paterno.data,
                apellido_materno=form.apellido_materno.data or '',
                fecha_nacimiento=datetime.combine(form.fecha_nacimiento.data, datetime.min.time()),
                rol=form.rol.data,
                activo=True,
                nuevo_user=True
            )

            # Establecer contraseña temporal
            nuevo_usuario.set_password(contrasena_temporal)

            db.session.add(nuevo_usuario)
            db.session.commit()

            # Enviar correo de bienvenida
            if enviar_correo_bienvenida(nuevo_usuario, contrasena_temporal):
                log_event(
                    current_user,
                    'email_bienvenida_enviado',
                    'admin.crear_usuario',
                    f"Correo enviado a {nuevo_usuario.email}"
                )
            else:
                log_event(
                    current_user,
                    'email_bienvenida_error',
                    'admin.crear_usuario',
                    f"Error al enviar correo a {nuevo_usuario.email}"
                )

            flash('Usuario creado exitosamente. Se ha enviado un correo con las credenciales.', 'success')
            log_event(
                user=current_user,
                event_type='user_created',
                endpoint='admin.crear_usuario',
                details=f'Usuario creado: {nuevo_usuario.usuario} (ID: {nuevo_usuario.id})'
            )
            return redirect(url_for('admin.gestion_usuarios'))

        except IntegrityError as e:
            db.session.rollback()
            if 'usuarios.email' in str(e.orig):
                flash('El correo electrónico ya está en uso por otro usuario', 'danger')
            elif 'usuarios.usuario' in str(e.orig):
                flash('El nombre de usuario ya está en uso', 'danger')
            else:
                flash(f'Error de base de datos: {str(e)}', 'danger')

            log_event(
                user=current_user,
                event_type='user_create_error',
                endpoint='admin.crear_usuario',
                details=f'Error de integridad al crear usuario: {str(e)}'
            )
            return render_template('admin/editar_usuario.html',
                                   form=form,
                                   accion='Crear',
                                   current_user=current_user)

        except Exception as e:
            db.session.rollback()
            current_app.logger.error(f"Error al crear usuario: {str(e)}")
            flash(f'Error al crear usuario: {str(e)}', 'danger')
            log_event(
                user=current_user,
                event_type='user_create_error',
                endpoint='admin.crear_usuario',
                details=f'Error al crear usuario: {str(e)}'
            )

    return render_template('admin/editar_usuario.html',
                           form=form,
                           accion='Crear',
                           current_user=current_user)


@admin_bp.route('/usuarios/editar/<int:id>', methods=['GET', 'POST'])
@jwt_required()
@role_required(['admin'])
def editar_usuario(id):
    usuario = Usuario.query.get_or_404(id)
    form = UsuarioForm(obj=usuario)
    form.usuario_obj = usuario

    if form.validate_on_submit():
        try:
            # Verificar si el correo ya existe en otro usuario
            if form.email.data != usuario.email:
                if Usuario.query.filter(Usuario.email == form.email.data,
                                        Usuario.id != usuario.id).first():
                    flash('El correo electrónico ya está en uso por otro usuario', 'danger')
                    return render_template('admin/editar_usuario.html',
                                           form=form,
                                           usuario=usuario,
                                           accion='Editar',
                                           current_user=current_user)

            # Actualizar datos
            usuario.usuario = form.usuario.data
            usuario.email = form.email.data
            usuario.nombre = form.nombre.data
            usuario.apellido_paterno = form.apellido_paterno.data
            usuario.apellido_materno = form.apellido_materno.data or ''
            usuario.fecha_nacimiento = datetime.combine(form.fecha_nacimiento.data, datetime.min.time())
            usuario.rol = form.rol.data
            usuario.activo = form.activo.data

            # Actualizar contraseña si se proporcionó
            if form.password.data:
                usuario.set_password(form.password.data)

            db.session.commit()
            flash('Usuario actualizado exitosamente', 'success')
            log_event(
                user=current_user,
                event_type='user_updated',
                endpoint='admin.editar_usuario',
                details=f'Usuario actualizado: {usuario.usuario} (ID: {usuario.id})'
            )
            return redirect(url_for('admin.gestion_usuarios'))

        except IntegrityError as e:
            db.session.rollback()
            if 'usuarios.email' in str(e.orig):
                flash('El correo electrónico ya está en uso por otro usuario', 'danger')
            elif 'usuarios.usuario' in str(e.orig):
                flash('El nombre de usuario ya está en uso', 'danger')
            else:
                flash(f'Error de base de datos: {str(e)}', 'danger')

            log_event(
                user=current_user,
                event_type='user_update_error',
                endpoint='admin.editar_usuario',
                details=f'Error de integridad al actualizar usuario ID {id}: {str(e)}'
            )
            return render_template('admin/editar_usuario.html',
                                   form=form,
                                   usuario=usuario,
                                   accion='Editar',
                                   current_user=current_user)

        except Exception as e:
            db.session.rollback()
            flash(f'Error al actualizar usuario: {str(e)}', 'danger')
            log_event(
                user=current_user,
                event_type='user_update_error',
                endpoint='admin.editar_usuario',
                details=f'Error al actualizar usuario ID {id}: {str(e)}'
            )

    return render_template('admin/editar_usuario.html',
                           form=form,
                           usuario=usuario,
                           accion='Editar',
                           current_user=current_user)


@admin_bp.route('/usuarios/desactivar/<int:id>', methods=['POST'])
@jwt_required()
@role_required(['admin'])
def desactivar_usuario(id):
    if not request.is_json:
        return jsonify({"error": "Missing JSON in request"}), 400

    try:
        usuario = Usuario.query.get_or_404(id)

        if usuario.id == current_user.id:
            return jsonify({"error": "No puedes desactivar tu propia cuenta"}), 400

        usuario.activo = False
        db.session.commit()
        log_event(
            user=current_user,
            event_type='user_deactivated',
            endpoint='admin.desactivar_usuario',
            details=f'Usuario desactivado: {usuario.usuario} (ID: {usuario.id})'
        )
        return jsonify({"success": True, "message": "Usuario desactivado"})

    except Exception as e:
        db.session.rollback()
        log_event(
            user=current_user,
            event_type='user_deactivate_error',
            endpoint='admin.desactivar_usuario',
            details=f'Error al desactivar usuario ID {id}: {str(e)}'
        )
        return jsonify({"error": str(e)}), 500


@admin_bp.route('/usuarios/activar/<int:id>', methods=['POST'])
@jwt_required()
@role_required(['admin'])
def activar_usuario(id):
    if not request.is_json:
        return jsonify({"error": "Missing JSON in request"}), 400

    try:
        usuario = Usuario.query.get_or_404(id)

        usuario.activo = True
        db.session.commit()
        log_event(
            user=current_user,
            event_type='user_activated',
            endpoint='admin.activar_usuario',
            details=f'Usuario activado: {usuario.usuario} (ID: {usuario.id})'
        )
        return jsonify({"success": True, "message": "Usuario activado"})

    except Exception as e:
        db.session.rollback()
        log_event(
            user=current_user,
            event_type='user_activate_error',
            endpoint='admin.activar_usuario',
            details=f'Error al activar usuario ID {id}: {str(e)}'
        )
        return jsonify({"error": str(e)}), 500

#CONFIGURACION
@admin_bp.route('/configuracion', methods=['GET', 'POST'])
@jwt_required()
@role_required(['admin'])
def configuracion():
    # Registrar acceso a la página de configuración
    log_event(
        user=current_user,
        event_type='config_page_access',
        endpoint='admin.configuracion',
        details='Acceso a página de configuración del sistema'
    )

    config = Configuracion.obtener_config()
    form = ConfiguracionForm()

    # Poblar el formulario excluyendo campos de archivo
    if request.method == 'GET':
        for field in form:
            if field.name not in ['logo_municipio', 'logo_admin', 'imagen_fondo']:
                field.data = getattr(config, field.name, None)

    # Rutas para archivos
    UPLOAD_FOLDER_LOGOS = os.path.join(current_app.root_path, 'static', 'images', 'logos')
    UPLOAD_FOLDER_FONDOS = os.path.join(current_app.root_path, 'static', 'images', 'fondos')
    os.makedirs(UPLOAD_FOLDER_LOGOS, exist_ok=True)
    os.makedirs(UPLOAD_FOLDER_FONDOS, exist_ok=True)

    if form.validate_on_submit():
        try:
            cambios = []

            # Manejar subida de logos
            for field in ['logo_municipio', 'logo_admin']:
                file = getattr(form, field).data
                if file and hasattr(file, 'filename') and file.filename != '':
                    filename = secure_filename(file.filename)
                    file_path = os.path.join(UPLOAD_FOLDER_LOGOS, filename)
                    file.save(file_path)

                    # Registrar cambio de logo
                    old_value = getattr(config, field, '')
                    setattr(config, field, filename)
                    if old_value != filename:
                        cambios.append(f"{field}: {old_value} → {filename}")

            # Manejar imagen de fondo
            file_fondo = form.imagen_fondo.data
            if file_fondo and hasattr(file_fondo, 'filename') and file_fondo.filename != '':
                filename = secure_filename(file_fondo.filename)
                file_path = os.path.join(UPLOAD_FOLDER_FONDOS, filename)
                file_fondo.save(file_path)

                # Registrar cambio de fondo
                old_value = config.imagen_fondo
                config.imagen_fondo = filename
                if old_value != filename:
                    cambios.append(f"imagen_fondo: {old_value} → {filename}")

            # Registrar cambios en otros campos
            for field in form:
                if field.name not in ['logo_municipio', 'logo_admin', 'imagen_fondo', 'submit']:
                    old_value = getattr(config, field.name, '')
                    new_value = field.data
                    setattr(config, field.name, new_value)

                    # Solo registrar si hubo cambio
                    if str(old_value) != str(new_value):
                        cambios.append(f"{field.name}: {old_value} → {new_value}")

            db.session.commit()

            # Registrar éxito solo si hubo cambios
            if cambios:
                detalles = " | ".join(cambios)
                log_event(
                    user=current_user,
                    event_type='config_updated',
                    endpoint='admin.configuracion',
                    details=f"Configuración actualizada: {detalles}"
                )
                flash('Configuración actualizada exitosamente', 'success')
            else:
                flash('No se realizaron cambios en la configuración', 'info')

            return redirect(url_for('admin.configuracion'))

        except Exception as e:
            db.session.rollback()

            # Registrar error en el log
            log_event(
                user=current_user,
                event_type='config_update_error',
                endpoint='admin.configuracion',
                details=f"Error al guardar configuración: {str(e)}"
            )

            flash(f'Error al guardar configuración: {str(e)}', 'danger')

    return render_template('admin/configuracion.html',
                           form=form,
                           config=config,
                           current_user=current_user)


# Perfil de usuario
@routes_bp.route('/perfil')
@jwt_required()
def perfil_usuario():
    try:
        user_id = get_jwt_identity()
        usuario = Usuario.query.get(user_id)

        # Verificar si tiene solicitud pendiente
        tiene_solicitud_pendiente = SolicitudBaja.query.filter_by(
            usuario_id=user_id,
            estado='pendiente'
        ).first() is not None

        log_event(current_user, 'profile_view', request.endpoint, f"Vista perfil usuario {user_id}")
        return render_template('user/perfil.html',
                               current_user=usuario,
                               tiene_solicitud_pendiente=tiene_solicitud_pendiente)
    except Exception as e:
        log_event(current_user, 'error', request.endpoint, str(e))
        flash('Error al cargar perfil', 'danger')
        return redirect(url_for('main.user_dashboard'))


# Solicitud de baja
@routes_bp.route('/solicitar_baja', methods=['POST'])
@jwt_required()
def solicitar_baja():
    try:
        user_id = get_jwt_identity()
        motivo = request.form.get('motivo')

        solicitud = SolicitudBaja(
            usuario_id=user_id,
            motivo=motivo
        )
        db.session.add(solicitud)
        db.session.commit()

        log_event(current_user, 'deactivation_request', request.endpoint,
                  f"Solicitud baja usuario {user_id}")
        flash('Solicitud enviada correctamente', 'success')
    except Exception as e:
        log_event(current_user, 'error', request.endpoint, str(e))
        flash('Error al enviar solicitud', 'danger')

    return redirect(url_for('main.perfil_usuario'))


# Panel de solicitudes (Admin)
@admin_bp.route('/solicitudes_de_baja')
@jwt_required()
@role_required(['admin'])
def solicitudes_de_baja():
    # CORRECCIÓN: Cargar relaciones usando joinedload
    solicitudes = SolicitudBaja.query.options(
        joinedload(SolicitudBaja.usuario),
        joinedload(SolicitudBaja.admin)
    ).filter_by(estado='pendiente').all()

    return render_template('admin/solicitudes_baja.html',
                           solicitudes=solicitudes,
                           current_user=current_user)


# Procesar solicitud (Admin)
@admin_bp.route('/procesar_solicitud/<int:id>', methods=['POST'])
@jwt_required()
@role_required(['admin'])
def procesar_solicitud(id):
    try:
        admin_id = get_jwt_identity()
        accion = request.form.get('accion')
        observaciones = request.form.get('observaciones', '')

        # Usar stored procedure
        db.engine.execute(
            "EXEC sp_gestion_baja_usuario ?, ?, ?, ?",
            (id, admin_id, accion, observaciones)
        )

        # Enviar email
        usuario = Usuario.query.get(id)
        enviar_notificacion_baja(usuario, accion, observaciones)

        log_event(current_user, f'request_{accion}', request.endpoint,
                  f"Solicitud {id} {accion} por admin {admin_id}")
        flash(f'Solicitud {accion} correctamente', 'success')
    except Exception as e:
        log_event(current_user, 'error', request.endpoint, str(e))
        flash('Error al procesar solicitud', 'danger')

    return redirect(url_for('admin.solicitudes_baja'))


@admin_bp.route('/debug_db')
def debug_db():
    try:
        # 1. Probando conexión básica
        result = db.session.execute(text("SELECT 1 AS test")).scalar()

        # 2. Probando lectura de usuarios
        users = db.session.execute(text("SELECT TOP 1 * FROM usuarios")).fetchall()

        # 3. Probando lectura de solicitudes
        solicitudes = db.session.execute(text("SELECT TOP 1 * FROM solicitudes_baja")).fetchall()

        return jsonify({
            "db_test": result,
            "users_count": len(users),
            "solicitudes_count": len(solicitudes)
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@routes_bp.route('/')
def home():
    return redirect(url_for('main.login'))