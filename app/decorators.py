from functools import wraps
from flask import abort
from flask_login import current_user
from app.models import Permission

#自定义修饰器，权限登入
def permission_required(permission):
	def decorator(f):
		@wraps(f)
		def decorated_function(*args, **kwargs):
			if not current_user.can(permission):
				abort(403)
			return f(*args, **kwargs)
		return decorated_function
	return decorator

#自定义修饰器，管理员准入
def admin_required(f):
	return permission_required(Permission.ADMINISTER)(f)



