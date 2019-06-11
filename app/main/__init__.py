from flask import Blueprint
#创建蓝本
main = Blueprint('main', __name__)
#导入路由和错误处理
from app.main import views, errors
from app.models import Permission

#由于模板中可能也会用到Permission参数，该出使用上下文处理器，使得变量全局可以访问
@main.app_context_processor
def inject_permission():
	return dict(Permission=Permission)