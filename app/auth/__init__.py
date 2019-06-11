from flask import Blueprint

#创建认证蓝本
auth = Blueprint('auth', __name__)
#引用视图模块
from app.auth import views
