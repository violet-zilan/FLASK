from flask_bootstrap import Bootstrap
from flask_moment import Moment
from flask_mail import Mail
from flask_sqlalchemy import SQLAlchemy
from flask import Flask
from config import config
from flask_login import LoginManager
from flask_pagedown import PageDown

pagedown = PageDown()
bootstrap = Bootstrap()
mail = Mail()
moment = Moment()
db = SQLAlchemy()
login_manager = LoginManager()
#设置session_protection属性提高安全
login_manager.session_protection = 'strong'
#设置登录页面的端点
login_manager.login_view = 'auth.login'

def create_app(config_name):
    app = Flask(__name__)
    #配置参数
    app.config.from_object(config[config_name])
    config[config_name].init_app(app)
    #扩展对象初始化
    bootstrap.init_app(app)
    mail.init_app(app)
    moment.init_app(app)
    db.init_app(app)
    login_manager.init_app(app)
    pagedown.init_app(app)
    if app.config['SSL_REDIRECT']:
        from flask_sslify import SSLify
        sslify = SSLify(app)
    #注册蓝本
    from app.main import main as main_blueprint
    app.register_blueprint(main_blueprint)
    #添加auth蓝本
    from app.auth import auth as auth_blueprint
    #url_prefix 是可选参数。如果使用了这个参数，注册后蓝本中定义的所有路由都会加上指定的前缀
    app.register_blueprint(auth_blueprint, url_prefix='/auth')
    from app.api import api as api_blueprint
    app.register_blueprint(api_blueprint, url_prefix='/api/v1.0')
    #返回创建的函数实例
    return app