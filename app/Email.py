from threading import Thread
from flask import current_app, render_template
from flask_mail import Message
from app import mail

#定义线程函数
def send_async_email(app, msg):
    #启动上下文程序
    with app.app_context():
        mail.send(msg)

#定义发送方法：to，主题，模板目录，其他参数
def send_email(to, subject, template, **kwargs):
    #此处没明白获取真实app对象
    app = current_app._get_current_object()
    msg = Message(app.config['FLASKY_MAIL_SUBJECT_PREFIX'] + ' ' + subject,
                  sender=app.config['FLASKY_MAIL_SENDER'], recipients=[to])
    msg.body = render_template(template + '.txt', **kwargs)
    msg.html = render_template(template + '.html', **kwargs)
    #加入线程
    thr = Thread(target=send_async_email, args=[app, msg])
    #启动线程
    thr.start()
    return thr