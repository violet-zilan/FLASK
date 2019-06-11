from flask import render_template, redirect, request, flash, url_for
from app.auth import auth
from app.auth.forms import LoginForm, RegistrationForm, ChangeEmailForm, ChangePasswordForm, PasswordResetForm, PasswordResetRequestForm
from flask_login import login_user, login_required, logout_user
from app import db
from app.Email import send_email
from flask_login import current_user
from app.models import User
@auth.route('/login', methods=['GET','POST'])
def login():
	#建立对象
	form = LoginForm()
	#提交验证
	if form.validate_on_submit():
		#比对数据库user是否存在
		user = User.query.filter_by(email=form.email.data).first()
		#如果存在用户且密码验证通过
		if user is not None and user.verify_password(form.password.data):
			#使用login_user函数将用户标记为登录状态，如果布尔选项标定则生成cookie选项
			login_user(user, form.remember_me.data)
			#提交请求后重定向
			return redirect(request.args.get('next') or url_for('main.index'))
		#如果登录错误，重新渲染表单
		flash('Invalid username or password')
	#指定模板保存在app/template/auth中
	return  render_template('auth/login.html', form=form)

#登出路由
@auth.route('/logout')
#保护路由
@login_required
def logout():
	#删除并重设用户对话函数
	logout_user()
	#随后显示flash信息确认该操作
	flash('you have been logged out')
	#重定向
	return redirect(url_for('main.index'))

#注册路由
@auth.route('/register', methods=['GET', 'POST'])
def register():
	#表单导入
	form = RegistrationForm()
	#提交确认
	if form.validate_on_submit():
		#注册信息
		user = User(email=form.email.data,
					username=form.username.data,
					password=form.password.data)
		#添加用户信息
		db.session.add(user)
		#提交用户信息
		db.session.commit()
		#生成令牌
		token = user.generate_confirmation_token()
		#邮箱发送验证网站
		send_email(user.email, 'Confirm your Account', 'auth/email/confirm', user=user, token=token )
		#flash提醒
		flash('confirmation email has been sent to you by email')
		#返回主页
		return redirect(url_for('main.index'))
	return render_template('auth/register.html', form=form)

#验证路由
@auth.route('/confirm/<token>')
#修饰器保护用户登录才会执行该视图函数
@login_required
def confirm(token):
    if current_user.confirmed:
        return redirect(url_for('main.index'))
    if current_user.confirm(token):
        flash('You have confirmed your account. Thanks!')
    else:
        flash('The confirmation link is invalid or has expired.')
    return redirect(url_for('main.index'))


#决定用户登录前可以做什么，每次请求前都会调用该函数
@auth.before_app_request
def before_request():
    #用户已登录，用户还没确认，请求端点不在用户蓝本里就会重定向
	if current_user.is_authenticated:
		#每次登陆调用ping方法更新最后登录时间
		current_user.ping()
		if not current_user.confirmed \
				and request.endpoint[:5] != 'auth.'\
				and request.endpoint != 'static':
            #重定向
			return redirect(url_for('auth.unconfirmed'))

#重定向路由
@auth.route('/unconfirmed')
def unconfirmed():
    #登录用户匿名，或者确认返回主页面
    if current_user.is_anonymous or current_user.confirmed:
        return redirect(url_for('main.index'))
    #返回重定向页面
    return render_template('auth/unconfirmed.html')

#用户确认路由
@auth.route('/confirm')
@login_required
#定义方法
def resend_confirmation():
    #当前用户生成令牌
	token = current_user.generate_confirmation_token()
    #重新发送验证邮件
	send_email(current_user.email, 'Confirm Your Account',
                'auth/email/confirm', user=current_user, token=token)
    #flash消息
	flash('A new confirmation email has been sent to you by email.')
    #重定向
	return redirect(url_for('main.index'))

#更改邮箱
@auth.route('/change-password', methods=['GET', 'POST'])
#登记required
@login_required
def change_password():
	#邮箱更改表单
    form = ChangePasswordForm()
	#如果提交
    if form.validate_on_submit():
	    #提交旧密码通过密码验证函数
        if current_user.verify_password(form.old_password.data):
	        #新密码赋值
            current_user.password = form.password.data
            db.session.add(current_user)
	        #提交
            db.session.commit()
	        #flash提醒密码改变
            flash('Your password has been updated.')
	        #返回主页面
            return redirect(url_for('main.index'))
        #如果旧密码没有验证通过
        else:
	        #flash提醒
            flash('Invalid password.')
	#返回网页
    return render_template("auth/change_password.html", form=form)

#重置密码
@auth.route('/reset', methods=['GET', 'POST'])
def password_reset_request():
	#如果当前用户匿名，返回主页
    if not current_user.is_anonymous:
        return redirect(url_for('main.index'))
	#如果不是匿名用户，表单实例
    form = PasswordResetRequestForm()
	#如果提交
    if form.validate_on_submit():
	    #筛选出邮箱正确的用户
        user = User.query.filter_by(email=form.email.data).first()
	    #如果用户存在
        if user:
	        #生成token
            token = user.generate_reset_token()
	        #发送邮件
            send_email(user.email, 'Reset Your Password',
                       'auth/email/reset_password',
                       user=user, token=token)
		#flash
        flash('An email with instructions to reset your password has been '
              'sent to you.')
	    #重定向到login页面
        return redirect(url_for('auth.login'))
	#返回重设邮箱密码界面
    return render_template('auth/reset_password.html', form=form)

#重设密码token验证
@auth.route('/reset/<token>', methods=['GET', 'POST'])
def password_reset(token):
	#如果当前用户非匿名，重返主页面
    if not current_user.is_anonymous:
        return redirect(url_for('main.index'))
	#表单实例化
    form = PasswordResetForm()
	#如果提交
    if form.validate_on_submit():
	    #通过token验证
        if User.reset_password(token, form.password.data):
            db.session.commit()
            flash('Your password has been updated.')
            return redirect(url_for('auth.login'))
        #未通过验证，定向回主页
        else:
            return redirect(url_for('main.index'))
    return render_template('auth/reset_password.html', form=form)

#更改邮箱
@auth.route('/change_email', methods=['GET', 'POST'])
@login_required
def change_email_request():
	#表单实例化
    form = ChangeEmailForm()
	#提交验证
    if form.validate_on_submit():
	    #密码验证通过
        if current_user.verify_password(form.password.data):
	        #更改邮箱
            new_email = form.email.data
	        #生成新邮箱
            token = current_user.generate_email_change_token(new_email)
            send_email(new_email, 'Confirm your email address',
                       'auth/email/change_email',
                       user=current_user, token=token)
            flash('An email with instructions to confirm your new email '
                  'address has been sent to you.')
            return redirect(url_for('main.index'))
        else:
            flash('Invalid email or password.')
    return render_template("auth/change_email.html", form=form)

#更改邮箱token验证
@auth.route('/change_email/<token>')
@login_required
def change_email(token):
	#通过token验证
    if current_user.change_email(token):
	    #邮箱提交
        db.session.commit()
        flash('Your email address has been updated.')
	#未通过验证
    else:
        flash('Invalid request.')
	#重定向
    return redirect(url_for('main.index'))
