from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, BooleanField, ValidationError
from wtforms.validators import  DataRequired, Length, Email, Regexp, EqualTo
from app.models import User
#登录表单设置
class LoginForm(FlaskForm):
	#设置邮箱表格,用到Length()和Email()函数
	email = StringField('Email', validators=[DataRequired(), Length(1, 64), Email()])
	#设置password表格
	password = PasswordField('Password', validators=[DataRequired()])
	#设置复选框
	remember_me = BooleanField('Keep me logged in')
	#设置提交
	submit = SubmitField('Log In')

#注册表单设置
class RegistrationForm(FlaskForm):
	#注册邮箱
	email = StringField('Email', validators=[DataRequired(), Length(1, 64), Email()])
	#注册用户名
	username = StringField('Username', validators=[DataRequired(), Length(1,64),Regexp('^[A-Za-z][A-Za-z0-9_.]*$', 0,
																				   'Usernames must have only letters, '
																				   'numbers, dots or underscores')])
	#注册密码
	password =PasswordField('Password', validators=[
		DataRequired(), EqualTo('password2', message='Password must match')])
	#二次密码确认
	password2 = PasswordField('Confirm password', validators=[DataRequired()])
	#提交
	submit = SubmitField('Register')
	#邮箱验证重名
	def validate_email(self, field):
		#数据库查重
		if User.query.filter_by(email=field.data).first():
			#抛出错误
			raise ValidationError('Email has already registered')
	#用户验证重名,
	def validate_username(self,field):
		#数据库查重
		if User.query.filter_by(username=field.data).first():
			#抛出错误
			raise ValidationError('Username  already in use')

#更改密码表单
class ChangePasswordForm(FlaskForm):
	#旧密码
    old_password = PasswordField('Old password', validators=[DataRequired()])
	#新密码
    password = PasswordField('New password', validators=[
        DataRequired(), EqualTo('password2', message='Passwords must match.')])
	#新密码二次验证
    password2 = PasswordField('Confirm new password',
                              validators=[DataRequired()])
	#提交
    submit = SubmitField('Update Password')

#密码重设请求表单
class PasswordResetRequestForm(FlaskForm):
	#邮箱
    email = StringField('Email', validators=[DataRequired(), Length(1, 64),
                                             Email()])
	#提交
    submit = SubmitField('Reset Password')

#重设密码表单
class PasswordResetForm(FlaskForm):
	#新密码
    password = PasswordField('New Password', validators=[
        DataRequired(), EqualTo('password2', message='Passwords must match')])
	#新密码二次验证
    password2 = PasswordField('Confirm password', validators=[DataRequired()])
	#提交
    submit = SubmitField('Reset Password')


#更改邮箱表单
class ChangeEmailForm(FlaskForm):
	#新邮箱
    email = StringField('New Email', validators=[DataRequired(), Length(1, 64),
                                                 Email()])
	#当前验证密码
    password = PasswordField('Password', validators=[DataRequired()])
	#提交
    submit = SubmitField('Update Email Address')
	#邮箱验证是否已用
    def validate_email(self, field):
        if User.query.filter_by(email=field.data).first():
            raise ValidationError('Email already registered.')