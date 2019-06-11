from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, SubmitField, BooleanField, ValidationError, SelectField
from wtforms.validators import  Length, DataRequired, Email, Regexp
from app.models import User, Role
from flask_pagedown.fields import PageDownField
#修改个人资料表单
class EditProfileForm(FlaskForm):
	name = StringField('Real name', validators=[Length(0, 64)] )
	location = StringField('Location', validators=[Length(0,64)])
	about_me = TextAreaField('About me')
	submit = SubmitField('Submit')

#管理员修改资料表单
class EditProfileAdminForm(FlaskForm):
	email = StringField('Email',validators=[DataRequired(), Length(1, 64),
	                                        Email()])
	username = StringField('Username', validators=[
		DataRequired(), Length(1, 64),Regexp('^[A-Za-z][A-Za-z0-9_.]*$', 0,
		                                'Usernames must have only letters, '
		                                'numbers, dots or underscores')])
	confirmed = BooleanField('Confirmed')
	#元组中的标识符是角色的id整数
	role = SelectField('Role',coerce=int)
	name = StringField('Name', validators=[Length(0,64)])
	location = StringField('Location', validators=[Length(0, 64)])
	about_me = TextAreaField('About me')
	submit = SubmitField('Submit')
	#初始化赋值
	def __init__(self, user, *args, **kwargs):
		super(EditProfileAdminForm, self).__init__(*args, **kwargs)
		#SelectField 实例必须在其choices 属性中设置各选项。由多个两个元素的元组组成，选项标识符和文本字符串
		self.role.choices = [(role.id, role.name)
		                     for role in Role.query.order_by(Role.name).all()]
		self.user = user
	#email验证，排除自身邮箱和存在邮箱
	def validate_email(self, field):
		#如果输入email存在且不等于本身返回错误
		if field.data != self.user.email and \
				User.query.filter_by(email=field.data).first():
			raise ValidationError('email already registered')
	#用户昵称验证，如果昵称存在且不是当前昵称返回错误
	def validate_username(self, field):
		if field.data != self.user.username and \
				User.query.filter_by(username=field.data).first():
			raise ValidationError('username already in user')
		
		
#文章写入表单
class PostForm(FlaskForm):
	body = PageDownField('what is your mind', validators=[DataRequired()])
	submit = SubmitField('Submit')

#评论写入表单
class CommentForm(FlaskForm):
	body = StringField('Enter your comment', validators=[DataRequired()])
	submit = SubmitField('Submit')