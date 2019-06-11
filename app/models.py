from app import db
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin, AnonymousUserMixin
from app import login_manager
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from flask import current_app, request, url_for
from datetime import datetime
import hashlib
from markdown import markdown
import bleach
from app.exceptions import ValidationError

#定义Permission类
class Permission:
	#关注权限
	FOLLOW = 0x01
	#评论权限
	COMMENT = 0x02
	#发文章评论
	WRITE_ARTICLES = 0x04
	#中控评论
	MODERATE_COMMENTS = 0x08
	#管理者
	ADMINISTER = 0x80

class Role(db.Model):
    #设置表名
	__tablename__ = 'roles'
    #设置id，表主键
	id = db.Column(db.Integer, primary_key=True)
    #设置名称，不允许重复出现
	name = db.Column(db.String(64), unique=True)
    #关联users表
	users = db.relationship('User', backref='role', lazy='dynamic')
    #default表
	default = db.Column(db.Boolean, default=False, index=True)
    #角色写入
	permissions = db.Column(db.Integer)

	#静态函数
	@staticmethod
	#添加角色
	def insert_roles():
		roles = {
			#普通用户权限
            'User':(Permission.FOLLOW|
                    Permission.COMMENT|
                    Permission.WRITE_ARTICLES, True),
			#控评用户权限
            'Moderator':(Permission.FOLLOW|
                         Permission.WRITE_ARTICLES|
                         Permission.MODERATE_COMMENTS|
                         Permission.COMMENT, False),
			#管理者
            'Administrators':(0xff, False)
        }
		#列表循环
		for r in roles:
			#确认列表中是否存在
			role = Role.query.filter_by(name=r).first()
			#导入角色
			if role is None:
				role = Role(name=r)
				role.permissions = roles[r][0]
				role.default = roles[r][1]
				db.session.add(role)
		#提交
		db.session.commit()
	
	def __repr__(self):
		return  '<Role %r>' % self.name

#关注类
class Follow(db.Model):
	#表格
	__table_name__ = 'follows'
	#关注者id
	follower_id = db.Column(db.Integer, db.ForeignKey('users.id'), primary_key=True)
	#被关注者id
	followed_id = db.Column(db.Integer, db.ForeignKey('users.id'), primary_key=True)
	#时间戳
	timestamp = db.Column(db.DateTime, default=datetime.utcnow)

#用户类
class User(UserMixin, db.Model):
	#设置表名
	__tablename__ = 'users'
	#设置id，表主键
	id = db.Column(db.Integer, primary_key=True)
	#设置邮箱
	email = db.Column(db.String(64), unique=True,index=True)
	#设置名称,设置为引录
	username = db.Column(db.String(64), unique=True, index=True)
	#返回一个可读性的字符串表示模型，可在调试和测试时使用
	#外键
	role_id = db.Column(db.Integer, db.ForeignKey('roles.id'))
	#设置密码散列值
	password_hash = db.Column(db.String(128))
	#令牌表
	confirmed = db.Column(db.Boolean, default=False)
	#名字
	name = db.Column(db.String(64))
	#地址
	location = db.Column(db.String(64))
	#说明
	about_me = db.Column(db.Text())
	#创号时间
	member_since = db.Column(db.DateTime(), default=datetime.utcnow)
	#最后登录时间
	last_seen = db.Column(db.DateTime(), default=datetime.utcnow)
	#图标hash
	avatar_hash = db.Column(db.String(32))
	#关联表格一对多一人多文
	posts = db.relationship('Post', backref='author', lazy='dynamic')
	#关联表格一对多一人关注多人
	followed = db.relationship('Follow', foreign_keys=[Follow.follower_id], backref=db.backref('follower',lazy='joined'), lazy='dynamic',
	                           cascade='all, delete-orphan')
	#关联表格一对多一人被多人关注，dynamic，因此关系属性不会直接返回记录，而是返回查询对象
	followers = db.relationship('Follow', foreign_keys=[Follow.followed_id], backref=db.backref('followed',lazy='joined'), lazy='dynamic',
								cascade='all, delete-orphan')
	#关联表格一对多一人多评论，lazy 参数作用不一样。lazy 参数都在“一”这一侧设定，返回的结果是“多”这一侧中的记录。
	comments = db.relationship('Comment', backref='author', lazy='dynamic')
	
	
	
	# 用户角色化方法
	def __init__(self, **kwargs):
		#super函数
		super(User, self).__init__(**kwargs)
		#自己关注自己
		self.follow(self)
		# 用户角色化
		if self.role is None:
			# 如果为管理员
			if self.email == current_app.config['FLASKY_ADMIN']:
				#用户角色赋予管理员
				self.role = Role.query.filter_by(permissions=0xff).first()
			#用户角色如果不存在就自定义为真
			if self.role is None:
				# 普通角色
				self.role = Role.query.filter_by(default=True).first()
	
	
	# 普通角色角色认证方法
	def can(self, permissions):
		return self.role is not None and \
		       (self.role.permissions & permissions) == permissions
	# 管理员认证
	def is_administrator(self):
		#套用普通角色方法
		return self.can(Permission.ADMINISTER)
	#生成图像hash
	def gravatar_hash(self):
		return hashlib.md5(self.email.lower().encode('utf-8')).hexdigest()
	#图像生成
	def gravatar(self, size=10, default='identicon', rating='g'):
		if  request.is_secure:
			url = 'https://secure.gravatar.com/avatar'
		else:
			url = 'http://www.gravatar.com/avatar'
		hash = hashlib.md5(self.email.encode('utf-8')).hexdigest()
		return '{url}/{hash}?s={size}&d={default}&r={rating}'.format(url=url, hash=hash, size=size, default=default, rating=rating)
	#刷新用户的最后访问时间
	def ping(self):
		#最后访问时间赋值
		self.last_seen = datetime.utcnow()
		db.session.add(self)
	#关注函数
	def follow(self, user):
		if not self.is_following(user):
			f = Follow(follower=self, followed=user)
			db.session.add(f)
	#取消关注函数
	def unfollow(self, user):
		#筛选关注者id是user_id的用户
		f = self.followed.filter_by(followed_id=user.id).first()
		if f:
			#如果为真删除关注者
			db.session.delete(f)
	
	#确认关注函数
	def is_following(self, user):
		#如果user不存在，则为假
		if user.id is None:
			return False
		#如果user存在通过关注函数返回真假
		return  self.followed.filter_by(followed_id=user.id).first() is not None
	#确认被关注函数
	def is_followed_by(self, user):
		#如果用户存在，返回False
		if user.id is None:
			return False
		#否则通过被关注函数返回真假
		return self.followers.filter_by(follower_id=user.id).first() is not None
	#返回json数据
	def to_json(self):
		json_user = {
			#user的url地址
			'url': url_for('api.get_user', id=self.id, _external=True),
			#username
			'username': self.username,
			#注册时间
			'member_since': self.member_since,
			#随后登录时间
			'last_seen': self.last_seen,
			#返回文章地址
			'posts_url': url_for('api.get_user_posts', id=self.id, _external=True),
			#返回被关注者文章地址
			'followed_posts_url': url_for('api.get_user_followed_posts',
			                              id=self.id, _external=True),
			#返回文章数
			'post_count': self.posts.count()
		}
		return json_user
	
	
	
	#用户自己关注自己函数
	@staticmethod
	def add_self_follows():
		for user in User.query.all():
			if not user.is_following(user):
				user.follow(user)
				db.session.add(user)
				db.session.commit()

	#生成令牌方法
	def generate_confirmation_token(self, expiration=3600):
		#导入密令和过期时间
		s = Serializer(current_app.config['SECRET_KEY'], expiration)
		#生成json格式的令牌
		return s.dumps({'confirm': self.id})
	#确认密匙
	def confirm(self, token):
		s = Serializer(current_app.config['SECRET_KEY'])
		#尝试解码令牌
		try:
			data = s.loads(token)
		except:
			return False
		#检验解码id是否对应当前用户id
		if data.get('confirm') != self.id:
			return False
		self.confirmed = True
		# 添加会话
		db.session.add(self)
		#提交数据
		db.session.commit()
		return True
	
	#生成重置密码token
	def generate_reset_token(self, expiration=3600):
		s = Serializer(current_app.config['SECRET_KEY'], expiration)
		return s.dumps({'reset': self.id}).decode('utf-8')
	
	@staticmethod
	#重置密码token验证
	def reset_password(token, new_password):
		s = Serializer(current_app.config['SECRET_KEY'])
		#使用try方法
		try:
			data = s.loads(token.encode('utf-8'))
		except:
			return False
		#使用数据库查询
		user = User.query.get(data.get('reset'))
		#用户存在就返回错误
		if user is None:
			return False
		#如果为真，用户密码修改
		user.password = new_password
		#加入会话
		db.session.add(user)
		return True
	#生成更改邮箱token
	def generate_email_change_token(self, new_email, expiration=3600):
		s = Serializer(current_app.config['SECRET_KEY'], expiration)
		return s.dumps(
			{'change_email': self.id, 'new_email': new_email}).decode('utf-8')
	#更改邮箱token验证
	def change_email(self, token):
		s = Serializer(current_app.config['SECRET_KEY'])
		try:
			data = s.loads(token.encode('utf-8'))
		except:
			return False
		#返回用户id如果不是当前用户id
		if data.get('change_email') != self.id:
			#返回错误
			return False
		#如果为真，新邮箱赋值
		new_email = data.get('new_email')
		if new_email is None:
			return False
		#如果邮箱用户存在返回错误
		if self.query.filter_by(email=new_email).first() is not None:
			return False
		#邮箱更改
		self.email = new_email
		#hash更改
		self.avatar_hash = self.gravatar_hash()
		#提交会话
		db.session.add(self)
		return True
	
	#生成密码散列值方法
	@property
	def password(self):
		raise AttributeError('password is not a readable attribute')
	@password.setter
	#生成散列值
	def password(self, password):
		self.password_hash = generate_password_hash(password)
	#校验散列值
	def verify_password(self,password):
		return check_password_hash(self.password_hash, password)
	
	#被关注者文章
	@property
	def followed_posts(self):
		#返回被关注者文章
		return Post.query.join(Follow, Follow.followed_id == Post.author_id)\
			.filter(Follow.follower_id ==self.id)
	
	@staticmethod
	#创造虚拟用户
	def generate_fake(count=100):
		from sqlalchemy.exc import IntegrityError
		from random import seed
		import forgery_py
		
		seed()
		for i in range(count):
			u = User(email=forgery_py.internet.email_address(),
			         username=forgery_py.internet.user_name(True),
			         password=forgery_py.lorem_ipsum.word(),
			         confirmed=True,
			         name=forgery_py.name.full_name(),
			         location=forgery_py.address.city(),
			         about_me=forgery_py.lorem_ipsum.sentence(),
			         member_since=forgery_py.date.date(True))
			db.session.add(u)
			#提交数据
			try:
				db.session.commit()
			#出现错误数据回滚
			except IntegrityError:
				db.session.rollback()
	
	#生成认证token
	def generate_auth_token(self, expiration):
		s = Serializer(current_app.config['SECRET_KEY'],
		               expires_in=expiration)
		return s.dumps({'id': self.id}).decode('utf-8')
	
	
	
	@staticmethod
	#检查认证token
	def verify_auth_token(token):
		s = Serializer(current_app.config['SECRET_KEY'])
		try:
			data = s.loads(token)
		except:
			return None
		return User.query.get(data['id'])
	
	def __repr__(self):
		return '<User %r>' % self.username

#匿名用户检查角色许可
class AnonymousUser(AnonymousUserMixin):
	def can(self, permissions):
		return False
	def is_administrator(self):
		return False
login_manager.anonymous_user = AnonymousUser

#FLASK-LOGIN要求使用回调函数，使用指定的标识符加载用户
@login_manager.user_loader
def load_user(user_id):
	return User.query.get(int(user_id))

#Post类
class Post(db.Model):
	#表格名
	__tablename__ = 'posts'
	#id
	id = db.Column(db.Integer, primary_key=True)
	#文章正文
	body = db.Column(db.Text)
	#时间戳
	timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)
	#作者id
	author_id = db.Column(db.Integer, db.ForeignKey('users.id'))
	#网页版正文
	body_html = db.Column(db.Text)
	#关系表
	comments = db.relationship('Comment', backref='post', lazy='dynamic')
	#生成json数据
	def to_json(self):
		json_post = {
			#文章地址
			'url': url_for('api.get_post', id=self.id, _external=True),
			#正文
			'body': self.body,
			#正文网页版
			'body_html': self.body_html,
			#时间戳
			'timestamp': self.timestamp,
			#作者地址
			'author': url_for('api.get_user', id=self.author_id,
			                  _external=True),
			#评论地址
			'comments_url': url_for('api.get_post_comments', id=self.id, _external=True),
			#评论数
			'comment_count': self.comments.count()
		}
		return json_post
	
	@staticmethod
	#从json数据创作
	def from_json(json_post):
		#获取body部分
		body = json_post.get('body')
		if body is None or body == '':
			raise ValidationError('post does not have a body')
		#返回Post
		return Post(body=body)
	
	#自动生成POST
	@staticmethod
	def generate_fake(count=100):
		from random import seed, randint
		import forgery_py
		
		seed()
		user_count = User.query.count()
		for i in range(count):
			#offset偏移生成用户
			u = User.query.offset(randint(0, user_count - 1)).first()
			#生成用户文章
			p = Post(body=forgery_py.lorem_ipsum.sentences(randint(1, 3)),
			         timestamp=forgery_py.date.date(True),
			         author=u)
			#提交会话
			db.session.add(p)
			#提交数据
			db.session.commit()
	
	@staticmethod
	#text转html方法markdown() 函数初步把Markdown 文本转换成HTML。然后，把得到的结果和允许使用的HTML
	# 标签列表传给clean() 函数。clean() 函数删除
	#所有不在白名单中的标签。转换的最后一步由linkify() 函数完成，这个函数由Bleach 提
	#供，把纯文本中的URL 转换成适当的<a> 链接。最后一步是很有必要的，因为Markdown
	#规范没有为自动生成链接提供官方支持。PageDown 以扩展的形式实现了这个功能，因此
	#在服务器上要调用linkify() 函数。
	def on_changed_body(target, value, oldvalue, initiator):
		allowed_tags = ['a', 'abbr', 'acronym', 'b', 'blockquote', 'code',
		                'em', 'i', 'li', 'ol', 'pre', 'strong', 'ul',
		                'h1', 'h2', 'h3', 'p']
		target.body_html = bleach.linkify(
			bleach.clean(markdown(value, output_format='html'), tags=allowed_tags, strip=True))
#只要这个类实例的body 字段设了新值，函数就会自动被调用
db.event.listen(Post.body, 'set', Post.on_changed_body)


#评论类
class Comment(db.Model):
	#表格名字
	__tablename__ = 'comments'
	#id
	id = db.Column(db.Integer, primary_key=True)
	#评论正文
	body = db.Column(db.Text)
	#评论正文网页版
	body_html = db.Column(db.Text)
	#时间戳
	timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)
	#bool值选择，控评选择
	disabled = db.Column(db.Boolean)
	#作者id外键
	author_id = db.Column(db.Integer, db.ForeignKey('users.id'))
	#文章id外键
	post_id = db.Column(db.Integer, db.ForeignKey('posts.id'))
	
	#生成json数据
	def to_json(self):
		json_comment = {
			#评论地址
			'url': url_for('api.get_comment', id=self.id, _external=True),
			#文章地址
			'post_url': url_for('api.get_post', id=self.post_id, _external=True),
			#评论正文
			'body': self.body,
			#评论html格式
			'body_html': self.body_html,
			#评论时间戳
			'timestamp': self.timestamp,
			#评论作者
			'author': url_for('api.get_user', id=self.author_id,
			                  _external=True)
		}
		return json_comment
	#生成json数据
	@staticmethod
	def from_json(json_comment):
		body = json_comment.get('body')
		if body is None or body == '':
			raise ValidationError('comment does not have a body')
		return Comment(body=body)
	
	
	#文本转html 实现markdown功能
	@staticmethod
	def on_changed_body(target, value, oldvalue, initiator):
		allowed_tags = ['a', 'abbr', 'acronym', 'b', 'code', 'em', 'i',
					'strong']
		target.body_html = bleach.linkify(
			bleach.clean(markdown(value, output_format='html'),tags=allowed_tags, strip=True))
db.event.listen(Comment.body, 'set', Comment.on_changed_body)