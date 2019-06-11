from flask import render_template, flash, redirect, url_for, abort, current_app, request, make_response
from app.main import main
from app.models import User, Role, Post, Permission, Comment
from app.main.forms import EditProfileForm, EditProfileAdminForm, PostForm, CommentForm
from flask_login import login_required, current_user
from app import db
from app.decorators import admin_required, permission_required
from flask_sqlalchemy import get_debug_queries

@main.after_app_request
def after_request(response):
    for query in get_debug_queries():
        if query.duration >= current_app.config['FLASKY_SLOW_DB_QUERY_TIME']:
            current_app.logger.warning(
                'Slow query: %s\nParameters: %s\nDuration: %fs\nContext: %s\n'
                % (query.statement, query.parameters, query.duration,
                   query.context))
    return response

#主页路由
@main.route('/', methods=['GET', 'POST'])
def index():
    #表单实例化
    form = PostForm()
    #如果当前用户能写文章并且提交表格成功
    if current_user.can(Permission.WRITE_ARTICLES) and \
            form.validate_on_submit():
        #post赋值
        post = Post(body=form.body.data,
                    author=current_user._get_current_object())
        #提交会话
        db.session.add(post)
        提交数据
        db.session.commit()
        #重新定向回主页
        return redirect(url_for('.index'))
    #显示关注变量定为假，如果当前用户认证，变量赋值bool值，存储cookie中show——followed字段
    show_followed = False
    if current_user.is_authenticated:
        show_followed = bool(request.cookies.get('show_followed', ''))
    #如果为真查询国有用户关注的文章
    if show_followed:
        query = current_user.followed_posts
    #否则查询所有文章
    else:
        query = Post.query
    #分页显示，渲染页数获取
    page = request.args.get('page', 1, type=int)
    #显示某页中记录，paginate参数page（显示当前页内容）必选，查询返回pagination对象
    pagination = query.order_by(Post.timestamp.desc()).paginate(
        page, per_page=current_app.config['FLASKY_POSTS_PER_PAGE'],
        #超出总页显示错误
        error_out=False)
    #显示所有页的文章
    posts = pagination.items
    return render_template('index.html', form=form, posts=posts, show_followed=show_followed, pagination=pagination)

#显示所有文章
@main.route('/all')
@login_required
def show_all():
    #返回回应
    resp = make_response(redirect(url_for('.index')))
    #设置cookie中show_followed值
    resp.set_cookie('show_followed', '', max_age=30*24*60*60)
    return resp

#显示关注文章
@main.route('/followed')
@login_required
def show_followed():
    resp = make_response(redirect(url_for('.index')))
    # 设置cookie中show_followed值
    resp.set_cookie('show_followed', '1', max_age=30*24*60*60)
    return resp

#显示用户资料路由
@main.route('/user/<username>')
def user(username):
    #用户查询
    user = User.query.filter_by(username=username).first()
    #如果用户不存在
    if user is None:
        abort(404)
    #用户存在通过时间戳排列文章注意order_by
    posts = user.posts.order_by(Post.timestamp.desc()).all()
    return render_template('user.html', user=user, posts=posts)

#更改用户资料路由
@main.route('/edit-profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    #表单实例化
    form = EditProfileForm()
    #提交认证，表单数据赋值
    if form.validate_on_submit():
        current_user.name = form.name.data
        current_user.location = form.location.data
        current_user.about_me = form.about_me.data
        db.session.add(current_user)
        db.session.commit()
        flash('Your profile has been updated.')
        #更改后重定向到用户资料页
        return redirect(url_for('.user', username=current_user.username))
    form.name.data = current_user.name
    form.location.data = current_user.location
    form.about_me.data = current_user.about_me
    return render_template('edit_profile.html', form=form)


#管理员更改资料路由
@main.route('/edit-profile/<int:id>', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_profile_admin(id):
    #用户用id得到
    user = User.query.get_or_404(id)
    form = EditProfileAdminForm(user=user)
    if form.validate_on_submit():
        edit_user = current_user
        user.email = form.email.data
        user.username = form.username.data
        user.confirmed = form.confirmed.data
        user.role = Role.query.get(form.role.data)
        user.name = form.name.data
        user.location = form.location.data
        user.about_me = form.about_me.data
        db.session.add(user)
        db.session.commit()
        flash('The profile has been updated.')
        #重定向为当前用户资料页
        return redirect(url_for('.user', username=current_user.username))
    #显示当前用户资料
    form.email.data = user.email
    form.username.data = user.username
    form.confirmed.data = user.confirmed
    form.role.data = user.role_id
    form.name.data = user.name
    form.location.data = user.location
    form.about_me.data = user.about_me
    return render_template('edit_profile.html', form=form, user=user)

#显示文章界面
@main.route('/post/<int:id>', methods=['GET', 'POST'])
def post(id):
    #id为文章id
    post = Post.query.get_or_404(id)
    #评论表格实例化
    form = CommentForm()
    #表格提交认证
    if form.validate_on_submit():
        comment = Comment(body=form.body.data,
                          post=post,
                          #获取真正的评论者
                          author=current_user._get_current_object())
        db.session.add(comment)
        db.session.commit()
        flash('Your comment has been published.')
        #重定向到显示自己评论的页面
        return redirect(url_for('.post', id=post.id, page=-1))
    #页面赋值
    page = request.args.get('page', 1, type=int)
    #如果page== -1，page进行重新赋值为了显示最后页
    if page == -1:
        page = (post.comments.count() - 1) // \
            current_app.config['FLASKY_COMMENTS_PER_PAGE'] + 1
    pagination = post.comments.order_by(Comment.timestamp.asc()).paginate(
        page, per_page=current_app.config['FLASKY_COMMENTS_PER_PAGE'],
        error_out=False)
    comments = pagination.items
    return render_template('post.html', posts=[post], form=form,
                           comments=comments, pagination=pagination)

#编辑文章
@main.route('/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit(id):
    #post查询
    post = Post.query.get_or_404(id)
    #如果用户不是作者或者管理员返回禁止
    if current_user != post.author and \
            not current_user.can(Permission.ADMINISTER):
        abort(403)
    #表格实例化
    form = PostForm()
    if form.validate_on_submit():
        #修改文章
        post.body = form.body.data
        db.session.add(post)
        db.session.commit()
        flash('the post has been upgrade')
        #返回文章页面
        return redirect(url_for('.post', id=post.id))
    form.body.data = post.body
    #编辑文章页面
    return render_template('edit_post.html',form=form)


#关注用户
@main.route('/follow/<username>')
@login_required
@permission_required(Permission.FOLLOW)
def follow(username):
    #用户查询
    user = User.query.filter_by(username=username).first()
    #如果不存在
    if user is None:
        flash('Invalid user')
        #重定向
        return redirect(url_for('.index'))
    #如果当前用户已经关注，重定向会用户资料页
    if current_user.is_following(user):
        flash('you are already following this user')
        return redirect(url_for('.user', username=username))
    #调用follow方法
    current_user.follow(user)
    #提交数据
    db.session.commit()
    flash('you are now following %s,' % username)
    #重定向
    return redirect(url_for('.user', username=username))

#取消关注
@main.route('/unfollow/<username>')
@login_required
@permission_required(Permission.FOLLOW)
def unfollow(username):
    user = User.query.filter_by(username=username).first()
    if user is None:
        flash('Invalid user.')
        return redirect(url_for('.index'))
    if not current_user.is_following(user):
        flash('You are not following this user.')
        return redirect(url_for('.user', username=username))
    current_user.unfollow(user)
    db.session.commit()
    flash('You are not following %s anymore.' % username)
    return redirect(url_for('.user', username=username))

#关注者列表
@main.route('/followers/<username>')
def followers(username):
    #用户查询
    user = User.query.filter_by(username=username).first()
    if user is None:
        flash('Invalid user.')
        return redirect(url_for('.index'))
    page = request.args.get('page', 1, type=int)
    pagination = user.followers.paginate(
        page, per_page=current_app.config['FLASKY_FOLLOWERS_PER_PAGE'],
        error_out=False)
    #follows组成新的列表
    follows = [{'user': item.follower, 'timestamp': item.timestamp}
               for item in pagination.items]
    #传入参数
    return render_template('followers.html', user=user, title="Followers of",
                           endpoint='.followers', pagination=pagination,
                           follows=follows)


#被关注者列表
@main.route('/followed_by/<username>')
def followed_by(username):
    user = User.query.filter_by(username=username).first()
    if user is None:
        flash('Invalid user.')
        return redirect(url_for('.index'))
    page = request.args.get('page', 1, type=int)
    pagination = user.followed.paginate(
        page, per_page=current_app.config['FLASKY_FOLLOWERS_PER_PAGE'],
        error_out=False)
    #组成新的列表
    follows = [{'user': item.followed, 'timestamp': item.timestamp}
               for item in pagination.items]
    #传入参数
    return render_template('followers.html', user=user, title="Followed by",
                           endpoint='.followed_by', pagination=pagination,
                           follows=follows)


@main.route('/moderate')
@login_required
@permission_required(Permission.MODERATE_COMMENTS)
def moderate():
    page = request.args.get('page', 1, type=int)
    pagination = Comment.query.order_by(Comment.timestamp.desc()).paginate(
        page, per_page=current_app.config['FLASKY_COMMENTS_PER_PAGE'],
        error_out=False)
    comments = pagination.items
    return render_template('moderate.html', comments=comments,
                           pagination=pagination, page=page)


#控制评论enable
@main.route('/moderate/enable/<int:id>')
@login_required
@permission_required(Permission.MODERATE_COMMENTS)
def moderate_enable(id):
    #筛选comment
    comment = Comment.query.get_or_404(id)
    #设定disable为假
    comment.disabled = False
    #添加会话
    db.session.add(comment)
    #提交数据
    db.session.commit()
    #重定向
    return redirect(url_for('.moderate',
                            page=request.args.get('page', 1, type=int)))


#控制评论disable
@main.route('/moderate/disable/<int:id>')
@login_required
@permission_required(Permission.MODERATE_COMMENTS)
def moderate_disable(id):
    #comment筛选
    comment = Comment.query.get_or_404(id)
    #设置comment.disabled为真
    comment.disabled = True
    #添加会话
    db.session.add(comment)
    #提交数据
    db.session.commit()
    #重定向
    return redirect(url_for('.moderate',
                            page=request.args.get('page', 1, type=int)))