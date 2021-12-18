from datetime import date
from functools import wraps
from sqlalchemy import ForeignKey
from flask_gravatar import Gravatar
from flask_ckeditor import CKEditor
from flask_bootstrap import Bootstrap
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from forms import RegisterForm, LoginForm, CreatePostForm, CommentForm
from werkzeug.security import generate_password_hash, check_password_hash
from flask import Flask, render_template, redirect, url_for, flash, request, abort, Response
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user

app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap(app)

# connect to database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)

gravatar = Gravatar(app, size=100, rating='g', default='retro',
                    force_default=False, force_lower=False, use_ssl=False, base_url=None)


# configure table
class User(UserMixin, db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(250), unique=True, nullable=False)
    password = db.Column(db.String(250), nullable=False)
    name = db.Column(db.String(250), nullable=False)
    blogposts = relationship('BlogPost', back_populates='user')
    comments = relationship('Comment', back_populates='user')


class BlogPost(db.Model):
    __tablename__ = "blogpost"
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, ForeignKey('user.id'))
    author = db.Column(db.String(250), nullable=False)
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=True)
    user = relationship('User', back_populates='blogposts')
    comments = relationship('Comment', back_populates='blogposts')


class Comment(db.Model):
    __tablename__ = 'comments'
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, ForeignKey('user.id'))
    blogpost_id = db.Column(db.Integer, ForeignKey('blogpost.id'))
    text = db.Column(db.String(250), nullable=False)
    author = db.Column(db.String(250), nullable=False)
    author_email = db.Column(db.String(250), nullable=False)
    user = relationship('User', back_populates='comments')
    blogposts = relationship('BlogPost', back_populates='comments')


db.create_all()


def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.id != 1:
            abort(403)
            abort(Response('Forbidden'))
        return f(*args, **kwargs)

    return decorated_function


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


@app.route('/')
def get_all_posts():
    posts = db.session.query(BlogPost).all()
    new_list_of_posts = [post for post in posts[::-1]]
    return render_template("index.html", all_posts=new_list_of_posts)


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if request.method == 'POST':
        email = request.form.get('email')
        user = db.session.query(User).filter_by(email=email).first()
        if user:
            error = 'You\'ve already signed up with that email, log in instead'
            return redirect(url_for('login', error=error))
        else:
            hashed_password = generate_password_hash(password=request.form.get('password'),
                                                     method='pbkdf2:sha256', salt_length=8)
            new_user = User(email=email,
                            password=hashed_password,
                            name=request.form.get('name'))
            db.session.add(new_user)
            db.session.commit()
            flash('Account created successfully')
            login_user(user=new_user, remember=True)
            return redirect(url_for('get_all_posts'))
    return render_template("register.html", form=form)


@app.route('/login', methods=['GET', 'POST'])
@app.route('/login/<error>', methods=['GET', 'POST'])
def login(error=None):
    form = LoginForm()
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = db.session.query(User).filter_by(email=email).first()
        if user:
            if check_password_hash(pwhash=user.password, password=password):
                login_user(user=user, remember=True)
                flash('Logged in successfully')
                return redirect(url_for('get_all_posts', user_name=user.name))
            else:
                error = 'Invalid password'
        else:
            error = 'Email address not found in our database'
    return render_template("login.html", form=form, error=error)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=['GET', 'POST'])
@app.route("/post/<int:post_id>/<error>", methods=['GET', 'POST'])
def show_post(post_id, error=None):
    form = CommentForm()
    all_comments = Comment.query.filter_by(blogpost_id=post_id).all()
    requested_post = BlogPost.query.get(post_id)
    if request.method == 'POST':
        if current_user.is_authenticated:
            new_comment = Comment(text=request.form.get('comment'), author=current_user.name,
                                  author_id=current_user.id, author_email=current_user.email, blogpost_id=post_id)
            db.session.add(new_comment)
            db.session.commit()
            flash('Comment created successfully')
            return redirect(url_for('show_post', post_id=post_id))
        else:
            error = 'You must login or register to comment'
            return redirect(url_for('login', error=error))
    return render_template("post.html", post=requested_post, form=form, all_comments=all_comments)


@app.route("/new-post", methods=['GET', 'POST'])
@login_required
@admin_only
def add_new_post():
    form = CreatePostForm()
    if request.method == 'POST':
        if form.validate_on_submit():
            new_post = BlogPost(
                title=form.title.data,
                subtitle=form.subtitle.data,
                body=form.body.data,
                img_url=form.img_url.data,
                author=current_user.name,
                author_id=current_user.id,
                date=date.today().strftime("%B %d, %Y")
            )
            db.session.add(new_post)
            db.session.commit()
            return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>", methods=['GET', 'POST'])
@login_required
@admin_only
def edit_post(post_id):
    post = db.session.query(BlogPost).filter_by(id=post_id).first()
    form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        body=post.body
    )
    if request.method == 'POST':
        rq = request.form.get
        edited_blog_post = BlogPost(title=rq('title'), date=post.date,
                                    subtitle=rq('subtitle'), author=post.author,
                                    img_url=rq('img_url'), body=rq('body'))
        ebp = edited_blog_post
        post.title = ebp.title
        post.subtitle = ebp.subtitle
        post.img_url = ebp.img_url
        post.author = ebp.author
        post.body = ebp.body
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))
    return render_template("make-post.html", form=form)


@app.route("/delete/<int:post_id>")
@login_required
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


if __name__ == "__main__":
    app.run(debug=True)
