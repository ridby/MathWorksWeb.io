from flask import render_template, url_for, flash, redirect, request, Blueprint, send_from_directory
from app import db, bcrypt
from app.forms import RegistrationForm, LoginForm, PostForm, PresentationForm
from app.models import User, Post, Presentation
from flask_login import login_user, current_user, logout_user, login_required
import os
import secrets
from PIL import Image
from flask import current_app
from flask import request, jsonify
from werkzeug.security import check_password_hash
from werkzeug.security import generate_password_hash

bp = Blueprint('routes', __name__)

@bp.route('/')
@bp.route('/index')
def index():
    return render_template('index.html', title='Главная')

@bp.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('routes.profile'))
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(name=form.name.data, email=form.email.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Ваш аккаунт создан!', 'success')
        return redirect(url_for('routes.login'))
    return render_template('register.html', title='Регистрация', form=form)


@bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('routes.profile'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('routes.profile'))
        else:
            flash('Вход не выполнен. Пожалуйста, проверьте email и пароль.', 'danger')
    return render_template('login.html', title='Вход', form=form)

@bp.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('routes.index'))

@bp.route('/profile')
@login_required
def profile():
    return render_template('profile.html', title='Профиль')

@bp.route('/presentations')
def presentations():
    presentations = Presentation.query.order_by(Presentation.date_posted.desc()).all()
    return render_template('presentations.html', title='Презентации', presentations=presentations)

def save_file(form_file):
    random_hex = secrets.token_hex(8)
    _, f_ext = os.path.splitext(form_file.filename)
    file_fn = random_hex + f_ext
    file_path = os.path.join(current_app.root_path, 'static/presentations', file_fn)
    form_file.save(file_path)
    return file_fn

@bp.route('/presentation/new', methods=['GET', 'POST'])
@login_required
def new_presentation():
    if not current_user.is_admin:
        flash('У вас нет прав для загрузки презентаций!', 'danger')
        return redirect(url_for('routes.presentations'))
    form = PresentationForm()
    if form.validate_on_submit():
        file_path = save_file(form.file.data)
        presentation = Presentation(title=form.title.data, author=current_user, file_path=file_path)
        db.session.add(presentation)
        db.session.commit()
        flash('Презентация была загружена!', 'success')
        return redirect(url_for('routes.presentations'))
    return render_template('create_presentation.html', title='Новая презентация', form=form, legend='Новая презентация')

@bp.route('/presentation/<int:presentation_id>')
def download_presentation(presentation_id):
    presentation = Presentation.query.get_or_404(presentation_id)
    return send_from_directory(directory='static/presentations', path=presentation.file_path, as_attachment=True)


@bp.route('/api/login', methods=['POST'])
def api_login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    
    user = User.query.filter_by(email=email).first()
    if user and bcrypt.check_password_hash(user.password, password):
        login_user(user)
        return jsonify({"status": "success", "message": "Logged in successfully", "user_id": user.id}), 200
    else:
        return jsonify({"status": "failure", "message": "Invalid email or password"}), 401

@bp.route('/api/user/<int:user_id>', methods=['GET'])
def get_user(user_id):
    user = User.query.get(user_id)
    if user:
        return jsonify({
            'id': user.id,
            'name': user.name,
            'email': user.email
        }), 200
    else:
        return jsonify({'message': 'User not found'}), 404

@bp.route('/increment_solved_tasks', methods=['POST'])
def increment_solved_tasks():
    try:
        # Ваш код для обработки POST-запроса здесь
        return 'Success', 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500
