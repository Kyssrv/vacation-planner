from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectField, IntegerField
from wtforms.validators import DataRequired, Regexp, Length, Optional, NumberRange
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
from contextlib import contextmanager
from datetime import date, timedelta

app = Flask(__name__)
app.secret_key = 'super_secret_key_change_in_production'

LOGIN_RE = r'^[a-zA-Z0-9!@#$%^&*()]+$'

@contextmanager
def get_db():
    conn = sqlite3.connect('vacations.db')
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

class LoginForm(FlaskForm):
    login = StringField('Логин', [DataRequired(), Regexp(LOGIN_RE, message="Только латиница, цифры, !@#$%^&*()")])
    password = PasswordField('Пароль', [DataRequired(), Length(min=6), Regexp(LOGIN_RE, message="Только латиница, цифры, !@#$%^&*()")])
    submit = SubmitField('Вход')

class RegisterForm(FlaskForm):
    full_name = StringField('ФИО', [DataRequired()])
    login = StringField('Логин', [DataRequired(), Regexp(LOGIN_RE, message="Только латиница, цифры, !@#$%^&*()")])
    password = PasswordField('Пароль', [DataRequired(), Length(min=6), Regexp(LOGIN_RE, message="Только латиница, цифры, !@#$%^&*()")])
    submit = SubmitField('Регистрация')

class AdminUserForm(FlaskForm):
    full_name = StringField('ФИО', [DataRequired()])
    login = StringField('Логин', [DataRequired(), Regexp(LOGIN_RE, message="Только латиница, цифры, !@#$%^&*()")])
    password = PasswordField('Пароль', [Optional(), Length(min=6), Regexp(LOGIN_RE, message="Только латиница, цифры, !@#$%^&*()")])
    submit = SubmitField('Добавить')

class AdminVacationForm(FlaskForm):
    user_id = SelectField('Пользователь', [DataRequired()])
    year = IntegerField('Год', [DataRequired(), NumberRange(2000, 2100)])
    week_num = IntegerField('Неделя', [DataRequired(), NumberRange(1, 52)])
    submit = SubmitField('Добавить отпуск')

class ProfileForm(FlaskForm):
    full_name = StringField('ФИО', [DataRequired()])
    new_password = PasswordField('Новый пароль', [
        Optional(),
        Length(min=6),
        Regexp(LOGIN_RE, message="Только латиница, цифры, !@#$%^&*()")
    ])
    submit = SubmitField('Сохранить')

@app.route('/', methods=['GET', 'POST'])
def index():
    if 'user_id' in session:
        return redirect(url_for('calendar'))

    form = LoginForm()
    if form.validate_on_submit():
        with get_db() as conn:
            user = conn.execute('SELECT * FROM users WHERE login = ?', (form.login.data,)).fetchone()
            if user and check_password_hash(user['password_hash'], form.password.data):
                session['user_id'] = user['id']
                session['full_name'] = user['full_name']
                session['is_admin'] = user['is_admin']
                return redirect(url_for('calendar'))
        flash('Неверный логин/пароль')
    return render_template('login.html', form=form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'user_id' in session:
        return redirect(url_for('calendar'))

    form = RegisterForm()
    if form.validate_on_submit():
        try:
            with get_db() as conn:
                pwd_hash = generate_password_hash(form.password.data)
                conn.execute(
                    'INSERT INTO users (full_name, login, password_hash, is_admin) VALUES (?, ?, ?, 0)',
                    (form.full_name.data, form.login.data, pwd_hash)
                )
            flash('Регистрация успешна!')
            return redirect(url_for('index'))
        except sqlite3.IntegrityError:
            flash('Логин уже занят')
    return render_template('register.html', form=form)

@app.route('/admin', methods=['GET', 'POST'])
def admin_dashboard():
    if not session.get('is_admin'):
        flash('Доступ только для администратора')
        return redirect(url_for('index'))

    form_user = AdminUserForm()
    form_vacation = AdminVacationForm()

    with get_db() as conn:
        users = conn.execute('SELECT * FROM users ORDER BY full_name').fetchall()
        vacations = conn.execute('''
            SELECT v.*, u.full_name FROM vacations v
            JOIN users u ON v.user_id = u.id
            ORDER BY v.year, v.week_num
        ''').fetchall()
        form_vacation.user_id.choices = [(str(u['id']), u['full_name']) for u in users]

    if form_user.validate_on_submit():
        with get_db() as conn:
            try:
                pwd_hash = generate_password_hash(form_user.password.data or 'default123')
                conn.execute(
                    'INSERT INTO users (full_name, login, password_hash, is_admin) VALUES (?, ?, ?, 0)',
                    (form_user.full_name.data, form_user.login.data, pwd_hash)
                )
                flash('Пользователь добавлен')
            except sqlite3.IntegrityError:
                flash('Логин уже существует')
        return redirect(url_for('admin_dashboard'))

    if form_vacation.validate_on_submit():
        with get_db() as conn:
            try:
                conn.execute(
                    'INSERT INTO vacations (user_id, year, week_num) VALUES (?, ?, ?)',
                    (int(form_vacation.user_id.data), form_vacation.year.data, form_vacation.week_num.data)
                )
                flash('Отпуск добавлен')
            except sqlite3.IntegrityError:
                flash('Неделя уже занята')
        return redirect(url_for('admin_dashboard'))

    return render_template('dashboard.html', users=users, vacations=vacations,
                           form_user=form_user, form_vacation=form_vacation)

@app.route('/calendar/<int:year>')
@app.route('/calendar/', defaults={'year': date.today().year})
def calendar(year=date.today().year):
    if 'user_id' not in session:
        return redirect(url_for('index'))

    is_admin = bool(session.get('is_admin'))

    with get_db() as conn:
        weeks = []
        first_day = date(year, 1, 1)

        for w in range(1, 53):
            week_start = first_day + timedelta(days=(w-1)*7)
            week_end = min(week_start + timedelta(days=6), date(year, 12, 31))

            owner = conn.execute('''
                SELECT u.full_name FROM vacations v
                JOIN users u ON v.user_id = u.id
                WHERE v.year = ? AND v.week_num = ?
            ''', (year, w)).fetchone()

            weeks.append({
                'num': w,
                'start': week_start,
                'end': week_end,
                'owner': owner['full_name'] if owner else None
            })

        user_vacations = set(
            row['week_num'] for row in conn.execute(
                'SELECT week_num FROM vacations WHERE user_id = ? AND year = ?',
                (session['user_id'], year)
            )
        )

    taken_count = len(user_vacations)

    is_past = year < date.today().year

    if is_admin:
        is_past = True

    warning = (taken_count < 4) and (year >= date.today().year) and (not is_admin)

    return render_template('calendar.html', weeks=weeks, year=year,
                           user_vacations=user_vacations, taken_count=taken_count,
                           warning=warning, is_past=is_past, is_admin=is_admin)

@app.route('/toggle_vacation', methods=['POST'])
def toggle_vacation():
    if 'user_id' not in session or session.get('is_admin'):
        return redirect(url_for('index'))

    year = int(request.form['year'])
    week = int(request.form['week'])

    if year < date.today().year:
        return redirect(url_for('calendar', year=year))

    with get_db() as conn:
        vacation = conn.execute(
            'SELECT id, user_id FROM vacations WHERE year = ? AND week_num = ?',
            (year, week)
        ).fetchone()

        if vacation:
            if vacation['user_id'] == session['user_id']:
                conn.execute('DELETE FROM vacations WHERE id = ?', (vacation['id'],))
            else:
                flash('Неделя занята другим сотрудником!')
        else:
            count = conn.execute(
                'SELECT COUNT(*) AS cnt FROM vacations WHERE user_id = ? AND year = ?',
                (session['user_id'], year)
            ).fetchone()['cnt']

            if count < 4:
                conn.execute(
                    'INSERT INTO vacations (user_id, year, week_num) VALUES (?, ?, ?)',
                    (session['user_id'], year, week)
                )
            else:
                flash('Максимум 4 недели в год!')

    return redirect(url_for('calendar', year=year))

@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'user_id' not in session:
        return redirect(url_for('index'))

    form = ProfileForm()

    with get_db() as conn:
        user = conn.execute('SELECT id, full_name, login FROM users WHERE id = ?', (session['user_id'],)).fetchone()
        if not user:
            session.clear()
            return redirect(url_for('index'))

        if request.method == 'GET':
            form.full_name.data = user['full_name']

        if form.validate_on_submit():
            conn.execute('UPDATE users SET full_name = ? WHERE id = ?', (form.full_name.data, session['user_id']))
            session['full_name'] = form.full_name.data

            if form.new_password.data and form.new_password.data.strip():
                conn.execute(
                    'UPDATE users SET password_hash = ? WHERE id = ?',
                    (generate_password_hash(form.new_password.data), session['user_id'])
                )

            flash('Профиль обновлён')
            return redirect(url_for('profile'))

    return render_template('profile.html', form=form, user=user)

@app.route('/delete_profile', methods=['POST'])
def delete_profile():
    if 'user_id' not in session:
        return redirect(url_for('index'))

    if session.get('is_admin'):
        flash('Администратора удалять нельзя')
        return redirect(url_for('profile'))

    with get_db() as conn:
        conn.execute('DELETE FROM users WHERE id = ?', (session['user_id'],))

    session.clear()
    flash('Профиль удалён')
    return redirect(url_for('index'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)
