import os
import re
import base64
import sqlite3
from datetime import datetime, timedelta
from functools import wraps
from flask import (
    Flask, g, render_template, request, redirect,
    url_for, session, flash, send_from_directory
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = 'supersecretkey'  # Change in production

DATABASE = 'database.db'
UPLOAD_FOLDER = 'static/uploads'
PER_PAGE = 6
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exc=None):
    db = g.pop('db', None)
    if db is not None:
        db.close()


def init_db():
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        # Users table with ban fields and role
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT "user",
            is_banned BOOLEAN NOT NULL DEFAULT 0,
            ban_until TIMESTAMP NULL,
            uploads_enabled INTEGER DEFAULT 0

        );
        """)
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS art (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            creator_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            image_filename TEXT,
            likes INTEGER DEFAULT 0,
            dislikes INTEGER DEFAULT 0,
            created TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (creator_id) REFERENCES users (id)
        );
        """)
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            art_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            comment TEXT NOT NULL,
            created TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (art_id) REFERENCES art (id),
            FOREIGN KEY (user_id) REFERENCES users (id)
        );
        """)
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS profile_comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            profile_owner_id INTEGER NOT NULL,
            commenter_id INTEGER NOT NULL,
            comment TEXT NOT NULL,
            created TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (profile_owner_id) REFERENCES users (id),
            FOREIGN KEY (commenter_id) REFERENCES users (id)
        );
        """)
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS followers (
            follower_id INTEGER NOT NULL,
            followed_id INTEGER NOT NULL,
            PRIMARY KEY (follower_id, followed_id),
            FOREIGN KEY (follower_id) REFERENCES users (id),
            FOREIGN KEY (followed_id) REFERENCES users (id)
        );
        """)
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS likes_dislikes (
            user_id INTEGER NOT NULL,
            art_id INTEGER NOT NULL,
            is_like BOOLEAN NOT NULL,
            PRIMARY KEY (user_id, art_id),
            FOREIGN KEY (user_id) REFERENCES users (id),
            FOREIGN KEY (art_id) REFERENCES art (id)
        );
        """)
        # Insert admin if missing
        admin_username = "admin"
        admin_password = "N9!d8R/o)!)Ym*Gu4p:G#NK"
        hashed_admin_pw = generate_password_hash(admin_password)
        cursor.execute("SELECT * FROM users WHERE username = ?", (admin_username,))
        if not cursor.fetchone():
            cursor.execute(
                "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                (admin_username, hashed_admin_pw, "admin")
            )
        conn.commit()


init_db()


# Decorators
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.')
            return redirect(url_for('index'))
        user = get_user(session['user_id'])
        if user['is_banned']:
            ban_txt = "permanently banned" if user['ban_until'] is None else f"banned until {user['ban_until']}"
            ban_until = user['ban_until']
            # Check if ban expired
            if ban_until:
                ban_time = datetime.strptime(ban_until, '%Y-%m-%d %H:%M:%S')
                if ban_time <= datetime.now():
                    db = get_db()
                    db.execute('UPDATE users SET is_banned=0, ban_until=NULL WHERE id=?', (user['id'],))
                    db.commit()
                else:
                    flash(f'Your account is {ban_txt}.')
                    session.clear()
                    return redirect(url_for('index'))
            else:
                flash(f'Your account is {ban_txt}.')
                session.clear()
                return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in first.')
            return redirect(url_for('login'))
        user = get_user(session['user_id'])
        if user['role'] != 'admin':
            flash('You do not have permission to view this page.')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function


# Utilities
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def get_user(user_id):
    db = get_db()
    return db.execute('SELECT * FROM users WHERE id=?', (user_id,)).fetchone()


def get_user_by_username(username):
    db = get_db()
    return db.execute('SELECT * FROM users WHERE username=?', (username,)).fetchone()


# Routes

@app.route('/')
def index():
    db = get_db()
    page = request.args.get('page', 1, type=int)
    sort = request.args.get('sort', 'relevance')
    order_by = 'created DESC'
    if sort == 'most-liked':
        order_by = 'likes DESC'
    elif sort == 'most-disliked':
        order_by = 'dislikes DESC'

    total = db.execute('SELECT COUNT(*) FROM art').fetchone()[0]
    pages = (total + PER_PAGE - 1) // PER_PAGE
    offset = (page - 1) * PER_PAGE

    arts = db.execute(f'''
        SELECT art.*, users.username as creator_name
        FROM art JOIN users ON art.creator_id = users.id
        ORDER BY {order_by}
        LIMIT ? OFFSET ?
    ''', (PER_PAGE, offset)).fetchall()

    artworks = []
    for art in arts:
        comments_rows = db.execute('''
            SELECT comments.comment, users.username 
            FROM comments JOIN users ON comments.user_id = users.id
            WHERE art_id = ?
            ORDER BY comments.created DESC
        ''', (art['id'],)).fetchall()
        comments = [f"{c['username']}: {c['comment']}" for c in comments_rows]
        artworks.append({
            'id': art['id'],
            'creator': art['creator_name'],
            'creator_id': art['creator_id'],
            'title': art['title'],
            'image_url': url_for('uploaded_file', filename=art['image_filename']) if art['image_filename'] else url_for('static', filename='placeholder.png'),
            'likes': art['likes'],
            'dislikes': art['dislikes'],
            'comments': comments,
            'created': art['created']
        })

    user = get_user(session['user_id']) if 'user_id' in session else None
    return render_template('index.html', artworks=artworks, user=user, page=page, pages=pages, sort=sort)


@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        if len(password) >= 8:
            db = get_db()
            if get_user_by_username(username):
                flash('Username already exists')
                return redirect(url_for('signup'))
            hashed = generate_password_hash(password)
            db.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, hashed))
            db.commit()
            flash('Account created. Please login.')
            return redirect(url_for('index'))
    return render_template('signup.html')


@app.route('/login', methods=['POST'])
def login():
    username = request.form['username'].strip()
    password = request.form['password']
    user = get_user_by_username(username)
    if user:
        if user['is_banned']:
            ban_txt = "permanently banned" if user['ban_until'] is None else f"banned until {user['ban_until']}"
            ban_until = user['ban_until']
            if ban_until:
                ban_time = datetime.strptime(ban_until, '%Y-%m-%d %H:%M:%S')
                if ban_time <= datetime.now():
                    db = get_db()
                    db.execute('UPDATE users SET is_banned=0, ban_until=NULL WHERE id=?', (user['id'],))
                    db.commit()
                else:
                    flash(f'Your account is {ban_txt}.')
                    return redirect(url_for('index'))
            else:
                flash(f'Your account is {ban_txt}.')
                return redirect(url_for('index'))
        if check_password_hash(user['password'], password):
            session.clear()
            session['user_id'] = user['id']
            flash(f'Welcome back, {username}!')
            return redirect(url_for('index'))
    flash('Invalid username or password.')
    return redirect(url_for('index'))


@app.route('/logout', methods=['POST'])
@login_required
def logout():
    session.clear()
    flash('Logged out.')
    return redirect(url_for('index'))


@app.route('/admin')
@admin_required
def admin_dashboard():
    db = get_db()
    users = db.execute('SELECT * FROM users').fetchall()
    arts = db.execute('SELECT art.*, users.username as creator_name FROM art JOIN users ON art.creator_id = users.id').fetchall()
    return render_template('admin_dashboard.html', users=users, arts=arts)


@app.route('/admin/delete_art/<int:art_id>', methods=['POST'])
@admin_required
def admin_delete_art(art_id):
    db = get_db()
    art = db.execute('SELECT * FROM art WHERE id=?', (art_id,)).fetchone()
    if art:
        if art['image_filename']:
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], art['image_filename'])
            if os.path.exists(filepath):
                os.remove(filepath)
        db.execute('DELETE FROM art WHERE id=?', (art_id,))
        db.execute('DELETE FROM comments WHERE art_id=?', (art_id,))
        db.execute('DELETE FROM likes_dislikes WHERE art_id=?', (art_id,))
        db.commit()
        flash('Artwork deleted by admin.')
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/ban_user/<int:user_id>', methods=['POST'])
@admin_required
def admin_ban_user(user_id):
    db = get_db()
    user = db.execute('SELECT * FROM users WHERE id=?', (user_id,)).fetchone()
    if not user:
        flash('User not found.')
        return redirect(url_for('admin_dashboard'))
    if user['role'] == 'admin':
        flash('You cannot ban another admin.')
        return redirect(url_for('admin_dashboard'))

    action = request.form.get('ban_action', '')  # 'temp' or 'perm'
    duration = request.form.get('duration', '')  # e.g. '1d', '5h'
    ban_until = None

    if action == 'perm':
        ban_until = None
    elif action == 'temp' and duration:
        match = re.match(r'^(\d+)([dhm])$', duration.lower())
        if match:
            amount, unit = match.groups()
            amount = int(amount)
            if unit == 'd':
                ban_until = datetime.now() + timedelta(days=amount)
            elif unit == 'h':
                ban_until = datetime.now() + timedelta(hours=amount)
            elif unit == 'm':
                ban_until = datetime.now() + timedelta(minutes=amount)
            ban_until = ban_until.strftime('%Y-%m-%d %H:%M:%S')
        else:
            flash('Invalid duration format. Use e.g. 1d, 5h, 30m.')
            return redirect(url_for('admin_dashboard'))
    else:
        flash('Invalid ban parameters.')
        return redirect(url_for('admin_dashboard'))

    db.execute('UPDATE users SET is_banned=1, ban_until=? WHERE id=?', (ban_until, user_id))
    db.commit()
    ban_msg = 'User banned '
    ban_msg += 'permanently.' if ban_until is None else f'until {ban_until}.'
    flash(ban_msg)
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/unban_user/<int:user_id>', methods=['POST'])
@admin_required
def admin_unban_user(user_id):
    db = get_db()
    user = db.execute('SELECT * FROM users WHERE id=?', (user_id,)).fetchone()
    if not user:
        flash('User not found.')
        return redirect(url_for('admin_dashboard'))
    db.execute('UPDATE users SET is_banned=0, ban_until=NULL WHERE id=?', (user_id,))
    db.commit()
    flash('User unbanned.')
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/delete_user_content/<int:user_id>', methods=['POST'])
@admin_required
def admin_delete_user_content(user_id):
    db = get_db()
    db.execute('DELETE FROM art WHERE creator_id=?', (user_id,))
    db.execute('DELETE FROM comments WHERE user_id=?', (user_id,))
    db.execute('DELETE FROM comments WHERE art_id IN (SELECT id FROM art WHERE creator_id=?)', (user_id,))
    db.execute('DELETE FROM followers WHERE follower_id=? OR followed_id=?', (user_id, user_id))
    db.execute('DELETE FROM likes_dislikes WHERE user_id=?', (user_id,))
    db.execute('DELETE FROM profile_comments WHERE profile_owner_id=? OR commenter_id=?', (user_id, user_id))
    db.commit()
    flash('User content deleted.')
    return redirect(url_for('admin_dashboard'))


@app.route('/delete_art/<int:art_id>', methods=['POST'])
@login_required
def delete_art(art_id):
    db = get_db()
    art = db.execute('SELECT * FROM art WHERE id=?', (art_id,)).fetchone()
    if not art:
        flash('Artwork not found.')
    elif art['creator_id'] != session['user_id']:
        flash('You do not have permission to delete this artwork.')
    else:
        if art['image_filename']:
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], art['image_filename'])
            if os.path.exists(filepath):
                os.remove(filepath)
        db.execute('DELETE FROM art WHERE id=?', (art_id,))
        db.execute('DELETE FROM comments WHERE art_id=?', (art_id,))
        db.execute('DELETE FROM likes_dislikes WHERE art_id=?', (art_id,))
        db.commit()
        flash('Your artwork was deleted.')
    return redirect(url_for('index'))


@app.route('/delete_account', methods=['POST'])
@login_required
def delete_account():
    user_id = session.get('user_id')
    if not user_id:
        flash('Not logged in.')
        return redirect(url_for('index'))
    db = get_db()
    db.execute('DELETE FROM art WHERE creator_id=?', (user_id,))
    db.execute('DELETE FROM comments WHERE user_id=?', (user_id,))
    db.execute('DELETE FROM comments WHERE art_id IN (SELECT id FROM art WHERE creator_id=?)', (user_id,))
    db.execute('DELETE FROM followers WHERE follower_id=? OR followed_id=?', (user_id, user_id))
    db.execute('DELETE FROM likes_dislikes WHERE user_id=?', (user_id,))
    db.execute('DELETE FROM profile_comments WHERE profile_owner_id=? OR commenter_id=?', (user_id, user_id))
    db.execute('DELETE FROM users WHERE id=?', (user_id,))
    db.commit()
    session.clear()
    flash('Your account and all content have been deleted.')
    return redirect(url_for('index'))


@app.route('/create_art', methods=['GET', 'POST'])
@login_required
def create_art():
    if request.method == 'POST':
        title = request.form['title'].strip()
        if 'image' not in request.files:
            flash('No file part')
            return redirect(request.url)
        file = request.files['image']
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)
        if file and allowed_file(file.filename):
            filename = secure_filename(f"{datetime.now().strftime('%Y%m%d%H%M%S')}_{file.filename}")
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            db = get_db()
            db.execute('INSERT INTO art (creator_id, title, image_filename) VALUES (?, ?, ?)', (session['user_id'], title, filename))
            db.commit()
            flash('Artwork created successfully!')
            return redirect(url_for('index'))
        else:
            flash('Allowed image types: png, jpg, jpeg, gif.')
            return redirect(request.url)
        
    # In the create art route (or in index route context):
    can_upload = False
    print(session['user_id'])
    if session.get('user_id'):
        db = get_db()
        user = db.execute('SELECT uploads_enabled FROM users WHERE id=?', (session['user_id'],)).fetchone()
        print("user" + str(user))
        if user and user['uploads_enabled']:
            print(can_upload)
            can_upload = True

    return render_template('create_art.html', can_upload=can_upload)


@app.route('/like/<int:art_id>', methods=['POST'])
@login_required
def like_art(art_id):
    user_id = session['user_id']
    db = get_db()
    existing = db.execute('SELECT * FROM likes_dislikes WHERE user_id=? AND art_id=?', (user_id, art_id)).fetchone()
    if existing:
        if existing['is_like']:
            flash('You already liked this art.')
        else:
            db.execute('UPDATE likes_dislikes SET is_like=1 WHERE user_id=? AND art_id=?', (user_id, art_id))
            db.execute('UPDATE art SET likes=likes+1, dislikes=dislikes-1 WHERE id=?', (art_id,))
            db.commit()
            flash('Changed dislike to like.')
    else:
        db.execute('INSERT INTO likes_dislikes (user_id, art_id, is_like) VALUES (?, ?, 1)', (user_id, art_id))
        db.execute('UPDATE art SET likes=likes+1 WHERE id=?', (art_id,))
        db.commit()
        flash('You liked the art.')
    return redirect(url_for('index'))


@app.route('/dislike/<int:art_id>', methods=['POST'])
@login_required
def dislike_art(art_id):
    user_id = session['user_id']
    db = get_db()
    existing = db.execute('SELECT * FROM likes_dislikes WHERE user_id=? AND art_id=?', (user_id, art_id)).fetchone()
    if existing:
        if not existing['is_like']:
            flash('You already disliked this art.')
        else:
            db.execute('UPDATE likes_dislikes SET is_like=0 WHERE user_id=? AND art_id=?', (user_id, art_id))
            db.execute('UPDATE art SET dislikes=dislikes+1, likes=likes-1 WHERE id=?', (art_id,))
            db.commit()
            flash('Changed like to dislike.')
    else:
        db.execute('INSERT INTO likes_dislikes (user_id, art_id, is_like) VALUES (?, ?, 0)', (user_id, art_id))
        db.execute('UPDATE art SET dislikes=dislikes+1 WHERE id=?', (art_id,))
        db.commit()
        flash('You disliked the art.')
    return redirect(url_for('index'))


@app.route('/comment/<int:art_id>', methods=['POST'])
@login_required
def add_comment(art_id):
    user_id = session['user_id']
    comment = request.form['comment'].strip()
    if not comment:
        flash('Comment cannot be empty.')
        return redirect(url_for('index'))
    db = get_db()
    db.execute('INSERT INTO comments (art_id, user_id, comment) VALUES (?, ?, ?)', (art_id, user_id, comment))
    db.commit()
    flash('Comment added.')
    return redirect(url_for('index'))


@app.route('/follow/<int:creator_id>', methods=['POST'])
@login_required
def follow_creator(creator_id):
    user_id = session['user_id']
    if user_id == creator_id:
        flash('You cannot follow yourself.')
        # Redirect back to the artist profile of the creator
        creator = get_user(creator_id)
        return redirect(url_for('artist_profile', username=creator['username']))
    db = get_db()
    exists = db.execute('SELECT * FROM followers WHERE follower_id=? AND followed_id=?', (user_id, creator_id)).fetchone()
    if exists:
        flash('You already follow this user.')
    else:
        db.execute('INSERT INTO followers (follower_id, followed_id) VALUES (?, ?)', (user_id, creator_id))
        db.commit()
        flash('You started following.')
    creator = get_user(creator_id)
    return redirect(url_for('artist_profile', username=creator['username']))


@app.route('/unfollow/<int:creator_id>', methods=['POST'])
@login_required
def unfollow_creator(creator_id):
    user_id = session['user_id']
    if user_id == creator_id:
        flash('You cannot unfollow yourself.')
        creator = get_user(creator_id)
        return redirect(url_for('artist_profile', username=creator['username']))
    db = get_db()
    exists = db.execute('SELECT * FROM followers WHERE follower_id=? AND followed_id=?', (user_id, creator_id)).fetchone()
    if exists:
        db.execute('DELETE FROM followers WHERE follower_id=? AND followed_id=?', (user_id, creator_id))
        db.commit()
        flash('You unfollowed the user.')
    else:
        flash('You do not follow this user.')
    creator = get_user(creator_id)
    return redirect(url_for('artist_profile', username=creator['username']))

@app.route('/admin-users/enable-uploads/<int:user_id>', methods=['POST'])
def enable_uploads(user_id):
    db = get_db()
    db.execute('UPDATE users SET uploads_enabled = 1 WHERE id = ?', (user_id,))
    db.commit()
    return redirect(url_for('admin_dashboard'))

@app.route('/admin-users/disable-uploads/<int:user_id>', methods=['POST'])
def disable_uploads(user_id):
    db = get_db()
    db.execute('UPDATE users SET uploads_enabled = 0 WHERE id = ?', (user_id,))
    db.commit()
    return redirect(url_for('admin_dashboard'))


@app.route('/search')
def search():
    query = request.args.get('q', '').strip()
    if not query:
        flash('Please enter a search term.')
        return redirect(url_for('index'))
    db = get_db()
    search_pattern = f'%{query}%'
    arts = db.execute('''
        SELECT art.*, users.username as creator_name
        FROM art JOIN users ON art.creator_id = users.id
        WHERE art.title LIKE ?
        ORDER BY art.created DESC
    ''', (search_pattern,)).fetchall()
    artworks = []
    for art in arts:
        comments_rows = db.execute('''
            SELECT comments.comment, users.username FROM comments
            JOIN users ON comments.user_id = users.id
            WHERE art_id = ?
            ORDER BY comments.created DESC
        ''', (art['id'],)).fetchall()
        comments = [f"{c['username']}: {c['comment']}" for c in comments_rows]
        artworks.append({
            'id': art['id'],
            'creator': art['creator_name'],
            'creator_id': art['creator_id'],
            'title': art['title'],
            'image_url': url_for('uploaded_file', filename=art['image_filename']) if art['image_filename'] else url_for('static', filename='placeholder.png'),
            'likes': art['likes'],
            'dislikes': art['dislikes'],
            'comments': comments,
            'created': art['created']
        })
    user = get_user(session['user_id']) if 'user_id' in session else None
    return render_template('index.html', artworks=artworks, user=user, page=1, pages=1, sort='relevance')


@app.route('/pixel_art_editor')
@login_required
def pixel_art_editor():
    user = get_user(session['user_id'])
    return render_template('pixel_art_editor.html', user=user)


@app.route('/save_pixel_art', methods=['POST'])
@login_required
def save_pixel_art():
    data_url = request.form.get('pixelArtData')
    title = request.form.get('title', '').strip()
    if not title:
        flash('Art title is required.')
        return redirect(url_for('pixel_art_editor'))
    if not data_url:
        flash('No pixel art data received.')
        return redirect(url_for('pixel_art_editor'))
    if not re.match(r'data:image/png;base64,', data_url):
        flash('Invalid image data format.')
        return redirect(url_for('pixel_art_editor'))
    header, encoded = data_url.split(',', 1)
    binary_data = base64.b64decode(encoded)
    filename = secure_filename(f"{datetime.now().strftime('%Y%m%d%H%M%S')}_pixelart.png")
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    with open(filepath, 'wb') as f:
        f.write(binary_data)
    db = get_db()
    db.execute(
        'INSERT INTO art (creator_id, title, image_filename) VALUES (?, ?, ?)',
        (session['user_id'], title, filename)
    )
    db.commit()
    flash('Pixel art saved successfully!')
    return redirect(url_for('index'))


@app.route('/artist/<username>')
def artist_profile(username):
    db = get_db()
    user_art = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
    if user_art is None:
        flash('Artist not found.')
        return redirect(url_for('index'))

    # Get artworks by this artist
    arts = db.execute('SELECT * FROM art WHERE creator_id = ? ORDER BY created DESC', (user_art['id'],)).fetchall()

    artworks = []
    for art in arts:
        comments_rows = db.execute('''
            SELECT comments.comment, users.username FROM comments
            JOIN users ON comments.user_id = users.id
            WHERE art_id = ?
            ORDER BY comments.created DESC
        ''', (art['id'],)).fetchall()
        comments = [f"{c['username']}: {c['comment']}" for c in comments_rows]
        artworks.append({
            'id': art['id'],
            'title': art['title'],
            'image_url': url_for('uploaded_file', filename=art['image_filename']) if art['image_filename'] else url_for('static', filename='placeholder.png'),
            'likes': art['likes'],
            'dislikes': art['dislikes'],
            'comments': comments,
            'created': art['created']
        })

    # Get profile comments made to this artist
    profile_comments_rows = db.execute('''
        SELECT profile_comments.comment, users.username, profile_comments.created
        FROM profile_comments JOIN users ON profile_comments.commenter_id = users.id
        WHERE profile_owner_id = ?
        ORDER BY profile_comments.created DESC
    ''', (user_art['id'],)).fetchall()
    profile_comments = [{
        'username': pc['username'],
        'comment': pc['comment'],
        'created': pc['created']
    } for pc in profile_comments_rows]

    # Logged in user
    logged_in_user = get_user(session.get('user_id')) if 'user_id' in session else None

    # Followers count (users who follow this artist)
    followers_count = db.execute(
        'SELECT COUNT(*) FROM followers WHERE followed_id = ?', (user_art['id'],)
    ).fetchone()[0]

    # Following count (users this artist follows)
    following_count = db.execute(
        'SELECT COUNT(*) FROM followers WHERE follower_id = ?', (user_art['id'],)
    ).fetchone()[0]

    # Whether the logged-in user follows this artist
    is_followed_by_user = False
    if logged_in_user:
        exists = db.execute(
            'SELECT 1 FROM followers WHERE follower_id = ? AND followed_id = ?',
            (logged_in_user['id'], user_art['id'])
        ).fetchone()
        is_followed_by_user = bool(exists)

    user = get_user(session.get('user_id')) if 'user_id' in session else None


    return render_template(
        'artist_profile.html',
        artist=user_art, 
        artworks=artworks, 
        user=user,
        profile_comments=profile_comments,
        followers_count=followers_count,
        following_count=following_count,
        is_followed_by_user=is_followed_by_user
    )



@app.route('/profile_comment/<int:profile_owner_id>', methods=['POST'])
@login_required
def profile_comment(profile_owner_id):
    comment = request.form.get('comment', '').strip()
    if not comment:
        flash('Comment cannot be empty.')
        return redirect(url_for('artist_profile', username=get_user(profile_owner_id)['username']))
    user_id = session['user_id']
    db = get_db()
    db.execute('INSERT INTO profile_comments (profile_owner_id, commenter_id, comment) VALUES (?, ?, ?)',
               (profile_owner_id, user_id, comment))
    db.commit()
    flash('Comment added to profile.')
    return redirect(url_for('artist_profile', username=get_user(profile_owner_id)['username']))


@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        current_password = request.form.get('current_password', '')
        new_password = request.form.get('new_password', '')
        confirm_password = request.form.get('confirm_password', '')

        user = get_user(session['user_id'])

        if not check_password_hash(user['password'], current_password):
            flash('Current password is incorrect.')
            return redirect(url_for('change_password'))

        if not new_password:
            flash('New password cannot be empty.')
            return redirect(url_for('change_password'))

        if new_password != confirm_password:
            flash('New password and confirmation do not match.')
            return redirect(url_for('change_password'))

        hashed = generate_password_hash(new_password)
        db = get_db()
        db.execute('UPDATE users SET password=? WHERE id=?', (hashed, user['id']))
        db.commit()
        flash('Your password has been changed successfully.')
        return redirect(url_for('profile'))

    return render_template('change_password.html')


@app.route('/profile')
@login_required
def profile():
    user = get_user(session['user_id'])
    return redirect("/artist/" + str(user['username']))


@app.route('/settings')
@login_required
def settings():
    user = get_user(session['user_id'])
    return render_template('settings.html', user=user)


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=8080)
