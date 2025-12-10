from flask import Flask, render_template, request, redirect, url_for, session, flash, g, send_from_directory, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
import os
import random
import string
from flask_socketio import SocketIO, join_room, leave_room, send
from datetime import datetime
import pytz
from werkzeug.utils import secure_filename
import base64
import logging
from logging.handlers import RotatingFileHandler

from sqlalchemy.orm import joinedload

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'instance', 'db.sqlite3')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
socketio = SocketIO(app, max_http_buffer_size=50*1024*1024, ping_interval=60, ping_timeout=30)  # 50MB limit for Socket.IO messages

# Configure logging
log_formatter = logging.Formatter('%(asctime)s %(levelname)s %(funcName)s(%(lineno)d) %(message)s')
logFile = 'app.log'
my_handler = RotatingFileHandler(logFile, mode='a', maxBytes=5*1024*1024, backupCount=2, encoding=None, delay=0)
my_handler.setFormatter(log_formatter)
my_handler.setLevel(logging.INFO)
app.logger.addHandler(my_handler)
app.logger.setLevel(logging.INFO)

# Create profile_pics folder if it doesn't exist
profile_pics_path = os.path.join(basedir, 'static', 'profile_pics')
if not os.path.exists(profile_pics_path):
    os.makedirs(profile_pics_path)

# Create uploads folder for media files
uploads_path = os.path.join(basedir, 'static', 'uploads')
if not os.path.exists(uploads_path):
    os.makedirs(uploads_path)

# Media configuration
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'mp4', 'webm', 'mov'}
MAX_FILE_SIZE = 50 * 1024 * 1024 # 50MB per file
MAX_TOTAL_SIZE = 50 * 1024 * 1024  # 50MB total per message
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

def to_ist(dt):
    utc = pytz.utc.localize(dt)
    ist = pytz.timezone('Asia/Kolkata')
    return utc.astimezone(ist)

app.jinja_env.filters['to_ist'] = to_ist

def generate_room_id():
    while True:
        room_id = ''.join(random.choices(string.digits, k=5))
        if not Room.query.filter_by(room_id=room_id).first():
            return room_id

def allowed_file(filename):
    """Check if file extension is allowed"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_file_type(filename):
    """Determine if file is image or video"""
    ext = filename.rsplit('.', 1)[1].lower()
    if ext in {'png', 'jpg', 'jpeg', 'gif'}:
        return 'image'
    elif ext in {'mp4', 'webm', 'mov'}:
        return 'video'
    return 'unknown'

def generate_unique_filename(original_filename):
    """Generate a unique filename to prevent conflicts"""
    ext = original_filename.rsplit('.', 1)[1].lower()
    timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
    random_string = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
    return f"{timestamp}_{random_string}.{ext}"

# Association table for the many-to-many relationship between users and rooms
user_rooms = db.Table('user_rooms', 
    db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
    db.Column('room_id', db.Integer, db.ForeignKey('room.id'), primary_key=True)
)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    profile_picture = db.Column(db.String(150), nullable=False, default='placeholder-person.jpg')
    last_seen = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(pytz.utc))
    status = db.Column(db.String(10), default='offline')
    rooms = db.relationship('Room', secondary=user_rooms, lazy='subquery',
        backref=db.backref('users', lazy=True))

class Room(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    room_id = db.Column(db.String(5), unique=True, nullable=False, default=generate_room_id)
    password = db.Column(db.String(150), nullable=False)
    messages = db.relationship('Message', backref='room', lazy=True, cascade="all, delete-orphan")

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(500), nullable=True)
    message_type = db.Column(db.String(20), nullable=False, default='text')
    original_content = db.Column(db.String(500), nullable=True)
    edit_count = db.Column(db.Integer, default=0)
    timestamp = db.Column(db.DateTime, nullable=False, default=db.func.now())
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    room_id = db.Column(db.Integer, db.ForeignKey('room.id'), nullable=False)
    user = db.relationship('User', backref='messages')
    seen_by = db.relationship('MessageSeen', backref='message', lazy=True, cascade="all, delete-orphan")
    parent_id = db.Column(db.Integer, db.ForeignKey('message.id'), nullable=True)
    parent = db.relationship('Message', remote_side=[id], backref='replies')
    media_files = db.relationship('Media', backref='message', lazy=True, cascade="all, delete-orphan")

class Media(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    original_filename = db.Column(db.String(255), nullable=False)
    message_id = db.Column(db.Integer, db.ForeignKey('message.id'), nullable=False)
    file_type = db.Column(db.String(50), nullable=False)  # 'image' or 'video'
    file_size = db.Column(db.Integer, nullable=False)  # Size in bytes
    uploaded_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)




class MessageSeen(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    message_id = db.Column(db.Integer, db.ForeignKey('message.id'), nullable=False)
    seen_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    user = db.relationship('User')

@app.before_request
def before_request():
    g.user = None
    if 'username' in session:
        g.user = User.query.filter_by(username=session['username']).first()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/room/<int:room_id>', methods=['GET', 'POST'])
def room(room_id):
    if 'username' not in session:
        return redirect(url_for('login'))
    
    room = Room.query.get_or_404(room_id)
    user = User.query.filter_by(username=session['username']).first()

    if user not in room.users:
        flash('You are not a member of this room.', 'danger')
        return redirect(url_for('home'))

    # Password handling
    if room.password:
        session_key = f'room_password_verified_{room_id}'
        if request.method == 'POST':
            password_attempt = request.form.get('password')
            if bcrypt.check_password_hash(room.password, password_attempt):
                session[session_key] = True
            else:
                flash('Incorrect password.', 'danger')
                return redirect(url_for('home'))
        
        if not session.get(session_key):
                return render_template('join_room_password.html', room=room)

    # If we are here, user is authenticated and password is correct (or not needed)
    page = request.args.get('page', 1, type=int)
    per_page = 20  # Number of messages per page
    
    messages_pagination = Message.query.options(joinedload(Message.media_files)).filter_by(room_id=room.id).order_by(Message.timestamp.desc()).paginate(page=page, per_page=per_page, error_out=False)
    messages_query = messages_pagination.items
    messages_query.reverse()

    messages_by_date = {}
    for message in messages_query:
        date_str = to_ist(message.timestamp).strftime('%Y-%m-%d')
        if date_str not in messages_by_date:
            messages_by_date[date_str] = []
        messages_by_date[date_str].append(message)

    # Get last seen times for the latest message
    last_seen_times = {}
    last_message_by_user = Message.query.filter_by(room_id=room.id, user_id=user.id).order_by(Message.timestamp.desc()).first()
    if last_message_by_user:
        seen_record = MessageSeen.query.filter(
            MessageSeen.message_id == last_message_by_user.id,
            MessageSeen.user_id != user.id
        ).order_by(MessageSeen.seen_at.desc()).first()
        if seen_record:
            last_seen_times[last_message_by_user.id] = seen_record.seen_at

    # Get the last message seen by the current user for unread highlighting
    last_seen_message_id = None
    last_seen_by_user = MessageSeen.query.join(Message).filter(
        MessageSeen.user_id == user.id, 
        Message.room_id == room.id
    ).order_by(MessageSeen.seen_at.desc()).first()
    if last_seen_by_user:
        last_seen_message_id = last_seen_by_user.message_id

    return render_template(
        'room.html', 
        room=room, 
        messages_by_date=messages_by_date, 
        last_seen_times=last_seen_times, 
        last_message_id=last_message_by_user.id if last_message_by_user else None, 
        last_seen_message_id=last_seen_message_id,
        pagination=messages_pagination
    )

@app.route('/upload_media', methods=['POST'])
def upload_media():
    app.logger.info('Upload media request received')
    if 'username' not in session:
        app.logger.warning('Unauthorized access attempt to upload_media')
        return jsonify({'error': 'Unauthorized'}), 401

    if 'file' not in request.files:
        app.logger.error('No file part in the request')
        return jsonify({'error': 'No file part in the request'}), 400

    file = request.files['file']

    if file.filename == '':
        app.logger.error('No file selected for upload')
        return jsonify({'error': 'No file selected for upload'}), 400

    if file and allowed_file(file.filename):
        try:
            original_filename = secure_filename(file.filename)
            unique_filename = generate_unique_filename(original_filename)
            file_path = os.path.join(uploads_path, unique_filename)
            
            app.logger.info(f'Saving file {original_filename} to {file_path}')
            file.save(file_path)
            app.logger.info(f'File {original_filename} saved successfully')
            
            return jsonify({'filename': unique_filename}), 200
        except Exception as e:
            app.logger.error(f'Error saving file: {e}', exc_info=True)
            return jsonify({'error': f'Failed to save file: {e}'}), 500
    
    elif not allowed_file(file.filename):
        app.logger.error(f'File type not allowed: {file.filename}')
        return jsonify({'error': 'File type not allowed'}), 400
        
    return jsonify({'error': 'An unknown error occurred'}), 500

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'username' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    if 'files' not in request.files:
        return jsonify({'error': 'No files provided'}), 400
    
    files = request.files.getlist('files')
    if not files or all(file.filename == '' for file in files):
        return jsonify({'error': 'No files selected'}), 400
    
    uploaded_files = []
    total_size = 0
    
    for file in files:
        if file and file.filename:
            # Check file extension
            if not allowed_file(file.filename):
                return jsonify({'error': f'File type not allowed: {file.filename}'}), 400
            
            # Check file size
            file.seek(0, os.SEEK_END)
            file_size = file.tell()
            file.seek(0)  # Reset file pointer
            
            if file_size > MAX_FILE_SIZE:
                return jsonify({'error': f'File too large: {file.filename}. Maximum size: 10MB'}), 400
            
            total_size += file_size
            if total_size > MAX_TOTAL_SIZE:
                return jsonify({'error': 'Total file size exceeds 50MB limit'}), 400
            
            # Generate unique filename and save
            filename = generate_unique_filename(file.filename)
            filepath = os.path.join(uploads_path, filename)
            file.save(filepath)
            
            uploaded_files.append({
                'filename': filename,
                'original_filename': file.filename,
                'file_type': get_file_type(file.filename),
                'file_size': file_size
            })
    
    return jsonify({
        'success': True,
        'files': uploaded_files
    })

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    """Serve uploaded files"""
    return send_from_directory(uploads_path, filename)


@socketio.on('send_message')
def handle_send_message(data):
    print(f"BACKEND: === SEND_MESSAGE HANDLER STARTED ====")
    print(f"BACKEND: send_message event received with data: {data}")
    print(f"BACKEND: Session data: {dict(session)}")
    print(f"BACKEND: Request data: {request.sid if hasattr(request, 'sid') else 'No SID'}")

    if 'username' not in session:
        print("BACKEND: No username in session, using default user for testing")
        default_username = 'desktop_user'
        user = User.query.filter_by(username=default_username).first()
        if not user:
            from werkzeug.security import generate_password_hash
            user = User(
                username=default_username,
                password=generate_password_hash('test123'),
                profile_picture='placeholder-person.jpg'
            )
            db.session.add(user)
            db.session.commit()
            print(f"BACKEND: Created default user: {default_username}")
    else:
        user = User.query.filter_by(username=session['username']).first()

    if not user:
        print("BACKEND: No user found, returning error")
        return {'status': 'error', 'message': 'User not found'}

    room = Room.query.get(data['room_id'])

    if user and room:
        if user not in room.users:
            room.users.append(user)
            db.session.commit()
            print(f"BACKEND: Added user {user.username} to room {room.name}")
        parent_id = data.get('parent_id')
        message_content = data.get('message', '')
        media_files = data.get('media_files', [])

        if media_files:
            message_type = 'media'
        else:
            message_type = 'text'
            if not message_content.strip():
                return

        message = Message(
            content=message_content if message_content else None,
            user_id=user.id,
            room_id=room.id,
            parent_id=parent_id,
            message_type=message_type
        )
        db.session.add(message)
        db.session.flush()

        print(f"BACKEND: Processing {len(media_files)} media files")
        print(f"BACKEND: Full data received: {data}")
        print(f"BACKEND: Media files data: {media_files}")

        if media_files:
            for i, file_data in enumerate(media_files):
                print(f"BACKEND: Processing file {i+1}: {file_data}")
                media = Media(
                    filename=file_data['filename'],
                    original_filename=file_data['original_filename'],
                    file_type=file_data['file_type'],
                    file_size=file_data.get('file_size', 0),
                    message_id=message.id
                )
                db.session.add(media)

        try:
            db.session.commit()
            print(f"BACKEND: Message and media committed successfully")
        except Exception as e:
            db.session.rollback()
            print(f"BACKEND: Database error: {e}")
            return {'status': 'error', 'message': str(e)}

        emit_data = {
            'user': user.username,
            'profile_picture': user.profile_picture,
            'timestamp': message.timestamp.isoformat() + 'Z',
            'message_id': message.id,
            'message_type': message_type,
            'message': message_content if message_content else ''
        }

        if message.media_files:
            emit_data['media_files'] = [
                {
                    'file_path': media.filename,
                    'contentType': media.file_type  # Pass the correct content type
                }
                for media in message.media_files
            ]

        if parent_id:
            parent = Message.query.get(parent_id)
            if parent:
                parent_data = {
                    'message_id': parent.id,
                    'username': parent.user.username,
                    'content': parent.content if parent.message_type == 'text' else 'Media'
                }
                if parent.message_type == 'media' and parent.media_files:
                    parent_data['thumbnail'] = parent.media_files[0].filename
                emit_data['parent'] = parent_data

        if data.get('temp_id'):
            emit_data['temp_id'] = data['temp_id']

        print(f"BACKEND: Emitting message to room {room.id}: {emit_data}")
        socketio.emit('new_message', emit_data, room=str(room.id))
        print(f"BACKEND: === SEND_MESSAGE HANDLER COMPLETED ====")

@socketio.on('connect')
def handle_connect():
    print(f"BACKEND: Client connected: {request.sid}")

@socketio.on('disconnect')
def handle_disconnect():
    print(f"BACKEND: Client disconnected: {request.sid}")

@socketio.on('join')
def on_join(data):
    username = session.get('username')
    room_id = data.get('room_id')
    print(f"BACKEND: User {username} joining room {room_id}")
    if username and room_id:
        user = User.query.filter_by(username=username).first()
        if user:
            user.status = 'online'
            db.session.commit()
            join_room(room_id)
            join_room(str(user.id)) # Join a room named after the user's ID
            socketio.emit('status_update', {
                'user': user.username,
                'status': 'online',
                'last_seen': None
            }, room=room_id)

@socketio.on('leave')
def on_leave(data):
    username = session.get('username')
    room_id = data.get('room_id')
    if username and room_id:
        leave_room(room_id)
        send({'message': f'{username} has left the room.'}, room=room_id)

@socketio.on('typing')
def on_typing(data):
    if 'username' in session:
        room_id = data.get('room_id')
        if room_id:
            socketio.emit('user_typing', {'user': session['username']}, room=room_id)

@socketio.on('stop_typing')
def on_stop_typing(data):
    if 'username' in session:
        room_id = data.get('room_id')
        if room_id:
            socketio.emit('user_stop_typing', {'user': session['username']}, room=room_id)

@socketio.on('disconnect')
def on_disconnect():
    if 'username' in session:
        user = User.query.filter_by(username=session['username']).first()
        if user:
            user.status = 'offline'
            user.last_seen = datetime.now(pytz.utc)
            db.session.commit()
            for room in user.rooms:
                socketio.emit('status_update', {
                'user': user.username,
                'status': 'offline',
                'last_seen': user.last_seen.isoformat() if user.last_seen else None
            }, room=room.room_id)

@socketio.on('edit_message')
def handle_edit_message(data):
    if 'username' not in session:
        return

    user = User.query.filter_by(username=session['username']).first()
    message = Message.query.get(data['message_id'])

    if user and message and message.user_id == user.id:
        if message.edit_count < 3:
            if message.edit_count == 0:
                message.original_content = message.content
            message.content = data['new_content']
            message.edit_count += 1
            db.session.commit()
            emit_data = {
                'message_id': message.id, 
                'new_content': message.content, 
                'original_content': message.original_content,
                'edit_count': message.edit_count
            }
            print(f"BACKEND: Broadcasting message_edited with data: {emit_data}")
            socketio.emit('message_edited', emit_data)
        else:
            # Optionally, send a message to the user that they can't edit anymore
            pass

@socketio.on('unsend_message')
def handle_unsend_message(data):
    if 'username' not in session:
        return

    user = User.query.filter_by(username=session['username']).first()
    message = Message.query.get(data['message_id'])

    if user and message and message.user_id == user.id:
        message_id = message.id
        db.session.delete(message)
        db.session.commit()
        emit_data = {'message_id': message_id}
        print(f"BACKEND: Broadcasting message_unsent with data: {emit_data}")
        socketio.emit('message_unsent', emit_data)

@socketio.on('message_seen')
def handle_message_seen(data):
    if 'username' not in session:
        return

    user = User.query.filter_by(username=session['username']).first()
    message = Message.query.get(data['message_id'])

    if user and message and user.id != message.user_id:
        existing_seen = MessageSeen.query.filter_by(user_id=user.id, message_id=message.id).first()
        if not existing_seen:
            seen = MessageSeen(user_id=user.id, message_id=message.id)
            db.session.add(seen)
            db.session.commit()

            # Notify the sender that the message has been seen
            sender = User.query.get(message.user_id)
            if sender and sender.status == 'online':
                socketio.emit('message_seen_update', {
                    'message_id': message.id,
                    'seen_at': seen.seen_at.isoformat() + 'Z'
                }, room=str(sender.id)) # Send to a room named after the sender's user ID

@socketio.on('update_status')
def update_user_status(data):
    if 'username' not in session:
        return
    user = User.query.filter_by(username=session['username']).first()
    if user:
        user.status = data['status']
        if data['status'] == 'offline':
            user.last_seen = datetime.now(pytz.utc)
        db.session.commit()
        for room in user.rooms:
            socketio.emit('status_update', {
                'user': user.username,
                'status': user.status,
                'last_seen': user.last_seen.isoformat() if user.last_seen else None
            }, room=room.room_id)

@app.route('/change_password', methods=['POST'])
def change_password():
    if 'username' not in session:
        return redirect(url_for('login'))
    user = User.query.filter_by(username=session['username']).first()
    if not bcrypt.check_password_hash(user.password, request.form['current_password']):
        flash('Incorrect current password.', 'danger')
        return redirect(url_for('profile'))
    if request.form['new_password'] != request.form['confirm_new_password']:
        flash('New passwords do not match.', 'danger')
        return redirect(url_for('profile'))
    if not (8 <= len(request.form['new_password']) <= 24):
        flash('Password must be between 8 to 24 characters long.', 'danger')
        return redirect(url_for('profile'))
    hashed_password = bcrypt.generate_password_hash(request.form['new_password']).decode('utf-8')
    user.password = hashed_password
    db.session.commit()
    flash('Your password has been updated!', 'success')
    return redirect(url_for('profile'))

@app.route('/logout')
def logout():
    session.pop('username', None)
    session.pop('room_password_verified', None)
    return redirect(url_for('index'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        if request.form['password'] != request.form['confirm_password']:
            flash('Passwords do not match!', 'danger')
            return redirect(url_for('register'))

        if not (8 <= len(request.form['password']) <= 24):
            flash('Password must be between 8 to 24 characters long.', 'danger')
            return redirect(url_for('register'))
        
        hashed_password = bcrypt.generate_password_hash(request.form['password']).decode('utf-8')
        new_user = User(username=request.form['username'], password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('Account created successfully!', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username_attempt = request.form['username']
        password_attempt = request.form['password']
        print(f"Login attempt for username: {username_attempt}")
        user = User.query.filter_by(username=username_attempt).first()
        if user:
            print(f"User found: {user.username}")
            if bcrypt.check_password_hash(user.password, password_attempt):
                print("Password matched!")
                session['username'] = user.username
                print(f"Session username set to: {session['username']}")
                return redirect(url_for('index'))
            else:
                print("Password mismatch.")
                flash('Login unsuccessful. Please check your username and password.', 'danger')
        else:
            print("User not found.")
            flash('Login unsuccessful. Please check your username and password.', 'danger')
    return render_template('login.html')

@app.route('/home')
def home():
    if 'username' not in session:
        return redirect(url_for('login'))
    user = User.query.filter_by(username=session['username']).first()
    if user is None:
        session.pop('username', None)
        flash('Your session has expired, please log in again.', 'info')
        return redirect(url_for('login'))
    return render_template('home.html', user=user)

@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'username' not in session:
        return redirect(url_for('login'))
    user = User.query.filter_by(username=session['username']).first()
    if request.method == 'POST':
        if 'username' in request.form:
            user.username = request.form['username']
            session['username'] = user.username # Update session username
        if 'profile_picture' in request.files:
            picture_file = request.files['profile_picture']
            if picture_file.filename != '':
                picture_fn = secure_filename(picture_file.filename)
                picture_path = os.path.join(app.root_path, 'static/profile_pics', picture_fn)
                picture_file.save(picture_path)
                user.profile_picture = picture_fn
        db.session.commit()
        flash('Your profile has been updated!', 'success')
        return redirect(url_for('profile'))
    return render_template('profile.html', user=user)

@app.route('/create_room', methods=['POST'])
def create_room():
    if 'username' not in session:
        return redirect(url_for('login'))
    room_name = request.form['room_name']
    room_password = request.form['room_password']
    hashed_password = bcrypt.generate_password_hash(room_password).decode('utf-8')
    new_room = Room(name=room_name, password=hashed_password)
    user = User.query.filter_by(username=session['username']).first()
    new_room.users.append(user)
    db.session.add(new_room)
    db.session.commit()
    flash(f'Room created successfully! Your room ID is {new_room.room_id}', 'success')
    return redirect(url_for('home'))

@app.route('/join_room', methods=['POST'])
def join_room_route():
    if 'username' not in session:
        return redirect(url_for('login'))
    room_id = request.form['room_id']
    room_password = request.form['join_room_password']
    room = Room.query.filter_by(room_id=room_id).first()
    if room and bcrypt.check_password_hash(room.password, room_password):
        user = User.query.filter_by(username=session['username']).first()
        if user in room.users:
            flash('You are already in this room.', 'info')
            return redirect(url_for('home'))
        room.users.append(user)
        db.session.commit()
        flash('Joined room successfully!', 'success')
    else:
        flash('Invalid room ID or password.', 'danger')
    return redirect(url_for('home'))

@app.route('/edit_room/<int:room_id>', methods=['POST'])
def edit_room(room_id):
    if 'username' not in session:
        return redirect(url_for('login'))
    room = Room.query.get_or_404(room_id)
    user = User.query.filter_by(username=session['username']).first()
    if room.users[0].id != user.id:
        flash('You are not the owner of this room.', 'danger')
        return redirect(url_for('home'))

    if not bcrypt.check_password_hash(room.password, request.form['current_password']):
        flash('Incorrect current password.', 'danger')
        return redirect(url_for('home'))

    room.name = request.form['name']
    password = request.form.get('password')
    if password:
        room.password = bcrypt.generate_password_hash(password).decode('utf-8')
    db.session.commit()
    flash('Room updated successfully.', 'success')
    return redirect(url_for('home'))

@app.route('/remove_room/<int:room_id>')
def remove_room(room_id):
    if 'username' not in session:
        return redirect(url_for('login'))
    room = Room.query.get_or_404(room_id)
    user = User.query.filter_by(username=session['username']).first()
    if user in room.users:
        room.users.remove(user)
        db.session.commit()
        flash('You have been removed from the room.', 'success')
    return redirect(url_for('home'))

@app.route('/delete_room/<int:room_id>', methods=['POST'])
def delete_room(room_id):
    if 'username' not in session:
        return redirect(url_for('login'))
    room = Room.query.get_or_404(room_id)
    user = User.query.filter_by(username=session['username']).first()
    if room.users[0].id != user.id:
        flash('You are not the owner of this room.', 'danger')
        return redirect(url_for('home'))
    # Delete associated media files from the filesystem
    uploads_path = os.path.join(app.root_path, 'static/uploads')
    for message in room.messages:
        for media in message.media_files:
            try:
                os.remove(os.path.join(uploads_path, media.filename))
            except OSError as e:
                print(f"Error deleting file {media.filename}: {e}")

    # Delete associated messages
    Message.query.filter_by(room_id=room.id).delete()

    db.session.delete(room)
    db.session.commit()
    flash('Room deleted successfully!', 'success')
    return redirect(url_for('home'))


def time_ago(time):
    if not time:
        return "No last seen data"

    utc_now = datetime.now(pytz.utc)
    ist = pytz.timezone('Asia/Kolkata')
    now_ist = utc_now.astimezone(ist)

    if time.tzinfo is None:
        time_utc = pytz.utc.localize(time)
    else:
        time_utc = time

    time_ist = time_utc.astimezone(ist)

    diff = now_ist - time_ist
    seconds = diff.total_seconds()

    if seconds < 60:
        return "just now"
    elif seconds < 3600:
        minutes = int(seconds / 60)
        return f"{minutes} minute{'s' if minutes > 1 else ''} ago"
    elif seconds < 86400:
        hours = int(seconds / 3600)
        return f"{hours} hour{'s' if hours > 1 else ''} ago"
    else:
        days = int(seconds / 86400)
        return f"{days} day{'s' if days > 1 else ''} ago"

@app.route('/room_details/<int:room_id>')
def room_details(room_id):
    if 'username' not in session:
        return redirect(url_for('login'))
    room = Room.query.get_or_404(room_id)
    users_with_status = []
    for user in room.users:
        users_with_status.append({
            'username': user.username,
            'status': user.status,
            'last_seen': time_ago(user.last_seen),
            'profile_picture': url_for('static', filename='profile_pics/' + user.profile_picture)
        })
    return render_template('room_details.html', room=room, users=users_with_status)

@app.route('/uploads/<filename>')
def serve_uploaded_file(filename):
    """Serve uploaded files from the static/uploads directory"""
    return send_from_directory('static/uploads', filename)




if __name__ == '__main__':
    with app.app_context():
        try:
            print("Resetting all online user statuses to 'offline'...")
            online_users = User.query.filter_by(status='online').all()
            for user in online_users:
                user.status = 'offline'
            db.session.commit()
            print("All online user statuses have been reset to 'offline'.")
        except Exception as e:
            print(f"Error resetting user statuses: {e}")
            db.session.rollback()
    socketio.run(app, debug=True, host='0.0.0.0', port=5001, use_reloader=False)