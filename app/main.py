import os
from flask import Flask, render_template, redirect, url_for, session, request, flash, jsonify, send_file, abort, send_from_directory
from flask_mail import Mail, Message
from flask_wtf import FlaskForm 
from wtforms import StringField, PasswordField, SubmitField, SelectField, Form
from wtforms import validators
from wtforms.validators import DataRequired, Email, Length, EqualTo
from flask_pymongo import PyMongo
from pymongo import MongoClient
import gridfs
from bson import ObjectId
from werkzeug.utils import secure_filename
from pdfminer.high_level import extract_text
from flask import request
import PyPDF2
import fitz  # PyMuPDF
import re
from docx import Document
import docx
from datetime import datetime

# Configuration
class Config:
    SECRET_KEY = os.getenv('SECRET_KEY', 'ISLAMIC2025')  # Change to secure one in production
    MONGO_URI = 'mongodb+srv://islamic_online:I6ak9kqgdxRN9pBr@cluster0.nwyxn.mongodb.net/islamic_online?retryWrites=true&w=majority&appName=Cluster0'
    WTF_CSRF_ENABLED = False 

# Initialize Flask app and MongoDB
app = Flask(__name__)
app.config.from_object(Config)
mongo = PyMongo(app)

# Configure mail settings
app.config["MAIL_SERVER"] = "smtp.gmail.com"
app.config["MAIL_PORT"] = 587
app.config["MAIL_USE_TLS"] = True
app.config["MAIL_USERNAME"] = "your_email@gmail.com"  # Gali Email-ka Jaamacadda
app.config["MAIL_PASSWORD"] = "your_email_password"  # Gali Password-ka (ama App Password)
app.config["MAIL_DEFAULT_SENDER"] = "your_email@gmail.com"

mail = Mail()
mail.init_app(app) 

mail = Mail(app)

# MongoDB Collections
db = mongo.db
users_collection = db['users']
questions_collection = db['questions']
results_collection = db['results']
lessons_collection = db['lessons']
access_codes_collection = db['access_codes']
activity_collection = db['activity']  # For admin activity logging

exercise_id = "67c7136169d439da62ee910b"  # BADAL HADDII AY KHALDAN TAHAY

result = lessons_collection.find_one(
    {"exercises.exercise_id": exercise_id},
    {"exercises.$": 1}
)

# Forms
class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email(message='Enter a valid email')])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6, message='Password must be at least 6 characters')])
    level = SelectField('Level', choices=[('', 'Choose Level'), ('beginner', 'Beginner'), ('intermediate', 'Intermediate'), ('advanced', 'Advanced')], validators=[DataRequired(message='Please choose a level')])
    submit = SubmitField('Login')

class ResetDeviceForm(FlaskForm):
    email = StringField('Email', [validators.DataRequired(), validators.Email()])
    password = PasswordField('Password', [validators.DataRequired()])

class RegistrationForm(FlaskForm):
    name = StringField('Full Name', validators=[DataRequired(), Length(min=2, max=50)])
    email = StringField('Email', validators=[DataRequired(), Email(message='Enter a valid email')])
    password = PasswordField('Password', validators=[
        DataRequired(),
        Length(min=6, message='Password must be at least 6 characters'),
        EqualTo('confirm_password', message='Passwords must match')
    ])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired()])
    level = SelectField('Level', choices=[
        ('', 'Choose Level'), 
        ('beginner', 'Beginner'), 
        ('intermediate', 'Intermediate'), 
        ('advanced', 'Advanced')
    ], validators=[DataRequired(message='Please choose a level')])
    submit = SubmitField('Register')

class AdminAccessForm(FlaskForm):
    access_code = StringField('Access Code', validators=[DataRequired()])
    submit = SubmitField('Enter Admin Panel')

class EditUserForm(FlaskForm):
    name = StringField('Full Name', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    level = SelectField('Level', choices=[
        ('beginner', 'Beginner'),
        ('intermediate', 'Intermediate'),
        ('advanced', 'Advanced')
    ], validators=[DataRequired()])
    status = SelectField('Status', choices=[
        ('active', 'Active'),
        ('inactive', 'Inactive'),
        ('suspended', 'Suspended')
    ], validators=[DataRequired()])
    submit = SubmitField('Save Changes')

def log_activity(action, details):
    activity_collection.insert_one({
        'action': action,
        'details': details,
        'timestamp': datetime.now(),
        'admin': session.get('admin_email', 'Unknown')
    })

# ====================== ADMIN DASHBOARD ROUTES ======================

@app.route('/admin', methods=['GET', 'POST'])
def admin_dashboard():
    if not session.get('admin_verified'):
        return redirect(url_for('admin_login'))
    
    form = request.args
    level_filter = form.get('level', 'all')
    page = int(form.get('page', 1))
    per_page = 10
    
    query = {} if level_filter == 'all' else {'level': level_filter}
    total_users = users_collection.count_documents(query)
    users = list(users_collection.find(query).skip((page-1)*per_page).limit(per_page))
    
    # Get stats for cards
    stats = {
        'total': users_collection.count_documents({}),
        'beginner': users_collection.count_documents({'level': 'beginner'}),
        'intermediate': users_collection.count_documents({'level': 'intermediate'}),
        'advanced': users_collection.count_documents({'level': 'advanced'})
    }
    
    # Get recent activity
    recent_activity = list(activity_collection.find().sort('timestamp', -1).limit(3))
    
    return render_template('admin_dashboard.html', 
                         users=users, 
                         current_filter=level_filter,
                         stats=stats,
                         recent_activity=recent_activity,
                         pagination={
                             'page': page,
                             'per_page': per_page,
                             'total': total_users,
                             'pages': (total_users // per_page) + (1 if total_users % per_page else 0)
                         })

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if session.get('admin_verified'):
        return redirect(url_for('admin_dashboard'))
    
    form = AdminAccessForm()
    if form.validate_on_submit():
        if form.access_code.data == "UGAAS0011":
            session['admin_verified'] = True
            session['admin_email'] = 'admin@school.com'  # Replace with actual admin email
            log_activity('Login', 'Admin logged in')
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Invalid access code. Please try again.', 'danger')
            log_activity('Failed Login', f'Failed attempt with code: {form.access_code.data}')
    
    return render_template('admin_login.html', form=form)

@app.route('/admin/logout')
def admin_logout():
    log_activity('Logout', 'Admin logged out')
    session.clear()
    return redirect(url_for('admin_login'))

@app.route('/admin/user/<user_id>')
def view_user(user_id):
    if not session.get('admin_verified'):
        return redirect(url_for('admin_login'))
    
    user = users_collection.find_one({'_id': ObjectId(user_id)})
    if not user:
        flash('User not found', 'danger')
        return redirect(url_for('admin_dashboard'))
    
    # Get user-specific activity
    user_activity = list(activity_collection.find({'user_id': user_id}).sort('timestamp', -1).limit(5))
    
    log_activity('View User', f'Viewed user: {user["name"]}')
    return render_template('view_user.html', user=user, user_activity=user_activity)

@app.route('/admin/edit/<user_id>', methods=['GET', 'POST'])
def edit_user(user_id):
    if not session.get('admin_verified'):
        return redirect(url_for('admin_login'))
    
    user = users_collection.find_one({'_id': ObjectId(user_id)})
    if not user:
        flash('User not found', 'danger')
        return redirect(url_for('admin_dashboard'))
    
    form = EditUserForm()
    
    if form.validate_on_submit():
        users_collection.update_one(
            {'_id': ObjectId(user_id)},
            {'$set': {
                'name': form.name.data,
                'email': form.email.data,
                'level': form.level.data,
                'status': form.status.data,
                'updated_at': datetime.now()
            }}
        )
        flash('User updated successfully', 'success')
        log_activity('User Updated', f'Updated user: {form.name.data}')
        return redirect(url_for('view_user', user_id=user_id))
    
    # Pre-populate form for GET request
    if request.method == 'GET':
        form.name.data = user['name']
        form.email.data = user['email']
        form.level.data = user['level']
        form.status.data = user.get('status', 'active')
    
    return render_template('edit_user.html', form=form, user=user)

@app.route('/admin/delete/<user_id>')
def delete_user(user_id):
    if not session.get('admin_verified'):
        return redirect(url_for('admin_login'))
    
    user = users_collection.find_one({'_id': ObjectId(user_id)})
    if user:
        users_collection.delete_one({'_id': ObjectId(user_id)})
        flash('User deleted successfully', 'success')
        log_activity('User Deleted', f'Deleted user: {user["name"]}')
    else:
        flash('User not found', 'danger')
    
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/message/<user_id>', methods=['GET', 'POST'])
def message_user(user_id):
    if not session.get('admin_verified'):
        return redirect(url_for('admin_login'))
    
    user = users_collection.find_one({'_id': ObjectId(user_id)})
    if not user:
        flash('User not found', 'danger')
        return redirect(url_for('admin_dashboard'))
    
    if request.method == 'POST':
        message = request.form.get('message')
        # Here you would implement actual messaging functionality
        flash(f'Message sent to {user["name"]}', 'success')
        log_activity('Message Sent', f'To: {user["name"]}, Message: {message[:20]}...')
        return redirect(url_for('view_user', user_id=user_id))
    
    return render_template('message_user.html', user=user)

@app.route('/admin/stats')
def admin_stats():
    if not session.get('admin_verified'):
        return redirect(url_for('admin_login'))
    
    stats = {
        'total': users_collection.count_documents({}),
        'beginner': users_collection.count_documents({'level': 'beginner'}),
        'intermediate': users_collection.count_documents({'level': 'intermediate'}),
        'advanced': users_collection.count_documents({'level': 'advanced'})
    }
    
    return jsonify(stats)

# ====================== EXISTING APPLICATION ROUTES ======================

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route("/send_message", methods=["POST"])
def send_message():
    name = request.form.get("name", "")
    email = request.form.get("email", "")
    message = request.form.get("message", "")

    msg = Message(
        subject=f"New Message from {name}",
        recipients=["contact@amouduniversity.edu.so"],
        body=f"Name: {name}\nEmail: {email}\n\nMessage:\n{message}"
    )

    try:
        mail.send(msg)
        flash("Message sent successfully!", "success")
    except Exception as e:
        flash(f"Failed to send message: {str(e)}", "danger")

    return redirect("/")

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data.strip()
        password = form.password.data.strip()
        user = users_collection.find_one({"email": email})

        if user and user.get('password') == password:
            device_id = f"{request.remote_addr}_{request.user_agent.string}"
            devices = user.get('devices', [])
            
            if len(devices) >= 2 and device_id not in devices:
                flash('You have reached the maximum allowed devices.', 'danger')
                return redirect(url_for('login', reset_devices=True))

            if device_id not in devices:
                users_collection.update_one(
                    {'_id': user['_id']},
                    {'$push': {'devices': device_id}}
                )

            session['user_id'] = str(user['_id'])
            session['role'] = user.get('role', 'student')
            session['level'] = form.level.data

            if session['role'] == 'teacher':
                return redirect(url_for('teacher_dashboard'))
            else:
                return redirect(url_for('student_dashboard'))

        flash('Username or password is incorrect', 'danger')
    else:
        for field, errors in form.errors.items():
            for error in errors:
                flash(f"{field.capitalize()}: {error}", 'danger')

    return render_template('login.html', form=form)

@app.route('/reset_devices', methods=['GET', 'POST'])
def reset_devices():
    form = ResetDeviceForm(request.form)
    if request.method == 'POST' and form.validate():
        email = form.email.data.strip()
        password = form.password.data.strip()
        user = users_collection.find_one({"email": email})
        if user and user.get('password') == password:
            users_collection.update_one({'_id': user['_id']}, {'$set': {'devices': []}})
            flash('The device list has been reset. Please log in again.', 'success')
            return redirect(url_for('login'))
        else:
            flash('Invalid credentials. Please try again.', 'danger')
    return render_template('reset_devices.html', form=form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        email = form.email.data.strip().lower()
        
        if users_collection.find_one({"email": email}):
            flash('Email already registered!', 'danger')
        else:
            user_data = {
                "name": form.name.data.strip(),
                "email": email,
                "password": form.password.data,
                "level": form.level.data,
                "role": "student",
                "created_at": datetime.now(),
                "status": "active"
            }
            users_collection.insert_one(user_data)
            flash('Student registered successfully!', 'success')
            return redirect(url_for('register'))
    
    return render_template('register.html', form=form)

@app.route('/unit1')
def unit_one():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    lessons = list(lessons_collection.find({"unit": 1}))
    if not lessons:
        return "No lessons found for Unit One", 404

    return render_template('unitone.html', lessons=lessons)

@app.route('/unit2')
def unit_two():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('unitTwo.html')

@app.route('/unit3')
def unit_three():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('unitthree.html')

@app.route('/unit4')
def unit_four():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('unitthree.html')

@app.route('/verify_code', methods=['POST'])
def verify_code():
    user_level = session.get('level', 'beginner')
    data = request.json
    entered_code = data.get('code')
    requested_level = data.get('level')

    level_hierarchy = ["beginner", "intermediate", "upper-intermediate", "advanced"]

    if level_hierarchy.index(requested_level) > level_hierarchy.index(user_level):
        return jsonify({"error": "You cannot access this level"}), 403

    code_doc = access_codes_collection.find_one({"level": requested_level})
    
    if not code_doc:
        return jsonify({"error": "Invalid level"}), 400

    correct_code = code_doc.get("code")

    if entered_code == correct_code:
        return jsonify({"message": "Access granted", "redirect": url_for('profile')})
    else:
        return jsonify({"error": "Incorrect code"}), 401

@app.route('/remove_device', methods=['POST'])
def remove_device():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 403

    user_id = session['user_id']
    device_id = request.json.get('device_id')

    users_collection.update_one(
        {'_id': ObjectId(user_id)},
        {'$pull': {'devices': device_id}}
    )

    return jsonify({'message': 'Device removed successfully'})

@app.route("/basic_grammar")
def basic_grammar():
    return render_template("basic_grammar.html")

@app.route("/advance_grammar")
def advance_grammar():
    return render_template("advance_grammar.html")

@app.route("/vocabulary")
def vocabulary():
    return render_template("vocabulary.html")

@app.route('/add_questions', methods=['POST'])
def add_questions():
    data = request.json
    level = data.get('level')
    questions = data.get('questions')

    if not level or not questions:
        return jsonify({'error': 'Level and questions are required'}), 400

    for question in questions:
        questions_collection.insert_one({
            'level': level,
            'question': question['question'],
            'options': question['options'],
            'answer': question['answer']
        })

    return jsonify({'message': 'Questions added successfully'}), 201

fs = gridfs.GridFS(db)

@app.route('/get_lessons/<level>/<unit>')
def get_lessons(level, unit):
    try:
        unit_int = int(unit)
    except ValueError:
        return jsonify({"error": "Invalid unit"}), 400

    lessons = list(lessons_collection.find({"lesson_level": level, "unit": unit_int}))
    
    for lesson in lessons:
        lesson['_id'] = str(lesson['_id'])
    return jsonify(lessons)

@app.route('/upload_lesson', methods=['POST'])
def upload_lesson():
    lesson_title = request.form.get('lesson_title')
    lesson_level = request.form.get('lesson_level')
    unit = 1

    lesson_video = request.files.get('lesson_video')
    exercise_file1 = request.files.get('exercise_file1')
    exercise_file2 = request.files.get('exercise_file2')
    exercise_file3 = request.files.get('exercise_file3')
    first_exam = request.files.get('first_exam')
    second_exam = request.files.get('second_exam')
    final_exam = request.files.get('final_exam')

    if not (lesson_title and lesson_level and lesson_video and exercise_file1 and exercise_file2 and exercise_file3 and first_exam and second_exam and final_exam):
        return jsonify({'error': 'Please fill all fields and upload all files!'}), 400

    video_filename = secure_filename(lesson_video.filename)
    video_save_path = os.path.join(app.config['UPLOAD_FOLDER_VIDEO'], video_filename)
    lesson_video.save(video_save_path)
    video_url = '/static/videos/' + video_filename

    exercise_filename1 = secure_filename(exercise_file1.filename)
    exercise_save_path1 = os.path.join(app.config['UPLOAD_FOLDER_EXERCISES'], exercise_filename1)
    exercise_file1.save(exercise_save_path1)
    exercise_file_path1 = '/static/exercises/' + exercise_filename1

    exercise_filename2 = secure_filename(exercise_file2.filename)
    exercise_save_path2 = os.path.join(app.config['UPLOAD_FOLDER_EXERCISES'], exercise_filename2)
    exercise_file2.save(exercise_save_path2)
    exercise_file_path2 = '/static/exercises/' + exercise_filename2

    exercise_filename3 = secure_filename(exercise_file3.filename)
    exercise_save_path3 = os.path.join(app.config['UPLOAD_FOLDER_EXERCISES'], exercise_filename3)
    exercise_file3.save(exercise_save_path3)
    exercise_file_path3 = '/static/exercises/' + exercise_filename3

    exam_filename1 = secure_filename(first_exam.filename)
    exam_save_path1 = os.path.join(app.config['UPLOAD_FOLDER_EXAMS'], exam_filename1)
    first_exam.save(exam_save_path1)
    exam_file_path1 = '/static/exams/' + exam_filename1

    exam_filename2 = secure_filename(second_exam.filename)
    exam_save_path2 = os.path.join(app.config['UPLOAD_FOLDER_EXAMS'], exam_filename2)
    second_exam.save(exam_save_path2)
    exam_file_path2 = '/static/exams/' + exam_filename2

    exam_filename3 = secure_filename(final_exam.filename)
    exam_save_path3 = os.path.join(app.config['UPLOAD_FOLDER_EXAMS'], exam_filename3)
    final_exam.save(exam_save_path3)
    exam_file_path3 = '/static/exams/' + exam_filename3

    exercise_id1 = str(ObjectId())
    exercise_id2 = str(ObjectId())
    exercise_id3 = str(ObjectId())
    exam_id1 = str(ObjectId())
    exam_id2 = str(ObjectId())
    exam_id3 = str(ObjectId())

    lesson_document = {
        "lesson_title": lesson_title,
        "lesson_level": lesson_level,
        "unit": unit,
        "video_url": video_url,
        "exercises": [
            {"exercise_id": exercise_id1, "title": "Exercise One", "file_path": exercise_file_path1},
            {"exercise_id": exercise_id2, "title": "Exercise Two", "file_path": exercise_file_path2},
            {"exercise_id": exercise_id3, "title": "Exercise Three", "file_path": exercise_file_path3}
        ],
        "exams": [
            {"exam_id": exam_id1, "title": "First Exam", "file_path": exam_file_path1},
            {"exam_id": exam_id2, "title": "Second Exam", "file_path": exam_file_path2},
            {"exam_id": exam_id3, "title": "Final Exam", "file_path": exam_file_path3}
        ]
    }
    
    lessons_collection.insert_one(lesson_document)
    return jsonify({"message": "Lesson uploaded successfully!"})

@app.route('/upload_exam', methods=['POST'])
def upload_exam():
    try:
        if 'exam_file' not in request.files:
            return jsonify({"error": "No file uploaded"}), 400

        file = request.files['exam_file']
        exam_title = request.form.get('exam_title', '').strip()
        exam_level = request.form.get('exam_level', '').strip()

        if not exam_title:
            return jsonify({"error": "Exam title is required"}), 400
        if not exam_level:
            return jsonify({"error": "Exam level is required"}), 400

        if file.filename == '':
            return jsonify({"error": "No selected file"}), 400

        file_id = fs.put(file, filename=secure_filename(file.filename), content_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document")

        file.seek(0)
        exam_data = parse_docx_to_json(file)

        exam_document = {
            "exam_title": exam_title,
            "level": exam_level,
            "file_id": str(file_id),
            "questions": exam_data.get("questions", [])
        }
        questions_collection.insert_one(exam_document)

        print("✅ Exam uploaded successfully:", exam_document)

        return jsonify({
            "message": "Exam uploaded, converted to JSON, and saved successfully",
            "exam_title": exam_title,
            "exam_level": exam_level,
            "exam_data": exam_data
        }), 201

    except Exception as e:
        print("❌ Error processing exam:", str(e))
        return jsonify({"error": "An error occurred", "details": str(e)}), 500

def parse_docx_to_json(file):
    doc = docx.Document(file)
    questions = []
    current_question = None

    for para in doc.paragraphs:
        text = para.text.strip()

        if text.startswith("Q:"):
            if current_question:
                questions.append(current_question)
            current_question = {"question": text[2:].strip(), "options": [], "answer": ""}

        elif text.startswith("A:"):
            if current_question:
                current_question["answer"] = text[2:].strip()

        elif text:
            if current_question:
                current_question["options"].append(text)

    if current_question:
        questions.append(current_question)

    return {"questions": questions}

@app.route('/get_questions', methods=['GET'])
def get_questions():
    level = request.args.get('level')
    if level not in ['beginner', 'intermediate', 'advanced']:
        return jsonify({'error': 'Invalid level. Choose from beginner, intermediate, or advanced'}), 400

    questions = list(questions_collection.find({'level': level}, {'_id': 0}))
    return jsonify({'level': level, 'questions': questions})

@app.route('/contact', methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        message = request.form['message']
        flash('Message sent successfully!', 'success')
        return redirect(url_for('contact'))
    return render_template('contact.html')

@app.route('/get_exercise', methods=['GET'])
def get_exercise():
    exercise_id = request.args.get('exercise_id')

    if not exercise_id:
        return jsonify({"error": "Exercise ID is required"}), 400

    result = lessons_collection.find_one(
        {"exercises.exercise_id": exercise_id},
        {"exercises.$": 1}
    )

    if not result:
        return jsonify({"error": "Exercise not found"}), 404

    return jsonify(result["exercises"][0])

@app.route('/read_lesson/<file_id>', methods=['GET'])
def read_lesson(file_id):
    try:
        file_id = ObjectId(file_id)
        lesson_file = fs.get(file_id)

        lesson_data = extract_text(lesson_file)

        return jsonify(lesson_data)

    except Exception as e:
        return jsonify({"error": "Lesson not found", "details": str(e)}), 404

@app.route('/teacher/dashboard', methods=['GET', 'POST'])
def teacher_dashboard():
    if 'user_id' not in session or session.get('role') != 'teacher':
        return redirect(url_for('login'))

    if request.method == 'POST':
        title = request.form.get('title')
        content = request.form.get('content')
        questions_collection.insert_one({
            "title": title,
            "content": content
        })
        flash('New quiz added successfully!', 'success')

    quizzes = list(questions_collection.find())
    return render_template('teacher_dashboard.html', quizzes=quizzes)

@app.route('/student_dashboard')
def student_dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    level = session.get('level')
    questions = list(questions_collection.find({'level': level}, {'_id': 0}))
    return render_template('student_dashboard.html', level=level, questions=questions)

@app.route('/see_answers/<int:quiz_id>')
def see_answers(quiz_id):
    questions_list = list(questions_collection.find({"quiz_id": quiz_id}))
    return render_template('see_answers.html', questions=questions_list)

@app.route('/quiz_dynamic')
def quiz_dynamic():
    unit = request.args.get('unit', '1')
    lesson = request.args.get('lesson', '1')
    exercise = request.args.get('exercise')
    exam = request.args.get('exam')

    if exam:
        exam_type = exam
        exercise_data = None
    else:
        exam_type = "exercise"
        exercise_id = exercise if exercise else "1"
        exercise_data = {
            'exercise_id': exercise_id,
            'title': f"Exercise {exercise_id} for Lesson {lesson} of Unit {unit}"
        }
    
    return render_template("quiz_dynamic.html", exam_type=exam_type, exercise=exercise_data)

@app.route("/exercise1_lesson1")
def exercise1_lesson1():
    return render_template("exercise1_lesson1.html")

@app.route("/exercise2_lesson1")
def exercise2_lesson1():
    return render_template("exercise2_lesson1.html")

@app.route("/exercise3_lesson1")
def exercise3_lesson1():
    return render_template("exercise3_lesson1.html")

@app.route("/exercise1_lesson2")
def exercise1_lesson2():
    return render_template("exercise1_lesson2.html")

@app.route("/exercise2_lesson2")
def exercise2_lesson2():
    return render_template("exercise2_lesson2.html")

@app.route("/exercise3_lesson2")
def exercise3_lesson2():
    return render_template("exercise3_lesson2.html")

@app.route('/submit_quiz', methods=['POST'])
def submit_quiz():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_answers = {}

    for key, value in request.form.items():
        if key.startswith("answer_"):
            question_id = key.split("_")[1]
            user_answers[question_id] = value

    session['answers'] = user_answers
    return redirect(url_for('results'))

@app.route('/results')
def results():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user_answers = session.get('answers', {})
    if not user_answers:
        flash("No quiz answers found. Please attempt the quiz first.")
        return redirect(url_for('exercise1'))

    correct_count = 0
    results_details = []

    for question_id, user_answer in user_answers.items():
        question_doc = questions_collection.find_one(
            {"_id": ObjectId(question_id)},
            {"question": 1, "answer": 1}
        )

        if question_doc:
            question_text = question_doc.get("question", "No question text")
            correct_ans = question_doc.get("answer", "").strip().lower()
            user_ans = user_answer.strip().lower()

            is_correct = (user_ans == correct_ans)
            if is_correct:
                correct_count += 1

            results_details.append({
                "question": question_text,
                "user_answer": user_answer,
                "correct_answer": question_doc["answer"],
                "correct": is_correct
            })
        else:
            results_details.append({
                "question": f"Question not found (ID: {question_id})",
                "user_answer": user_answer,
                "correct_answer": "Unknown",
                "correct": False
            })

    return render_template(
        "results.html",
        results=results_details,
        score=correct_count,
        total=len(user_answers)
    )

@app.route('/profile')
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user = users_collection.find_one({'_id': ObjectId(session['user_id'])})
    profile_picture = user.get('profile_picture', 'default_profile.jpg')

    return render_template('profile.html', user=user, profile_picture=profile_picture)

@app.route('/change_password', methods=['POST'])
def change_password():
    if 'user_id' not in session:
        return jsonify({"error": "Unauthorized"}), 401
    
    new_password = request.json.get('new_password')
    if not new_password:
        return jsonify({"error": "Password is required"}), 400

    users_collection.update_one({'_id': ObjectId(session['user_id'])}, {'$set': {'password': new_password}})

    return jsonify({"message": "Password updated successfully"}), 200

@app.route('/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({"message": "Logged out successfully"}), 200

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory('static/uploads', filename)

if __name__ == '__main__':
    app.run(debug=True, port=5001)