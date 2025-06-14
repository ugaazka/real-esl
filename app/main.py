import os
from flask import Flask, render_template, redirect, url_for, session, request, flash, jsonify, send_file, abort
from flask_mail import Mail, Message
from flask_wtf import FlaskForm 
from wtforms import StringField, PasswordField, SubmitField, SelectField, Form
from wtforms import validators
from wtforms.validators import DataRequired, Email, Length
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


# Configuration
class Config:
    SECRET_KEY = os.getenv('SECRET_KEY', 'ISLAMIC2025')  # Change to secure one in production
    MONGO_URI = 'mongodb+srv://islamic_online:I6ak9kqgdxRN9pBr@cluster0.nwyxn.mongodb.net/islamic_online?retryWrites=true&w=majority&appName=Cluster0'

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

exercise_id = "67c7136169d439da62ee910b"  # BADAL HADDII AY KHALDAN TAHAY

result = lessons_collection.find_one(
    {"exercises.exercise_id": exercise_id},
    {"exercises.$": 1}
)

# Qeex dariiqyada folder-yada

# Abuuri folder-yada haddii aysan jirin


# Forms


# Routes
@app.route('/')
def index():
    return render_template('index.html')  # Home page (Intro)


@app.route('/about')
def about():
    return render_template('about.html')  # Home page (Intro)

@app.route("/send_message", methods=["POST"])
def send_message():
    name = request.form.get("name", "")
    email = request.form.get("email", "")
    message = request.form.get("message", "")

    msg = Message(
        subject=f"New Message from {name}",
        recipients=["contact@amouduniversity.edu.so"],  # Email-ka fariimaha la diro
        body=f"Name: {name}\nEmail: {email}\n\nMessage:\n{message}"
    )

    try:
        mail.send(msg)
        flash("Message sent successfully!", "success")
    except Exception as e:
        flash(f"Failed to send message: {str(e)}", "danger")

    return redirect("/")


# Login Form
class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email(message='Enter a valid email')])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6, message='Password must be at least 6 characters')])
    level = SelectField('Level', choices=[('', 'Choose Level'), ('beginner', 'Beginner'), ('intermediate', 'Intermediate'), ('advanced', 'Advanced')], validators=[DataRequired(message='Please choose a level')])
    submit = SubmitField('Login')

class ResetDeviceForm(FlaskForm):
    email = StringField('Email', [validators.DataRequired(), validators.Email()])
    password = PasswordField('Password', [validators.DataRequired()])

# Example MongoDB collection for users
# users_collection = your_database.users_collection

# Define a ResetDeviceForm with email and password fiel

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()  # Make sure the LoginForm is defined beforehand
    if form.validate_on_submit():
        email = form.email.data.strip()
        password = form.password.data.strip()
        user = users_collection.find_one({"email": email})

        if user and user.get('password') == password:
            device_id = f"{request.remote_addr}_{request.user_agent.string}"
            # Retrieve the device list if available, otherwise use an empty list.
            devices = user.get('devices', [])
            
            # If the user has already used at least two devices and the new device is not in the list,
            # display a warning message and redirect to login with a parameter to show the reset option.
            if len(devices) >= 2 and device_id not in devices:
                flash('You have reached the maximum allowed devices.', 'danger')
                return redirect(url_for('login', reset_devices=True))

            # If the new device is not already in the list, add it.
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

# Updated route for Reset Devices that works without a prior login
@app.route('/reset_devices', methods=['GET', 'POST'])
def reset_devices():
    form = ResetDeviceForm(request.form)
    if request.method == 'POST' and form.validate():
        email = form.email.data.strip()
        password = form.password.data.strip()
        user = users_collection.find_one({"email": email})
        if user and user.get('password') == password:
            # Clear the user's device list by setting it to an empty list.
            users_collection.update_one({'_id': user['_id']}, {'$set': {'devices': []}})
            flash('The device list has been reset. Please log in again.', 'success')
            return redirect(url_for('login'))
        else:
            flash('Invalid credentials. Please try again.', 'danger')
    return render_template('reset_devices.html', form=form)

@app.route('/unit2')
def unit_two():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('unitTwo.html')

# Route for Next Lesson (Example)

@app.route('/unit1')
def unit_one():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    # Hel xogta Unit One cashiradiisa
    lessons = list(lessons_collection.find({"unit": 1}))

    if not lessons:
        return "No lessons found for Unit One", 404

    return render_template('unitone.html', lessons=lessons)

# Route for Next Lesson (Example)


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
    user_level = session.get('level', 'beginner')  # Hel levelka qofka
    data = request.json
    entered_code = data.get('code')
    requested_level = data.get('level')

    # Hubi in user-ka uu xaq u leeyahay inuu galo level-kan
    level_hierarchy = ["beginner", "intermediate", "upper-intermediate", "advanced"]

    if level_hierarchy.index(requested_level) > level_hierarchy.index(user_level):
        return jsonify({"error": "You cannot access this level"}), 403

    # Hel code sax ah MongoDB
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

# Route for the Advanced Grammar page
@app.route("/advance_grammar")
def advance_grammar():
    return render_template("advance_grammar.html")

# Route for the Vocabulary page
@app.route("/vocabulary")
def vocabulary():
    return render_template("vocabulary.html")

# Teacher Dashboard: Add questions
@app.route('/add_questions', methods=['POST'])
def add_questions():
    data = request.json
    level = data.get('level')  # beginner, intermediate, advanced
    questions = data.get('questions')

    if not level or not questions:
        return jsonify({'error': 'Level and questions are required'}), 400

    for question in questions:
        questions_collection.insert_one({
            'level': level,
            'question': question['question'],
            'options': question['options'],  # List of options
            'answer': question['answer']    # Correct answer
        })

    return jsonify({'message': 'Questions added successfully'}), 201

fs = gridfs.GridFS(db)  # Initialize GridFS


@app.route('/get_lessons/<level>/<unit>')
def get_lessons(level, unit):
    try:
        unit_int = int(unit)
    except ValueError:
        return jsonify({"error": "Invalid unit"}), 400

    lessons = list(lessons_collection.find({"lesson_level": level, "unit": unit_int}))
    
    # (Ikhtiyaari) Ku badal ObjectId string haddii aad rabto in JSON-ka uu si sax ah u muujiyo id-ga
    for lesson in lessons:
        lesson['_id'] = str(lesson['_id'])
    return jsonify(lessons)



@app.route('/upload_lesson', methods=['POST'])
def upload_lesson():
    lesson_title = request.form.get('lesson_title')
    lesson_level = request.form.get('lesson_level')
    # Halkan waxaad ku qeexeysaa unit – tusaale ahaan unit 1
    unit = 1

    # Hel file-yada
    lesson_video = request.files.get('lesson_video')
    exercise_file1 = request.files.get('exercise_file1')
    exercise_file2 = request.files.get('exercise_file2')
    exercise_file3 = request.files.get('exercise_file3')
    first_exam = request.files.get('first_exam')
    second_exam = request.files.get('second_exam')
    final_exam = request.files.get('final_exam')

    if not (lesson_title and lesson_level and lesson_video and exercise_file1 and exercise_file2 and exercise_file3 and first_exam and second_exam and final_exam):
        return jsonify({'error': 'Please fill all fields and upload all files!'}), 400

    # Kaydi file-yada (waxaad u baahan tahay inaad ku qeexdo folder-yada ku jira config)
    video_filename = secure_filename(lesson_video.filename)
    video_save_path = os.path.join(app.config['UPLOAD_FOLDER_VIDEO'], video_filename)
    lesson_video.save(video_save_path)
    video_url = '/static/videos/' + video_filename

    # Exercises
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

    # Exams
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

    # Abuur id-yada gaar ahaaneed
    exercise_id1 = str(ObjectId())
    exercise_id2 = str(ObjectId())
    exercise_id3 = str(ObjectId())
    exam_id1 = str(ObjectId())
    exam_id2 = str(ObjectId())
    exam_id3 = str(ObjectId())

    # Dhis document-ka casharka
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

        # Save the Word file in MongoDB GridFS
        file_id = fs.put(file, filename=secure_filename(file.filename), content_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document")

        # Convert Word file to JSON
        file.seek(0)  # Reset file pointer for reading
        exam_data = parse_docx_to_json(file)

        # Save extracted questions to MongoDB with title and level
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
    """Extract questions and answers from a .docx file and return as JSON"""
    doc = docx.Document(file)
    questions = []
    current_question = None

    for para in doc.paragraphs:
        text = para.text.strip()

        if text.startswith("Q:"):  # Identify questions
            if current_question:
                questions.append(current_question)
            current_question = {"question": text[2:].strip(), "options": [], "answer": ""}

        elif text.startswith("A:"):  # Identify correct answer
            if current_question:
                current_question["answer"] = text[2:].strip()

        elif text:  # Add multiple choice options
            if current_question:
                current_question["options"].append(text)

    if current_question:
        questions.append(current_question)

    return {"questions": questions}

def parse_docx_to_json(file):
    """Extract questions and answers from a .docx file and return as JSON"""
    doc = docx.Document(file)
    questions = []
    current_question = None

    for para in doc.paragraphs:
        text = para.text.strip()

        if text.startswith("Q:"):  # Identify questions
            if current_question:
                questions.append(current_question)
            current_question = {"question": text[2:].strip(), "options": [], "answer": ""}

        elif text.startswith("A:"):  # Identify correct answer
            if current_question:
                current_question["answer"] = text[2:].strip()

        elif text:  # Add multiple choice options
            if current_question:
                current_question["options"].append(text)

    if current_question:
        questions.append(current_question)

    return {"questions": questions}

# Student Dashboard: Get questions by level
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
        # Halkan ayaad database ugu diri kartaa message-ka
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
        {"exercises.$": 1}  # Only return the matched exercise
    )

    if not result:
        return jsonify({"error": "Exercise not found"}), 404

    return jsonify(result["exercises"][0])  # Return first matched exercise

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

# Student Dashboard Route
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

quiz_data = {
    "ex1": {
        "quizTitle": "Quiz for Exercise One",
        "questions": [
            {
                "_id": "q1",
                "question": "What is 2 + 2?",
                "options": ["3", "4", "5", "6"],
                "correct_answer": "4"
            },
            {
                "_id": "q2",
                "question": "What is the capital of France?",
                "options": ["Paris", "London", "Berlin", "Rome"],
                "correct_answer": "Paris"
            }
        ]
    },
    "ex2": {
        "quizTitle": "Quiz for Exercise Two",
        "questions": [
            {
                "_id": "q3",
                "question": "What is 3 + 3?",
                "options": ["5", "6", "7", "8"],
                "correct_answer": "6"
            }
        ]
    }
}

def extract_questions_from_pdf(pdf_path):
    questions = []
    with open(pdf_path, 'rb') as file:
        reader = PyPDF2.PdfFileReader(file)
        for page_num in range(reader.numPages):
            page = reader.getPage(page_num)
            text = page.extract_text()
            # Assuming questions are separated by new lines
            questions.extend(text.split('\n'))
    return questions


@app.route('/quiz_dynamic')
def quiz_dynamic():
    # Akhri query parameters
    unit = request.args.get('unit', '1')
    lesson = request.args.get('lesson', '1')
    exercise = request.args.get('exercise')  # Tusaale: "1", "2", "3"
    exam = request.args.get('exam')          # Tusaale: "midterm1", "midterm2", "finalExam"

    # Haddii exam parameter la siiyo, exam_type waa midterm ama finalExam,
    # haddii kale exam_type waa "exercise"
    if exam:
        exam_type = exam
        exercise_data = None
    else:
        exam_type = "exercise"
        # Halkan waxaad ku abuuri kartaa xogta exercise iyadoo la saleynayo unit, lesson iyo exercise.
        # Haddii exercise uu ka maqan yahay, waxaad default ka dhigi kartaa "1".
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

    user_answers = {}  # Store answers

    for key, value in request.form.items():
        if key.startswith("answer_"):  # Only collect answers
            question_id = key.split("_")[1]  # Extract MongoDB _id
            user_answers[question_id] = value  # Store user answer

    session['answers'] = user_answers  # Save in session

    return redirect(url_for('results'))


@app.route('/results')
def results():
    # 1) Haddii user aan logged in ahayn, dib ugu celin login
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    # 2) Hel jawaabihii user-ku bixiyay
    user_answers = session.get('answers', {})
    if not user_answers:
        flash("No quiz answers found. Please attempt the quiz first.")
        # A) Haddii aad haysato route laga helo 'exercise1'
        #    Waa in aad haysato: @app.route("/exercise1") def exercise1(): ...
        return redirect(url_for('exercise1'))
        # B) Ama aad si toos ah ugu boodayso file:
        # return redirect('/exercise1.html')
        # Laakiin tan ma ahan sida ugu fiican Flask

    correct_count = 0
    results_details = []

    # 3) Loop su'aal walba oo uu user-ku ka jawaabay
    for question_id, user_answer in user_answers.items():
        question_doc = questions_collection.find_one(
            {"_id": ObjectId(question_id)},
            {"question": 1, "answer": 1}
        )

        if question_doc:
            # Ka soo saar su'aasha & jawaabta saxda ah
            question_text = question_doc.get("question", "No question text")
            correct_ans = question_doc.get("answer", "").strip().lower()
            user_ans = user_answer.strip().lower()

            # Hubi sax/khalad
            is_correct = (user_ans == correct_ans)
            if is_correct:
                correct_count += 1

            results_details.append({
                "question": question_text,
                "user_answer": user_answer,  # user answer sida uu qoray
                "correct_answer": question_doc["answer"],  # original doc
                "correct": is_correct
            })
        else:
            # Haddii su'aasha laga waayo DB
            results_details.append({
                "question": f"Question not found (ID: {question_id})",
                "user_answer": user_answer,
                "correct_answer": "Unknown",
                "correct": False
            })

    # 4) U dir natiijooyinkii template-ka results.html
    return render_template(
        "results.html",
        results=results_details,
        score=correct_count,
        total=len(user_answers)
    )

  
# Profile Route
@app.route('/profile')
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user = users_collection.find_one({'_id': ObjectId(session['user_id'])})
    profile_picture = user.get('profile_picture', 'default_profile.jpg')

    return render_template('profile.html', user=user, profile_picture=profile_picture)

# Change Password Route (NO HASHING)
@app.route('/change_password', methods=['POST'])
def change_password():
    if 'user_id' not in session:
        return jsonify({"error": "Unauthorized"}), 401
    
    new_password = request.json.get('new_password')
    if not new_password:
        return jsonify({"error": "Password is required"}), 400

    users_collection.update_one({'_id': ObjectId(session['user_id'])}, {'$set': {'password': new_password}})

    return jsonify({"message": "Password updated successfully"}), 200

# Change Profile Picture Route (FIXED IMAGE UPDATE ISSUE)

# Logout Route
@app.route('/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({"message": "Logged out successfully"}), 200

from flask import send_from_directory

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory('static/uploads', filename)


import docx

# Run the app
if __name__ == '__main__':
    app.run(debug=True, port=5001)