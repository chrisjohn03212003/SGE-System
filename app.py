from flask import Flask, render_template, request, jsonify, session, redirect, url_for
import firebase_admin
from firebase_admin import credentials,firestore as admin_firestore
from google.cloud.firestore_v1 import FieldFilter
import hashlib
import logging
import json
from datetime import datetime
import os
from traceback import print_exc

app = Flask(__name__)
app.secret_key = 'dev-secret-key-123'  # Change this to a secure secret key


def initialize_firebase():
    if os.environ.get('FIREBASE_CREDENTIALS'):
        # For production (Render) - use env variable with full JSON key
        service_account_info = json.loads(os.environ['FIREBASE_CREDENTIALS'])
        cred = credentials.Certificate(service_account_info)
    else:
        # For local development - use the local JSON file
        cred = credentials.Certificate(
            'sge-system-18570-firebase-adminsdk-fbsvc-28bbdc64ba.json')

    if not firebase_admin._apps:
        firebase_admin.initialize_app(cred)
    db = admin_firestore.client()
    return db


# Initialize Firebase
db = initialize_firebase()

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)


def hash_password(password):
    """Ensure consistent password hashing"""
    if not password:
        return None
    return hashlib.sha256(password.encode('utf-8')).hexdigest()


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/admin_login')
def admin_login():
    return render_template('admin_login.html')


@app.route('/student_login')
def student_login():
    return render_template('student_login.html')

    

@app.route('/login/admin', methods=['POST'])
def admin_auth():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    # Default admin credentials (change these!)
    if username == 'admin' and password == 'admin123':
        session['admin'] = True
        return jsonify({'success': True})

    return jsonify({'success': False, 'message': 'Invalid credentials'})

# Replace the existing student login routes in app.py with this corrected version


@app.route('/api/student_login', methods=['POST'])
def api_student_login():
    data = request.get_json()
    student_id = data.get('student_id', '').strip()
    password = data.get('password', '').strip()

    logger.debug(f"Login attempt for student ID: {student_id}")

    # Validate input
    if not student_id or not password:
        logger.debug("Missing student_id or password")
        return jsonify({'error': 'Student ID and password are required'}), 400

    try:
        # Find student by student_id
        students_ref = db.collection('students')
        query = students_ref.where(
            filter=FieldFilter('student_id', '==', student_id)).limit(1)
        docs = list(query.stream())

        if not docs:
            logger.debug(f"No student found with ID: {student_id}")
            return jsonify({'error': 'Invalid student ID or password'}), 401

        student_doc = docs[0]
        student_data = student_doc.to_dict()

        # Get stored password hash
        stored_password_hash = student_data.get('password')
        if not stored_password_hash:
            logger.debug("No password hash stored for student")
            return jsonify({'error': 'Account setup incomplete. Contact administrator.'}), 401

        # Hash the entered password and compare
        entered_password_hash = hash_password(password)

        logger.debug(f"Stored hash: {stored_password_hash[:10]}...")
        logger.debug(f"Entered hash: {entered_password_hash[:10]}...")
        logger.debug(
            f"Password match: {stored_password_hash == entered_password_hash}")

        if stored_password_hash == entered_password_hash:
            # Password matches - set ONLY student session data
            session.clear()
            
            session['student_id'] = student_id
            session['student_name'] = student_data.get('name')
            session['student_doc_id'] = student_doc.id
            session['has_voted'] = student_data.get('has_voted', False)
            # DO NOT set session['admin'] = True here!

            logger.debug(
                f"Login successful for student: {student_data.get('name')}")
            logger.debug(f"Session after login: {dict(session)}")  # Debug new session

            return jsonify({
                'token': 'authenticated',  # Frontend expects this
                'student_name': student_data.get('name'),
                'has_voted': student_data.get('has_voted', False)
            })
        else:
            logger.debug("Password mismatch")
            return jsonify({'error': 'Invalid student ID or password'}), 401

    except Exception as e:
        logger.error(f"Student login error: {str(e)}")
        return jsonify({'error': 'Login failed. Please try again.'}), 500


@app.route('/admin_dashboard')
def admin_dashboard():
    if not session.get('admin'):
        return redirect(url_for('admin_login'))
    return render_template('admin_dashboard.html')


# Add this route to your app.py (replace the existing student_dashboard function):

@app.route('/student_dashboard')
def student_dashboard():
    # Check if student is logged in
    if not session.get('student_id'):
        logger.debug("Student not logged in, redirecting to login")
        return redirect(url_for('student_login'))

    logger.debug(
        f"Student dashboard accessed by: {session.get('student_name')}")
    logger.debug(f"Session data: {dict(session)}")  # Debug session data

    return render_template('student_dashboard.html')


@app.route('/voting')
def voting():
    if not session.get('student_id'):
        logger.debug("Student not logged in for voting")
        return redirect(url_for('student_login'))

    # Check if student has already voted
    if session.get('has_voted'):
        logger.debug("Student has already voted")
        return redirect(url_for('student_dashboard'))

    return render_template('voting.html')



@app.route('/api/students', methods=['GET', 'POST'])
def manage_students():
    if not session.get('admin'):
        return jsonify({'error': 'Unauthorized'}), 401

    if request.method == 'POST':
        data = request.get_json()

        # Validate required fields
        required_fields = ['student_id', 'name', 'age', 'password']
        for field in required_fields:
            if not data.get(field):
                return jsonify({'error': f'{field} is required'}), 400

        try:
            # Check if student ID already exists
            existing_query = db.collection('students').where(
                filter=FieldFilter('student_id', '==', data['student_id'])).limit(1)
            existing_docs = list(existing_query.stream())

            if existing_docs:
                return jsonify({'error': 'Student ID already exists'}), 400

            # Make sure password is properly hashed
            raw_password = data['password'].strip()
            hashed_password = hash_password(raw_password)

            logger.debug(f"Creating student with ID: {data['student_id']}")
            logger.debug(f"Raw password length: {len(raw_password)}")
            # Only log first 10 chars for security
            logger.debug(f"Hashed password: {hashed_password[:10]}...")

            student_data = {
                'student_id': data['student_id'].strip(),
                'name': data['name'].strip(),
                'age': int(data['age']),
                'password': hashed_password,
                'has_voted': False,
                'created_at': datetime.now()
            }

            # Add the student to database
            doc_ref = db.collection('students').add(student_data)
            logger.debug(f"Student added with doc ID: {doc_ref[1].id}")

            return jsonify({'success': True})

        except Exception as e:
            logger.error(f"Error adding student: {str(e)}")
            return jsonify({'error': str(e)}), 500

    else:
        # GET request - return students list
        try:
            students = []
            docs = db.collection('students').stream()
            for doc in docs:
                student = doc.to_dict()
                student['id'] = doc.id
                # Don't send password hash to frontend
                student.pop('password', None)
                students.append(student)
            return jsonify(students)
        except Exception as e:
            logger.error(f"Error loading students: {str(e)}")
            return jsonify({'error': str(e)}), 500


@app.route('/api/students/<student_id>', methods=['DELETE'])
def delete_student(student_id):
    if not session.get('admin'):
        return jsonify({'error': 'Unauthorized'}), 401

    try:
        db.collection('students').document(student_id).delete()
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# Replace these routes in your app.py file

@app.route('/api/election-settings', methods=['GET', 'POST'])
def election_settings():
    if request.method == 'POST':
        # Only admins can modify settings
        if not session.get('admin'):
            return jsonify({'error': 'Unauthorized'}), 401
        
        data = request.get_json()
        try:
            db.collection('settings').document('election').set({
                'title': data.get('title', 'Student Government Election'),
                'updated_at': datetime.now()
            })
            return jsonify({'success': True})
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    else:
        # GET request - allow both students and admins to view settings
        try:
            doc = db.collection('settings').document('election').get()
            if doc.exists:
                return jsonify(doc.to_dict())
            else:
                return jsonify({'title': 'Student Government Election'})
        except Exception as e:
            return jsonify({'error': str(e)}), 500


@app.route('/api/positions', methods=['GET', 'POST'])
def manage_positions():
    if request.method == 'POST':
        # Only admins can create/modify positions
        if not session.get('admin'):
            return jsonify({'error': 'Unauthorized'}), 401
        
        data = request.get_json()
        try:
            position_data = {
                'name': data['name'],
                'order': int(data.get('order', 0)),
                'created_at': datetime.now()
            }
            db.collection('positions').add(position_data)
            return jsonify({'success': True})
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    else:
        # GET request - allow both students and admins to view positions
        try:
            positions = []
            docs = db.collection('positions').order_by('order').stream()
            for doc in docs:
                position = doc.to_dict()
                position['id'] = doc.id
                positions.append(position)
            return jsonify(positions)
        except Exception as e:
            return jsonify({'error': str(e)}), 500


@app.route('/api/candidates', methods=['GET', 'POST'])
def manage_candidates():
    if request.method == 'POST':
        # Only admins can create/modify candidates
        if not session.get('admin'):
            return jsonify({'error': 'Unauthorized'}), 401
        
        data = request.get_json()
        try:
            candidate_data = {
                'name': data['name'],
                'position_id': data['position_id'],
                'platform': data.get('platform', ''),
                'votes': 0,
                'created_at': datetime.now()
            }
            db.collection('candidates').add(candidate_data)
            return jsonify({'success': True})
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    else:
        # GET request - allow both students and admins to view candidates
        try:
            candidates = []
            docs = db.collection('candidates').stream()
            for doc in docs:
                candidate = doc.to_dict()
                candidate['id'] = doc.id
                candidates.append(candidate)
            return jsonify(candidates)
        except Exception as e:
            return jsonify({'error': str(e)}), 500


@app.route('/api/submit-vote', methods=['POST'])
def submit_vote():
    if not session.get('student_id'):
        return jsonify({'error': 'Unauthorized'}), 401

    data = request.get_json()
    student_id = session['student_id']

    try:
        # Check if student has already voted
        students_ref = db.collection('students')
        query = students_ref.where(
            filter=FieldFilter('student_id', '==', student_id)).limit(1)
        docs = list(query.stream())  # Convert to list to iterate properly

        student_doc_id = None
        for doc in docs:
            student_data = doc.to_dict()
            if student_data.get('has_voted'):
                return jsonify({'error': 'You have already voted'}), 400
            student_doc_id = doc.id
            break

        if not student_doc_id:
            return jsonify({'error': 'Student not found'}), 404

        # Get the votes (array of candidate IDs)
        candidate_ids = data.get('votes', [])
        
        if not candidate_ids:
            return jsonify({'error': 'No votes submitted'}), 400

        # Process votes using a batch
        batch = db.batch()

        # Increment vote count for each selected candidate
        for candidate_id in candidate_ids:
            if candidate_id:  # Skip null/empty values
                candidate_ref = db.collection('candidates').document(candidate_id)
                candidate_doc = candidate_ref.get()
                if candidate_doc.exists:
                    current_votes = candidate_doc.to_dict().get('votes', 0)
                    batch.update(candidate_ref, {'votes': current_votes + 1})
                else:
                    logger.warning(f"Candidate {candidate_id} not found")

        # Mark student as voted
        student_ref = db.collection('students').document(student_doc_id)
        batch.update(student_ref, {
            'has_voted': True,
            'voted_at': datetime.now()
        })

        # Record vote details for audit
        vote_record = {
            'student_id': student_id,
            'candidate_ids': candidate_ids,
            'timestamp': datetime.now()
        }
        vote_record_ref = db.collection('vote_records').document()
        batch.set(vote_record_ref, vote_record)

        # Commit all changes
        batch.commit()

        # Update session to reflect voting status
        session['has_voted'] = True
        session.permanent = True  # Make session persistent

        logger.info(f"Vote submitted successfully for student: {student_id}")
        return jsonify({
            'success': True, 
            'message': 'Vote submitted successfully',
            'has_voted': True
        })

    except Exception as e:
        logger.error(f"Error submitting vote: {str(e)}")
        return jsonify({'error': 'Failed to submit vote. Please try again.'}), 500


@app.route('/api/results')
def get_results():
    if not session.get('admin'):
        return jsonify({'error': 'Unauthorized'}), 401

    try:
        results = {}

        # Get all positions
        positions = []
        position_docs = db.collection('positions').order_by('order').stream()
        for doc in position_docs:
            position = doc.to_dict()
            position['id'] = doc.id
            positions.append(position)

        # Get candidates for each position
        for position in positions:
            candidates = []
            candidate_docs = db.collection('candidates').where(
                filter=FieldFilter('position_id', '==', position['id'])
            ).stream()  # 🚫 removed .order_by

            for doc in candidate_docs:
                candidate = doc.to_dict()
                candidate['id'] = doc.id
                candidate['votes'] = candidate.get('votes', 0)  # ✅ default to 0
                candidates.append(candidate)

            # ✅ sort candidates by vote count in Python
            candidates.sort(key=lambda c: c['votes'], reverse=True)

            results[position['name']] = {
                'position_id': position['id'],
                'candidates': candidates,
                'winner': candidates[0] if candidates else None
            }

        return jsonify(results)

    except Exception as e:
        print_exc()  # 🔍 show full traceback in terminal
        return jsonify({'error': str(e)}), 500


@app.route('/api/student-info')
def get_student_info():
    if not session.get('student_id'):
        return jsonify({'error': 'Unauthorized'}), 401

    try:
        student_id = session['student_id']
        students_ref = db.collection('students')
        query = students_ref.where(filter=FieldFilter("student_id", "==", student_id)).limit(1)
        docs = query.stream()

        for doc in docs:
            student_data = doc.to_dict()
            return jsonify({
                'name': student_data.get('name'),
                'student_id': student_data.get('student_id'),
                'age': student_data.get('age'),
                'has_voted': student_data.get('has_voted', False)
            })

        return jsonify({'error': 'Student not found'}), 404

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/check-auth')
def check_auth():
    """Check if user is authenticated and return user info"""
    if session.get('admin'):
        return jsonify({'authenticated': True, 'user_type': 'admin'})
    elif session.get('student_id'):
        return jsonify({
            'authenticated': True,
            'user_type': 'student',
            'student_id': session['student_id'],
            'student_name': session.get('student_name'),
            'has_voted': session.get('has_voted', False)
        })
    else:
        return jsonify({'authenticated': False})
    
    
# Add these endpoints to your app.py file

@app.route('/api/candidates/<candidate_id>', methods=['DELETE'])
def delete_candidate(candidate_id):
    if not session.get('admin'):
        return jsonify({'error': 'Unauthorized'}), 401

    try:
        # Check if candidate exists
        candidate_ref = db.collection('candidates').document(candidate_id)
        candidate_doc = candidate_ref.get()
        
        if not candidate_doc.exists:
            return jsonify({'error': 'Candidate not found'}), 404
        
        # Delete the candidate
        candidate_ref.delete()
        logger.info(f"Candidate {candidate_id} deleted successfully")
        return jsonify({'success': True})
        
    except Exception as e:
        logger.error(f"Error deleting candidate {candidate_id}: {str(e)}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/positions/<position_id>', methods=['DELETE'])
def delete_position(position_id):
    if not session.get('admin'):
        return jsonify({'error': 'Unauthorized'}), 401

    try:
        # Check if position exists
        position_ref = db.collection('positions').document(position_id)
        position_doc = position_ref.get()
        
        if not position_doc.exists:
            return jsonify({'error': 'Position not found'}), 404
        
        # Check if there are candidates for this position
        candidates_query = db.collection('candidates').where(
            filter=FieldFilter('position_id', '==', position_id)
        ).limit(1)
        
        candidates_docs = list(candidates_query.stream())
        if candidates_docs:
            return jsonify({'error': 'Cannot delete position with existing candidates. Delete candidates first.'}), 400
        
        # Delete the position
        position_ref.delete()
        logger.info(f"Position {position_id} deleted successfully")
        return jsonify({'success': True})
        
    except Exception as e:
        logger.error(f"Error deleting position {position_id}: {str(e)}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/candidates/<candidate_id>', methods=['PUT'])
def update_candidate(candidate_id):
    if not session.get('admin'):
        return jsonify({'error': 'Unauthorized'}), 401

    try:
        data = request.get_json()
        
        # Check if candidate exists
        candidate_ref = db.collection('candidates').document(candidate_id)
        candidate_doc = candidate_ref.get()
        
        if not candidate_doc.exists:
            return jsonify({'error': 'Candidate not found'}), 404
        
        # Update candidate data
        update_data = {
            'name': data.get('name'),
            'platform': data.get('platform', ''),
            'updated_at': datetime.now()
        }
        
        # Only update position_id if provided
        if 'position_id' in data:
            update_data['position_id'] = data['position_id']
        
        candidate_ref.update(update_data)
        logger.info(f"Candidate {candidate_id} updated successfully")
        return jsonify({'success': True})
        
    except Exception as e:
        logger.error(f"Error updating candidate {candidate_id}: {str(e)}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/positions/<position_id>', methods=['PUT'])
def update_position(position_id):
    if not session.get('admin'):
        return jsonify({'error': 'Unauthorized'}), 401

    try:
        data = request.get_json()
        
        # Check if position exists
        position_ref = db.collection('positions').document(position_id)
        position_doc = position_ref.get()
        
        if not position_doc.exists:
            return jsonify({'error': 'Position not found'}), 404
        
        # Update position data
        update_data = {
            'name': data.get('name'),
            'order': int(data.get('order', 0)),
            'updated_at': datetime.now()
        }
        
        position_ref.update(update_data)
        logger.info(f"Position {position_id} updated successfully")
        return jsonify({'success': True})
        
    except Exception as e:
        logger.error(f"Error updating position {position_id}: {str(e)}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/reset-election', methods=['POST'])
def reset_election():
    """Reset all votes and voting status - DANGEROUS OPERATION"""
    if not session.get('admin'):
        return jsonify({'error': 'Unauthorized'}), 401

    try:
        data = request.get_json()
        confirm = data.get('confirm', False)
        
        if not confirm:
            return jsonify({'error': 'Confirmation required'}), 400
        
        batch = db.batch()
        
        # Reset all candidate vote counts to 0
        candidates_docs = db.collection('candidates').stream()
        for doc in candidates_docs:
            batch.update(doc.reference, {'votes': 0})
        
        # Reset all students' voting status
        students_docs = db.collection('students').stream()
        for doc in students_docs:
            batch.update(doc.reference, {
                'has_voted': False,
                'voted_at': None
            })
        
        # Delete all vote records
        vote_records_docs = db.collection('vote_records').stream()
        for doc in vote_records_docs:
            batch.delete(doc.reference)
        
        # Commit all changes
        batch.commit()
        
        logger.info("Election reset successfully")
        return jsonify({'success': True, 'message': 'Election reset successfully'})
        
    except Exception as e:
        logger.error(f"Error resetting election: {str(e)}")
        return jsonify({'error': str(e)}), 500


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))


if __name__ == "__main__":
    # Set port for Render compatibility
    port = int(os.environ.get("PORT", 5000))
    
    # Run the Flask app
    app.run(host="0.0.0.0", port=port)
