# app.py
from flask import Flask, render_template, request, jsonify, redirect, url_for, flash
import os
from werkzeug.utils import secure_filename
import requests
from bs4 import BeautifulSoup
import PyPDF2
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import json
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# --- Configuration ---
app.config['SECRET_KEY'] = 'your_super_secret_key_here' # IMPORTANT: Change this in production!
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///hubai.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Secret codes for privileged roles (for demo purposes, store securely in env vars in production)
ADMIN_REG_CODE = os.environ.get('ADMIN_REG_CODE', 'admin_secret_123')
SUPPORT_REG_CODE = os.environ.get('SUPPORT_REG_CODE', 'support_secret_123')
ANALYST_REG_CODE = os.environ.get('ANALYST_REG_CODE', 'analyst_secret_123')


# --- Initialize Extensions ---
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login' # Redirect to login page if unauthenticated

# Custom Jinja2 filter to parse JSON strings in templates
@app.template_filter('from_json')
def from_json_filter(value):
    """Parses a JSON string value into a Python object."""
    if value:
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return {} # Return empty dict or handle error appropriately
    return {} # Return empty dict for None/empty values

# --- File Upload Configuration ---
UPLOAD_FOLDER = 'uploads'
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16 MB max upload size

ALLOWED_EXTENSIONS = {'pdf', 'doc', 'docx', 'txt', 'csv', 'json', 'log'}

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# --- Database Models ---
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    # Default role is now 'analyst', merging previous 'user' and 'analyst' roles
    role = db.Column(db.String(50), default='analyst', nullable=False) # 'analyst', 'support', 'admin'

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f'<User {self.username} ({self.role})>'

# User loader for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class ComplianceReport(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    project_name = db.Column(db.String(255), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    uploaded_files = db.Column(db.Text) # Storing as JSON string
    regulatory_docs_processed = db.Column(db.Text) # Storing as JSON string
    compliance_score = db.Column(db.Text) # Storing as JSON string (e.g., {"GDPR": 80, ...})
    recommendations = db.Column(db.Text) # Storing as JSON string (list of strings)
    severity_levels = db.Column(db.Text) # Storing as JSON string
    extracted_uploaded_content_sample = db.Column(db.Text)
    note = db.Column(db.Text)
    user_rel = db.relationship('User', backref='compliance_reports') # Renamed to avoid conflict with 'user' field in AuditLogEntry

    def __repr__(self):
        return f'<ComplianceReport {self.project_name} - {self.timestamp}>'

class RiskAssessment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    project_name = db.Column(db.String(255), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    overall_risk = db.Column(db.String(50)) # Low, Medium, High
    risk_scores = db.Column(db.Text) # JSON string
    risk_heatmaps = db.Column(db.Text) # JSON string
    alerts = db.Column(db.Text) # JSON string (list of alerts)
    user_rel = db.relationship('User', backref='risk_assessments')

    def __repr__(self):
        return f'<RiskAssessment {self.project_name} - {self.overall_risk}>'

class AuditLogEntry(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True) # Can be system or user
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.Column(db.String(100)) # Storing username directly for simplicity in logs
    action = db.Column(db.String(255))
    project = db.Column(db.String(255))
    details = db.Column(db.Text) # Optional, for more log details
    user_rel = db.relationship('User', backref='audit_logs') # Added relationship

    def __repr__(self):
        return f'<AuditLogEntry {self.action} by {self.user} on {self.timestamp}>'

class ConsentRecord(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    dataset_name = db.Column(db.String(255), nullable=False)
    consent_status = db.Column(db.String(50)) # e.g., 'Valid', 'Expired', 'Missing'
    expires_on = db.Column(db.Date, nullable=True)
    agreement_type = db.Column(db.String(100)) # e.g., 'consent_form', 'data_usage_agreement'
    consent_doc_filename = db.Column(db.String(255), nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user_rel = db.relationship('User', backref='consent_records')

    def __repr__(self):
        return f'<ConsentRecord {self.dataset_name} - {self.consent_status}>'

# --- Helper Functions for Text Extraction ---
def extract_text_from_pdf(filepath_or_url):
    text = ""
    try:
        if filepath_or_url.startswith('http://') or filepath_or_url.startswith('https://'):
            response = requests.get(filepath_or_url, stream=True)
            response.raise_for_status()
            with open("temp_pdf_download.pdf", "wb") as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
            pdf_file_obj = open("temp_pdf_download.pdf", 'rb')
        else:
            pdf_file_obj = open(filepath_or_url, 'rb')

        pdf_reader = PyPDF2.PdfReader(pdf_file_obj)
        for page_num in range(len(pdf_reader.pages)):
            page_obj = pdf_reader.pages[page_num]
            text += page_obj.extract_text()
        pdf_file_obj.close()
        if filepath_or_url.startswith('http://') or filepath_or_url.startswith('https://'):
            os.remove("temp_pdf_download.pdf")
    except Exception as e:
        print(f"Error extracting text from PDF {filepath_or_url}: {e}")
        text = f"Error: Could not extract text from PDF. {e}"
    return text

def extract_text_from_html(url):
    text = ""
    try:
        response = requests.get(url)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')
        for script in soup(["script", "style"]):
            script.extract()
        text = soup.get_text(separator=' ', strip=True)
    except Exception as e:
        print(f"Error extracting text from HTML {url}: {e}")
        text = f"Error: Could not extract text from HTML. {e}"
    return text

def extract_text_from_txt(filepath):
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            return f.read()
    except Exception as e:
        print(f"Error extracting text from TXT {filepath}: {e}")
        return f"Error: Could not extract text from TXT. {e}"

def extract_text_from_csv_json_log(filepath, file_type):
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
        return f"Content from {file_type} file: {content[:500]}..."
    except Exception as e:
        print(f"Error extracting text from {file_type} {filepath}: {e}")
        return f"Error: Could not extract text from {file_type}. {e}"

# --- Authentication Routes ---
@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        # Default role is now 'analyst'
        role = request.form.get('role', 'analyst') 
        registration_code = request.form.get('registration_code', '')

        user = User.query.filter_by(username=username).first()
        if user:
            flash('Username already exists. Please choose a different one.', 'error')
            return render_template('register.html')
        
        user = User.query.filter_by(email=email).first()
        if user:
            flash('Email already registered. Please use a different one or log in.', 'error')
            return render_template('register.html')

        # Validate registration code for privileged roles
        if role == 'admin' and registration_code != ADMIN_REG_CODE:
            flash('Invalid registration code for Admin role.', 'error')
            return render_template('register.html')
        elif role == 'support' and registration_code != SUPPORT_REG_CODE:
            flash('Invalid registration code for Support role.', 'error')
            return render_template('register.html')
        elif role == 'analyst' and registration_code != ANALYST_REG_CODE:
            # Analyst role now requires a code
            flash('Invalid registration code for Analyst role.', 'error')
            return render_template('register.html')
        elif role not in ['analyst', 'admin', 'support']: # Ensure only valid roles are accepted
            flash('Invalid role selected.', 'error')
            return render_template('register.html')

        new_user = User(username=username, email=email, role=role)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        flash(f'Registration successful for role: {role}! Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user is None or not user.check_password(password):
            flash('Invalid username or password', 'error')
            return render_template('login.html')
        login_user(user)
        flash('Logged in successfully!', 'success')
        return redirect(url_for('index'))
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login')) # Redirect to login after logout

@app.route('/forgot_password_request')
def forgot_password_request():
    """
    Placeholder route for initiating a password reset.
    In a real application, this would render a form to enter email,
    send a reset link, etc.
    """
    flash('Password reset functionality is not fully implemented in this demo. Please contact support.', 'info')
    return render_template('login.html') # Redirect back to login or a dedicated info page


# --- Main Application Routes (Protected with RBAC) ---
@app.route('/')
@login_required
def index():
    """Renders the main dashboard page."""
    # Admin can see latest of any, Support/Analysts see their own
    if current_user.role == 'admin':
        recent_compliance = ComplianceReport.query.order_by(ComplianceReport.timestamp.desc()).first()
        recent_risk = RiskAssessment.query.order_by(RiskAssessment.timestamp.desc()).first()
        recent_audit = AuditLogEntry.query.order_by(AuditLogEntry.timestamp.desc()).first()
        recent_consent = ConsentRecord.query.order_by(ConsentRecord.timestamp.desc()).first()
    else: # Support, Analyst roles see only their own data
        recent_compliance = ComplianceReport.query.filter_by(user_id=current_user.id).order_by(ComplianceReport.timestamp.desc()).first()
        recent_risk = RiskAssessment.query.filter_by(user_id=current_user.id).order_by(RiskAssessment.timestamp.desc()).first()
        # Audit trail is restricted for analysts, so no recent audit for them here
        recent_audit = AuditLogEntry.query.filter_by(user_id=current_user.id).order_by(AuditLogEntry.timestamp.desc()).first()
        recent_consent = ConsentRecord.query.filter_by(user_id=current_user.id).order_by(ConsentRecord.timestamp.desc()).first()

    return render_template('index.html',
                           recent_compliance=recent_compliance,
                           recent_risk=recent_risk,
                           recent_audit=recent_audit,
                           recent_consent=recent_consent)

@app.route('/compliance-scanner')
@login_required
def compliance_scanner():
    """Renders the Compliance Scanner module page."""
    # Admin can view all compliance reports. Support/Analysts view their own.
    if current_user.role == 'admin':
        reports_db = ComplianceReport.query.order_by(ComplianceReport.timestamp.desc()).all()
    else: # Support, Analyst roles
        reports_db = ComplianceReport.query.filter_by(user_id=current_user.id).order_by(ComplianceReport.timestamp.desc()).all()
    
    reports_serializable = []
    for report in reports_db:
        reports_serializable.append({
            'id': report.id,
            'project_name': report.project_name,
            'timestamp': report.timestamp.isoformat(),
            'uploaded_files': json.loads(report.uploaded_files) if report.uploaded_files else [],
            'regulatory_docs_processed': json.loads(report.regulatory_docs_processed) if report.regulatory_docs_processed else [],
            'compliance_score': json.loads(report.compliance_score) if report.compliance_score else {},
            'recommendations': json.loads(report.recommendations) if report.recommendations else [],
            'severity_levels': json.loads(report.severity_levels) if report.severity_levels else {},
            'extracted_uploaded_content_sample': report.extracted_uploaded_content_sample,
            'note': report.note
        })
    
    return render_template('compliance_scanner.html', reports=reports_serializable)

@app.route('/risk-dashboard')
@login_required
def risk_dashboard():
    """Renders the Risk Dashboard module page."""
    return render_template('risk_dashboard.html')

@app.route('/audit-trail-generator')
@login_required
def audit_trail_generator():
    """Renders the Audit Trail Generator module page."""
    # Analysts cannot view the audit trail
    if current_user.role == 'analyst':
        flash('Permission denied. Analysts cannot view the audit trail.', 'error')
        return redirect(url_for('index')) # Redirect to dashboard or appropriate page

    # Admin/Support can view all logs.
    if current_user.role in ['admin', 'support']:
        logs = AuditLogEntry.query.order_by(AuditLogEntry.timestamp.desc()).all()
    else: # This case should ideally not be hit if analyst is redirected, but as a fallback
        logs = [] # No logs for other roles if they somehow bypass the redirect
    
    return render_template('audit_trail_generator.html', logs=logs)

@app.route('/consent-tracker')
@login_required
def consent_tracker():
    """Renders the Consent Tracker module page."""
    # Admin can view all consent records. Support/Analysts view their own.
    if current_user.role == 'admin':
        consent_records = ConsentRecord.query.order_by(ConsentRecord.timestamp.desc()).all()
    else: # Support, Analyst roles
        consent_records = ConsentRecord.query.filter_by(user_id=current_user.id).order_by(ConsentRecord.timestamp.desc()).all()
    return render_template('consent_tracker.html', consent_records=consent_records)

# --- API Endpoints (Protected with RBAC) ---

@app.route('/api/scan-compliance', methods=['POST'])
@login_required
def api_scan_compliance():
    """
    Handles file uploads and regulatory document URLs for compliance scanning.
    Saves the compliance report to the database, associated with the current user.
    Support role cannot make changes.
    """
    if current_user.role == 'support':
        return jsonify({"error": "Permission denied. Support users cannot initiate scans."}), 403

    if 'projectName' not in request.form:
        return jsonify({"error": "Project name is required"}), 400

    project_name = request.form['projectName']
    uploaded_files_info = []
    uploaded_content_for_scan = []
    regulatory_docs_urls = request.form.get('regulatoryDocsUrls', '').splitlines()
    regulatory_docs_urls = [url.strip() for url in regulatory_docs_urls if url.strip()]

    # Process uploaded files
    for key in ['modelDoc', 'datasetLogs']:
        if key in request.files:
            files = request.files.getlist(key) if key == 'datasetLogs' else [request.files[key]]
            for file in files:
                if file and allowed_file(file.filename):
                    filename = secure_filename(file.filename)
                    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                    file.save(filepath)
                    uploaded_files_info.append(f"{key.replace('Doc', ' Documentation').replace('Logs', '/Log')}: {filename}")
                    
                    file_extension = filename.rsplit('.', 1)[1].lower()
                    if file_extension == 'pdf':
                        uploaded_content_for_scan.append(extract_text_from_pdf(filepath))
                    elif file_extension == 'txt':
                        uploaded_content_for_scan.append(extract_text_from_txt(filepath))
                    elif file_extension in ['csv', 'json', 'log']:
                        uploaded_content_for_scan.append(extract_text_from_csv_json_log(filepath, file_extension))
                    else:
                        uploaded_content_for_scan.append(f"Unsupported uploaded file type for text extraction: {filename}")
                elif file.filename != '':
                    uploaded_files_info.append(f"{key.replace('Doc', ' Documentation').replace('Logs', '/Log')}: File type not allowed for {file.filename}")

    # Process regulatory document URLs
    regulatory_content = {}
    for url in regulatory_docs_urls:
        if 'pdf' in url.lower():
            regulatory_content[url] = extract_text_from_pdf(url)
        elif 'http' in url.lower():
            regulatory_content[url] = extract_text_from_html(url)
        else:
            regulatory_content[url] = "Unsupported URL type or format."

    # --- Basic Compliance Logic (Example) ---
    combined_uploaded_text = " ".join(uploaded_content_for_scan).lower()
    
    # Define keywords for each regulation
    gdpr_keywords = ["gdpr", "data protection", "consent", "right to be forgotten", "data portability"]
    hipaa_keywords = ["hipaa", "protected health information", "phi", "patient privacy", "security rule"]
    eu_ai_act_keywords = ["eu ai act", "artificial intelligence", "high-risk ai", "transparency", "human oversight"]
    barbados_dpa_keywords = ["barbados data protection act", "data commissioner", "personal data", "data subject rights"]

    compliance_scores = {
        "GDPR": 0, "HIPAA": 0, "EU AI Act": 0, "Barbados Data Protection Act": 0
    }
    recommendations = []
    severity_levels = {}

    if any(keyword in combined_uploaded_text for keyword in gdpr_keywords):
        compliance_scores["GDPR"] = 70
        recommendations.append("Consider more explicit GDPR compliance statements.")
    else:
        compliance_scores["GDPR"] = 30
        recommendations.append("Significant gaps in GDPR compliance identified. Review data processing principles.")
        severity_levels["GDPR_gap"] = "High"

    if any(keyword in combined_uploaded_text for keyword in hipaa_keywords):
        compliance_scores["HIPAA"] = 65
        recommendations.append("Ensure all PHI handling procedures are clearly documented per HIPAA.")
    else:
        compliance_scores["HIPAA"] = 20
        recommendations.append("HIPAA compliance requires urgent attention, especially regarding PHI security.")
        severity_levels["HIPAA_gap"] = "High"

    eu_ai_act_content = regulatory_content.get("https://data.consilium.europa.eu/doc/document/ST-5662-2024-INIT/en/pdf", "").lower()
    if "high-risk ai system" in eu_ai_act_content and "risk assessment" in combined_uploaded_text:
        compliance_scores["EU AI Act"] = 75
        recommendations.append("Good start on EU AI Act, ensure comprehensive risk assessment documentation.")
    else:
        compliance_scores["EU AI Act"] = 40
        recommendations.append("EU AI Act compliance needs significant work, especially for high-risk systems.")
        severity_levels["EU_AI_Act_gap"] = "High"

    barbados_dpa_content = regulatory_content.get("https://www.barbadosparliament.com/uploads/acts/52f6ac1a5b35d7a717f5287c71d2acb4.pdf", "").lower()
    if "data protection commissioner" in barbados_dpa_content and "data residency" in combined_uploaded_text:
        compliance_scores["Barbados Data Protection Act"] = 85
        recommendations.append("Barbados DPA compliance looks good, verify data residency policies.")
    else:
        compliance_scores["Barbados Data Protection Act"] = 50
        recommendations.append("Review Barbados Data Protection Act requirements, especially data subject rights.")
        severity_levels["Barbados_DPA_gap"] = "Medium"


    # Create a new ComplianceReport entry, associated with current_user
    new_report = ComplianceReport(
        user_id=current_user.id,
        project_name=project_name,
        uploaded_files=json.dumps(uploaded_files_info),
        regulatory_docs_processed=json.dumps(list(regulatory_content.keys())),
        compliance_score=json.dumps(compliance_scores),
        recommendations=json.dumps(recommendations),
        severity_levels=json.dumps(severity_levels),
        extracted_uploaded_content_sample=combined_uploaded_text[:5000],
        note="This is a basic, keyword-based compliance check. A robust system requires advanced NLP and detailed rule sets."
    )
    db.session.add(new_report)
    db.session.commit()

    # Also log this action to the Audit Trail
    audit_entry = AuditLogEntry(
        user_id=current_user.id,
        user=current_user.username,
        action=f"Ran compliance scan for project '{project_name}'",
        project=project_name,
        details=f"Compliance score: {compliance_scores}"
    )
    db.session.add(audit_entry)
    db.session.commit()

    report_output = {
        "status": "Compliance Scan Completed and Saved",
        "report_id": new_report.id,
        "project_name": project_name,
        "uploaded_files": uploaded_files_info,
        "regulatory_documents_processed": list(regulatory_content.keys()),
        "compliance_score": compliance_scores,
        "recommendations": recommendations,
        "severity_levels": severity_levels,
        "extracted_uploaded_content_sample": combined_uploaded_text[:500] + "..." if len(combined_uploaded_text) > 500 else combined_uploaded_text,
        "note": "This is a basic, keyword-based compliance check. A robust system requires advanced NLP and detailed rule sets."
    }
    return jsonify(report_output)

@app.route('/api/get-risk-data', methods=['GET'])
@login_required
def api_get_risk_data():
    """
    Fetches the most recent risk data for the current user from the database.
    If no data, returns a default/simulated entry and saves it.
    """
    # Admin can view latest of any, Support/Analysts see their own
    if current_user.role == 'admin':
        risk_assessments = RiskAssessment.query.order_by(RiskAssessment.timestamp.desc()).first()
    else: # Support, Analyst roles
        risk_assessments = RiskAssessment.query.filter_by(user_id=current_user.id).order_by(RiskAssessment.timestamp.desc()).first()
    
    if not risk_assessments:
        # If no data, return a default/simulated entry and save it for the current user
        simulated_risk = {
            "overall_risk": "Medium",
            "risk_scores": {
                "AI Model X": {"score": 75, "category": "High"},
                "Customer Service Bot": {"score": 40, "category": "Low"},
                "Fraud Detection System": {"score": 88, "category": "High"}
            },
            "risk_heatmaps": {
                "department_A": {"Bias": "Medium", "Security": "Low", "Legal": "High"},
                "department_B": {"Bias": "Low", "Security": "Medium", "Legal": "Low"}
            },
            "alerts": ["Simulated: Bias detected in 'AI Model X'", "Simulated: Legal compliance overdue for 'Project Alpha'"]
        }
        new_risk = RiskAssessment(
            user_id=current_user.id,
            project_name="Simulated Portfolio",
            overall_risk=simulated_risk["overall_risk"],
            risk_scores=json.dumps(simulated_risk["risk_scores"]),
            risk_heatmaps=json.dumps(simulated_risk["risk_heatmaps"]),
            alerts=json.dumps(simulated_risk["alerts"])
        )
        db.session.add(new_risk)
        db.session.commit()
        
        # Return the newly created simulated data
        return jsonify({
            "overall_risk": new_risk.overall_risk,
            "risk_scores": json.loads(new_risk.risk_scores),
            "risk_heatmaps": json.loads(new_risk.risk_heatmaps),
            "alerts": json.loads(new_risk.alerts)
        })

    # Return the most recent risk assessment
    return jsonify({
        "overall_risk": risk_assessments.overall_risk,
        "risk_scores": json.loads(risk_assessments.risk_scores),
        "risk_heatmaps": json.loads(risk_assessments.risk_heatmaps),
        "alerts": json.loads(risk_assessments.alerts)
    })

@app.route('/api/get-all-risk-assessments', methods=['GET'])
@login_required
def api_get_all_risk_assessments():
    """
    Fetches all risk assessments for the current user from the database.
    Admin can view all.
    """
    if current_user.role == 'admin':
        risk_assessments_db = RiskAssessment.query.order_by(RiskAssessment.timestamp.desc()).all()
    else: # Support, Analyst roles
        risk_assessments_db = RiskAssessment.query.filter_by(user_id=current_user.id).order_by(RiskAssessment.timestamp.desc()).all()
    
    assessments_serializable = []
    for assessment in risk_assessments_db:
        assessments_serializable.append({
            'id': assessment.id,
            'project_name': assessment.project_name,
            'timestamp': assessment.timestamp.isoformat(),
            'overall_risk': assessment.overall_risk,
            'risk_scores': json.loads(assessment.risk_scores) if assessment.risk_scores else {},
            'risk_heatmaps': json.loads(assessment.risk_heatmaps) if assessment.risk_heatmaps else {},
            'alerts': json.loads(assessment.alerts) if assessment.alerts else []
        })
    return jsonify(assessments_serializable)


@app.route('/api/submit-risk-assessment', methods=['POST'])
@login_required
def api_submit_risk_assessment():
    """
    API endpoint for submitting a new risk assessment, associated with the current user.
    Support role cannot make changes.
    """
    if current_user.role == 'support':
        return jsonify({"error": "Permission denied. Support users cannot submit risk assessments."}), 403

    data = request.json
    project_name = data.get('projectName', 'N/A')
    overall_risk = data.get('overallRisk', 'Medium')
    risk_scores = data.get('riskScores', {})
    alerts = data.get('alerts', [])
    risk_heatmaps = data.get('riskHeatmaps', {})

    new_risk_assessment = RiskAssessment(
        user_id=current_user.id,
        project_name=project_name,
        overall_risk=overall_risk,
        risk_scores=json.dumps(risk_scores),
        risk_heatmaps=json.dumps(risk_heatmaps),
        alerts=json.dumps(alerts)
    )
    db.session.add(new_risk_assessment)
    db.session.commit()

    # Log to audit trail
    audit_entry = AuditLogEntry(
        user_id=current_user.id,
        user=current_user.username,
        action=f"Submitted risk assessment for project '{project_name}'",
        project=project_name,
        details=f"Overall risk: {overall_risk}"
    )
    db.session.add(audit_entry)
    db.session.commit()

    return jsonify({"message": "Risk assessment saved successfully", "id": new_risk_assessment.id})


@app.route('/api/get-audit-logs', methods=['GET'])
@login_required
def api_get_audit_logs():
    """
    Fetches audit logs from the database, filtered by current user's role.
    Analysts cannot view audit logs.
    """
    if current_user.role == 'analyst':
        return jsonify({"error": "Permission denied. Analysts cannot view audit logs."}), 403

    if current_user.role in ['admin', 'support']:
        logs = AuditLogEntry.query.order_by(AuditLogEntry.timestamp.desc()).all()
    else: # This case should ideally not be hit if analyst is redirected, but as a fallback
        logs = [] # No logs for other roles if they somehow bypass the redirect
    
    return jsonify([{
        "timestamp": log.timestamp.isoformat(),
        "user": log.user,
        "action": log.action,
        "project": log.project,
        "details": log.details
    } for log in logs])

@app.route('/api/get-consent-status', methods=['GET'])
@login_required
def api_get_consent_status():
    """
    Fetches consent status summary for the current user from the database.
    Admin/Support can view all.
    """
    if current_user.role == 'admin':
        consent_records = ConsentRecord.query.all()
    else: # Support, Analyst roles
        consent_records = ConsentRecord.query.filter_by(user_id=current_user.id).all()

    total_datasets = len(consent_records)
    datasets_with_consent = sum(1 for rec in consent_records if rec.consent_status == 'Valid')
    datasets_without_consent = total_datasets - datasets_with_consent
    
    expiring_agreements = []
    today = datetime.utcnow().date()
    for rec in consent_records:
        if rec.expires_on and rec.expires_on > today and (rec.expires_on - today).days <= 60:
            expiring_agreements.append({
                "dataset": rec.dataset_name,
                "expires": rec.expires_on.isoformat() # Corrected: used expires_on.isoformat()
            })

    # If no user-specific data, provide simulated data for the current user
    if not consent_records and current_user.role not in ['admin', 'support']: # Only simulate for individual users
        # Save simulated data to DB for the current user
        db.session.add(ConsentRecord(user_id=current_user.id, dataset_name="marketing_leads_Q3", consent_status="Valid", expires_on=datetime(2025,8,31).date(), agreement_type="data_usage_agreement"))
        db.session.add(ConsentRecord(user_id=current_user.id, dataset_name="customer_feedback_2024", consent_status="Valid", expires_on=datetime(2025,9,15).date(), agreement_type="consent_form"))
        db.session.add(ConsentRecord(user_id=current_user.id, dataset_name="internal_metrics", consent_status="Valid", agreement_type="proprietary"))
        db.session.add(ConsentRecord(user_id=current_user.id, dataset_name="public_data_set", consent_status="Valid", agreement_type="creative_commons"))
        db.session.add(ConsentRecord(user_id=current_user.id, dataset_name="unconsented_data", consent_status="Missing", agreement_type="N/A"))
        db.session.commit()
        
        # Re-query after saving
        consent_records = ConsentRecord.query.filter_by(user_id=current_user.id).all()
        total_datasets = len(consent_records)
        datasets_with_consent = sum(1 for rec in consent_records if rec.consent_status == 'Valid')
        datasets_without_consent = total_datasets - datasets_with_consent
        expiring_agreements = []
        for rec in consent_records:
            if rec.expires_on and rec.expires_on > today and (rec.expires_on - today).days <= 60:
                expiring_agreements.append({
                    "dataset": rec.dataset_name,
                    "expires": rec.expires_on.isoformat()
                })

    return jsonify({
        "total_datasets": total_datasets,
        "datasets_with_consent": datasets_with_consent,
        "datasets_without_consent": datasets_without_consent,
        "expiring_agreements": expiring_agreements
    })

@app.route('/api/get-all-consent-records', methods=['GET'])
@login_required
def api_get_all_consent_records():
    """
    Fetches all consent records for the current user from the database for the detailed table.
    Admin/Support can view all.
    """
    if current_user.role == 'admin':
        consent_records_db = ConsentRecord.query.order_by(ConsentRecord.timestamp.desc()).all()
    else: # Support, Analyst roles
        consent_records_db = ConsentRecord.query.filter_by(user_id=current_user.id).order_by(ConsentRecord.timestamp.desc()).all()
    
    records_serializable = []
    for record in consent_records_db:
        records_serializable.append({
            'id': record.id,
            'dataset_name': record.dataset_name,
            'consent_status': record.consent_status,
            'expires_on': record.expires_on.isoformat() if record.expires_on else None,
            'agreement_type': record.agreement_type,
            'consent_doc_filename': record.consent_doc_filename,
            'timestamp': record.timestamp.isoformat()
        })
    return jsonify(records_serializable)


@app.route('/api/upload-consent-doc', methods=['POST'])
@login_required
def api_upload_consent_doc():
    """
    Handles uploading consent documentation and creating a ConsentRecord, associated with the current user.
    Support role cannot make changes.
    """
    if current_user.role == 'support':
        return jsonify({"error": "Permission denied. Support users cannot upload consent documents."}), 403

    dataset_name = request.form.get('datasetName')
    agreement_type = request.form.get('agreementType')
    expires_on_str = request.form.get('expiresOn')

    if not dataset_name or not agreement_type:
        return jsonify({"error": "Dataset name and agreement type are required"}), 400

    consent_doc_filename = None
    if 'consentDoc' in request.files:
        consent_doc_file = request.files['consentDoc']
        if consent_doc_file and allowed_file(consent_doc_file.filename):
            filename = secure_filename(consent_doc_file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            consent_doc_file.save(filepath)
            consent_doc_filename = filename
        elif consent_doc_file.filename != '':
            return jsonify({"error": f"Consent document: File type not allowed for {consent_doc_file.filename}"}), 400

    expires_on = None
    if expires_on_str:
        try:
            expires_on = datetime.strptime(expires_on_str, '%Y-%m-%d').date()
        except ValueError:
            return jsonify({"error": "Invalid date format for expires_on. Use YYYY-MM-DD."}), 400

    new_consent_record = ConsentRecord(
        user_id=current_user.id,
        dataset_name=dataset_name,
        consent_status='Valid' if consent_doc_filename else 'Missing',
        expires_on=expires_on,
        agreement_type=agreement_type,
        consent_doc_filename=consent_doc_filename
    )
    db.session.add(new_consent_record)
    db.session.commit()

    # Log to audit trail
    audit_entry = AuditLogEntry(
        user_id=current_user.id,
        user=current_user.username,
        action=f"Added consent record for dataset '{dataset_name}'",
        project="Consent Management",
        details=f"Status: {new_consent_record.consent_status}, Doc: {consent_doc_filename}"
    )
    db.session.add(audit_entry)
    db.session.commit()

    return jsonify({"message": "Consent record saved successfully", "id": new_consent_record.id})


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
