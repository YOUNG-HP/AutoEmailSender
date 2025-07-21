import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
from email.header import Header
import mimetypes
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, Response
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet
import os
import click
import re
import pandas as pd
import time
from werkzeug.utils import secure_filename
from dotenv import load_dotenv
from datetime import datetime
from threading import Thread

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "a_default_secret_key_for_development")
app.config['SQLALCHEMY_DATABASE_URI'] = f"sqlite:///{os.path.join(app.instance_path, 'app.db')}"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message = "请先登录以访问此页面。"

# --- Global variable for tracking progress ---
progress_data = {
    'progress': 0,
    'total': 0,
    'status': 'idle',
    'log_path': None,
    'failure_path': None
}

# --- Encryption Setup ---
key_path = os.path.join(app.instance_path, 'secret.key')
if not os.path.exists(key_path):
    os.makedirs(app.instance_path, exist_ok=True)
    key = Fernet.generate_key()
    with open(key_path, 'wb') as key_file:
        key_file.write(key)
else:
    with open(key_path, 'rb') as key_file:
        key = key_file.read()

cipher_suite = Fernet(key)

class Encryption:
    @staticmethod
    def encrypt(data):
        if not data:
            return None
        return cipher_suite.encrypt(data.encode('utf-8'))

    @staticmethod
    def decrypt(encrypted_data):
        if not encrypted_data:
            return None
        return cipher_suite.decrypt(encrypted_data).decode('utf-8')

# --- Database Models (Many-to-Many) ---
config_user_association = db.Table('config_user_association',
    db.Column('config_id', db.Integer, db.ForeignKey('smtp_config.id'), primary_key=True),
    db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True)
)

template_user_association = db.Table('template_user_association',
    db.Column('template_id', db.Integer, db.ForeignKey('email_template.id'), primary_key=True),
    db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True)
)

class SmtpConfig(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    smtp_server = db.Column(db.String(100), nullable=False)
    smtp_port = db.Column(db.Integer, nullable=False)
    email_username = db.Column(db.String(100), nullable=False)
    encrypted_password = db.Column(db.LargeBinary, nullable=False)
    assigned_users = db.relationship('User', secondary=config_user_association, back_populates='assigned_configs')

class EmailTemplate(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False, unique=True)
    subject = db.Column(db.String(200), nullable=False)
    body = db.Column(db.Text, nullable=False)
    assigned_users = db.relationship('User', secondary=template_user_association, back_populates='assigned_templates')

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Boolean, default=False, nullable=False)
    assigned_configs = db.relationship('SmtpConfig', secondary=config_user_association, back_populates='assigned_users')
    assigned_templates = db.relationship('EmailTemplate', secondary=template_user_association, back_populates='assigned_users')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_admin:
            flash("您没有权限访问此页面。", "danger")
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

# --- Path Definitions ---
UPLOADS_DIR = os.path.join(app.root_path, 'uploads')
ATTACHMENT_REPO = os.path.join(app.root_path, 'attachments_repository')
LOGS_DIR = os.path.join(app.root_path, 'logs')
os.makedirs(UPLOADS_DIR, exist_ok=True)
os.makedirs(ATTACHMENT_REPO, exist_ok=True)
os.makedirs(LOGS_DIR, exist_ok=True)

# --- Helper Functions ---
def parse_email_addresses(address_string):
    if not isinstance(address_string, str):
        return []
    return [addr.strip() for addr in re.split(r'[\s,;]+', address_string) if addr.strip()]

def read_data_file(file_path):
    try:
        return pd.read_csv(file_path, encoding='utf-8')
    except UnicodeDecodeError:
        return pd.read_csv(file_path, encoding='gbk')
    except Exception:
        return pd.read_excel(file_path)

def add_attachment(msg, filepath, original_filename=None):
    ctype, _ = mimetypes.guess_type(filepath)
    if ctype is None:
        ctype = 'application/octet-stream'
    maintype, subtype = ctype.split('/', 1)
    with open(filepath, 'rb') as fp:
        part = MIMEBase(maintype, subtype)
        part.set_payload(fp.read())
    encoders.encode_base64(part)
    filename = original_filename if original_filename else os.path.basename(filepath)
    
    # Correctly handle filenames with non-ASCII characters (RFC 2231).
    try:
        filename.encode('ascii')
        # If the filename is pure ASCII, use the simple format.
        part.add_header('Content-Disposition', 'attachment', filename=filename)
    except UnicodeEncodeError:
        # If it contains non-ASCII characters, use the (charset, language, value) tuple.
        part.add_header('Content-Disposition', 'attachment', filename=('UTF-8', '', filename))
        
    msg.attach(part)

# --- Core Routes ---
@app.route('/')
def home():
    return redirect(url_for('index' if current_user.is_authenticated else 'login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == 'POST':
        user = db.session.execute(db.select(User).filter_by(username=request.form['username'])).scalar_one_or_none()
        if user and user.check_password(request.form['password']):
            login_user(user)
            return redirect(url_for('index'))
        flash('无效的用户名或密码', 'danger')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('您已成功登出。', 'success')
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def index():
    return render_template('index.html', smtp_configs=current_user.assigned_configs, email_templates=current_user.assigned_templates)

# --- Admin: SMTP Config Management ---
@app.route('/configs')
@login_required
@admin_required
def manage_configs():
    configs = db.session.execute(db.select(SmtpConfig).order_by(SmtpConfig.name)).scalars().all()
    all_users = db.session.execute(db.select(User).order_by(User.username)).scalars().all()
    return render_template('manage_configs.html', configs=configs, all_users=all_users)

@app.route('/configs/add', methods=['POST'])
@login_required
@admin_required
def add_config():
    password = request.form.get('email_password')
    if not password:
        flash('新增配置时，密码为必填项。', 'danger')
        return redirect(url_for('manage_configs'))
    
    new_config = SmtpConfig(
        name=request.form.get('name'),
        smtp_server=request.form.get('smtp_server'),
        smtp_port=int(request.form.get('smtp_port')),
        email_username=request.form.get('email_username'),
        encrypted_password=Encryption.encrypt(password)
    )
    
    assigned_user_ids = request.form.getlist('assigned_users')
    new_config.assigned_users = db.session.execute(db.select(User).where(User.id.in_(assigned_user_ids))).scalars().all()
    
    db.session.add(new_config)
    db.session.commit()
    flash('发件人配置已成功添加！', 'success')
    return redirect(url_for('manage_configs'))

@app.route('/configs/edit', methods=['POST'])
@login_required
@admin_required
def edit_config():
    config = db.session.get(SmtpConfig, int(request.form.get('config_id')))
    if not config:
        return "Config not found", 404

    config.name = request.form.get('name')
    config.smtp_server = request.form.get('smtp_server')
    config.smtp_port = int(request.form.get('smtp_port'))
    config.email_username = request.form.get('email_username')
    
    if password := request.form.get('email_password'):
        config.encrypted_password = Encryption.encrypt(password)

    assigned_user_ids = request.form.getlist('assigned_users')
    config.assigned_users = db.session.execute(db.select(User).where(User.id.in_(assigned_user_ids))).scalars().all()

    db.session.commit()
    flash('发件人配置已成功更新！', 'success')
    return redirect(url_for('manage_configs'))

@app.route('/configs/delete/<int:config_id>')
@login_required
@admin_required
def delete_config(config_id):
    config = db.session.get(SmtpConfig, config_id)
    if config:
        db.session.delete(config)
        db.session.commit()
        flash('发件人配置已删除。', 'success')
    return redirect(url_for('manage_configs'))

# --- Admin: Email Template Management ---
@app.route('/templates')
@login_required
@admin_required
def manage_templates():
    templates = db.session.execute(db.select(EmailTemplate).order_by(EmailTemplate.name)).scalars().all()
    all_users = db.session.execute(db.select(User).order_by(User.username)).scalars().all()
    return render_template('manage_templates.html', templates=templates, all_users=all_users)

@app.route('/templates/add', methods=['POST'])
@login_required
@admin_required
def add_template():
    new_template = EmailTemplate(
        name=request.form.get('name'),
        subject=request.form.get('subject'),
        body=request.form.get('body')
    )
    assigned_user_ids = request.form.getlist('assigned_users')
    new_template.assigned_users = db.session.execute(db.select(User).where(User.id.in_(assigned_user_ids))).scalars().all()
    db.session.add(new_template)
    db.session.commit()
    flash('邮件模板已成功创建！', 'success')
    return redirect(url_for('manage_templates'))

@app.route('/templates/edit', methods=['POST'])
@login_required
@admin_required
def edit_template():
    template = db.session.get(EmailTemplate, int(request.form.get('template_id')))
    if not template:
        return "Template not found", 404
    template.name = request.form.get('name')
    template.subject = request.form.get('subject')
    template.body = request.form.get('body')
    assigned_user_ids = request.form.getlist('assigned_users')
    template.assigned_users = db.session.execute(db.select(User).where(User.id.in_(assigned_user_ids))).scalars().all()
    db.session.commit()
    flash('邮件模板已成功更新！', 'success')
    return redirect(url_for('manage_templates'))

@app.route('/templates/delete/<int:template_id>')
@login_required
@admin_required
def delete_template(template_id):
    template = db.session.get(EmailTemplate, template_id)
    if template:
        db.session.delete(template)
        db.session.commit()
        flash('邮件模板已删除。', 'success')
    return redirect(url_for('manage_templates'))

# --- Admin: User Management ---
@app.route('/users')
@login_required
@admin_required
def manage_users():
    users = db.session.execute(db.select(User).order_by(User.username)).scalars().all()
    return render_template('manage_users.html', users=users)

@app.route('/users/add', methods=['POST'])
@login_required
@admin_required
def add_user():
    username = request.form.get('username')
    if db.session.execute(db.select(User).filter_by(username=username)).scalar_one_or_none():
        flash(f'用户名 "{username}" 已存在。', 'danger')
        return redirect(url_for('manage_users'))
    new_user = User(username=username, is_admin='is_admin' in request.form)
    new_user.set_password(request.form.get('password'))
    db.session.add(new_user)
    db.session.commit()
    flash(f'用户 "{username}" 已成功创建。', 'success')
    return redirect(url_for('manage_users'))

@app.route('/users/delete/<int:user_id>')
@login_required
@admin_required
def delete_user(user_id):
    if user_id == current_user.id:
        flash('不能删除自己。', 'danger')
        return redirect(url_for('manage_users'))
    user_to_delete = db.session.get(User, user_id)
    if user_to_delete:
        db.session.delete(user_to_delete)
        db.session.commit()
        flash(f'用户 "{user_to_delete.username}" 已被删除。', 'success')
    else:
        flash('用户未找到。', 'warning')
    return redirect(url_for('manage_users'))

# --- AJAX and Sending Logic ---
@app.route('/get_columns_and_placeholders', methods=['POST'])
@login_required
def get_columns_and_placeholders():
    template_id = request.form.get('template_id')
    data_file = request.files.get('data_file')
    if not template_id or not data_file:
        return jsonify({'error': '请先选择模板并上传数据文件。'}), 400
    template = db.session.get(EmailTemplate, int(template_id))
    if not template or (not current_user.is_admin and current_user not in template.assigned_users):
        return jsonify({'error': 'Unauthorized'}), 403
    body = template.body
    subject = template.subject
    placeholders = sorted(list(set(re.findall(r'{{(.*?)}}', subject + body))))
    filename = secure_filename(data_file.filename)
    file_path = os.path.join(UPLOADS_DIR, filename)
    data_file.save(file_path)
    try:
        df = read_data_file(file_path)
        columns = df.columns.tolist()
        total_rows = len(df)
        first_row = df.head(1).to_dict(orient='records')[0] if not df.empty else {}
        first_row_str = {k: str(v) for k, v in first_row.items()}
    except Exception as e:
        return jsonify({'error': f'读取数据文件出错: {e}'}), 400
    columns_lower = {col.lower(): col for col in columns}
    suggested_mappings = {}
    for ph in placeholders:
        if ph.lower() in columns_lower:
            suggested_mappings[ph] = columns_lower[ph.lower()]
    return jsonify({
        'placeholders': placeholders,
        'columns': columns,
        'total_rows': total_rows,
        'first_row': first_row_str,
        'suggested_mappings': suggested_mappings
    })

@app.route('/preview_template/<int:template_id>')
@login_required
def preview_template(template_id):
    template = db.session.get(EmailTemplate, template_id)
    if not template or (not current_user.is_admin and current_user not in template.assigned_users):
        return jsonify({'error': 'Unauthorized'}), 403
    preview_subject = re.sub(r'{{(.*?)}}', r'<span class="badge bg-secondary">\1</span>', template.subject)
    preview_body = re.sub(r'{{(.*?)}}', r'<span class="badge bg-secondary">\1</span>', template.body)
    return jsonify({'subject': preview_subject, 'body': preview_body})

@app.route('/get_column_data', methods=['POST'])
@login_required
def get_column_data():
    data_file = request.files.get('data_file')
    column_name = request.form.get('column_name')
    if not data_file or not column_name:
        return jsonify({'error': '未提供数据文件或列名。'}), 400

    filename = secure_filename(data_file.filename)
    file_path = os.path.join(UPLOADS_DIR, filename)
    data_file.seek(0) # Ensure file pointer is at the beginning
    data_file.save(file_path)

    try:
        df = read_data_file(file_path)
        if column_name not in df.columns:
            return jsonify({'error': f'列 "{column_name}" 在文件中未找到。'}), 400
        
        labels = df[column_name].astype(str).tolist()
        return jsonify({'labels': labels})
    except Exception as e:
        return jsonify({'error': f'读取文件时出错: {e}'}), 400

def send_emails_task(app, config_id, template_id, data_file_path, attachment_paths, individual_attachment_map, mappings, send_delay):
    with app.app_context():
        global progress_data
        config = db.session.get(SmtpConfig, config_id)
        template = db.session.get(EmailTemplate, template_id)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        log_filename = f"sending_log_{timestamp}.csv"
        log_filepath = os.path.join(LOGS_DIR, log_filename)
        failure_filename = f"failures_{timestamp}.csv"
        failure_filepath = os.path.join(LOGS_DIR, failure_filename)

        progress_data['log_path'] = os.path.relpath(log_filepath, app.root_path)
        progress_data['failure_path'] = os.path.relpath(failure_filepath, app.root_path)

        try:
            df = read_data_file(data_file_path)
            total_rows = len(df)
            progress_data['total'] = total_rows
            progress_data['status'] = 'sending'
        except Exception as e:
            progress_data['status'] = f'error: 读取数据文件出错: {e}'
            return

        log_records = []
        failed_rows_df = []

        try:
            decrypted_password = Encryption.decrypt(config.encrypted_password)
            with smtplib.SMTP_SSL(config.smtp_server, config.smtp_port) as server:
                server.login(config.email_username, decrypted_password)

                for index, row in df.iterrows():
                    log_entry = row.to_dict()
                    status = "失败"
                    error_message = ""
                    try:
                        msg = MIMEMultipart()
                        final_subject = template.subject
                        final_body = template.body
                        for placeholder, column in mappings.items():
                            value = ''
                            if column in row and pd.notna(row[column]):
                                value = str(row[column])
                            final_subject = final_subject.replace(f'{{{{{placeholder}}}}}', value)
                            final_body = final_body.replace(f'{{{{{placeholder}}}}}', value)

                        msg['Subject'] = Header(final_subject, 'utf-8')
                        msg['From'] = config.email_username
                        
                        to_emails = parse_email_addresses(row.get(mappings.get('recipient_to', '')))
                        if not to_emails:
                            raise ValueError("收件人(To)字段为空或无效")
                        msg['To'] = ', '.join(to_emails)
                        all_recipients = to_emails

                        if 'recipient_cc' in mappings and pd.notna(row.get(mappings['recipient_cc'])):
                            cc_emails = parse_email_addresses(row[mappings['recipient_cc']])
                            if cc_emails:
                                msg['Cc'] = ', '.join(cc_emails)
                                all_recipients.extend(cc_emails)
                        
                        if 'recipient_bcc' in mappings and pd.notna(row.get(mappings['recipient_bcc'])):
                            bcc_emails = parse_email_addresses(row[mappings['recipient_bcc']])
                            if bcc_emails:
                                all_recipients.extend(bcc_emails)

                        content_type = 'html' if '<html>' in final_body.lower() else 'plain'
                        msg.attach(MIMEText(final_body, content_type, 'utf-8'))

                        # Add common attachments
                        for attachment_info in attachment_paths:
                            add_attachment(msg, attachment_info['path'], attachment_info['original_name'])

                        # Add individual attachments for this row if they exist
                        if str(index) in individual_attachment_map:
                            for attachment_info in individual_attachment_map[str(index)]:
                                add_attachment(msg, attachment_info['path'], attachment_info['original_name'])

                        server.sendmail(config.email_username, all_recipients, msg.as_string())
                        status = "成功"

                    except Exception as e:
                        error_message = str(e)
                        app.logger.error(f"Failed to send email to {row.get(mappings.get('recipient_to'))}: {e}")
                        failed_rows_df.append(row)
                    
                    finally:
                        log_entry['sending_status'] = status
                        log_entry['error_message'] = error_message
                        log_records.append(log_entry)
                        progress_data['progress'] = index + 1
                        time.sleep(send_delay)

        except Exception as e:
            progress_data['status'] = f'error: 邮件发送过程中出现严重错误: {e}'
            if not log_records: # If connection fails before loop starts
                for index, row in df.iterrows():
                    log_entry = row.to_dict()
                    log_entry['sending_status'] = "失败"
                    log_entry['error_message'] = f"SMTP连接或登录错误: {e}"
                    log_records.append(log_entry)
                    failed_rows_df.append(row)
            
        if log_records:
            pd.DataFrame(log_records).to_csv(log_filepath, index=False, encoding='utf-8-sig')
        if failed_rows_df:
            pd.DataFrame(failed_rows_df).to_csv(failure_filepath, index=False, encoding='utf-8-sig')
        
        progress_data['status'] = 'complete'

@app.route('/send_emails', methods=['POST'])
@login_required
def send_emails():
    global progress_data
    if progress_data['status'] == 'sending':
        return jsonify({'status': 'error', 'message': '一个发送任务正在进行中，请稍后再试。'}), 409

    progress_data = {'progress': 0, 'total': 0, 'status': 'starting', 'log_path': None, 'failure_path': None}

    config_id = request.form.get('config_select')
    template_id = request.form.get('template_select')
    config = db.session.get(SmtpConfig, int(config_id))
    template = db.session.get(EmailTemplate, int(template_id))

    if not config or not template:
        return jsonify({'status': 'error', 'message': '选择的配置或模板无效。'}), 400
    if not current_user.is_admin and (current_user not in config.assigned_users or current_user not in template.assigned_users):
        return jsonify({'status': 'error', 'message': '权限错误，无法使用该配置或模板。'}), 403

    data_file = request.files.get('data_file')
    if not data_file:
        return jsonify({'status': 'error', 'message': '没有上传数据文件。'}), 400

    filename = secure_filename(data_file.filename)
    data_file_path = os.path.join(UPLOADS_DIR, filename)
    data_file.seek(0) # Reset file pointer before saving
    data_file.save(data_file_path)

    # Handle common attachments
    attachments = request.files.getlist('attachments')
    attachment_paths = []
    for attachment in attachments:
        if attachment.filename:
            original_filename = attachment.filename
            safe_filename_part = secure_filename(attachment.filename)
            unique_filename = f"com_{datetime.now().timestamp()}_{safe_filename_part}"
            attach_path = os.path.join(UPLOADS_DIR, unique_filename)
            attachment.save(attach_path)
            attachment_paths.append({
                'path': attach_path,
                'original_name': original_filename
            })

    # Handle individual attachments
    individual_attachment_map = {}
    # Group files by their index (e.g., all files for individual_attachment_0)
    for key in request.files:
        if key.startswith('individual_attachment_'):
            index = key.split('_')[-1]
            files = request.files.getlist(key)
            for file in files:
                if file.filename:
                    if index not in individual_attachment_map:
                        individual_attachment_map[index] = []
                    
                    original_filename = file.filename
                    safe_filename_part = secure_filename(file.filename)
                    unique_filename = f"ind_{index}_{datetime.now().timestamp()}_{safe_filename_part}"
                    individual_path = os.path.join(UPLOADS_DIR, unique_filename)
                    file.save(individual_path)
                    
                    individual_attachment_map[index].append({
                        'path': individual_path,
                        'original_name': original_filename
                    })

    mappings = {key.replace('map_', ''): value for key, value in request.form.items() if key.startswith('map_')}
    send_delay = float(request.form.get('send_delay', 1))

    thread = Thread(target=send_emails_task, args=(app, config_id, template_id, data_file_path, attachment_paths, individual_attachment_map, mappings, send_delay))
    thread.start()

    return jsonify({'status': 'success', 'message': '邮件发送任务已在后台启动。'})

@app.route('/sending_status')
@login_required
def sending_status():
    def generate():
        import json
        while progress_data['status'] in ['starting', 'sending']:
            yield f"data: {json.dumps(progress_data)}\n\n"
            time.sleep(1)
        yield f"data: {json.dumps(progress_data)}\n\n"
    return Response(generate(), mimetype='text/event-stream')

# --- Attachment Repository Upload ---
@app.route('/upload_to_repository', methods=['POST'])
@login_required
def upload_to_repository():
    files = request.files.getlist('repository_files')
    if not files or all(f.filename == '' for f in files):
        return jsonify({'error': '没有选择文件。'}), 400

    saved_count = 0
    failed_files = []
    for file in files:
        if file and file.filename:
            relative_path = file.filename
            destination = os.path.join(ATTACHMENT_REPO, relative_path)
            
            # Security check: Prevent path traversal
            abs_destination = os.path.abspath(destination)
            abs_repo_path = os.path.abspath(ATTACHMENT_REPO)
            
            if not abs_destination.startswith(abs_repo_path):
                app.logger.warning(f"Path traversal attempt by user {current_user.username}: {relative_path}")
                failed_files.append(file.filename)
                continue

            try:
                os.makedirs(os.path.dirname(destination), exist_ok=True)
                file.save(destination)
                saved_count += 1
            except Exception as e:
                app.logger.error(f"File upload failed for {relative_path}: {e}")
                failed_files.append(file.filename)

    if not failed_files:
        return jsonify({'message': f'成功上传 {saved_count} 个文件到附件仓库。'})
    elif saved_count > 0:
        return jsonify({'message': f'成功上传 {saved_count} 个文件，但有 {len(failed_files)} 个文件上传失败: {", ".join(failed_files)}'})
    else:
        return jsonify({'error': f'所有 {len(failed_files)} 个文件都上传失败。'}), 500


# --- CLI Commands ---
@app.cli.command("init-db")
def init_db():
    """Clears the existing data and creates new tables."""
    with app.app_context():
        db.create_all()
    print("Initialized the database.")

@app.cli.command("create-user")
@click.argument("username")
@click.argument("password")
@click.option('--admin', is_flag=True, help='Create an administrator user.')
def create_user(username, password, admin):
    """Creates a new user."""
    with app.app_context():
        user = User(username=username, is_admin=admin)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        print(f"User '{username}' created successfully. Admin: {admin}")

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=True)
