# Organizador de E-mail Flask - Locaweb
# ===========================================

import os
import json
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from functools import wraps
from email_service.connection import EmailConnection
from email_service.spam_detector import SpamDetector
from email_service.folder_manager import FolderManager
from apscheduler.schedulers.background import BackgroundScheduler
from config import LOCAWEB_CONFIG
from database import verify_user, init_database, create_user, get_all_users, delete_user, toggle_user_status
import secrets
import atexit

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

# Configurações Locaweb
LOCAWEB_IMAP_SERVER = 'email-ssl.com.br'
LOCAWEB_IMAP_PORT = 993
LOCAWEB_SMTP_SERVER = 'email-ssl.com.br'
LOCAWEB_SMTP_PORT = 465

# Arquivo de configurações persistentes
CONFIG_FILE = os.path.join(os.path.dirname(__file__), 'user_config.json')

# Scheduler para tarefas agendadas
scheduler = BackgroundScheduler()
scheduler.start()

# Registra para encerrar o scheduler quando a aplicação parar
atexit.register(lambda: scheduler.shutdown())


def load_config():
    """Carrega configurações do arquivo JSON"""
    default_config = {
        'auto_delete_spam': True,
        'auto_delete_fraud': True,
        'spam_threshold': 70,
        'auto_scan_enabled': True,
        'auto_scan_time': '12:00',
        'last_scan': None,
        'accounts': {}
    }
    
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, 'r') as f:
                config = json.load(f)
                # Merge with defaults for any missing keys
                for key, value in default_config.items():
                    if key not in config:
                        config[key] = value
                return config
        except:
            pass
    
    return default_config


def save_config(config):
    """Salva configurações no arquivo JSON"""
    with open(CONFIG_FILE, 'w') as f:
        json.dump(config, f, indent=2)


def scheduled_scan():
    """Executa análise agendada de e-mails"""
    config = load_config()
    
    if not config.get('auto_scan_enabled', True):
        return
    
    print(f"[{datetime.now()}] 🔍 Iniciando análise agendada de e-mails...")
    
    # Processa cada conta salva
    for email, account_data in config.get('accounts', {}).items():
        try:
            password = account_data.get('password', '')
            if not password:
                continue
            
            conn = EmailConnection(
                email, password,
                LOCAWEB_IMAP_SERVER, LOCAWEB_IMAP_PORT,
                LOCAWEB_SMTP_SERVER, LOCAWEB_SMTP_PORT
            )
            
            if conn.connect():
                detector = SpamDetector(threshold=config.get('spam_threshold', 70))
                folder_manager = FolderManager(conn)
                
                # Garante que as pastas existem
                folder_manager.ensure_default_folders()
                
                # Busca e analisa e-mails
                emails_list = conn.fetch_emails('INBOX', limit=200)
                spam_count = 0
                fraud_count = 0
                
                for email_data in emails_list:
                    analysis = detector.analyze(email_data)
                    uid = email_data.get('uid', email_data.get('id', ''))
                    
                    if analysis['is_fraud'] and config.get('auto_delete_fraud', True):
                        conn.move_to_trash(uid, 'INBOX')
                        fraud_count += 1
                    elif analysis['is_spam'] and config.get('auto_delete_spam', True):
                        conn.move_to_trash(uid, 'INBOX')
                        spam_count += 1
                
                conn.disconnect()
                print(f"[{datetime.now()}] ✅ {email}: {spam_count} spam, {fraud_count} fraudes excluídos")
        
        except Exception as e:
            print(f"[{datetime.now()}] ❌ Erro ao processar {email}: {e}")
    
    # Atualiza última execução
    config['last_scan'] = datetime.now().isoformat()
    save_config(config)


def setup_scheduler():
    """Configura o scheduler para executar ao meio dia"""
    config = load_config()
    
    # Remove job anterior se existir
    if scheduler.get_job('daily_scan'):
        scheduler.remove_job('daily_scan')
    
    if config.get('auto_scan_enabled', True):
        scan_time = config.get('auto_scan_time', '12:00')
        hour, minute = map(int, scan_time.split(':'))
        
        scheduler.add_job(
            scheduled_scan,
            'cron',
            hour=hour,
            minute=minute,
            id='daily_scan',
            name='Análise diária de spam'
        )
        print(f"⏰ Análise agendada para {scan_time} todos os dias")


# Configura scheduler na inicialização
setup_scheduler()


def login_required(f):
    """Decorator para proteger rotas que requerem autenticação"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'email' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


def get_email_connection():
    """Obtém conexão IMAP com credenciais da sessão"""
    if 'email' not in session or 'password' not in session:
        return None
    return EmailConnection(
        session['email'],
        session['password'],
        LOCAWEB_IMAP_SERVER,
        LOCAWEB_IMAP_PORT,
        LOCAWEB_SMTP_SERVER,
        LOCAWEB_SMTP_PORT
    )


@app.route('/')
def index():
    """Página inicial - redireciona para dashboard ou login"""
    if 'email' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    """Página de login com usuário e senha (MySQL)"""
    # Email configurado como padrão
    default_email = LOCAWEB_CONFIG.get('DEFAULT_EMAIL', 'contato@isna.org.br')
    
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        
        print(f"[LOGIN] Tentativa: username='{username}'")
        
        if not username or not password:
            flash('Por favor, preencha usuário e senha.', 'error')
            return render_template('login.html')
        
        # Verifica credenciais no banco de dados MySQL
        user = verify_user(username, password)
        print(f"[LOGIN] Resultado verify_user: {user}")
        
        if user:
            # Usa email do usuário ou o padrão
            email = user.get('email') or default_email
            
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['email'] = email
            
            # Carrega senha do email das configurações
            config = load_config()
            accounts = config.get('accounts', {})
            if email in accounts:
                session['password'] = accounts[email].get('password', '')
            
            session['is_admin'] = user.get('is_admin', False)
            
            print(f"[LOGIN] Sucesso! Redirecionando para dashboard")
            flash(f'Bem-vindo, {username}!', 'success')
            return redirect(url_for('dashboard'))
        else:
            print(f"[LOGIN] Falha: usuário ou senha incorretos")
            flash('Usuário ou senha inválidos.', 'error')
    
    return render_template('login.html')


def admin_required(f):
    """Decorator para rotas que requerem acesso de administrador"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            flash('Por favor, faça login.', 'error')
            return redirect(url_for('login'))
        if not session.get('is_admin', False):
            flash('Acesso negado. Você não tem permissão de administrador.', 'error')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function


@app.route('/admin/usuarios', methods=['GET', 'POST'])
@admin_required
def admin_users():
    """Página de administração de usuários"""
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'create':
            username = request.form.get('username', '').strip()
            email = request.form.get('email', '').strip()
            password = request.form.get('password', '')
            is_admin = request.form.get('is_admin') == 'on'
            
            if username and password:
                if create_user(username, password, email or None, is_admin):
                    flash(f'Usuário "{username}" criado com sucesso!', 'success')
                else:
                    flash(f'Erro ao criar usuário "{username}". Pode já existir.', 'error')
            else:
                flash('Usuário e senha são obrigatórios.', 'error')
        
        elif action == 'delete':
            username = request.form.get('username', '')
            if username and username != session.get('username'):
                if delete_user(username):
                    flash(f'Usuário "{username}" excluído com sucesso!', 'success')
                else:
                    flash(f'Erro ao excluir usuário "{username}".', 'error')
            else:
                flash('Você não pode excluir seu próprio usuário.', 'error')
        
        elif action == 'toggle':
            user_id = request.form.get('user_id', type=int)
            if user_id:
                if toggle_user_status(user_id):
                    flash('Status do usuário alterado com sucesso!', 'success')
                else:
                    flash('Erro ao alterar status do usuário.', 'error')
        
        return redirect(url_for('admin_users'))
    
    users = get_all_users()
    return render_template('admin_users.html', 
                          users=users, 
                          email=session.get('email'),
                          current_user=session.get('username'))


@app.route('/logout')
def logout():
    """Encerra sessão do usuário"""
    session.clear()
    flash('Você saiu da sua conta.', 'info')
    return redirect(url_for('login'))


@app.route('/dashboard')
@login_required
def dashboard():
    """Dashboard principal com estatísticas"""
    conn = get_email_connection()
    stats = {'total': 0, 'unread': 0, 'spam': 0, 'folders': []}
    
    if conn and conn.connect():
        stats = conn.get_stats()
        conn.disconnect()
    
    config = load_config()
    
    return render_template('dashboard.html', 
                          stats=stats, 
                          email=session.get('email'),
                          last_scan=config.get('last_scan'))


@app.route('/emails')
@app.route('/emails/<folder>')
@login_required
def emails(folder='INBOX'):
    """Lista e-mails de uma pasta específica"""
    conn = get_email_connection()
    emails_list = []
    folders = []
    
    if conn and conn.connect():
        folders = conn.list_folders()
        emails_list = conn.fetch_emails(folder, limit=50)
        conn.disconnect()
    
    return render_template('emails.html', 
                          emails=emails_list, 
                          folders=folders, 
                          current_folder=folder,
                          email=session.get('email'))


@app.route('/email/<folder>/<uid>')
@login_required
def view_email(folder, uid):
    """Visualiza um e-mail específico"""
    conn = get_email_connection()
    email_data = None
    
    if conn and conn.connect():
        email_data = conn.fetch_email_by_uid(folder, uid)
        conn.disconnect()
    
    if not email_data:
        flash('E-mail não encontrado.', 'error')
        return redirect(url_for('emails', folder=folder))
    
    return render_template('view_email.html', email=email_data, folder=folder)


@app.route('/scan', methods=['POST'])
@login_required
def scan_emails():
    """Analisa e-mails para detectar spam e fraude"""
    conn = get_email_connection()
    config = load_config()
    detector = SpamDetector(threshold=config.get('spam_threshold', 70))
    results = {'total_scanned': 0, 'spam_found': 0, 'fraud_found': 0, 'deleted': 0, 'items': []}
    
    if conn and conn.connect():
        emails_list = conn.fetch_emails('INBOX', limit=100)
        results['total_scanned'] = len(emails_list)
        
        for email_data in emails_list:
            analysis = detector.analyze(email_data)
            if analysis['is_spam'] or analysis['is_fraud']:
                uid = email_data.get('uid', email_data.get('id', ''))
                
                results['items'].append({
                    'uid': uid,
                    'subject': email_data['subject'],
                    'from': email_data['from'],
                    'is_spam': analysis['is_spam'],
                    'is_fraud': analysis['is_fraud'],
                    'score': analysis['score'],
                    'reasons': analysis['reasons']
                })
                
                if analysis['is_spam']:
                    results['spam_found'] += 1
                if analysis['is_fraud']:
                    results['fraud_found'] += 1
                
                # Auto-delete se configurado
                should_delete = False
                if analysis['is_fraud'] and config.get('auto_delete_fraud', True):
                    should_delete = True
                elif analysis['is_spam'] and config.get('auto_delete_spam', True):
                    should_delete = True
                
                if should_delete:
                    try:
                        conn.move_to_trash(uid, 'INBOX')
                        results['deleted'] += 1
                    except:
                        pass
        
        conn.disconnect()
        
        # Atualiza última análise
        config['last_scan'] = datetime.now().isoformat()
        save_config(config)
    
    return jsonify(results)


@app.route('/organize', methods=['POST'])
@login_required
def organize_emails():
    """Organiza e-mails automaticamente em pastas"""
    conn = get_email_connection()
    folder_manager = FolderManager(conn)
    results = {'moved': 0, 'errors': []}
    
    if conn and conn.connect():
        # Garante que as pastas padrão existem
        folder_manager.ensure_default_folders()
        
        # Organiza e-mails
        results = folder_manager.auto_organize()
        conn.disconnect()
    
    return jsonify(results)


@app.route('/delete-spam', methods=['POST'])
@login_required
def delete_spam():
    """Move e-mails de spam/fraude para a lixeira"""
    conn = get_email_connection()
    uids = request.json.get('uids', [])
    results = {'deleted': 0, 'errors': []}
    
    if conn and conn.connect():
        for uid in uids:
            try:
                conn.move_to_trash(uid)
                results['deleted'] += 1
            except Exception as e:
                results['errors'].append(str(e))
        conn.disconnect()
    
    return jsonify(results)


@app.route('/folders', methods=['GET', 'POST'])
@login_required
def folders():
    """Gerencia pastas de e-mail"""
    conn = get_email_connection()
    folders_list = []
    
    if request.method == 'POST':
        action = request.form.get('action')
        folder_name = request.form.get('folder_name', '').strip()
        
        if conn and conn.connect():
            if action == 'create' and folder_name:
                if conn.create_folder(folder_name):
                    flash(f'Pasta "{folder_name}" criada com sucesso!', 'success')
                else:
                    flash(f'Erro ao criar pasta "{folder_name}".', 'error')
            elif action == 'delete' and folder_name:
                if conn.delete_folder(folder_name):
                    flash(f'Pasta "{folder_name}" excluída com sucesso!', 'success')
                else:
                    flash(f'Erro ao excluir pasta "{folder_name}".', 'error')
            conn.disconnect()
    
    if conn and conn.connect():
        folders_list = conn.list_folders()
        conn.disconnect()
    
    return render_template('folders.html', folders=folders_list, email=session.get('email'))


@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    """Configurações do usuário"""
    config = load_config()
    
    if request.method == 'POST':
        # Atualiza configurações
        config['auto_delete_spam'] = request.form.get('auto_delete_spam') == 'on'
        config['auto_delete_fraud'] = request.form.get('auto_delete_fraud') == 'on'
        config['spam_threshold'] = int(request.form.get('spam_threshold', 70))
        config['auto_scan_enabled'] = request.form.get('auto_scan_enabled') == 'on'
        config['auto_scan_time'] = request.form.get('auto_scan_time', '12:00')
        
        save_config(config)
        
        # Reconfigura scheduler
        setup_scheduler()
        
        flash('Configurações salvas com sucesso!', 'success')
    
    # Informações do scheduler
    next_scan = None
    job = scheduler.get_job('daily_scan')
    if job and job.next_run_time:
        next_scan = job.next_run_time.strftime('%d/%m/%Y às %H:%M')
    
    return render_template('settings.html', 
                          email=session.get('email'),
                          config=config,
                          next_scan=next_scan)


@app.route('/run-scan-now', methods=['POST'])
@login_required
def run_scan_now():
    """Executa análise manual imediatamente - auto-exclui spam/fraude"""
    config = load_config()
    conn = get_email_connection()
    detector = SpamDetector(threshold=config.get('spam_threshold', 70))
    
    results = {'scanned': 0, 'spam': 0, 'fraud': 0, 'deleted': 0}
    
    if conn and conn.connect():
        emails_list = conn.fetch_emails('INBOX', limit=200)
        results['scanned'] = len(emails_list)
        
        for email_data in emails_list:
            analysis = detector.analyze(email_data)
            uid = email_data.get('uid', email_data.get('id', ''))
            
            # Auto-exclui spam e fraude imediatamente
            if analysis['is_fraud']:
                results['fraud'] += 1
                try:
                    conn.move_to_trash(uid, 'INBOX')
                    results['deleted'] += 1
                except:
                    pass
            elif analysis['is_spam']:
                results['spam'] += 1
                try:
                    conn.move_to_trash(uid, 'INBOX')
                    results['deleted'] += 1
                except:
                    pass
        
        conn.disconnect()
        
        config['last_scan'] = datetime.now().isoformat()
        save_config(config)
    
    return jsonify(results)


@app.route('/analise')
@login_required
def analise_interativa():
    """Página de análise interativa - mostra resultados para revisão"""
    conn = get_email_connection()
    config = load_config()
    detector = SpamDetector(threshold=config.get('spam_threshold', 70))
    
    results = {
        'total_scanned': 0,
        'spam_list': [],
        'fraud_list': [],
        'safe_count': 0
    }
    
    if conn and conn.connect():
        emails_list = conn.fetch_emails('INBOX', limit=100)
        results['total_scanned'] = len(emails_list)
        
        for email_data in emails_list:
            analysis = detector.analyze(email_data)
            uid = email_data.get('uid', email_data.get('id', ''))
            
            if analysis['is_fraud']:
                results['fraud_list'].append({
                    'uid': uid,
                    'subject': email_data.get('subject', 'Sem assunto'),
                    'from': email_data.get('from', 'Desconhecido'),
                    'date': email_data.get('date', ''),
                    'score': analysis['score'],
                    'reasons': analysis['reasons']
                })
            elif analysis['is_spam']:
                results['spam_list'].append({
                    'uid': uid,
                    'subject': email_data.get('subject', 'Sem assunto'),
                    'from': email_data.get('from', 'Desconhecido'),
                    'date': email_data.get('date', ''),
                    'score': analysis['score'],
                    'reasons': analysis['reasons']
                })
            else:
                results['safe_count'] += 1
        
        conn.disconnect()
    
    return render_template('analise.html',
                          email=session.get('email'),
                          results=results)


@app.route('/delete-email', methods=['POST'])
@login_required
def delete_email():
    """Exclui um email específico"""
    conn = get_email_connection()
    uid = request.json.get('uid')
    
    if not uid:
        return jsonify({'success': False, 'error': 'UID não informado'})
    
    if conn and conn.connect():
        try:
            conn.move_to_trash(uid, 'INBOX')
            conn.disconnect()
            return jsonify({'success': True})
        except Exception as e:
            conn.disconnect()
            return jsonify({'success': False, 'error': str(e)})
    
    return jsonify({'success': False, 'error': 'Não foi possível conectar'})


@app.route('/delete-multiple', methods=['POST'])
@login_required
def delete_multiple():
    """Exclui múltiplos emails"""
    conn = get_email_connection()
    uids = request.json.get('uids', [])
    
    results = {'deleted': 0, 'errors': 0}
    
    if conn and conn.connect():
        for uid in uids:
            try:
                conn.move_to_trash(uid, 'INBOX')
                results['deleted'] += 1
            except:
                results['errors'] += 1
        conn.disconnect()
    
    return jsonify(results)


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=2000)

