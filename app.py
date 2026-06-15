# Organizador de E-mail Flask - Locaweb
# ===========================================

import os
import json
import re
import copy
from datetime import datetime
from html import escape, unescape
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from functools import wraps
from threading import RLock
from markupsafe import Markup
from email_service.connection import EmailConnection
from email_service.folder_manager import FolderManager
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.schedulers.base import SchedulerNotRunningError
from config import FRAUD_RISK_CONFIG, LOCAWEB_CONFIG
from database import create_user, get_all_users, delete_user, toggle_user_status
import secrets
import atexit

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = int(os.getenv('STATIC_CACHE_TTL_SECONDS', '3600'))

# Configurações Locaweb
LOCAWEB_IMAP_SERVER = LOCAWEB_CONFIG['IMAP_SERVER']
LOCAWEB_IMAP_PORT = LOCAWEB_CONFIG['IMAP_PORT']
LOCAWEB_SMTP_SERVER = LOCAWEB_CONFIG['SMTP_SERVER']
LOCAWEB_SMTP_PORT = LOCAWEB_CONFIG['SMTP_PORT']

# Arquivo de configurações persistentes
CONFIG_FILE = os.getenv(
    'USER_CONFIG_FILE',
    os.path.join(os.path.dirname(__file__), 'user_config.json')
)
_CONFIG_LOCK = RLock()
_CONFIG_CACHE = None
_CONFIG_CACHE_MTIME = None

# Scheduler para tarefas agendadas
scheduler = BackgroundScheduler()
scheduler.start()

# Registra para encerrar o scheduler quando a aplicação parar
def shutdown_scheduler():
    try:
        scheduler.shutdown()
    except SchedulerNotRunningError:
        pass


atexit.register(shutdown_scheduler)


def _default_config():
    """Retorna configuração padrão"""
    return {
        'auto_delete_spam': True,
        'auto_delete_fraud': True,
        'spam_threshold': 70,
        'auto_scan_enabled': True,
        'auto_scan_time': '03:00',
        'last_scan': None,
        'fraud_risk': dict(FRAUD_RISK_CONFIG),
        'accounts': {}
    }


def _merge_config(config_data):
    """Garante presença das chaves esperadas e tipos mínimos"""
    merged = _default_config()
    if isinstance(config_data, dict):
        merged.update(config_data)
    if not isinstance(merged.get('accounts'), dict):
        merged['accounts'] = {}
    if not isinstance(merged.get('fraud_risk'), dict):
        merged['fraud_risk'] = {}
    fraud_risk = dict(FRAUD_RISK_CONFIG)
    fraud_risk.update(merged.get('fraud_risk', {}))
    merged['fraud_risk'] = fraud_risk
    return merged


def get_risk_config(config=None):
    """Obtém configuração normalizada do motor de risco."""
    loaded = config or load_config()
    risk_config = dict(FRAUD_RISK_CONFIG)
    risk_config.update(loaded.get('fraud_risk', {}))
    # Compatibilidade com o controle antigo de threshold.
    risk_config['quarantine_threshold'] = int(loaded.get('spam_threshold', risk_config['quarantine_threshold']))
    if loaded.get('auto_delete_spam', True):
        risk_config['delete_threshold'] = risk_config['quarantine_threshold']
    if not loaded.get('auto_delete_fraud', True):
        risk_config['delete_threshold'] = 101
    if loaded.get('auto_delete_spam', True) or loaded.get('auto_delete_fraud', True):
        risk_config['dry_run'] = False
    return risk_config


def format_log_timestamp(value):
    """Formata timestamps ISO para leitura humana na UI."""
    if not value:
        return ''
    try:
        normalized = str(value).replace('Z', '+00:00')
        parsed = datetime.fromisoformat(normalized)
        return parsed.strftime('%d/%m/%Y %H:%M:%S')
    except (TypeError, ValueError):
        return str(value)


def load_risk_logs(limit=500):
    """Carrega decisões de risco registradas em JSONL."""
    risk_config = get_risk_config()
    log_file = risk_config.get('log_file') or 'logs/fraud_decisions.jsonl'
    logs = []

    if not os.path.exists(log_file):
        return logs

    try:
        with open(log_file, 'r', encoding='utf-8') as log_handle:
            lines = log_handle.readlines()
    except OSError:
        return logs

    current_email = session.get('email', '').strip().lower()
    is_admin = session.get('is_admin', False)

    for raw_line in reversed(lines):
        if len(logs) >= limit:
            break
        try:
            entry = json.loads(raw_line)
        except (TypeError, ValueError):
            continue

        account = str(entry.get('account', '')).strip().lower()
        if current_email and not is_admin and account != current_email:
            continue

        logs.append({
            'timestamp': entry.get('timestamp', ''),
            'timestamp_display': format_log_timestamp(entry.get('timestamp', '')),
            'event': entry.get('event', 'action'),
            'account': entry.get('account', ''),
            'uid': entry.get('uid', ''),
            'from': entry.get('from', ''),
            'subject': entry.get('subject', ''),
            'score': entry.get('score', 0),
            'classification': entry.get('classification', ''),
            'rules': entry.get('rules', []),
            'action': entry.get('action', ''),
            'success': entry.get('success', False),
            'error': entry.get('error', ''),
        })

    return logs


def write_system_log(entry):
    """Registra eventos manuais no mesmo log de auditoria do motor de risco."""
    risk_config = get_risk_config()
    log_file = risk_config.get('log_file') or 'logs/fraud_decisions.jsonl'
    log_dir = os.path.dirname(log_file)
    payload = {
        'timestamp': datetime.now().isoformat(),
        'event': entry.get('event', 'action'),
        'account': entry.get('account', session.get('email', '')),
        'uid': entry.get('uid', ''),
        'from': entry.get('from', ''),
        'subject': entry.get('subject', ''),
        'score': entry.get('score', 0),
        'classification': entry.get('classification', 'manual'),
        'rules': entry.get('rules', []),
        'action': entry.get('action', ''),
        'success': entry.get('success', True),
        'error': entry.get('error', ''),
    }

    try:
        if log_dir:
            os.makedirs(log_dir, exist_ok=True)
        with open(log_file, 'a', encoding='utf-8') as log_handle:
            log_handle.write(json.dumps(payload, ensure_ascii=False) + '\n')
    except OSError as exc:
        print(f"Erro ao registrar log do sistema: {exc}")


def load_config():
    """Carrega configurações do arquivo JSON com cache em memória"""
    global _CONFIG_CACHE, _CONFIG_CACHE_MTIME

    with _CONFIG_LOCK:
        file_mtime = os.path.getmtime(CONFIG_FILE) if os.path.exists(CONFIG_FILE) else None

        if _CONFIG_CACHE is not None and file_mtime == _CONFIG_CACHE_MTIME:
            return copy.deepcopy(_CONFIG_CACHE)

        loaded = {}
        if file_mtime is not None:
            try:
                with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
                    loaded = json.load(f)
            except (OSError, ValueError, TypeError):
                loaded = {}

        merged = _merge_config(loaded)
        _CONFIG_CACHE = merged
        _CONFIG_CACHE_MTIME = file_mtime
        return copy.deepcopy(merged)


def save_config(config):
    """Salva configurações no arquivo JSON"""
    global _CONFIG_CACHE, _CONFIG_CACHE_MTIME

    normalized = _merge_config(config)
    temp_file = f'{CONFIG_FILE}.tmp'

    with _CONFIG_LOCK:
        try:
            with open(temp_file, 'w', encoding='utf-8') as f:
                json.dump(normalized, f, indent=2)
            os.replace(temp_file, CONFIG_FILE)
        except PermissionError:
            # Fallback: alguns ambientes permitem atualizar o arquivo existente,
            # mas não criar um novo .tmp no diretório.
            with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
                json.dump(normalized, f, indent=2)
            try:
                if os.path.exists(temp_file):
                    os.remove(temp_file)
            except OSError:
                pass
        _CONFIG_CACHE = normalized
        _CONFIG_CACHE_MTIME = os.path.getmtime(CONFIG_FILE) if os.path.exists(CONFIG_FILE) else None


def get_admin_emails():
    """Retorna e-mails com permissão administrativa"""
    admin_emails = {
        item.strip().lower()
        for item in os.getenv('ADMIN_EMAILS', '').split(',')
        if item.strip()
    }
    default_admin = LOCAWEB_CONFIG.get('DEFAULT_EMAIL', '').strip().lower()
    if default_admin:
        admin_emails.add(default_admin)
    return admin_emails


def is_admin_email(email_address: str) -> bool:
    """Verifica se o e-mail possui acesso administrativo"""
    return email_address.strip().lower() in get_admin_emails()


def parse_emails_field(raw_value: str):
    """Normaliza campo de destinatários separado por vírgula"""
    if not raw_value:
        return []
    return [item.strip() for item in raw_value.split(',') if item.strip()]


HTML_TAG_PATTERN = re.compile(r'<[a-zA-Z][^>]*>')
REPLY_HEADER_PATTERN = re.compile(r'^em\s+.+\sescreveu:\s*$', re.IGNORECASE)


def body_looks_like_html(body_text: str) -> bool:
    """Detecta se o corpo já está em HTML"""
    if not body_text:
        return False
    return bool(HTML_TAG_PATTERN.search(body_text))


def normalize_plain_email_text(body_text: str) -> str:
    """Normaliza texto plano de e-mail para melhorar leitura"""
    text = (body_text or '').replace('\r\n', '\n').replace('\r', '\n')

    # Alguns provedores entregam texto com entidades HTML em corpo plain/text.
    # Decodifica para evitar exibir "&nbsp;" e "&aacute;" literalmente.
    if '&' in text:
        text = unescape(text).replace('\xa0', ' ')

    # Alguns servidores retornam citações inline como " > " sem quebra de linha.
    if text.count('\n') < 3 and ' > ' in text:
        text = re.sub(r'\s+>\s*', '\n> ', text)

    # Separa headers de resposta e assinatura legal em mensagens compactadas.
    text = re.sub(
        r'([.!?,])\s+(Em [^\n]{8,220} escreveu:\s*)',
        r'\1\n\n\2',
        text,
        flags=re.IGNORECASE
    )
    text = re.sub(r'(\bescreveu:\s*)>\s*', r'\1\n> ', text, flags=re.IGNORECASE)
    text = re.sub(
        r'\s+--\s*(?=(\*?\s*(aviso legal|disclaimer)))',
        '\n\n-- ',
        text,
        flags=re.IGNORECASE
    )

    # Remove excesso de linhas em branco mantendo separação visual.
    text = re.sub(r'\n{3,}', '\n\n', text)
    return text.strip()


def plain_email_to_html(body_text: str) -> str:
    """Converte corpo em texto plano para HTML sem perder estrutura"""
    lines = normalize_plain_email_text(body_text).split('\n')

    if not lines or (len(lines) == 1 and not lines[0].strip()):
        return '<p class="email-empty">Sem conteúdo no corpo da mensagem.</p>'

    html_parts = []
    paragraph_lines = []
    quote_lines = []
    signature_lines = []
    in_signature = False

    def flush_paragraph():
        if paragraph_lines:
            content = '<br>'.join(escape(item) for item in paragraph_lines if item.strip())
            if content:
                html_parts.append(f'<p>{content}</p>')
            paragraph_lines.clear()

    def flush_quote():
        if quote_lines:
            content = '<br>'.join(escape(item) for item in quote_lines if item.strip())
            if content:
                html_parts.append(f'<blockquote class="email-quote">{content}</blockquote>')
            quote_lines.clear()

    def first_signature_marker(line_lower: str):
        markers = ['aviso legal', 'disclaimer']
        indexes = [line_lower.find(marker) for marker in markers if marker in line_lower]
        if not indexes:
            return -1
        return min(indexes)

    for raw_line in lines:
        line = raw_line.rstrip()
        line_clean = line.strip()
        line_lower = line_clean.lower()

        if not line_clean:
            flush_paragraph()
            flush_quote()
            continue

        if not in_signature and REPLY_HEADER_PATTERN.match(line_clean):
            flush_paragraph()
            flush_quote()
            html_parts.append(f'<div class="email-reply-header">{escape(line_clean)}</div>')
            continue

        if not in_signature and line_clean.startswith('--'):
            flush_paragraph()
            flush_quote()
            in_signature = True
            signature_lines.append(line_clean)
            continue

        marker_index = -1 if in_signature else first_signature_marker(line_lower)
        if marker_index >= 0:
            prefix = line_clean[:marker_index].strip()
            signature_piece = line_clean[marker_index:].strip()
            if prefix:
                paragraph_lines.append(prefix)
            flush_paragraph()
            flush_quote()
            in_signature = True
            if signature_piece:
                signature_lines.append(signature_piece)
            continue

        if in_signature:
            signature_lines.append(line_clean)
            continue

        if line_clean.startswith('>'):
            flush_paragraph()
            quote_text = re.sub(r'^(>\s*)+', '', line_clean)
            quote_lines.append(quote_text)
            continue

        flush_quote()
        paragraph_lines.append(line_clean)

    flush_paragraph()
    flush_quote()

    if signature_lines:
        signature_html = '<br>'.join(escape(item.strip()) for item in signature_lines if item.strip())
        if signature_html:
            html_parts.append(f'<div class="email-signature">{signature_html}</div>')

    return ''.join(html_parts) if html_parts else '<p class="email-empty">Sem conteúdo no corpo da mensagem.</p>'


def format_email_body_for_display(body_text: str):
    """Gera HTML formatado para exibição do corpo da mensagem"""
    body = (body_text or '').strip()
    if not body:
        return Markup('<p class="email-empty">Sem conteúdo no corpo da mensagem.</p>'), False

    if body_looks_like_html(body):
        return Markup(body), True

    return Markup(plain_email_to_html(body)), False


def scheduled_scan():
    """Executa análise agendada de e-mails"""
    config = load_config()
    
    if not config.get('auto_scan_enabled', True):
        return
    
    print(f"[{datetime.now()}] 🔍 Iniciando análise agendada de e-mails...")
    
    # Processa cada conta salva
    for account_key, account_data in config.get('accounts', {}).items():
        email_address = account_key
        try:
            if not isinstance(account_data, dict):
                continue
            email_address = account_data.get('email') or account_key
            password = account_data.get('password', '')
            if not password:
                continue
            
            conn = EmailConnection(
                email_address, password,
                LOCAWEB_IMAP_SERVER, LOCAWEB_IMAP_PORT,
                LOCAWEB_SMTP_SERVER, LOCAWEB_SMTP_PORT
            )
            
            if conn.connect():
                folder_manager = FolderManager(conn, risk_config=get_risk_config(config))
                
                # Garante que as pastas existem
                folder_manager.ensure_default_folders()
                folder_manager.ensure_quarantine_folder()
                scan_results = folder_manager.process_inbox_risk(limit=None)
                
                conn.disconnect()
                print(
                    f"[{datetime.now()}] ✅ {email_address}: "
                    f"{scan_results['suspect']} suspeitos, {scan_results['fraud']} fraudes, "
                    f"{scan_results['quarantined']} quarentena, {scan_results['deleted']} exclusões, "
                    f"{scan_results['would_quarantine']} quarentenas simuladas, {scan_results['would_delete']} exclusões simuladas"
                )
        
        except Exception as e:
            print(f"[{datetime.now()}] ❌ Erro ao processar {email_address}: {e}")
    
    # Atualiza última execução
    config['last_scan'] = datetime.now().isoformat()
    save_config(config)


def setup_scheduler():
    """Configura o scheduler para executar diariamente."""
    config = load_config()
    
    # Remove job anterior se existir
    if scheduler.get_job('daily_scan'):
        scheduler.remove_job('daily_scan')
    
    if config.get('auto_scan_enabled', True):
        scan_time = config.get('auto_scan_time', '03:00')
        try:
            hour, minute = map(int, scan_time.split(':', 1))
            if not (0 <= hour <= 23 and 0 <= minute <= 59):
                raise ValueError
        except ValueError:
            hour, minute = 3, 0
            scan_time = '03:00'

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
    """Página inicial - redireciona para e-mails ou login"""
    if 'email' in session:
        return redirect(url_for('emails'))
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login usando e-mail e senha da conta de e-mail"""
    default_email = LOCAWEB_CONFIG.get('DEFAULT_EMAIL', 'contato@isna.org.br')
    
    if request.method == 'POST':
        email_address = request.form.get('email', '').strip()
        account_key = email_address.lower()
        password = request.form.get('password', '')
        
        print(f"[LOGIN] Tentativa para: {email_address} em {LOCAWEB_IMAP_SERVER}:{LOCAWEB_IMAP_PORT}")
        
        if not email_address or not password:
            flash('Por favor, preencha e-mail e senha.', 'error')
            return render_template('login.html', default_email=default_email)

        conn = EmailConnection(
            email_address, password,
            LOCAWEB_IMAP_SERVER, LOCAWEB_IMAP_PORT,
            LOCAWEB_SMTP_SERVER, LOCAWEB_SMTP_PORT
        )

        if conn.connect():
            conn.disconnect()

            session['user_id'] = email_address
            session['username'] = email_address.split('@')[0]
            session['email'] = email_address
            session['password'] = password
            session['is_admin'] = is_admin_email(email_address)

            # Mantém conta salva para automações agendadas
            config = load_config()
            accounts = config.get('accounts', {})
            accounts[account_key] = {
                'password': password,
                'email': email_address,
                'last_login': datetime.now().isoformat()
            }
            config['accounts'] = accounts
            save_config(config)

            print(f"[LOGIN] Sucesso! Redirecionando para e-mails")
            flash(f'Bem-vindo, {email_address}!', 'success')
            return redirect(url_for('emails'))
        
        error_message = conn.last_error or 'Falha na autenticação do e-mail. Verifique as credenciais.'
        print(f"[LOGIN] Falha: {error_message}")
        flash(error_message, 'error')
    
    return render_template('login.html', default_email=default_email)


def admin_required(f):
    """Decorator para rotas que requerem acesso de administrador"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'email' not in session:
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
        emails_list = conn.fetch_emails(folder, limit=50, include_body=False)
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
    folders = []
    
    if conn and conn.connect():
        email_data = conn.fetch_email_by_uid(folder, uid)
        folders = conn.list_folders()
        conn.set_read_status(uid, folder, True)
        conn.disconnect()
    
    if not email_data:
        flash('E-mail não encontrado.', 'error')
        return redirect(url_for('emails', folder=folder))

    body_html, body_is_html = format_email_body_for_display(email_data.get('body', ''))
    email_data['body_formatted'] = body_html
    email_data['body_is_html'] = body_is_html
    
    return render_template(
        'view_email.html',
        message=email_data,
        folder=folder,
        folders=folders,
        email=session.get('email')
    )


@app.route('/scan', methods=['POST'])
@login_required
def scan_emails():
    """Analisa e-mails para detectar spam e fraude"""
    conn = get_email_connection()
    config = load_config()
    results = {
        'total_scanned': 0,
        'spam_found': 0,
        'fraud_found': 0,
        'deleted': 0,
        'quarantined': 0,
        'would_delete': 0,
        'would_quarantine': 0,
        'items': []
    }
    
    if conn and conn.connect():
        folder_manager = FolderManager(conn, risk_config=get_risk_config(config))
        folder_manager.ensure_default_folders()
        folder_manager.ensure_quarantine_folder()
        scan_results = folder_manager.process_inbox_risk(limit=None)
        results['total_scanned'] = scan_results['scanned']
        results['spam_found'] = scan_results['suspect']
        results['fraud_found'] = scan_results['fraud']
        results['deleted'] = scan_results['deleted']
        results['quarantined'] = scan_results['quarantined']
        results['would_delete'] = scan_results['would_delete']
        results['would_quarantine'] = scan_results['would_quarantine']
        results['items'] = scan_results['items']
        
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
    results = {'moved': 0, 'errors': []}
    
    if conn and conn.connect():
        # Garante que as pastas padrão existem
        folder_manager = FolderManager(conn, risk_config=get_risk_config())
        folder_manager.ensure_default_folders()
        folder_manager.ensure_quarantine_folder()
        
        # Organiza e-mails
        results = folder_manager.auto_organize()
        conn.disconnect()
    
    return jsonify(results)


@app.route('/delete-spam', methods=['POST'])
@login_required
def delete_spam():
    """Move e-mails de spam/fraude para a lixeira"""
    conn = get_email_connection()
    payload = request.get_json(silent=True) or {}
    uids = payload.get('uids', [])
    source_folder = payload.get('folder', 'INBOX')
    results = {'deleted': 0, 'errors': []}
    
    if conn and conn.connect():
        if not uids:
            folder_manager = FolderManager(conn, risk_config=get_risk_config())
            results = folder_manager.delete_spam_and_fraud(permanent=False)
        else:
            if conn.move_to_trash_bulk(uids, source_folder):
                results['deleted'] = len(uids)
                for uid in uids:
                    write_system_log({
                        'event': 'action',
                        'uid': uid,
                        'classification': 'manual',
                        'rules': ['Exclusão manual de spam/fraude'],
                        'action': 'delete',
                        'success': True,
                    })
            else:
                for uid in uids:
                    try:
                        ok = conn.move_to_trash(uid, source_folder)
                        if ok:
                            results['deleted'] += 1
                        write_system_log({
                            'event': 'action',
                            'uid': uid,
                            'classification': 'manual',
                            'rules': ['Exclusão manual de spam/fraude'],
                            'action': 'delete',
                            'success': ok,
                            'error': '' if ok else 'Falha ao mover para lixeira',
                        })
                    except Exception as e:
                        results['errors'].append(str(e))
                        write_system_log({
                            'event': 'action',
                            'uid': uid,
                            'classification': 'manual',
                            'rules': ['Exclusão manual de spam/fraude'],
                            'action': 'delete',
                            'success': False,
                            'error': str(e),
                        })
        conn.disconnect()
    
    return jsonify(results)


@app.route('/emails/action', methods=['POST'])
@login_required
def email_action():
    """Executa ações em lote de interação com e-mails"""
    conn = get_email_connection()
    payload = request.get_json(silent=True) or {}
    action = (payload.get('action') or '').strip().lower()
    uids = payload.get('uids') or []
    source_folder = payload.get('source_folder', 'INBOX')
    target_folder = payload.get('target_folder', '')

    valid_actions = {'delete', 'move', 'archive', 'mark_read', 'mark_unread'}
    if action not in valid_actions:
        return jsonify({'success': False, 'error': 'Ação inválida'}), 400
    if not isinstance(uids, list) or not uids:
        return jsonify({'success': False, 'error': 'Nenhum e-mail selecionado'}), 400
    if action == 'move' and not target_folder:
        return jsonify({'success': False, 'error': 'Pasta de destino não informada'}), 400

    results = {'success': True, 'processed': 0, 'errors': []}

    if not conn or not conn.connect():
        return jsonify({'success': False, 'error': 'Não foi possível conectar à conta de e-mail'}), 500

    # Usa caminho em lote primeiro para reduzir round-trips IMAP
    bulk_ok = False
    try:
        if action == 'delete':
            bulk_ok = conn.move_to_trash_bulk(uids, source_folder)
        elif action == 'move':
            bulk_ok = conn.move_emails(uids, source_folder, target_folder)
        elif action == 'archive':
            bulk_ok = conn.archive_emails_bulk(uids, source_folder)
        elif action == 'mark_read':
            bulk_ok = conn.set_read_status_bulk(uids, source_folder, True)
        elif action == 'mark_unread':
            bulk_ok = conn.set_read_status_bulk(uids, source_folder, False)
    except Exception:
        bulk_ok = False

    if bulk_ok:
        results['processed'] = len(uids)
        if action == 'delete':
            for uid in uids:
                write_system_log({
                    'event': 'action',
                    'uid': uid,
                    'classification': 'manual',
                    'rules': ['Exclusão manual em lote'],
                    'action': 'delete',
                    'success': True,
                })
        conn.disconnect()
        return jsonify(results)

    # Fallback individual se o lote falhar
    for uid in uids:
        ok = False
        try:
            if action == 'delete':
                ok = conn.move_to_trash(uid, source_folder)
            elif action == 'move':
                ok = conn.move_email(uid, source_folder, target_folder)
            elif action == 'archive':
                ok = conn.archive_email(uid, source_folder)
            elif action == 'mark_read':
                ok = conn.set_read_status(uid, source_folder, True)
            elif action == 'mark_unread':
                ok = conn.set_read_status(uid, source_folder, False)
        except Exception as e:
            results['errors'].append(f'{uid}: {str(e)}')
            continue

        if ok:
            results['processed'] += 1
            if action == 'delete':
                write_system_log({
                    'event': 'action',
                    'uid': uid,
                    'classification': 'manual',
                    'rules': ['Exclusão manual'],
                    'action': 'delete',
                    'success': True,
                })
        else:
            results['errors'].append(f'{uid}: falha ao executar ação')
            if action == 'delete':
                write_system_log({
                    'event': 'action',
                    'uid': uid,
                    'classification': 'manual',
                    'rules': ['Exclusão manual'],
                    'action': 'delete',
                    'success': False,
                    'error': 'Falha ao executar ação',
                })

    conn.disconnect()
    return jsonify(results)


@app.route('/emails/send', methods=['POST'])
@login_required
def send_email():
    """Envia e-mail (novo, resposta ou encaminhamento)"""
    conn = get_email_connection()
    payload = request.get_json(silent=True) or {}

    to = (payload.get('to') or '').strip()
    cc = parse_emails_field(payload.get('cc', ''))
    bcc = parse_emails_field(payload.get('bcc', ''))
    subject = (payload.get('subject') or '').strip()
    body = payload.get('body') or ''
    is_html = bool(payload.get('html', False))
    reply_to = (payload.get('reply_to') or '').strip()

    if not to:
        return jsonify({'success': False, 'error': 'Destinatário obrigatório'}), 400
    if not subject:
        return jsonify({'success': False, 'error': 'Assunto obrigatório'}), 400
    if not body.strip():
        return jsonify({'success': False, 'error': 'Mensagem obrigatória'}), 400

    if not conn:
        return jsonify({'success': False, 'error': 'Sessão inválida'}), 401

    ok = conn.send_email(
        to=to,
        subject=subject,
        body=body,
        html=is_html,
        cc=cc,
        bcc=bcc,
        reply_to=reply_to if reply_to else None
    )

    if not ok:
        return jsonify({'success': False, 'error': 'Falha ao enviar e-mail'}), 500

    return jsonify({'success': True, 'message': 'E-mail enviado com sucesso'})


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


@app.route('/logs')
@login_required
def system_logs():
    """Página de auditoria das decisões de risco."""
    logs = load_risk_logs(limit=500)
    return render_template(
        'logs.html',
        logs=logs,
        email=session.get('email')
    )


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
        config['auto_scan_time'] = request.form.get('auto_scan_time', '03:00')
        
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
    """Executa análise manual imediatamente com política segura de risco."""
    config = load_config()
    conn = get_email_connection()
    
    results = {
        'scanned': 0,
        'spam': 0,
        'fraud': 0,
        'quarantined': 0,
        'deleted': 0,
        'would_quarantine': 0,
        'would_delete': 0,
        'dry_run': True
    }
    
    if conn and conn.connect():
        folder_manager = FolderManager(conn, risk_config=get_risk_config(config))
        folder_manager.ensure_default_folders()
        folder_manager.ensure_quarantine_folder()
        scan_results = folder_manager.process_inbox_risk(limit=None)
        results['scanned'] = scan_results['scanned']
        results['spam'] = scan_results['suspect']
        results['fraud'] = scan_results['fraud']
        results['quarantined'] = scan_results['quarantined']
        results['deleted'] = scan_results['deleted']
        results['would_quarantine'] = scan_results['would_quarantine']
        results['would_delete'] = scan_results['would_delete']
        results['dry_run'] = scan_results['dry_run']
        
        conn.disconnect()
        
        config['last_scan'] = datetime.now().isoformat()
        save_config(config)
    
    return jsonify(results)


@app.route('/analise')
@login_required
def analise_interativa():
    """Página de análise interativa. A análise só roda após clique do usuário."""
    results = {
        'total_scanned': 0,
        'spam_list': [],
        'fraud_list': [],
        'safe_count': 0
    }

    return render_template('analise.html',
                          email=session.get('email'),
                          results=results)


@app.route('/delete-email', methods=['POST'])
@login_required
def delete_email():
    """Exclui um email específico"""
    conn = get_email_connection()
    payload = request.get_json(silent=True) or {}
    uid = payload.get('uid')
    folder = payload.get('folder', 'INBOX')
    
    if not uid:
        return jsonify({'success': False, 'error': 'UID não informado'})
    
    if conn and conn.connect():
        try:
            ok = conn.move_to_trash(uid, folder)
            conn.disconnect()
            write_system_log({
                'event': 'action',
                'uid': uid,
                'classification': 'manual',
                'rules': ['Exclusão manual individual'],
                'action': 'delete',
                'success': ok,
                'error': '' if ok else 'Falha ao mover para lixeira',
            })
            return jsonify({'success': ok})
        except Exception as e:
            conn.disconnect()
            write_system_log({
                'event': 'action',
                'uid': uid,
                'classification': 'manual',
                'rules': ['Exclusão manual individual'],
                'action': 'delete',
                'success': False,
                'error': str(e),
            })
            return jsonify({'success': False, 'error': str(e)})
    
    return jsonify({'success': False, 'error': 'Não foi possível conectar'})


@app.route('/delete-multiple', methods=['POST'])
@login_required
def delete_multiple():
    """Exclui múltiplos emails"""
    conn = get_email_connection()
    payload = request.get_json(silent=True) or {}
    uids = payload.get('uids', [])
    folder = payload.get('folder', 'INBOX')
    
    results = {'deleted': 0, 'errors': 0}
    
    if conn and conn.connect():
        if conn.move_to_trash_bulk(uids, folder):
            results['deleted'] = len(uids)
            for uid in uids:
                write_system_log({
                    'event': 'action',
                    'uid': uid,
                    'classification': 'manual',
                    'rules': ['Exclusão manual múltipla'],
                    'action': 'delete',
                    'success': True,
                })
        else:
            for uid in uids:
                try:
                    ok = conn.move_to_trash(uid, folder)
                    if ok:
                        results['deleted'] += 1
                    write_system_log({
                        'event': 'action',
                        'uid': uid,
                        'classification': 'manual',
                        'rules': ['Exclusão manual múltipla'],
                        'action': 'delete',
                        'success': ok,
                        'error': '' if ok else 'Falha ao mover para lixeira',
                    })
                except Exception as exc:
                    results['errors'] += 1
                    write_system_log({
                        'event': 'action',
                        'uid': uid,
                        'classification': 'manual',
                        'rules': ['Exclusão manual múltipla'],
                        'action': 'delete',
                        'success': False,
                        'error': str(exc),
                    })
        conn.disconnect()
    
    return jsonify(results)


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=2000)
