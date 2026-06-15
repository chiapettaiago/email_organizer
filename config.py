# Configurações do Organizador de E-mail
# =======================================

import os

try:
    from dotenv import load_dotenv
except ImportError:
    def load_dotenv(*args, **kwargs):
        return False

load_dotenv()

# Configurações do servidor Locaweb
LOCAWEB_CONFIG = {
    'IMAP_SERVER': os.getenv('IMAP_SERVER', 'email-ssl.com.br'),
    'IMAP_PORT': int(os.getenv('IMAP_PORT', '993')),
    'SMTP_SERVER': os.getenv('SMTP_SERVER', 'email-ssl.com.br'),
    'SMTP_PORT': int(os.getenv('SMTP_PORT', '465')),  # SSL/TLS
    'SMTP_PORT_STARTTLS': int(os.getenv('SMTP_PORT_STARTTLS', '587')),  # STARTTLS alternativo
    'USE_SSL': True,
    'DEFAULT_EMAIL': os.getenv('DEFAULT_EMAIL', 'contato@isna.org.br')  # Email padrão configurado
}

# Pastas padrão para organização
DEFAULT_FOLDERS = [
    'Trabalho',
    'Pessoal',
    'Newsletters',
    'Spam',
    'Fraude',
    'Quarentena/Fraude'
]

# Configurações de detecção de spam
SPAM_CONFIG = {
    'THRESHOLD': 70,  # Score mínimo para considerar spam (0-100)
    'AUTO_DELETE': False,  # Se True, deleta automaticamente
    'QUARANTINE_DAYS': 30  # Dias para manter em quarentena
}

# Configuração padrão do motor de risco. Pode ser sobrescrita em user_config.json
# pela chave "fraud_risk".
FRAUD_RISK_CONFIG = {
    'safe_threshold': 35,
    'quarantine_threshold': 55,
    'delete_threshold': 90,
    'dry_run': False,
    'quarantine_enabled': True,
    'quarantine_folder': 'Quarentena/Fraude',
    'log_file': os.getenv('FRAUD_LOG_FILE', 'logs/fraud_decisions.jsonl'),
    'allowed_domains': [],
    'trusted_senders': [],
    'blocked_domains': [],
    'blocked_attachment_extensions': [
        '.exe', '.scr', '.bat', '.cmd', '.js', '.vbs', '.jar', '.zip', '.rar', '.iso'
    ],
    'suspicious_keywords': [
        'urgente', 'ameaça', 'bloqueio', 'bloqueado', 'cobrança', 'cobranca',
        'prêmio', 'premio', 'senha', 'pix', 'boleto', 'nota fiscal',
        'nf-e', 'nfe', 'token', 'código', 'codigo', 'transferência',
        'transferencia', 'atualização cadastral', 'atualizacao cadastral',
        'regularize', 'pendência', 'pendencia', 'suspensão', 'suspensao'
    ],
    'sensitive_brands': [
        'banco', 'bradesco', 'itau', 'itaú', 'santander', 'caixa',
        'nubank', 'inter', 'mercadopago', 'mercado pago', 'gov',
        'govbr', 'receita', 'correios', 'microsoft', 'google',
        'apple', 'paypal', 'amazon', 'meta', 'instagram', 'whatsapp'
    ],
    'shortener_domains': [
        'bit.ly', 'goo.gl', 'tinyurl.com', 'ow.ly', 'is.gd', 't.co',
        'buff.ly', 'cutt.ly', 'rebrand.ly', 'lnkd.in', 's.id'
    ]
}

# Palavras-chave de spam (português e inglês)
SPAM_KEYWORDS = [
    # Urgência
    'urgente', 'urgent', 'ação imediata', 'immediate action',
    'última chance', 'last chance', 'expira hoje', 'expires today',
    
    # Prêmios e ofertas
    'você ganhou', 'you won', 'parabéns', 'congratulations',
    'prêmio', 'prize', 'sorteado', 'selected', 'grátis', 'free',
    
    # Dinheiro
    'dinheiro fácil', 'easy money', 'renda extra', 'extra income',
    'investimento garantido', 'guaranteed investment', 'lucro',
    
    # Segurança/Conta
    'senha expirada', 'password expired', 'conta suspensa',
    'verify your account', 'verifique sua conta', 'atualizar dados',
    'confirme sua identidade', 'confirm your identity',
    
    # Genéricos de spam
    'clique aqui', 'click here', 'não perca', 'dont miss',
    'oferta imperdível', 'amazing offer', 'promoção exclusiva'
]

# Padrões de fraude
FRAUD_PATTERNS = [
    # Domínios suspeitos
    r'@.*\.(xyz|top|club|info|pw|tk)$',
    
    # Links encurtados suspeitos
    r'bit\.ly|goo\.gl|tinyurl|ow\.ly|is\.gd|buff\.ly',
    
    # Padrões de phishing
    r'banco.*atualiz|bank.*update',
    r'senha.*reset|password.*reset',
    r'cartão.*bloqueado|card.*blocked',
    r'fatura.*pend|invoice.*pend',
    
    # Executáveis e anexos perigosos
    r'\.exe|\.scr|\.bat|\.cmd|\.vbs|\.js$'
]

# Regras de organização automática
ORGANIZATION_RULES = [
    {
        'name': 'Newsletters',
        'conditions': {
            'from_contains': ['newsletter', 'news@', 'noreply', 'no-reply'],
            'subject_contains': ['newsletter', 'digest', 'weekly', 'semanal']
        },
        'folder': 'Newsletters'
    },
    {
        'name': 'Trabalho',
        'conditions': {
            'from_domain': [],  # Será preenchido com domínio do usuário
            'subject_contains': ['reunião', 'meeting', 'projeto', 'project', 'relatório', 'report']
        },
        'folder': 'Trabalho'
    },
    {
        'name': 'Pessoal',
        'conditions': {
            'from_domain': ['gmail.com', 'hotmail.com', 'outlook.com', 'yahoo.com'],
        },
        'folder': 'Pessoal'
    }
]
