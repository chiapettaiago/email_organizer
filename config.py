# Configurações do Organizador de E-mail
# =======================================

import os

# Configurações do servidor Locaweb
LOCAWEB_CONFIG = {
    'IMAP_SERVER': 'email-ssl.com.br',
    'IMAP_PORT': 993,
    'SMTP_SERVER': 'email-ssl.com.br',
    'SMTP_PORT': 465,  # SSL/TLS
    'SMTP_PORT_STARTTLS': 587,  # STARTTLS alternativo
    'USE_SSL': True,
    'DEFAULT_EMAIL': 'contato@isna.org.br'  # Email padrão configurado
}

# Pastas padrão para organização
DEFAULT_FOLDERS = [
    'Trabalho',
    'Pessoal',
    'Newsletters',
    'Spam',
    'Fraude'
]

# Configurações de detecção de spam
SPAM_CONFIG = {
    'THRESHOLD': 70,  # Score mínimo para considerar spam (0-100)
    'AUTO_DELETE': False,  # Se True, deleta automaticamente
    'QUARANTINE_DAYS': 30  # Dias para manter em quarentena
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
