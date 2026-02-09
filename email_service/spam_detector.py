# Detector de Spam e Fraude
# ==========================

import re
from typing import Dict, List, Tuple
from config import SPAM_KEYWORDS, FRAUD_PATTERNS


class SpamDetector:
    """Analisa e-mails para detectar spam e tentativas de fraude"""
    
    def __init__(self, threshold: int = 70):
        self.threshold = threshold
        self.spam_keywords = SPAM_KEYWORDS
        self.fraud_patterns = [re.compile(p, re.IGNORECASE) for p in FRAUD_PATTERNS]
    
    def analyze(self, email_data: Dict) -> Dict:
        """
        Analisa um e-mail e retorna score de spam/fraude
        
        Returns:
            {
                'is_spam': bool,
                'is_fraud': bool,
                'score': int (0-100),
                'reasons': list
            }
        """
        score = 0
        reasons = []
        is_fraud = False
        
        subject = email_data.get('subject', '').lower()
        from_addr = email_data.get('from', '').lower()
        body = ''
        
        # Extrai corpo se disponível
        if 'body' in email_data:
            body = email_data['body'].lower()
        elif 'raw_msg' in email_data:
            body = self._extract_body_text(email_data['raw_msg']).lower()
        
        # 1. Análise de palavras-chave de spam
        keyword_score, keyword_reasons = self._check_keywords(subject, body)
        score += keyword_score
        reasons.extend(keyword_reasons)
        
        # 2. Análise de padrões de fraude
        fraud_score, fraud_reasons, detected_fraud = self._check_fraud_patterns(from_addr, body)
        score += fraud_score
        reasons.extend(fraud_reasons)
        if detected_fraud:
            is_fraud = True
        
        # 3. Análise do remetente
        sender_score, sender_reasons = self._check_sender(from_addr)
        score += sender_score
        reasons.extend(sender_reasons)
        
        # 4. Análise de headers (se disponível)
        if 'headers' in email_data:
            header_score, header_reasons, header_fraud = self._check_headers(email_data['headers'])
            score += header_score
            reasons.extend(header_reasons)
            if header_fraud:
                is_fraud = True
        
        # 5. Análise de links suspeitos no corpo
        link_score, link_reasons = self._check_links(body)
        score += link_score
        reasons.extend(link_reasons)
        
        # Limita score a 100
        score = min(score, 100)
        
        return {
            'is_spam': score >= self.threshold,
            'is_fraud': is_fraud,
            'score': score,
            'reasons': reasons
        }
    
    def _check_keywords(self, subject: str, body: str) -> Tuple[int, List[str]]:
        """Verifica palavras-chave de spam"""
        score = 0
        reasons = []
        found_keywords = set()
        
        text = f"{subject} {body}"
        
        for keyword in self.spam_keywords:
            if keyword.lower() in text:
                found_keywords.add(keyword)
        
        if found_keywords:
            # Cada palavra-chave adiciona pontos
            keyword_count = len(found_keywords)
            score = min(keyword_count * 10, 40)  # Máximo 40 pontos por keywords
            reasons.append(f"Palavras suspeitas encontradas: {', '.join(list(found_keywords)[:5])}")
        
        return score, reasons
    
    def _check_fraud_patterns(self, from_addr: str, body: str) -> Tuple[int, List[str], bool]:
        """Verifica padrões de fraude"""
        score = 0
        reasons = []
        is_fraud = False
        
        text = f"{from_addr} {body}"
        
        for pattern in self.fraud_patterns:
            match = pattern.search(text)
            if match:
                score += 25
                is_fraud = True
                reasons.append(f"Padrão de fraude detectado: {match.group()[:50]}")
        
        return min(score, 50), reasons, is_fraud
    
    def _check_sender(self, from_addr: str) -> Tuple[int, List[str]]:
        """Analisa o remetente"""
        score = 0
        reasons = []
        
        # Domínios suspeitos
        suspicious_tlds = ['.xyz', '.top', '.club', '.pw', '.tk', '.ml', '.ga', '.cf']
        for tld in suspicious_tlds:
            if tld in from_addr:
                score += 30
                reasons.append(f"Domínio suspeito: {tld}")
                break
        
        # E-mail com muitos números
        email_part = from_addr.split('@')[0] if '@' in from_addr else from_addr
        if sum(c.isdigit() for c in email_part) > 5:
            score += 15
            reasons.append("Remetente com muitos números")
        
        # Remetente muito longo
        if len(email_part) > 30:
            score += 10
            reasons.append("Endereço de e-mail muito longo")
        
        return score, reasons
    
    def _check_headers(self, headers: Dict) -> Tuple[int, List[str], bool]:
        """Analisa headers de e-mail"""
        score = 0
        reasons = []
        is_fraud = False
        
        # Verifica SPF
        spf = headers.get('spf', '')
        if 'fail' in spf.lower() or 'softfail' in spf.lower():
            score += 25
            reasons.append("Falha na verificação SPF")
            is_fraud = True
        
        # Verifica Reply-To diferente do From
        reply_to = headers.get('reply-to', '')
        if reply_to and '@' in reply_to:
            # Se reply-to tem domínio diferente, é suspeito
            reasons.append("Reply-To diferente do remetente")
            score += 15
        
        return score, reasons, is_fraud
    
    def _check_links(self, body: str) -> Tuple[int, List[str]]:
        """Verifica links suspeitos"""
        score = 0
        reasons = []
        
        # Padrões de links encurtados ou suspeitos
        shorteners = ['bit.ly', 'goo.gl', 'tinyurl', 'ow.ly', 'is.gd', 't.co', 'buff.ly']
        for shortener in shorteners:
            if shortener in body:
                score += 15
                reasons.append(f"Link encurtado detectado: {shortener}")
                break
        
        # Links com IPs em vez de domínios
        ip_pattern = r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
        if re.search(ip_pattern, body):
            score += 30
            reasons.append("Link com endereço IP detectado")
        
        # Muitos links no e-mail
        url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
        urls = re.findall(url_pattern, body)
        if len(urls) > 10:
            score += 10
            reasons.append(f"Muitos links no e-mail ({len(urls)} encontrados)")
        
        return score, reasons
    
    def _extract_body_text(self, msg) -> str:
        """Extrai texto do corpo do e-mail"""
        body = ''
        
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                if content_type == 'text/plain':
                    try:
                        payload = part.get_payload(decode=True)
                        charset = part.get_content_charset() or 'utf-8'
                        body = payload.decode(charset, errors='replace')
                        break
                    except:
                        pass
        else:
            try:
                payload = msg.get_payload(decode=True)
                if payload:
                    charset = msg.get_content_charset() or 'utf-8'
                    body = payload.decode(charset, errors='replace')
            except:
                pass
        
        return body
    
    def batch_analyze(self, emails: List[Dict]) -> Dict:
        """Analisa múltiplos e-mails e retorna resumo"""
        results = {
            'total': len(emails),
            'spam': [],
            'fraud': [],
            'safe': []
        }
        
        for email_data in emails:
            analysis = self.analyze(email_data)
            
            item = {
                'uid': email_data.get('uid', ''),
                'subject': email_data.get('subject', ''),
                'from': email_data.get('from', ''),
                'score': analysis['score'],
                'reasons': analysis['reasons']
            }
            
            if analysis['is_fraud']:
                results['fraud'].append(item)
            elif analysis['is_spam']:
                results['spam'].append(item)
            else:
                results['safe'].append(item)
        
        return results
