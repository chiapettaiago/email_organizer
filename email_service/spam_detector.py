# Detector de Spam e Fraude
# ==========================

import ipaddress
import re
from email.utils import parseaddr
from html import unescape
from typing import Dict, List, Tuple
from urllib.parse import urlparse

from config import FRAUD_PATTERNS, FRAUD_RISK_CONFIG, SPAM_KEYWORDS


class SpamDetector:
    """Motor de risco para classificar e-mails como seguro, suspeito ou fraude."""

    URL_PATTERN = re.compile(r'https?://[^\s<>"\'{}|\\^`\[\]]+', re.IGNORECASE)
    HREF_PATTERN = re.compile(
        r'<a\b[^>]*href=["\'](?P<href>https?://[^"\']+)["\'][^>]*>(?P<label>.*?)</a>',
        re.IGNORECASE | re.DOTALL
    )
    HTML_TAG_PATTERN = re.compile(r'<[^>]+>')
    IPV4_HOST_PATTERN = re.compile(r'^\d{1,3}(?:\.\d{1,3}){3}$')

    def __init__(self, threshold: int = None, risk_config: Dict = None):
        self.config = self._merge_risk_config(risk_config or {})
        self.threshold = threshold if threshold is not None else self.config['quarantine_threshold']
        self.spam_keywords = SPAM_KEYWORDS
        self.fraud_patterns = [re.compile(p, re.IGNORECASE) for p in FRAUD_PATTERNS]

    def analyze(self, email_data: Dict) -> Dict:
        """
        Analisa um e-mail e retorna score de risco.

        Mantém campos antigos para compatibilidade: is_spam, is_fraud, score, reasons.
        """
        score = 0
        triggered_rules = []

        subject = self._safe_text(email_data.get('subject', ''))
        from_header = self._safe_text(email_data.get('from', ''))
        body = self._safe_text(email_data.get('body', ''))
        html_body = self._safe_text(email_data.get('html_body', ''))
        raw_msg = email_data.get('raw_msg')
        headers = email_data.get('headers') if isinstance(email_data.get('headers'), dict) else {}
        attachments = email_data.get('attachments') if isinstance(email_data.get('attachments'), list) else []

        if not body and raw_msg is not None:
            body = self._extract_body_text(raw_msg)
        if not html_body and raw_msg is not None:
            html_body = self._extract_html_body(raw_msg)
        if not attachments and raw_msg is not None:
            attachments = self._extract_attachments(raw_msg)

        display_name, from_email = parseaddr(from_header)
        from_email = from_email.lower().strip()
        from_domain = self._domain_from_email(from_email)

        checks = [
            self._check_sender(from_header, display_name, from_email, from_domain),
            self._check_lists(from_email, from_domain),
            self._check_keywords(subject, body, html_body),
            self._check_fraud_patterns(from_header, body, html_body),
            self._check_links(body, html_body),
            self._check_attachments(attachments),
            self._check_headers(headers, from_email, from_domain),
            self._check_html_risks(html_body),
            self._check_typosquatting(from_domain, body, html_body),
        ]

        for rule_score, rule_reasons in checks:
            score += rule_score
            triggered_rules.extend(rule_reasons)

        if from_email in self.config['trusted_senders']:
            score = max(0, score - 25)
            triggered_rules.append('Remetente confiável reduziu o risco')
        elif from_domain in self.config['allowed_domains']:
            score = max(0, score - 10)
            triggered_rules.append('Domínio permitido reduziu o risco')

        score = min(max(score, 0), 100)
        classification = self._classify(score)

        return {
            'is_spam': classification in ('suspeito', 'fraude'),
            'is_fraud': classification == 'fraude',
            'classification': classification,
            'score': score,
            'reasons': triggered_rules,
            'rules': triggered_rules,
            'recommended_action': self.recommended_action(score),
        }

    def recommended_action(self, score: int) -> str:
        """Retorna a ação segura recomendada para o score."""
        if score >= self.config['delete_threshold']:
            return 'delete'
        if score >= self.config['quarantine_threshold']:
            return 'quarantine'
        return 'keep'

    def batch_analyze(self, emails: List[Dict]) -> Dict:
        """Analisa múltiplos e-mails e retorna resumo."""
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
                'classification': analysis['classification'],
                'reasons': analysis['reasons']
            }

            if analysis['is_fraud']:
                results['fraud'].append(item)
            elif analysis['is_spam']:
                results['spam'].append(item)
            else:
                results['safe'].append(item)

        return results

    def _merge_risk_config(self, risk_config: Dict) -> Dict:
        merged = dict(FRAUD_RISK_CONFIG)
        if isinstance(risk_config, dict):
            for key, value in risk_config.items():
                if value is not None:
                    merged[key] = value

        for list_key in (
            'allowed_domains', 'trusted_senders', 'blocked_domains',
            'blocked_attachment_extensions', 'suspicious_keywords',
            'sensitive_brands', 'shortener_domains'
        ):
            merged[list_key] = {
                self._normalize_token(item) for item in merged.get(list_key, []) if self._normalize_token(item)
            }

        return merged

    def _classify(self, score: int) -> str:
        if score >= self.config['delete_threshold']:
            return 'fraude'
        if score >= self.config['quarantine_threshold']:
            return 'suspeito'
        return 'seguro'

    def _check_lists(self, from_email: str, from_domain: str) -> Tuple[int, List[str]]:
        if from_domain in self.config['blocked_domains']:
            return 60, [f'Domínio bloqueado: {from_domain}']
        if from_email in self.config['trusted_senders']:
            return 0, []
        return 0, []

    def _check_keywords(self, subject: str, body: str, html_body: str = '') -> Tuple[int, List[str]]:
        text = self._normalize_text(f'{subject} {body} {self._strip_html(html_body)}')
        found = set()

        for keyword in set(self.spam_keywords) | self.config['suspicious_keywords']:
            normalized = self._normalize_text(keyword)
            if normalized and normalized in text:
                found.add(keyword)

        sensitive_requests = [
            'senha', 'password', 'codigo', 'código', 'token', 'pix', 'boleto',
            'pagamento', 'transferencia', 'transferência', 'atualizacao cadastral',
            'atualização cadastral'
        ]
        request_hits = [item for item in sensitive_requests if self._normalize_text(item) in text]

        score = min(len(found) * 8, 32)
        reasons = []
        if found:
            reasons.append(f'Palavras suspeitas: {", ".join(sorted(found)[:6])}')
        if request_hits:
            score += min(len(request_hits) * 10, 30)
            reasons.append(f'Solicitação sensível no texto: {", ".join(sorted(set(request_hits))[:5])}')

        return min(score, 55), reasons

    def _check_fraud_patterns(self, from_header: str, body: str, html_body: str) -> Tuple[int, List[str]]:
        text = f'{from_header} {body} {self._strip_html(html_body)}'
        reasons = []
        score = 0
        for pattern in self.fraud_patterns:
            match = pattern.search(text)
            if match:
                score += 18
                reasons.append(f'Padrão de fraude: {match.group()[:60]}')
        return min(score, 50), reasons

    def _check_sender(
        self,
        from_header: str,
        display_name: str,
        from_email: str,
        from_domain: str
    ) -> Tuple[int, List[str]]:
        score = 0
        reasons = []

        if not from_email or '@' not in from_email:
            return 35, ['Header From inválido ou sem e-mail parseável']

        suspicious_tlds = ('.xyz', '.top', '.club', '.pw', '.tk', '.ml', '.ga', '.cf', '.info')
        if from_domain.endswith(suspicious_tlds):
            score += 25
            reasons.append(f'TLD suspeito no remetente: {from_domain}')

        local_part = from_email.split('@', 1)[0]
        if sum(c.isdigit() for c in local_part) > 5:
            score += 12
            reasons.append('Remetente com muitos números')
        if len(local_part) > 35:
            score += 10
            reasons.append('Endereço de remetente muito longo')

        display_normalized = self._normalize_text(display_name)
        if display_normalized:
            for brand in self.config['sensitive_brands']:
                brand_key = self._normalize_brand(brand)
                if brand_key and brand_key in display_normalized and brand_key not in self._normalize_brand(from_domain):
                    score += 25
                    reasons.append(f'Nome exibido menciona marca diferente do domínio: {brand}')
                    break

        return min(score, 45), reasons

    def _check_headers(self, headers: Dict, from_email: str, from_domain: str) -> Tuple[int, List[str]]:
        score = 0
        reasons = []
        auth_text = self._normalize_text(' '.join([
            self._safe_text(headers.get('authentication-results', '')),
            self._safe_text(headers.get('received-spf', headers.get('spf', ''))),
            self._safe_text(headers.get('dkim', '')),
            self._safe_text(headers.get('dmarc', '')),
        ]))

        for auth_name in ('spf', 'dkim', 'dmarc'):
            if f'{auth_name}=fail' in auth_text or f'{auth_name} fail' in auth_text:
                score += 25
                reasons.append(f'Falha de autenticação {auth_name.upper()}')
            elif f'{auth_name}=softfail' in auth_text or f'{auth_name} softfail' in auth_text:
                score += 15
                reasons.append(f'Autenticação {auth_name.upper()} com softfail')

        if auth_text and all(marker not in auth_text for marker in ('spf=', 'dkim=', 'dmarc=', 'pass', 'fail')):
            score += 8
            reasons.append('Headers de autenticação inconclusivos')
        elif not auth_text:
            score += 8
            reasons.append('Headers SPF/DKIM/DMARC ausentes')

        reply_header = self._safe_text(headers.get('reply-to', ''))
        _, reply_email = parseaddr(reply_header)
        reply_domain = self._domain_from_email(reply_email.lower().strip())
        if reply_email and reply_email.lower() != from_email:
            score += 22
            reasons.append('Reply-To diferente do From')
            if reply_domain and from_domain and reply_domain != from_domain:
                score += 18
                reasons.append(f'Reply-To em domínio diferente: {reply_domain}')

        return min(score, 60), reasons

    def _check_links(self, body: str, html_body: str) -> Tuple[int, List[str]]:
        text_urls = self.URL_PATTERN.findall(f'{body} {html_body}')
        reasons = []
        score = 0

        normalized_urls = []
        for url in text_urls:
            parsed = urlparse(url.rstrip(').,;'))
            host = self._normalize_host(parsed.hostname or '')
            if not host:
                continue
            normalized_urls.append((url, host))

            if host in self.config['shortener_domains']:
                score += 20
                reasons.append(f'Link encurtado: {host}')
            if self._host_is_ip(host):
                score += 35
                reasons.append(f'URL com IP direto: {host}')
            if self._subdomain_depth(host) >= 4:
                score += 18
                reasons.append(f'URL com muitos subdomínios: {host}')

        for match in self.HREF_PATTERN.finditer(html_body):
            href = unescape(match.group('href')).strip()
            label = self._strip_html(unescape(match.group('label'))).strip()
            visible_url = self.URL_PATTERN.search(label)
            if visible_url:
                href_host = self._normalize_host(urlparse(href).hostname or '')
                label_host = self._normalize_host(urlparse(visible_url.group(0)).hostname or '')
                if href_host and label_host and href_host != label_host:
                    score += 35
                    reasons.append(f'Link exibe {label_host}, mas aponta para {href_host}')

        if len(normalized_urls) > 10:
            score += 10
            reasons.append(f'Muitos links no e-mail: {len(normalized_urls)}')

        return min(score, 70), list(dict.fromkeys(reasons))

    def _check_attachments(self, attachments: List[Dict]) -> Tuple[int, List[str]]:
        score = 0
        reasons = []
        blocked = self.config['blocked_attachment_extensions']
        for attachment in attachments:
            filename = self._safe_text(attachment.get('filename', '')).lower()
            for ext in blocked:
                if filename.endswith(ext):
                    score += 45 if ext not in ('.zip', '.rar', '.iso') else 30
                    reasons.append(f'Anexo perigoso: {filename}')
                    break
        return min(score, 70), reasons

    def _check_html_risks(self, html_body: str) -> Tuple[int, List[str]]:
        if not html_body:
            return 0, []
        score = 0
        reasons = []
        lower_html = html_body.lower()
        if '<form' in lower_html:
            score += 35
            reasons.append('HTML contém formulário')
        if '<script' in lower_html or 'javascript:' in lower_html:
            score += 35
            reasons.append('HTML contém script ou javascript')
        return min(score, 60), reasons

    def _check_typosquatting(self, from_domain: str, body: str, html_body: str) -> Tuple[int, List[str]]:
        domains = {from_domain} if from_domain else set()
        for url in self.URL_PATTERN.findall(f'{body} {html_body}'):
            host = self._normalize_host(urlparse(url.rstrip(').,;')).hostname or '')
            if host:
                domains.add(host)

        reasons = []
        score = 0
        for domain in domains:
            registrable = self._registrable_domain(domain)
            raw_domain = re.sub(r'[^a-z0-9]+', '', self._normalize_token(registrable))
            normalized_domain = self._normalize_brand(self._registrable_domain(domain))
            for brand in self.config['sensitive_brands']:
                brand_key = self._normalize_brand(brand)
                if not brand_key or len(brand_key) < 4:
                    continue
                obfuscated_brand = normalized_domain == brand_key and raw_domain != brand_key
                if normalized_domain == brand_key and not obfuscated_brand:
                    continue
                distance = self._levenshtein(normalized_domain, brand_key)
                looks_like = distance <= 1 or (
                    len(brand_key) >= 6 and distance <= 2 and brand_key[0] == normalized_domain[:1]
                )
                contains_brand = brand_key in normalized_domain and normalized_domain != brand_key
                if obfuscated_brand or looks_like or contains_brand:
                    score += 35
                    reasons.append(f'Possível typosquatting: {domain} parecido com {brand}')
                    break

        return min(score, 70), list(dict.fromkeys(reasons))

    def _extract_body_text(self, msg) -> str:
        body = ''
        try:
            if msg.is_multipart():
                for part in msg.walk():
                    if part.get_content_type() == 'text/plain' and 'attachment' not in str(part.get('Content-Disposition', '')):
                        payload = part.get_payload(decode=True)
                        if payload:
                            return payload.decode(part.get_content_charset() or 'utf-8', errors='replace')
            else:
                payload = msg.get_payload(decode=True)
                if payload:
                    body = payload.decode(msg.get_content_charset() or 'utf-8', errors='replace')
        except Exception:
            return ''
        return body

    def _extract_html_body(self, msg) -> str:
        try:
            for part in msg.walk() if msg.is_multipart() else [msg]:
                if part.get_content_type() == 'text/html' and 'attachment' not in str(part.get('Content-Disposition', '')):
                    payload = part.get_payload(decode=True)
                    if payload:
                        return payload.decode(part.get_content_charset() or 'utf-8', errors='replace')
        except Exception:
            return ''
        return ''

    def _extract_attachments(self, msg) -> List[Dict]:
        attachments = []
        try:
            for part in msg.walk():
                filename = part.get_filename()
                disposition = str(part.get('Content-Disposition', '')).lower()
                if filename or 'attachment' in disposition:
                    attachments.append({'filename': filename or '', 'content_type': part.get_content_type()})
        except Exception:
            return []
        return attachments

    def _safe_text(self, value) -> str:
        if value is None:
            return ''
        if isinstance(value, bytes):
            return value.decode('utf-8', errors='replace')
        if isinstance(value, list):
            return ' '.join(self._safe_text(item) for item in value)
        return str(value)[:20000]

    def _normalize_text(self, value: str) -> str:
        return self._safe_text(value).casefold()

    def _normalize_token(self, value: str) -> str:
        return self._safe_text(value).strip().casefold()

    def _normalize_host(self, host: str) -> str:
        return self._normalize_token(host).strip('.')

    def _normalize_brand(self, value: str) -> str:
        text = self._normalize_token(value)
        text = text.replace('0', 'o').replace('1', 'l').replace('3', 'e').replace('5', 's').replace('4', 'a')
        return re.sub(r'[^a-z0-9]+', '', text)

    def _domain_from_email(self, email_address: str) -> str:
        if '@' not in email_address:
            return ''
        return self._normalize_host(email_address.rsplit('@', 1)[1])

    def _registrable_domain(self, host: str) -> str:
        parts = [part for part in self._normalize_host(host).split('.') if part]
        if len(parts) >= 3 and parts[-2] in {'com', 'org', 'net', 'gov'} and len(parts[-1]) == 2:
            return parts[-3]
        if len(parts) >= 2:
            return parts[-2]
        return parts[0] if parts else ''

    def _subdomain_depth(self, host: str) -> int:
        return max(0, len([part for part in host.split('.') if part]) - 2)

    def _host_is_ip(self, host: str) -> bool:
        if not host:
            return False
        try:
            ipaddress.ip_address(host)
            return True
        except ValueError:
            return bool(self.IPV4_HOST_PATTERN.match(host))

    def _strip_html(self, html_text: str) -> str:
        return self.HTML_TAG_PATTERN.sub(' ', self._safe_text(html_text))

    def _levenshtein(self, left: str, right: str) -> int:
        if left == right:
            return 0
        if not left:
            return len(right)
        if not right:
            return len(left)

        previous = list(range(len(right) + 1))
        for i, char_left in enumerate(left, start=1):
            current = [i]
            for j, char_right in enumerate(right, start=1):
                insert_cost = current[j - 1] + 1
                delete_cost = previous[j] + 1
                replace_cost = previous[j - 1] + (char_left != char_right)
                current.append(min(insert_cost, delete_cost, replace_cost))
            previous = current
        return previous[-1]
