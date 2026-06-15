# Gerenciador de Pastas de E-mail
# ================================

import json
import os
from datetime import datetime
from typing import Dict, List, Optional
from config import DEFAULT_FOLDERS, FRAUD_RISK_CONFIG, ORGANIZATION_RULES
from email_service.spam_detector import SpamDetector


class FolderManager:
    """Gerencia pastas e organização automática de e-mails"""
    
    def __init__(self, email_connection, risk_config: Optional[Dict] = None):
        self.conn = email_connection
        self.risk_config = self._merge_risk_config(risk_config or {})
        self.spam_detector = SpamDetector(risk_config=self.risk_config)
    
    def ensure_default_folders(self) -> Dict:
        """Cria pastas padrão se não existirem"""
        results = {'created': [], 'existing': [], 'errors': []}
        
        if not self.conn or not self.conn.imap_conn:
            return results
        
        existing_folders = self.conn.list_folders()
        
        for folder in DEFAULT_FOLDERS:
            if folder in existing_folders:
                results['existing'].append(folder)
            else:
                if self.conn.create_folder(folder):
                    results['created'].append(folder)
                else:
                    results['errors'].append(folder)
        
        return results

    def _merge_risk_config(self, risk_config: Dict) -> Dict:
        merged = dict(FRAUD_RISK_CONFIG)
        if isinstance(risk_config, dict):
            merged.update({key: value for key, value in risk_config.items() if value is not None})
        return merged

    def ensure_quarantine_folder(self) -> bool:
        """Garante a pasta de quarentena, criando pai/filho quando o IMAP exigir."""
        quarantine_folder = self.risk_config.get('quarantine_folder', 'Quarentena/Fraude')
        if not self.conn or not self.conn.imap_conn:
            return False

        existing = set(self.conn.list_folders())
        if quarantine_folder in existing:
            return True

        parts = [part for part in quarantine_folder.split('/') if part]
        current = ''
        for part in parts:
            current = part if not current else f'{current}/{part}'
            if current not in existing:
                self.conn.create_folder(current)
                existing = set(self.conn.list_folders(force_refresh=True))

        return quarantine_folder in existing

    def apply_risk_action(self, email_data: Dict, analysis: Dict, source_folder: str = 'INBOX') -> Dict:
        """Executa keep/quarentena/delete de forma rastreável e respeitando dry-run."""
        uid = email_data.get('uid', email_data.get('id', ''))
        score = int(analysis.get('score', 0))
        action = self.spam_detector.recommended_action(score)
        dry_run = bool(self.risk_config.get('dry_run', True))
        quarantine_enabled = bool(self.risk_config.get('quarantine_enabled', True))
        quarantine_folder = self.risk_config.get('quarantine_folder', 'Quarentena/Fraude')
        success = True
        error = ''

        if action == 'quarantine' and not quarantine_enabled:
            action = 'keep'

        if not dry_run and uid:
            try:
                if action == 'delete':
                    # Exclusão automática ainda passa pela lixeira do servidor.
                    success = self.conn.move_to_trash(uid, source_folder)
                elif action == 'quarantine':
                    self.ensure_quarantine_folder()
                    success = self.conn.move_email(uid, source_folder, quarantine_folder)
            except Exception as exc:
                success = False
                error = str(exc)

        if dry_run and action in {'delete', 'quarantine'}:
            logged_action = f'dry-run:{action}'
        else:
            logged_action = action

        decision = {
            'timestamp': datetime.now().isoformat(),
            'event': 'action',
            'account': getattr(self.conn, 'email_address', ''),
            'uid': uid,
            'from': email_data.get('from', ''),
            'subject': email_data.get('subject', ''),
            'score': score,
            'classification': analysis.get('classification', ''),
            'rules': analysis.get('rules', analysis.get('reasons', [])),
            'action': logged_action,
            'success': success,
            'error': error,
        }
        self.log_risk_decision(decision)
        return decision

    def log_analysis_event(self, event: str, email_data: Dict, analysis: Dict, extra: Optional[Dict] = None):
        """Registra etapas de análise e detecção além da ação tomada."""
        entry = {
            'timestamp': datetime.now().isoformat(),
            'event': event,
            'account': getattr(self.conn, 'email_address', ''),
            'uid': email_data.get('uid', email_data.get('id', '')),
            'from': email_data.get('from', ''),
            'subject': email_data.get('subject', ''),
            'score': int(analysis.get('score', 0)),
            'classification': analysis.get('classification', ''),
            'rules': analysis.get('rules', analysis.get('reasons', [])),
            'action': extra.get('action', '') if isinstance(extra, dict) else '',
            'success': extra.get('success', True) if isinstance(extra, dict) else True,
            'error': extra.get('error', '') if isinstance(extra, dict) else '',
        }
        self.log_risk_decision(entry)

    def log_risk_decision(self, decision: Dict):
        """Registra decisão em JSONL para auditoria e resposta a incidentes."""
        log_file = self.risk_config.get('log_file') or 'logs/fraud_decisions.jsonl'
        log_dir = os.path.dirname(log_file)
        try:
            if log_dir:
                os.makedirs(log_dir, exist_ok=True)
            with open(log_file, 'a', encoding='utf-8') as log_handle:
                log_handle.write(json.dumps(decision, ensure_ascii=False) + '\n')
        except OSError as exc:
            print(f"Erro ao registrar decisão de risco: {exc}")

    def process_inbox_risk(self, limit: Optional[int] = None) -> Dict:
        """Analisa a INBOX e aplica a política de risco configurada."""
        results = {
            'scanned': 0,
            'safe': 0,
            'suspect': 0,
            'fraud': 0,
            'kept': 0,
            'quarantined': 0,
            'deleted': 0,
            'would_quarantine': 0,
            'would_delete': 0,
            'dry_run': bool(self.risk_config.get('dry_run', True)),
            'items': [],
            'errors': []
        }

        if not self.conn or not self.conn.imap_conn:
            return results

        emails = self.conn.fetch_emails('INBOX', limit=limit, include_body=True)
        results['scanned'] = len(emails)

        for email_data in emails:
            try:
                analysis = self.spam_detector.analyze(email_data)
                self.log_analysis_event('analysis', email_data, analysis)
                classification = analysis.get('classification', 'seguro')
                if classification == 'fraude':
                    results['fraud'] += 1
                elif classification == 'suspeito':
                    results['suspect'] += 1
                else:
                    results['safe'] += 1

                if classification in ('suspeito', 'fraude'):
                    self.log_analysis_event('detection', email_data, analysis)

                decision = self.apply_risk_action(email_data, analysis)
                is_dry_run_action = decision['action'].startswith('dry-run:')
                action = decision['action'].replace('dry-run:', '')
                if action == 'delete':
                    if is_dry_run_action:
                        results['would_delete'] += 1
                    else:
                        results['deleted'] += 1
                elif action == 'quarantine':
                    if is_dry_run_action:
                        results['would_quarantine'] += 1
                    else:
                        results['quarantined'] += 1
                else:
                    results['kept'] += 1

                results['items'].append({
                    'uid': decision['uid'],
                    'subject': decision['subject'],
                    'from': decision['from'],
                    'score': decision['score'],
                    'classification': decision['classification'],
                    'action': decision['action'],
                    'reasons': decision['rules'],
                    'success': decision['success'],
                })
            except Exception as exc:
                results['errors'].append(str(exc))

        return results
    
    def auto_organize(self) -> Dict:
        """Organiza e-mails automaticamente baseado em regras"""
        results = {
            'moved': 0,
            'spam_detected': 0,
            'fraud_detected': 0,
            'errors': [],
            'details': []
        }
        
        if not self.conn or not self.conn.imap_conn:
            return results
        
        # Busca e-mails da INBOX
        emails = self.conn.fetch_emails('INBOX', limit=None, include_body=True)
        
        for email_data in emails:
            try:
                uid = email_data.get('uid', email_data.get('id', ''))
                
                # Primeiro verifica spam/fraude
                analysis = self.spam_detector.analyze(email_data)
                
                if analysis['is_fraud']:
                    decision = self.apply_risk_action(email_data, analysis)
                    if decision['success']:
                        results['fraud_detected'] += 1
                        if not decision['action'].startswith('dry-run:') and decision['action'] != 'keep':
                            results['moved'] += 1
                        results['details'].append({
                            'uid': uid,
                            'subject': email_data.get('subject', ''),
                            'action': decision['action'],
                            'reason': ', '.join(analysis['reasons'][:2])
                        })
                    continue
                
                if analysis['is_spam']:
                    decision = self.apply_risk_action(email_data, analysis)
                    if decision['success']:
                        results['spam_detected'] += 1
                        if not decision['action'].startswith('dry-run:') and decision['action'] != 'keep':
                            results['moved'] += 1
                        results['details'].append({
                            'uid': uid,
                            'subject': email_data.get('subject', ''),
                            'action': decision['action'],
                            'reason': f"Score: {analysis['score']}"
                        })
                    continue
                
                # Aplica regras de organização
                target_folder = self._apply_rules(email_data)
                if target_folder and target_folder != 'INBOX':
                    if self.conn.move_email(uid, 'INBOX', target_folder):
                        results['moved'] += 1
                        results['details'].append({
                            'uid': uid,
                            'subject': email_data.get('subject', ''),
                            'action': f'Movido para {target_folder}',
                            'reason': 'Regra de organização'
                        })
                
            except Exception as e:
                results['errors'].append(str(e))
        
        return results
    
    def _apply_rules(self, email_data: Dict) -> Optional[str]:
        """Aplica regras de organização e retorna pasta destino"""
        from_addr = email_data.get('from', '').lower()
        subject = email_data.get('subject', '').lower()
        
        for rule in ORGANIZATION_RULES:
            conditions = rule.get('conditions', {})
            matches = True
            
            # Verifica condições de remetente
            if 'from_contains' in conditions:
                from_match = any(term in from_addr for term in conditions['from_contains'])
                if not from_match:
                    matches = False
            
            if 'from_domain' in conditions and conditions['from_domain']:
                domain_match = any(domain in from_addr for domain in conditions['from_domain'])
                if not domain_match:
                    matches = False
            
            # Verifica condições de assunto
            if 'subject_contains' in conditions:
                subject_match = any(term in subject for term in conditions['subject_contains'])
                if not subject_match:
                    matches = False
            
            if matches and any(conditions.values()):  # Pelo menos uma condição deve existir
                return rule.get('folder')
        
        return None
    
    def move_selected_to_folder(self, uids: List[str], target_folder: str) -> Dict:
        """Move e-mails selecionados para uma pasta"""
        results = {'moved': 0, 'errors': []}
        
        if not self.conn or not self.conn.imap_conn:
            return results
        
        for uid in uids:
            try:
                if self.conn.move_email(uid, 'INBOX', target_folder):
                    results['moved'] += 1
            except Exception as e:
                results['errors'].append(f"UID {uid}: {str(e)}")
        
        return results
    
    def delete_spam_and_fraud(self, permanent: bool = False) -> Dict:
        """Remove e-mails das pastas Spam e Fraude"""
        results = {'deleted': 0, 'errors': []}
        
        if not self.conn or not self.conn.imap_conn:
            return results
        
        folders_to_clean = ['Spam', 'Fraude']
        
        for folder in folders_to_clean:
            try:
                emails = self.conn.fetch_emails(folder, limit=500)
                
                uids = [email_data.get('uid', email_data.get('id', '')) for email_data in emails]
                uids = [uid for uid in uids if uid]

                if not uids:
                    continue

                if permanent:
                    # Deleta permanentemente em lote
                    self.conn.imap_conn.select(folder)
                    uid_set = ','.join(dict.fromkeys(uids))
                    status, _ = self.conn.imap_conn.uid('store', uid_set, '+FLAGS', '\\Deleted')
                    if status == 'OK':
                        results['deleted'] += len(uids)
                    else:
                        results['errors'].append(f"Erro ao marcar exclusão em {folder}")
                else:
                    # Move todos para lixeira em lote
                    if self.conn.move_to_trash_bulk(uids, folder):
                        results['deleted'] += len(uids)
                    else:
                        for uid in uids:
                            try:
                                if self.conn.move_to_trash(uid, folder):
                                    results['deleted'] += 1
                            except Exception as e:
                                results['errors'].append(f"{folder}/{uid}: {str(e)}")
                
                if permanent:
                    self.conn.imap_conn.expunge()
                    
            except Exception as e:
                results['errors'].append(f"Erro ao processar {folder}: {str(e)}")
        
        return results
    
    def get_folder_stats(self) -> List[Dict]:
        """Retorna estatísticas de todas as pastas"""
        stats = []
        
        if not self.conn or not self.conn.imap_conn:
            return stats
        
        folders = self.conn.list_folders()
        
        for folder in folders:
            try:
                status, _ = self.conn.imap_conn.select(folder, readonly=True)
                if status == 'OK':
                    status, messages = self.conn.imap_conn.search(None, 'ALL')
                    total = len(messages[0].split()) if messages[0] else 0
                    
                    status, unseen = self.conn.imap_conn.search(None, 'UNSEEN')
                    unread = len(unseen[0].split()) if unseen[0] else 0
                    
                    stats.append({
                        'name': folder,
                        'total': total,
                        'unread': unread
                    })
            except:
                stats.append({'name': folder, 'total': 0, 'unread': 0})
        
        return stats
