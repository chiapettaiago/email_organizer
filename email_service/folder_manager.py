# Gerenciador de Pastas de E-mail
# ================================

from typing import Dict, List, Optional
from config import DEFAULT_FOLDERS, ORGANIZATION_RULES
from email_service.spam_detector import SpamDetector


class FolderManager:
    """Gerencia pastas e organização automática de e-mails"""
    
    def __init__(self, email_connection):
        self.conn = email_connection
        self.spam_detector = SpamDetector()
    
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
        emails = self.conn.fetch_emails('INBOX', limit=100, include_body=True)
        
        for email_data in emails:
            try:
                uid = email_data.get('uid', email_data.get('id', ''))
                
                # Primeiro verifica spam/fraude
                analysis = self.spam_detector.analyze(email_data)
                
                if analysis['is_fraud']:
                    # Move para pasta de Fraude
                    if self.conn.move_email(uid, 'INBOX', 'Fraude'):
                        results['fraud_detected'] += 1
                        results['moved'] += 1
                        results['details'].append({
                            'uid': uid,
                            'subject': email_data.get('subject', ''),
                            'action': 'Movido para Fraude',
                            'reason': ', '.join(analysis['reasons'][:2])
                        })
                    continue
                
                if analysis['is_spam']:
                    # Move para pasta de Spam
                    if self.conn.move_email(uid, 'INBOX', 'Spam'):
                        results['spam_detected'] += 1
                        results['moved'] += 1
                        results['details'].append({
                            'uid': uid,
                            'subject': email_data.get('subject', ''),
                            'action': 'Movido para Spam',
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
