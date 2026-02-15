# Módulo de Conexão IMAP/SMTP para Locaweb
# ==========================================

import imaplib
import smtplib
import email
from email.header import decode_header
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import ssl
import re
from typing import List, Dict, Optional
from datetime import datetime


class EmailConnection:
    """Gerencia conexões IMAP/SMTP com servidor Locaweb"""
    
    def __init__(self, email_address: str, password: str,
                 imap_server: str, imap_port: int,
                 smtp_server: str, smtp_port: int):
        self.email_address = email_address
        self.password = password
        self.imap_server = imap_server
        self.imap_port = imap_port
        self.smtp_server = smtp_server
        self.smtp_port = smtp_port
        self.imap_conn = None
        self.smtp_conn = None
    
    def connect(self) -> bool:
        """Estabelece conexão IMAP com SSL"""
        try:
            context = ssl.create_default_context()
            self.imap_conn = imaplib.IMAP4_SSL(
                self.imap_server, 
                self.imap_port,
                ssl_context=context
            )
            self.imap_conn.login(self.email_address, self.password)
            return True
        except Exception as e:
            print(f"Erro na conexão IMAP: {e}")
            self.imap_conn = None
            return False
    
    def disconnect(self):
        """Encerra conexões"""
        if self.imap_conn:
            try:
                self.imap_conn.logout()
            except:
                pass
            self.imap_conn = None
    
    def list_folders(self) -> List[str]:
        """Lista todas as pastas do e-mail"""
        if not self.imap_conn:
            return []
        
        try:
            status, folders = self.imap_conn.list()
            if status != 'OK':
                return []
            
            folder_list = []
            for folder in folders:
                if isinstance(folder, bytes):
                    # Decodifica nome da pasta
                    match = re.search(rb'"([^"]+)"$|(\S+)$', folder)
                    if match:
                        folder_name = match.group(1) or match.group(2)
                        folder_list.append(folder_name.decode('utf-8'))
            
            return folder_list
        except Exception as e:
            print(f"Erro ao listar pastas: {e}")
            return []
    
    def fetch_emails(self, folder: str = 'INBOX', limit: int = 50) -> List[Dict]:
        """Busca e-mails de uma pasta"""
        if not self.imap_conn:
            return []
        
        try:
            status, _ = self.imap_conn.select(folder)
            if status != 'OK':
                return []
            
            # Busca todos os e-mails
            status, messages = self.imap_conn.search(None, 'ALL')
            if status != 'OK':
                return []
            
            email_ids = messages[0].split()
            # Pega os mais recentes primeiro
            email_ids = list(reversed(email_ids[-limit:]))
            
            emails = []
            for email_id in email_ids:
                email_data = self._fetch_email_data(email_id)
                if email_data:
                    emails.append(email_data)
            
            return emails
        except Exception as e:
            print(f"Erro ao buscar e-mails: {e}")
            return []
    
    def _fetch_email_data(self, email_id: bytes) -> Optional[Dict]:
        """Busca dados de um e-mail específico"""
        try:
            status, msg_data = self.imap_conn.fetch(email_id, '(RFC822 FLAGS)')
            if status != 'OK':
                return None
            
            for response_part in msg_data:
                if isinstance(response_part, tuple):
                    msg = email.message_from_bytes(response_part[1])
                    
                    # Decodifica assunto
                    subject = self._decode_header(msg['Subject'])
                    
                    # Decodifica remetente
                    from_addr = self._decode_header(msg['From'])
                    
                    # Data
                    date_str = msg['Date']
                    
                    # Verifica se foi lido
                    flags = response_part[0].decode() if isinstance(response_part[0], bytes) else str(response_part[0])
                    is_read = '\\Seen' in flags
                    
                    # UID
                    uid_match = re.search(rb'UID (\d+)', response_part[0]) if isinstance(response_part[0], bytes) else None
                    uid = uid_match.group(1).decode() if uid_match else email_id.decode()
                    
                    return {
                        'uid': uid,
                        'id': email_id.decode(),
                        'subject': subject or '(Sem assunto)',
                        'from': from_addr or '(Desconhecido)',
                        'date': date_str,
                        'is_read': is_read,
                        'raw_msg': msg
                    }
            return None
        except Exception as e:
            print(f"Erro ao processar e-mail: {e}")
            return None
    
    def fetch_email_by_uid(self, folder: str, uid: str) -> Optional[Dict]:
        """Busca um e-mail específico por UID"""
        if not self.imap_conn:
            return None
        
        try:
            status, _ = self.imap_conn.select(folder)
            if status != 'OK':
                return None
            
            status, msg_data = self.imap_conn.uid('fetch', uid, '(RFC822)')
            if status != 'OK':
                return None
            
            for response_part in msg_data:
                if isinstance(response_part, tuple):
                    msg = email.message_from_bytes(response_part[1])
                    
                    subject = self._decode_header(msg['Subject'])
                    from_addr = self._decode_header(msg['From'])
                    to_addr = self._decode_header(msg['To'])
                    date_str = msg['Date']
                    
                    # Extrai corpo do e-mail
                    body = self._get_email_body(msg)
                    
                    # Headers para análise de spam
                    headers = {
                        'received': msg.get_all('Received', []),
                        'spf': msg.get('Received-SPF', ''),
                        'dkim': msg.get('DKIM-Signature', ''),
                        'reply-to': msg.get('Reply-To', '')
                    }
                    
                    return {
                        'uid': uid,
                        'subject': subject or '(Sem assunto)',
                        'from': from_addr or '(Desconhecido)',
                        'to': to_addr,
                        'date': date_str,
                        'body': body,
                        'headers': headers,
                        'raw_msg': msg
                    }
            return None
        except Exception as e:
            print(f"Erro ao buscar e-mail por UID: {e}")
            return None
    
    def _decode_header(self, header: str) -> str:
        """Decodifica header de e-mail"""
        if not header:
            return ''
        
        try:
            decoded_parts = decode_header(header)
            result = []
            for content, charset in decoded_parts:
                if isinstance(content, bytes):
                    charset = charset or 'utf-8'
                    try:
                        result.append(content.decode(charset))
                    except:
                        result.append(content.decode('utf-8', errors='replace'))
                else:
                    result.append(content)
            return ' '.join(result)
        except:
            return str(header)
    
    def _get_email_body(self, msg) -> str:
        """Extrai corpo do e-mail"""
        body = ''
        
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                content_disposition = str(part.get('Content-Disposition', ''))
                
                if content_type == 'text/plain' and 'attachment' not in content_disposition:
                    try:
                        payload = part.get_payload(decode=True)
                        charset = part.get_content_charset() or 'utf-8'
                        body = payload.decode(charset, errors='replace')
                        break
                    except:
                        pass
                elif content_type == 'text/html' and 'attachment' not in content_disposition and not body:
                    try:
                        payload = part.get_payload(decode=True)
                        charset = part.get_content_charset() or 'utf-8'
                        body = payload.decode(charset, errors='replace')
                    except:
                        pass
        else:
            try:
                payload = msg.get_payload(decode=True)
                charset = msg.get_content_charset() or 'utf-8'
                body = payload.decode(charset, errors='replace')
            except:
                body = str(msg.get_payload())
        
        return body
    
    def get_stats(self) -> Dict:
        """Obtém estatísticas do e-mail"""
        stats = {
            'total': 0,
            'unread': 0,
            'spam': 0,
            'folders': []
        }
        
        if not self.imap_conn:
            return stats
        
        try:
            folders = self.list_folders()
            stats['folders'] = folders
            
            # Conta e-mails na INBOX
            status, _ = self.imap_conn.select('INBOX')
            if status == 'OK':
                status, messages = self.imap_conn.search(None, 'ALL')
                if status == 'OK':
                    stats['total'] = len(messages[0].split())
                
                status, unseen = self.imap_conn.search(None, 'UNSEEN')
                if status == 'OK':
                    stats['unread'] = len(unseen[0].split()) if unseen[0] else 0
            
            # Conta spam se a pasta existir
            if 'Spam' in folders or 'SPAM' in folders or 'Junk' in folders:
                spam_folder = 'Spam' if 'Spam' in folders else ('SPAM' if 'SPAM' in folders else 'Junk')
                status, _ = self.imap_conn.select(spam_folder)
                if status == 'OK':
                    status, messages = self.imap_conn.search(None, 'ALL')
                    if status == 'OK':
                        stats['spam'] = len(messages[0].split()) if messages[0] else 0
            
            return stats
        except Exception as e:
            print(f"Erro ao obter estatísticas: {e}")
            return stats
    
    def create_folder(self, folder_name: str) -> bool:
        """Cria uma nova pasta"""
        if not self.imap_conn:
            return False
        
        try:
            status, _ = self.imap_conn.create(folder_name)
            return status == 'OK'
        except Exception as e:
            print(f"Erro ao criar pasta: {e}")
            return False
    
    def delete_folder(self, folder_name: str) -> bool:
        """Deleta uma pasta"""
        if not self.imap_conn:
            return False
        
        try:
            status, _ = self.imap_conn.delete(folder_name)
            return status == 'OK'
        except Exception as e:
            print(f"Erro ao deletar pasta: {e}")
            return False
    
    def move_email(self, uid: str, from_folder: str, to_folder: str) -> bool:
        """Move um e-mail de uma pasta para outra"""
        if not self.imap_conn:
            return False
        
        try:
            self.imap_conn.select(from_folder)
            # Copia para a pasta destino
            status, _ = self.imap_conn.uid('copy', uid, to_folder)
            if status == 'OK':
                # Marca para deleção na pasta original
                self.imap_conn.uid('store', uid, '+FLAGS', '\\Deleted')
                self.imap_conn.expunge()
                return True
            return False
        except Exception as e:
            print(f"Erro ao mover e-mail: {e}")
            return False
    
    def move_to_trash(self, uid: str, from_folder: str = 'INBOX') -> bool:
        """Move e-mail para a lixeira"""
        trash_folders = ['Trash', 'Lixeira', 'Deleted', 'Deleted Items']
        folders = self.list_folders()
        
        trash_folder = None
        for tf in trash_folders:
            if tf in folders:
                trash_folder = tf
                break
        
        if trash_folder:
            return self.move_email(uid, from_folder, trash_folder)
        else:
            # Se não encontrar lixeira, marca para deleção
            try:
                self.imap_conn.select(from_folder)
                self.imap_conn.uid('store', uid, '+FLAGS', '\\Deleted')
                self.imap_conn.expunge()
                return True
            except:
                return False
    
    def set_read_status(self, uid: str, folder: str = 'INBOX', is_read: bool = True) -> bool:
        """Marca e-mail como lido ou não lido"""
        if not self.imap_conn:
            return False

        try:
            self.imap_conn.select(folder)
            flag_action = '+FLAGS' if is_read else '-FLAGS'
            status, _ = self.imap_conn.uid('store', uid, flag_action, '\\Seen')
            return status == 'OK'
        except Exception as e:
            print(f"Erro ao atualizar status de leitura: {e}")
            return False

    def archive_email(self, uid: str, from_folder: str = 'INBOX') -> bool:
        """Move e-mail para a pasta de arquivo"""
        if not self.imap_conn:
            return False

        folders = self.list_folders()
        archive_candidates = [
            'Archive',
            'Arquivo',
            'All Mail',
            'INBOX.Archive',
            'Arquivados'
        ]

        archive_folder = None
        for candidate in archive_candidates:
            if candidate in folders:
                archive_folder = candidate
                break

        if not archive_folder:
            # Tenta criar uma pasta de arquivo padrão se não existir
            if self.create_folder('Archive'):
                archive_folder = 'Archive'
            else:
                return False

        return self.move_email(uid, from_folder, archive_folder)

    def send_email(
        self,
        to: str,
        subject: str,
        body: str,
        html: bool = False,
        cc: Optional[List[str]] = None,
        bcc: Optional[List[str]] = None,
        reply_to: Optional[str] = None
    ) -> bool:
        """Envia um e-mail via SMTP"""
        try:
            to_list = [item.strip() for item in (to or '').split(',') if item.strip()]
            cc_list = [item.strip() for item in (cc or []) if item.strip()]
            bcc_list = [item.strip() for item in (bcc or []) if item.strip()]
            recipients = to_list + cc_list + bcc_list

            if not recipients:
                return False

            context = ssl.create_default_context()
            
            with smtplib.SMTP_SSL(self.smtp_server, self.smtp_port, context=context) as server:
                server.login(self.email_address, self.password)
                
                msg = MIMEMultipart('alternative')
                msg['From'] = self.email_address
                msg['To'] = ', '.join(to_list)
                msg['Subject'] = subject
                if cc_list:
                    msg['Cc'] = ', '.join(cc_list)
                if reply_to:
                    msg['Reply-To'] = reply_to
                
                if html:
                    msg.attach(MIMEText(body, 'html'))
                else:
                    msg.attach(MIMEText(body, 'plain'))
                
                server.send_message(msg, to_addrs=recipients)
                return True
        except Exception as e:
            print(f"Erro ao enviar e-mail: {e}")
            return False
