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
import socket
from typing import List, Dict, Optional


class EmailConnection:
    """Gerencia conexões IMAP/SMTP com servidor Locaweb"""

    TRASH_FOLDER_CANDIDATES = ('Trash', 'Lixeira', 'Deleted', 'Deleted Items')
    ARCHIVE_FOLDER_CANDIDATES = (
        'Archive',
        'Arquivo',
        'All Mail',
        'INBOX.Archive',
        'Arquivados'
    )
    UID_PATTERN = re.compile(rb'UID (\d+)')

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
        self._folders_cache = None
        self._trash_folder_cache = None
        self._archive_folder_cache = None
        self._selected_folder = None
        self._selected_readonly = None
        self._selected_message_count = 0
        self.last_error = ''

    def connect(self) -> bool:
        """Estabelece conexão IMAP com SSL"""
        self.last_error = ''
        try:
            context = ssl.create_default_context()
            self.imap_conn = imaplib.IMAP4_SSL(
                self.imap_server, 
                self.imap_port,
                ssl_context=context,
                timeout=15
            )
            self.imap_conn.login(self.email_address, self.password)
            return True
        except imaplib.IMAP4.error as e:
            self.last_error = (
                'Credenciais recusadas pelo servidor de e-mail. '
                'Confira a senha da caixa, se o IMAP está habilitado e se o provedor exige o e-mail completo como usuário.'
            )
            print(f"Erro na autenticação IMAP: {e}")
            self.imap_conn = None
            return False
        except socket.gaierror as e:
            self.last_error = 'Não foi possível resolver o servidor IMAP. Verifique a rede e o servidor configurado.'
            print(f"Erro de DNS na conexão IMAP: {e}")
            self.imap_conn = None
            return False
        except (socket.timeout, TimeoutError) as e:
            self.last_error = 'Tempo esgotado ao conectar no servidor IMAP.'
            print(f"Timeout na conexão IMAP: {e}")
            self.imap_conn = None
            return False
        except ssl.SSLError as e:
            self.last_error = 'Falha SSL/TLS ao conectar no servidor IMAP.'
            print(f"Erro SSL na conexão IMAP: {e}")
            self.imap_conn = None
            return False
        except Exception as e:
            self.last_error = f'Falha ao conectar no servidor IMAP: {e}'
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
        self._invalidate_folder_cache()
        self._selected_folder = None
        self._selected_readonly = None
        self._selected_message_count = 0

    def _invalidate_folder_cache(self):
        """Limpa caches locais de pastas"""
        self._folders_cache = None
        self._trash_folder_cache = None
        self._archive_folder_cache = None

    def _ensure_selected(self, folder: str, readonly: bool = False) -> bool:
        """Seleciona pasta apenas quando necessário"""
        if not self.imap_conn:
            return False

        if self._selected_folder == folder and self._selected_readonly == readonly:
            return True

        try:
            status, data = self.imap_conn.select(folder, readonly=readonly)
            if status != 'OK':
                return False

            self._selected_folder = folder
            self._selected_readonly = readonly
            self._selected_message_count = self._parse_message_count(data)
            return True
        except Exception as e:
            print(f"Erro ao selecionar pasta {folder}: {e}")
            return False

    def _parse_message_count(self, select_data) -> int:
        """Extrai total de mensagens do retorno de select"""
        if not select_data:
            return 0

        raw_total = select_data[0]
        if isinstance(raw_total, bytes):
            raw_total = raw_total.decode('utf-8', errors='ignore')
        try:
            return int(raw_total)
        except (TypeError, ValueError):
            return 0

    def list_folders(self, force_refresh: bool = False) -> List[str]:
        """Lista todas as pastas do e-mail"""
        if not self.imap_conn:
            return []

        if self._folders_cache is not None and not force_refresh:
            return list(self._folders_cache)

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
                        folder_list.append(folder_name.decode('utf-8', errors='replace'))

            self._folders_cache = folder_list
            return list(folder_list)
        except Exception as e:
            print(f"Erro ao listar pastas: {e}")
            return []

    def _resolve_trash_folder(self) -> Optional[str]:
        """Resolve e cacheia a pasta de lixeira"""
        if self._trash_folder_cache is not None:
            return self._trash_folder_cache

        folders = set(self.list_folders())
        for candidate in self.TRASH_FOLDER_CANDIDATES:
            if candidate in folders:
                self._trash_folder_cache = candidate
                return candidate

        self._trash_folder_cache = None
        return None

    def _resolve_archive_folder(self) -> Optional[str]:
        """Resolve e cacheia a pasta de arquivo"""
        if self._archive_folder_cache is not None:
            return self._archive_folder_cache

        folders = set(self.list_folders())
        for candidate in self.ARCHIVE_FOLDER_CANDIDATES:
            if candidate in folders:
                self._archive_folder_cache = candidate
                return candidate

        # Tenta criar uma pasta padrão para arquivamento
        if self.create_folder('Archive'):
            self._archive_folder_cache = 'Archive'
            return 'Archive'

        return None

    def fetch_emails(self, folder: str = 'INBOX', limit: Optional[int] = 50, include_body: bool = False) -> List[Dict]:
        """Busca e-mails de uma pasta"""
        if not self.imap_conn:
            return []
        if limit is not None and limit <= 0:
            return []

        try:
            if not self._ensure_selected(folder, readonly=True):
                return []

            total = self._selected_message_count
            if total <= 0:
                return []

            start = 1 if limit is None else max(1, total - limit + 1)
            fetch_query = '(UID FLAGS RFC822)' if include_body else '(UID FLAGS RFC822.HEADER)'

            emails = []
            for sequence_num in range(total, start - 1, -1):
                email_data = self._fetch_email_data(str(sequence_num), fetch_query, include_body=include_body)
                if email_data:
                    emails.append(email_data)

            return emails
        except Exception as e:
            print(f"Erro ao buscar e-mails: {e}")
            return []

    def _fetch_email_data(self, sequence_id: str, fetch_query: str, include_body: bool = False) -> Optional[Dict]:
        """Busca dados de um e-mail específico"""
        try:
            status, msg_data = self.imap_conn.fetch(sequence_id, fetch_query)
            if status != 'OK':
                return None

            for response_part in msg_data:
                if isinstance(response_part, tuple):
                    raw_meta = response_part[0]
                    msg = email.message_from_bytes(response_part[1])

                    # Decodifica assunto
                    subject = self._decode_header(msg['Subject'])

                    # Decodifica remetente
                    from_addr = self._decode_header(msg['From'])

                    # Data
                    date_str = msg['Date']

                    # Verifica se foi lido
                    flags = raw_meta.decode(errors='ignore') if isinstance(raw_meta, bytes) else str(raw_meta)
                    is_read = '\\Seen' in flags

                    # UID
                    uid = sequence_id
                    if isinstance(raw_meta, bytes):
                        uid_match = self.UID_PATTERN.search(raw_meta)
                        if uid_match:
                            uid = uid_match.group(1).decode('utf-8', errors='ignore')

                    data = {
                        'uid': uid,
                        'id': sequence_id,
                        'subject': subject or '(Sem assunto)',
                        'from': from_addr or '(Desconhecido)',
                        'date': date_str,
                        'is_read': is_read
                    }

                    if include_body:
                        data['body'] = self._get_email_body(msg)
                        data['html_body'] = self._get_email_html_body(msg)
                        data['attachments'] = self._get_attachments(msg)
                        data['headers'] = {
                            'received': msg.get_all('Received', []),
                            'authentication-results': msg.get('Authentication-Results', ''),
                            'received-spf': msg.get('Received-SPF', ''),
                            'spf': msg.get('Received-SPF', ''),
                            'dkim': msg.get('DKIM-Signature', ''),
                            'dmarc': msg.get('DMARC-Filter', ''),
                            'reply-to': msg.get('Reply-To', '')
                        }

                    return data
            return None
        except Exception as e:
            print(f"Erro ao processar e-mail: {e}")
            return None

    def fetch_email_by_uid(self, folder: str, uid: str) -> Optional[Dict]:
        """Busca um e-mail específico por UID"""
        if not self.imap_conn:
            return None

        try:
            if not self._ensure_selected(folder, readonly=True):
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
                    html_body = self._get_email_html_body(msg)
                    attachments = self._get_attachments(msg)

                    # Headers para análise de spam
                    headers = {
                        'received': msg.get_all('Received', []),
                        'authentication-results': msg.get('Authentication-Results', ''),
                        'received-spf': msg.get('Received-SPF', ''),
                        'spf': msg.get('Received-SPF', ''),
                        'dkim': msg.get('DKIM-Signature', ''),
                        'dmarc': msg.get('DMARC-Filter', ''),
                        'reply-to': msg.get('Reply-To', '')
                    }

                    return {
                        'uid': uid,
                        'subject': subject or '(Sem assunto)',
                        'from': from_addr or '(Desconhecido)',
                        'to': to_addr,
                        'date': date_str,
                        'body': body,
                        'html_body': html_body,
                        'attachments': attachments,
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

    def _get_email_html_body(self, msg) -> str:
        """Extrai corpo HTML do e-mail quando disponível."""
        if not msg:
            return ''

        try:
            parts = msg.walk() if msg.is_multipart() else [msg]
            for part in parts:
                content_type = part.get_content_type()
                content_disposition = str(part.get('Content-Disposition', ''))

                if content_type == 'text/html' and 'attachment' not in content_disposition:
                    payload = part.get_payload(decode=True)
                    if not payload:
                        continue
                    charset = part.get_content_charset() or 'utf-8'
                    return payload.decode(charset, errors='replace')
        except Exception:
            return ''

        return ''

    def _get_attachments(self, msg) -> List[Dict]:
        """Lista anexos sem carregar conteúdo para a lógica de risco."""
        attachments = []
        if not msg:
            return attachments

        try:
            for part in msg.walk():
                filename = self._decode_header(part.get_filename() or '')
                disposition = str(part.get('Content-Disposition', '')).lower()
                if filename or 'attachment' in disposition:
                    attachments.append({
                        'filename': filename,
                        'content_type': part.get_content_type(),
                    })
        except Exception as e:
            print(f"Erro ao listar anexos: {e}")

        return attachments

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
            if self._ensure_selected('INBOX', readonly=True):
                status, messages = self.imap_conn.search(None, 'ALL')
                if status == 'OK':
                    stats['total'] = len(messages[0].split())

                status, unseen = self.imap_conn.search(None, 'UNSEEN')
                if status == 'OK':
                    stats['unread'] = len(unseen[0].split()) if unseen[0] else 0

            # Conta spam se a pasta existir
            if 'Spam' in folders or 'SPAM' in folders or 'Junk' in folders:
                spam_folder = 'Spam' if 'Spam' in folders else ('SPAM' if 'SPAM' in folders else 'Junk')
                if self._ensure_selected(spam_folder, readonly=True):
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
            if status == 'OK':
                self._invalidate_folder_cache()
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
            if status == 'OK':
                self._invalidate_folder_cache()
            return status == 'OK'
        except Exception as e:
            print(f"Erro ao deletar pasta: {e}")
            return False

    def move_email(self, uid: str, from_folder: str, to_folder: str, expunge: bool = True) -> bool:
        """Move um e-mail de uma pasta para outra"""
        if not self.imap_conn:
            return False

        try:
            if not self._ensure_selected(from_folder, readonly=False):
                return False

            # Copia para a pasta destino
            status, _ = self.imap_conn.uid('copy', uid, to_folder)
            if status == 'OK':
                # Marca para deleção na pasta original
                self.imap_conn.uid('store', uid, '+FLAGS', '\\Deleted')
                if expunge:
                    self.imap_conn.expunge()
                return True
            return False
        except Exception as e:
            print(f"Erro ao mover e-mail: {e}")
            return False

    def move_emails(self, uids: List[str], from_folder: str, to_folder: str, expunge: bool = True) -> bool:
        """Move múltiplos e-mails de uma pasta para outra"""
        if not self.imap_conn or not uids:
            return False

        try:
            if not self._ensure_selected(from_folder, readonly=False):
                return False

            uid_set = ','.join(dict.fromkeys(str(uid) for uid in uids if uid))
            if not uid_set:
                return False

            status, _ = self.imap_conn.uid('copy', uid_set, to_folder)
            if status != 'OK':
                return False

            status, _ = self.imap_conn.uid('store', uid_set, '+FLAGS', '\\Deleted')
            if status != 'OK':
                return False

            if expunge:
                self.imap_conn.expunge()

            return True
        except Exception as e:
            print(f"Erro ao mover e-mails em lote: {e}")
            return False

    def move_to_trash(self, uid: str, from_folder: str = 'INBOX', expunge: bool = True) -> bool:
        """Move e-mail para a lixeira"""
        trash_folder = self._resolve_trash_folder()

        if trash_folder:
            return self.move_email(uid, from_folder, trash_folder, expunge=expunge)

        # Se não encontrar lixeira, marca para deleção na própria pasta
        try:
            if not self._ensure_selected(from_folder, readonly=False):
                return False
            self.imap_conn.uid('store', uid, '+FLAGS', '\\Deleted')
            if expunge:
                self.imap_conn.expunge()
            return True
        except Exception:
            return False

    def move_to_trash_bulk(self, uids: List[str], from_folder: str = 'INBOX', expunge: bool = True) -> bool:
        """Move múltiplos e-mails para lixeira"""
        if not uids:
            return False

        trash_folder = self._resolve_trash_folder()
        if trash_folder:
            return self.move_emails(uids, from_folder, trash_folder, expunge=expunge)

        try:
            if not self._ensure_selected(from_folder, readonly=False):
                return False
            uid_set = ','.join(dict.fromkeys(str(uid) for uid in uids if uid))
            if not uid_set:
                return False
            status, _ = self.imap_conn.uid('store', uid_set, '+FLAGS', '\\Deleted')
            if status != 'OK':
                return False
            if expunge:
                self.imap_conn.expunge()
            return True
        except Exception:
            return False

    def set_read_status(self, uid: str, folder: str = 'INBOX', is_read: bool = True) -> bool:
        """Marca e-mail como lido ou não lido"""
        if not self.imap_conn:
            return False

        try:
            if not self._ensure_selected(folder, readonly=False):
                return False
            flag_action = '+FLAGS' if is_read else '-FLAGS'
            status, _ = self.imap_conn.uid('store', uid, flag_action, '\\Seen')
            return status == 'OK'
        except Exception as e:
            print(f"Erro ao atualizar status de leitura: {e}")
            return False

    def set_read_status_bulk(self, uids: List[str], folder: str = 'INBOX', is_read: bool = True) -> bool:
        """Marca múltiplos e-mails como lidos ou não lidos"""
        if not self.imap_conn or not uids:
            return False

        try:
            if not self._ensure_selected(folder, readonly=False):
                return False

            uid_set = ','.join(dict.fromkeys(str(uid) for uid in uids if uid))
            if not uid_set:
                return False

            flag_action = '+FLAGS' if is_read else '-FLAGS'
            status, _ = self.imap_conn.uid('store', uid_set, flag_action, '\\Seen')
            return status == 'OK'
        except Exception as e:
            print(f"Erro ao atualizar status de leitura em lote: {e}")
            return False

    def archive_email(self, uid: str, from_folder: str = 'INBOX', expunge: bool = True) -> bool:
        """Move e-mail para a pasta de arquivo"""
        if not self.imap_conn:
            return False

        archive_folder = self._resolve_archive_folder()
        if not archive_folder:
            return False

        return self.move_email(uid, from_folder, archive_folder, expunge=expunge)

    def archive_emails_bulk(self, uids: List[str], from_folder: str = 'INBOX', expunge: bool = True) -> bool:
        """Move múltiplos e-mails para a pasta de arquivo"""
        if not self.imap_conn or not uids:
            return False

        archive_folder = self._resolve_archive_folder()
        if not archive_folder:
            return False

        return self.move_emails(uids, from_folder, archive_folder, expunge=expunge)

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
