import os
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(__file__))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from email_service.folder_manager import FolderManager
from email_service.spam_detector import SpamDetector


def test_config(**overrides):
    config = {
        'safe_threshold': 35,
        'quarantine_threshold': 55,
        'delete_threshold': 90,
        'dry_run': True,
        'quarantine_enabled': True,
        'quarantine_folder': 'Quarentena/Fraude',
        'log_file': os.path.join(tempfile.gettempdir(), 'fraud-decisions-test.jsonl'),
        'allowed_domains': ['empresa.com.br'],
        'trusted_senders': ['diretoria@empresa.com.br'],
        'blocked_domains': ['evil.example'],
        'blocked_attachment_extensions': ['.exe', '.scr', '.bat', '.cmd', '.js', '.vbs', '.jar', '.zip', '.rar', '.iso'],
        'suspicious_keywords': ['senha', 'pix', 'boleto', 'bloqueio', 'nota fiscal'],
        'sensitive_brands': ['microsoft', 'google', 'nubank', 'receita', 'correios', 'mercado pago'],
        'shortener_domains': ['bit.ly', 'tinyurl.com'],
    }
    config.update(overrides)
    return config


class SpamDetectorTest(unittest.TestCase):
    def setUp(self):
        self.detector = SpamDetector(risk_config=test_config())

    def test_legitimate_email_is_safe(self):
        result = self.detector.analyze({
            'from': 'Diretoria <diretoria@empresa.com.br>',
            'subject': 'Ata da reunião',
            'body': 'Segue a ata da reunião de hoje.',
            'headers': {'authentication-results': 'spf=pass dkim=pass dmarc=pass'},
        })

        self.assertEqual(result['classification'], 'seguro')
        self.assertLess(result['score'], 55)

    def test_phishing_with_mismatched_link_is_fraud(self):
        result = self.detector.analyze({
            'from': 'Microsoft Segurança <alerta@micros0ft-login.com>',
            'subject': 'Senha bloqueada - atualização urgente',
            'html_body': '<a href="https://evil.example/login">https://microsoft.com/login</a>',
            'headers': {'authentication-results': 'spf=fail dkim=fail dmarc=fail'},
        })

        self.assertEqual(result['classification'], 'fraude')
        self.assertGreaterEqual(result['score'], 90)
        self.assertIn('delete', result['recommended_action'])

    def test_dangerous_attachment_increases_risk(self):
        result = self.detector.analyze({
            'from': 'Financeiro <financeiro@unknown.example>',
            'subject': 'Nota fiscal pendente',
            'body': 'Segue nota fiscal para pagamento.',
            'attachments': [{'filename': 'nota-fiscal.exe'}],
            'headers': {'authentication-results': 'spf=pass'},
        })

        self.assertIn(result['classification'], {'suspeito', 'fraude'})
        self.assertTrue(any('Anexo perigoso' in reason for reason in result['reasons']))

    def test_typosquatting_domain_is_detected(self):
        result = self.detector.analyze({
            'from': 'Google <security@g00gle.com>',
            'subject': 'Confirme seu código',
            'body': 'Acesse https://g00gle.com/security para confirmar seu token.',
            'headers': {'authentication-results': 'spf=pass'},
        })

        self.assertGreaterEqual(result['score'], 55)
        self.assertTrue(any('typosquatting' in reason.lower() for reason in result['reasons']))

    def test_reply_to_different_domain_is_suspicious(self):
        result = self.detector.analyze({
            'from': 'Cobrança <cobranca@empresa.com.br>',
            'subject': 'Boleto em aberto',
            'body': 'Responda com comprovante de pagamento.',
            'headers': {
                'authentication-results': 'spf=pass dkim=pass dmarc=pass',
                'reply-to': 'financeiro@evil.example',
            },
        })

        self.assertGreaterEqual(result['score'], 55)
        self.assertTrue(any('Reply-To' in reason for reason in result['reasons']))

    def test_intermediate_score_goes_to_quarantine(self):
        detector = SpamDetector(risk_config=test_config())
        result = detector.analyze({
            'from': 'Atendimento <suporte@servico.example>',
            'subject': 'Boleto disponível',
            'body': 'Acesse https://bit.ly/abc para baixar o boleto.',
            'headers': {'authentication-results': 'spf=pass'},
        })

        self.assertEqual(result['recommended_action'], 'quarantine')
        self.assertGreaterEqual(result['score'], 55)
        self.assertLess(result['score'], 90)

    def test_delete_only_above_high_threshold(self):
        detector = SpamDetector(risk_config=test_config())

        self.assertEqual(detector.recommended_action(89), 'quarantine')
        self.assertEqual(detector.recommended_action(90), 'delete')


class FakeConnection:
    email_address = 'conta@empresa.com.br'
    imap_conn = object()

    def __init__(self):
        self.deleted = []
        self.moved = []

    def move_to_trash(self, uid, source_folder):
        self.deleted.append((uid, source_folder))
        return True

    def move_email(self, uid, source_folder, target_folder):
        self.moved.append((uid, source_folder, target_folder))
        return True

    def list_folders(self, force_refresh=False):
        return ['INBOX', 'Quarentena', 'Quarentena/Fraude']

    def create_folder(self, folder_name):
        return True


class FolderManagerPolicyTest(unittest.TestCase):
    def test_dry_run_does_not_delete(self):
        conn = FakeConnection()
        manager = FolderManager(conn, risk_config=test_config(dry_run=True))

        decision = manager.apply_risk_action(
            {'uid': '123', 'from': 'a@b.test', 'subject': 'x'},
            {'score': 95, 'classification': 'fraude', 'rules': ['teste']},
        )

        self.assertEqual(decision['action'], 'dry-run:delete')
        self.assertEqual(conn.deleted, [])


if __name__ == '__main__':
    unittest.main()
