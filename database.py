# Módulo de Banco de Dados - MySQL
# =================================

import mysql.connector
from mysql.connector import Error
import bcrypt
import os

# Configurações do banco de dados
DB_CONFIG = {
    'host': os.getenv('DB_HOST', '159.203.188.0'),
    'port': int(os.getenv('DB_PORT', 3306)),
    'user': os.getenv('DB_USER', 'organizer'),
    'password': os.getenv('DB_PASSWORD', 'xPX4MWSW7XEyAhph'),
    'database': os.getenv('DB_NAME', 'organizer'),
    'charset': 'utf8mb4',
    'collation': 'utf8mb4_general_ci',
    'ssl_disabled': True
}


def get_connection():
    """Cria e retorna uma conexão com o banco de dados"""
    try:
        connection = mysql.connector.connect(**DB_CONFIG)
        return connection
    except Error as e:
        print(f"Erro ao conectar ao MySQL: {e}")
        return None


def init_database():
    """Inicializa o banco de dados e cria as tabelas necessárias"""
    try:
        # Conecta sem especificar database para criar se não existir
        config_without_db = {k: v for k, v in DB_CONFIG.items() if k != 'database'}
        connection = mysql.connector.connect(**config_without_db)
        cursor = connection.cursor()
        
        # Cria o banco de dados se não existir
        cursor.execute(f"CREATE DATABASE IF NOT EXISTS {DB_CONFIG['database']} CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci")
        cursor.execute(f"USE {DB_CONFIG['database']}")
        
        # Cria tabela de usuários
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(50) NOT NULL UNIQUE,
                password_hash VARCHAR(255) NOT NULL,
                email VARCHAR(100),
                is_admin BOOLEAN DEFAULT FALSE,
                is_active BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP NULL,
                INDEX idx_username (username)
            ) ENGINE=InnoDB
        """)
        
        # Adiciona coluna is_admin se não existir (para migração)
        try:
            cursor.execute("ALTER TABLE users ADD COLUMN is_admin BOOLEAN DEFAULT FALSE AFTER email")
        except:
            pass  # Coluna já existe
        
        connection.commit()
        cursor.close()
        connection.close()
        
        print("✅ Banco de dados inicializado com sucesso!")
        return True
        
    except Error as e:
        print(f"❌ Erro ao inicializar banco de dados: {e}")
        return False


def create_user(username: str, password: str, email: str = None, is_admin: bool = False) -> bool:
    """Cria um novo usuário no banco de dados"""
    connection = get_connection()
    if not connection:
        return False
    
    try:
        cursor = connection.cursor()
        
        # Hash da senha
        password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        
        cursor.execute(
            "INSERT INTO users (username, password_hash, email, is_admin) VALUES (%s, %s, %s, %s)",
            (username, password_hash.decode('utf-8'), email, is_admin)
        )
        
        connection.commit()
        cursor.close()
        connection.close()
        
        print(f"✅ Usuário '{username}' criado com sucesso!")
        return True
        
    except Error as e:
        print(f"❌ Erro ao criar usuário: {e}")
        return False


def verify_user(username: str, password: str) -> dict:
    """Verifica credenciais do usuário e retorna dados se válido"""
    connection = get_connection()
    if not connection:
        return None
    
    try:
        cursor = connection.cursor(dictionary=True)
        
        cursor.execute(
            "SELECT id, username, password_hash, email, is_admin, is_active FROM users WHERE username = %s",
            (username,)
        )
        
        user = cursor.fetchone()
        
        if user and user['is_active']:
            # Verifica a senha
            if bcrypt.checkpw(password.encode('utf-8'), user['password_hash'].encode('utf-8')):
                # Atualiza último login
                cursor.execute(
                    "UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = %s",
                    (user['id'],)
                )
                connection.commit()
                
                cursor.close()
                connection.close()
                
                return {
                    'id': user['id'],
                    'username': user['username'],
                    'email': user['email'],
                    'is_admin': user.get('is_admin', False)
                }
        
        cursor.close()
        connection.close()
        return None
        
    except Error as e:
        print(f"❌ Erro ao verificar usuário: {e}")
        return None


def get_all_users() -> list:
    """Retorna lista de todos os usuários"""
    connection = get_connection()
    if not connection:
        return []
    
    try:
        cursor = connection.cursor(dictionary=True)
        cursor.execute("SELECT id, username, email, is_admin, is_active, created_at, last_login FROM users ORDER BY created_at DESC")
        users = cursor.fetchall()
        cursor.close()
        connection.close()
        return users
        
    except Error as e:
        print(f"❌ Erro ao listar usuários: {e}")
        return []


def delete_user(username: str) -> bool:
    """Remove um usuário do banco de dados"""
    connection = get_connection()
    if not connection:
        return False
    
    try:
        cursor = connection.cursor()
        cursor.execute("DELETE FROM users WHERE username = %s", (username,))
        connection.commit()
        affected = cursor.rowcount
        cursor.close()
        connection.close()
        return affected > 0
        
    except Error as e:
        print(f"❌ Erro ao deletar usuário: {e}")
        return False


def user_exists(username: str) -> bool:
    """Verifica se um usuário já existe"""
    connection = get_connection()
    if not connection:
        return False
    
    try:
        cursor = connection.cursor()
        cursor.execute("SELECT COUNT(*) FROM users WHERE username = %s", (username,))
        count = cursor.fetchone()[0]
        cursor.close()
        connection.close()
        return count > 0
        
    except Error as e:
        print(f"❌ Erro ao verificar usuário: {e}")
        return False


def toggle_user_status(user_id: int) -> bool:
    """Ativa ou desativa um usuário"""
    connection = get_connection()
    if not connection:
        return False
    
    try:
        cursor = connection.cursor()
        cursor.execute("UPDATE users SET is_active = NOT is_active WHERE id = %s", (user_id,))
        connection.commit()
        affected = cursor.rowcount
        cursor.close()
        connection.close()
        return affected > 0
        
    except Error as e:
        print(f"❌ Erro ao alterar status do usuário: {e}")
        return False


def update_user(user_id: int, username: str = None, email: str = None, password: str = None, is_admin: bool = None) -> bool:
    """Atualiza dados de um usuário"""
    connection = get_connection()
    if not connection:
        return False
    
    try:
        cursor = connection.cursor()
        updates = []
        values = []
        
        if username:
            updates.append("username = %s")
            values.append(username)
        if email is not None:
            updates.append("email = %s")
            values.append(email)
        if password:
            password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
            updates.append("password_hash = %s")
            values.append(password_hash.decode('utf-8'))
        if is_admin is not None:
            updates.append("is_admin = %s")
            values.append(is_admin)
        
        if updates:
            values.append(user_id)
            cursor.execute(f"UPDATE users SET {', '.join(updates)} WHERE id = %s", values)
            connection.commit()
        
        cursor.close()
        connection.close()
        return True
        
    except Error as e:
        print(f"❌ Erro ao atualizar usuário: {e}")
        return False


# Script para criar usuário admin se executado diretamente
if __name__ == '__main__':
    print("🔧 Inicializando banco de dados...")
    
    if init_database():
        # Cria usuário administrador se não existir
        if not user_exists('administrador'):
            create_user('administrador', 'isna2025', 'contato@isna.org.br', is_admin=True)
            print("👤 Usuário administrador criado: administrador / isna2025")
        else:
            # Atualiza para admin se já existe
            connection = get_connection()
            if connection:
                cursor = connection.cursor()
                cursor.execute("UPDATE users SET is_admin = TRUE WHERE username = 'administrador'")
                connection.commit()
                cursor.close()
                connection.close()
            print("👤 Usuário administrador atualizado")
