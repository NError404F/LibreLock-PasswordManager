import sqlite3
import argon2
from argon2 import PasswordHasher
from typing import List, Optional, Tuple
import secrets
import string
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os
from argon2.low_level import hash_secret_raw, Type
import hmac, hashlib
import binascii

def validate_master_password(password: str):
    if len(password) < 12:
        raise ValueError("Master password must be at least 12 characters long.")
    if not any(c.isupper() for c in password):
        raise ValueError("Master password must have at least one uppercase letter.")
    if not any(c.islower() for c in password):
        raise ValueError("Master password must have at least one lowercase letter.")
    if not any(c.isdigit() for c in password):
        raise ValueError("Master password must have at least one number.")
    if not any(c in string.punctuation for c in password):
        raise ValueError("Master password must have at least one symbol.")

class PasswordManager:
   def __init__(self, db_path: str = "LibrePass.db"):
      self.db_path = db_path
      self.ph = PasswordHasher(
         time_cost=4,
         memory_cost=2**17,
         parallelism=2,
         hash_len=32,
         salt_len=16
      )
      self._init_db()
      
   def _init_db(self):
      with sqlite3.connect(self.db_path, timeout=30) as conn:
         conn.execute('''
               CREATE TABLE IF NOT EXISTS users (
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  username TEXT UNIQUE NOT NULL,
                  master_password_hash TEXT NOT NULL,
                  search_salt BLOB DEFAULT NULL,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
               )
         ''')
         conn.execute('''
               CREATE TABLE IF NOT EXISTS passwords (
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  user_id INTEGER NOT NULL,
                  service_name TEXT NOT NULL,
                  username TEXT,
                  email TEXT,
                  encrypted_password TEXT NOT NULL,
                  encryption_salt TEXT NOT NULL,
                  hmac BLOB NOT NULL,
                  url TEXT,
                  notes TEXT,
                  search_tag TEXT DEFAULT NULL,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  FOREIGN KEY (user_id) REFERENCES users(id),
                  UNIQUE(user_id, service_name)
               )
         ''')
         conn.execute('''
               CREATE INDEX IF NOT EXISTS idx_passwords_user_search_tag ON passwords(user_id, search_tag)
         ''')
         conn.commit()
         
   def derive_encryption_key(self, master_password: str, salt: bytes) -> bytes:       
      raw_key = hash_secret_raw(
         secret=master_password.encode(),
         salt=salt,
         time_cost=4,
         memory_cost=2**17, 
         parallelism=2,
         hash_len=32,
         type=Type.ID
      )
      
      fernet_key = base64.urlsafe_b64encode(raw_key)
      
      if len(fernet_key) != 44:
        raise ValueError(f"Derived key length invalid: {len(fernet_key)} bytes")

      return fernet_key

   def _ensure_user_search_salt(self, conn, user_id: int) -> bytes:
      """
      Ensure the users.search_salt exists for a given user. Returns the salt bytes.
      Use this when migrating old users or on-demand.
      """
      cur = conn.execute("SELECT search_salt FROM users WHERE id = ?", (user_id,))
      row = cur.fetchone()
      if row and row[0]:
         return row[0]

      salt = os.urandom(16)
      conn.execute("UPDATE users SET search_salt = ? WHERE id = ?", (salt, user_id))
      conn.commit()
      return salt

   def derive_search_key(self, master_password: str, search_salt: bytes) -> bytes:
      """
      Derive a deterministic HMAC key for searchable tags from master password + per-user salt.
      Returns raw bytes suitable for hmac.
      """
      raw = hash_secret_raw(
         secret=master_password.encode(),
         salt=search_salt,
         time_cost=4,
         memory_cost=2**17,
         parallelism=2,
         hash_len=32,
         type=Type.ID
      )
      return raw 

   def compute_search_tag(self, search_key: bytes, service_name: str) -> str:
      """
      Compute deterministic search tag for a service name. Normalize by lowercasing & stripping.
      Returns hex string.
      """
      normalized = (service_name or "").strip().lower().encode('utf-8')
      tag = hmac.new(search_key, normalized, hashlib.sha256).hexdigest()
      return tag

   def compute_hmac(self, key: bytes, data: bytes) -> str:
      return hmac.new(key, data, hashlib.sha256).hexdigest()
   
         
   def encrypt_field(self, value: str, master_password: str, salt: bytes) -> str:
        if value is None:
            return None
        key = self.derive_encryption_key(master_password, salt)
        f = Fernet(key)
        return base64.urlsafe_b64encode(f.encrypt(value.encode())).decode()

   def decrypt_field(self, value: str, master_password: str, salt: bytes) -> str:
        if value is None:
            return None
        key = self.derive_encryption_key(master_password, salt)
        f = Fernet(key)
        return f.decrypt(base64.urlsafe_b64decode(value)).decode()
   
   def verify_master_password(self, hashed_password: str, password: str) -> bool:
      try: 
         return self.ph.verify(hashed_password, password)
      except argon2.exceptions.VerifyMismatchError:
         return False
   
   def register_user(self, username: str, master_password: str) -> bool:
      validate_master_password(master_password)
      with sqlite3.connect(self.db_path, timeout=30) as conn:
         master_hash = self.ph.hash(master_password)
         search_salt = os.urandom(16)
         try:
               conn.execute(
                  'INSERT INTO users (username, master_password_hash, search_salt) VALUES (?, ?, ?)',
                  (username, master_hash, search_salt)
               )
               conn.commit()
               return True
         except sqlite3.IntegrityError:
               raise ValueError('Username already exists.')

   
   def add_password(self, username, master_password, service_name, service_username, email, password, **kwargs):
      user_id = self.verify_and_get_user_id(username, master_password)
      salt = os.urandom(16)

      with sqlite3.connect(self.db_path, timeout=30) as conn:

         search_key = self.derive_search_key(master_password, self._ensure_user_search_salt(conn, user_id))
         search_tag = self.compute_search_tag(search_key, service_name)

         encrypted_service = self.encrypt_field(service_name, master_password, salt)
         encrypted_username = self.encrypt_field(service_username, master_password, salt)
         encrypted_email = self.encrypt_field(email, master_password, salt)
         encrypted_password = self.encrypt_field(password, master_password, salt)
         encrypted_url = self.encrypt_field(kwargs.get("url"), master_password, salt)
         encrypted_notes = self.encrypt_field(kwargs.get("notes"), master_password, salt)

         encryption_key = self.derive_encryption_key(master_password, salt)
         hmac_value = hmac.new(encryption_key, encrypted_password.encode(), hashlib.sha256).digest()

         conn.execute('''
               INSERT INTO passwords
               (user_id, service_name, username, email, encrypted_password,
               encryption_salt, hmac, url, notes, search_tag)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
         ''', (user_id, encrypted_service, encrypted_username, encrypted_email,
               encrypted_password, base64.urlsafe_b64encode(salt).decode(),
               hmac_value, encrypted_url, encrypted_notes, search_tag))
         conn.commit()
      return True

            
   def update_password(self, username: str, master_password: str, service_name: str, new_password: str, **kwargs) -> bool:
      user_id = self.verify_and_get_user_id(username, master_password)
      salt = os.urandom(16)

      with sqlite3.connect(self.db_path, timeout=30) as conn:

         search_key = self.derive_search_key(master_password, self._ensure_user_search_salt(conn, user_id))
         search_tag = self.compute_search_tag(search_key, service_name)
         
         encrypted_password = self.encrypt_field(new_password, master_password, salt)
         encrypted_url = self.encrypt_field(kwargs.get("url"), master_password, salt)
         encrypted_notes = self.encrypt_field(kwargs.get("notes"), master_password, salt)

         encryption_key = self.derive_encryption_key(master_password, salt)
         hmac_value = hmac.new(encryption_key, encrypted_password.encode(), hashlib.sha256).digest()

         cursor = conn.execute('''
               UPDATE passwords
               SET encrypted_password = ?, encryption_salt = ?, hmac = ?,
                  url = CASE WHEN ? IS NOT NULL THEN ? ELSE url END,
                  notes = CASE WHEN ? IS NOT NULL THEN ? ELSE notes END
               WHERE user_id = ? AND search_tag = ?
         ''', (
               encrypted_password, base64.urlsafe_b64encode(salt).decode(), hmac_value,
               kwargs.get("url"), kwargs.get("url"),
               kwargs.get("notes"), kwargs.get("notes"),
               user_id, search_tag
         ))

         if cursor.rowcount == 0:
               raise ValueError("Service not found.")
         conn.commit()
      return True

      
   def delete_password(self, username: str, master_password: str, service_name: str) -> bool:
      user_id = self.verify_and_get_user_id(username, master_password)

      with sqlite3.connect(self.db_path, timeout=30) as conn:
         search_key = self.derive_search_key(master_password, self._ensure_user_search_salt(conn, user_id))
         search_tag = self.compute_search_tag(search_key, service_name)

         cursor = conn.execute(
               'DELETE FROM passwords WHERE user_id = ? AND search_tag = ?',
               (user_id, search_tag)
         )

         if cursor.rowcount == 0:
               raise ValueError("Service not found for deletion.")
         conn.commit()
      return True

      
   def get_password(self, username: str, master_password: str, service_name: str) -> dict:
      user_id = self.verify_and_get_user_id(username, master_password)

      # find user's search_salt
      with sqlite3.connect(self.db_path, timeout=30) as conn:
         cur = conn.execute("SELECT search_salt FROM users WHERE id = ?", (user_id,))
         row = cur.fetchone()
         if not row or not row[0]:
               raise ValueError("Search salt missing for user.")
         search_salt = row[0]

         search_key = self.derive_search_key(master_password, search_salt)
         search_tag = self.compute_search_tag(search_key, service_name)

         cursor = conn.execute('''
               SELECT service_name, username, email, encrypted_password, encryption_salt, hmac, url, notes, created_at
               FROM passwords WHERE user_id = ? AND search_tag = ?
         ''', (user_id, search_tag))
         result = cursor.fetchone()
         if not result:
               raise ValueError('Service not found.')



         enc_service, enc_user, enc_email, enc_password, salt_b64, hmac_value, enc_url, enc_notes, enc_created = result
         salt = base64.urlsafe_b64decode(salt_b64)

         encryption_key = self.derive_encryption_key(master_password, salt)

         if not hmac.compare_digest(hmac.new(encryption_key, enc_password.encode(), hashlib.sha256).digest(), hmac_value):
            raise ValueError("Data integrity check failed (HMAC mismatch).")

         dec_service = self.decrypt_field(enc_service, master_password, salt)

         if dec_service.strip().lower() != service_name.strip().lower():

               raise ValueError('Service not found (integrity mismatch).')

         return {
               'service_name': dec_service,
               'username': self.decrypt_field(enc_user, master_password, salt),
               'email': self.decrypt_field(enc_email, master_password, salt),
               'password': self.decrypt_field(enc_password, master_password, salt),
               'url': self.decrypt_field(enc_url, master_password, salt),
               'notes': self.decrypt_field(enc_notes, master_password, salt),
               'created_at': self.decrypt_field(enc_created, master_password, salt)
         }

         
   def verify_and_get_user_id(self, username: str, master_password: str) -> int:
      with sqlite3.connect(self.db_path, timeout=30) as conn:
         cursor = conn.execute('SELECT id, master_password_hash FROM users WHERE username = ?', (username,))
         result = cursor.fetchone()
         if not result:
            raise ValueError('User not found.')
         user_id, master_hash = result
         if not self.verify_master_password(master_hash, master_password):
            raise ValueError('Invalid master password.')
         
         return user_id
      
   def list_all(self, username: str, master_password: str) -> list:
      user_id = self.verify_and_get_user_id(username, master_password)
      result_list = []

      with sqlite3.connect(self.db_path, timeout=30) as conn:
         cursor = conn.execute('SELECT service_name, encryption_salt FROM passwords WHERE user_id = ?', (user_id,))
         rows = cursor.fetchall()

         for enc_service, salt_b64 in rows:
               salt = base64.urlsafe_b64decode(salt_b64)
               service_name = self.decrypt_field(enc_service, master_password, salt)
               result_list.append(service_name)

      return sorted(result_list)

      