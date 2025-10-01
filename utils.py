import sqlite3
import argon2
from argon2 import PasswordHasher
from typing import List, Optional, Tuple
import string
import base64
from cryptography.fernet import Fernet
import os
from argon2.low_level import hash_secret_raw, Type
import hmac, hashlib
import logging
from weakref import WeakValueDictionary


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
         time_cost=8,
         memory_cost=2**18,
         parallelism=4,
         hash_len=32,
         salt_len=16
      )
      self._key_cache = {}
      self._init_db()
      
   def _init_db(self):
      with sqlite3.connect(self.db_path, timeout=30) as conn:
         cursor = conn.execute("PRAGMA journal_mode=WAL;")
         cursor.close()
         cursor = conn.execute('''
               CREATE TABLE IF NOT EXISTS users (
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  username TEXT UNIQUE NOT NULL,
                  master_password_hash TEXT NOT NULL,
                  search_salt BLOB DEFAULT NULL,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
               )
         ''')
         cursor.close()
         cursor = conn.execute('''
               CREATE TABLE IF NOT EXISTS passwords (
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  user_id INTEGER NOT NULL,
                  service_name TEXT NOT NULL,
                  original_service_name TEXT NOT NULL,
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
                  UNIQUE(user_id, search_tag)
               )
         ''')
         cursor.close()
         cursor = conn.execute('''
               CREATE INDEX IF NOT EXISTS idx_passwords_user_search_tag ON passwords(user_id, search_tag)
         ''')
         cursor.close()
         conn.commit()
         
   def derive_encryption_key(self, master_password: str, salt: bytes) -> bytes:
      cache_key = (master_password, salt)
      if cache_key not in self._key_cache:
         raw_key = hash_secret_raw(
            secret=master_password.encode(),
            salt=salt,
            time_cost=8,
            memory_cost=2**18,
            parallelism=4,
            hash_len=32,
            type=Type.ID
         )

         fernet_key = base64.urlsafe_b64encode(raw_key)

         if len(fernet_key) != 44:
           raise ValueError(f"Derived key length invalid: {len(fernet_key)} bytes")

         self._key_cache[cache_key] = fernet_key
      return self._key_cache[cache_key]

   def _get_user_search_salt(self, conn, user_id: int) -> bytes:
      """
      Get the user's search salt. Assumes it exists (set at registration).
      Raises ValueError if missing.
      """
      cur = conn.execute("SELECT search_salt FROM users WHERE id = ?", (user_id,))
      row = cur.fetchone()
      cur.close()
      if not row or not row[0]:
         raise ValueError("Service not found.")
      return row[0]

   def derive_search_key(self, master_password: str, search_salt: bytes) -> bytes:
      """
      Derive a deterministic HMAC key for searchable tags from master password + per-user salt.
      Returns raw bytes suitable for hmac.
      """
      raw = hash_secret_raw(
         secret=master_password.encode(),
         salt=search_salt,
         time_cost=8,
         memory_cost=2**18,
         parallelism=4,
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
   
         
   def encrypt_field(self, value: str, master_password: str, salt: bytes) -> str:
        if value is None:
            return None
        key = self.derive_encryption_key(master_password, salt)
        f = Fernet(key)
        return f.encrypt(value.encode()).decode()

   def decrypt_field(self, value: str, master_password: str, salt: bytes) -> str:
        if value is None:
            return None
        key = self.derive_encryption_key(master_password, salt)
        f = Fernet(key)
        try:
            return f.decrypt(value.encode()).decode()
        except Exception as e:
            from cryptography.fernet import InvalidToken
            if isinstance(e, InvalidToken):
                raise ValueError("Decryption failed: Invalid encryption token or incorrect password.")
            else:
                raise
   
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
               cursor = conn.execute(
                  'INSERT INTO users (username, master_password_hash, search_salt) VALUES (?, ?, ?)',
                  (username, master_hash, search_salt)
               )
               cursor.close()
               conn.commit()
               return True
         except sqlite3.IntegrityError:
               raise ValueError('Username already exists.')

   
   def add_password(self, username, master_password, service_name, service_username, email, password, **kwargs):
      user_id = self.verify_and_get_user_id(username, master_password)
      salt = os.urandom(16)

      with sqlite3.connect(self.db_path, timeout=30) as conn:

         search_key = self.derive_search_key(master_password, self._get_user_search_salt(conn, user_id))
         search_tag = self.compute_search_tag(search_key, service_name)

         encrypted_service = self.encrypt_field(service_name, master_password, salt)
         encrypted_username = self.encrypt_field(service_username, master_password, salt)
         encrypted_email = self.encrypt_field(email, master_password, salt)
         encrypted_password = self.encrypt_field(password, master_password, salt)
         encrypted_url = self.encrypt_field(kwargs.get("url"), master_password, salt)
         encrypted_notes = self.encrypt_field(kwargs.get("notes"), master_password, salt)

         encryption_key = self.derive_encryption_key(master_password, salt)
         hmac_value = hmac.new(encryption_key, encrypted_password.encode(), hashlib.sha256).digest()

         try:
            cursor = conn.execute('''
                  INSERT INTO passwords
                  (user_id, service_name, original_service_name, username, email, encrypted_password,
                  encryption_salt, hmac, url, notes, search_tag)
                  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (user_id, encrypted_service, encrypted_service, encrypted_username, encrypted_email,
                  encrypted_password, base64.urlsafe_b64encode(salt).decode(),
                  hmac_value, encrypted_url, encrypted_notes, search_tag))
            cursor.close()
            conn.commit()
         except sqlite3.IntegrityError:
            raise ValueError("Service already exists or search collision occurred.")

      master_password = None
      encrypted_password = None
      encrypted_username = None
      encrypted_email = None
      encrypted_service = None
      encrypted_url = None
      encrypted_notes = None
      return True

            
   def update_password(self, username: str, master_password: str, service_name: str, new_password: str, **kwargs) -> bool:
      user_id = self.verify_and_get_user_id(username, master_password)
      salt = os.urandom(16)

      with sqlite3.connect(self.db_path, timeout=30) as conn:

         search_key = self.derive_search_key(master_password, self._get_user_search_salt(conn, user_id))
         search_tag = self.compute_search_tag(search_key, service_name)

         cursor = conn.execute('''
               SELECT service_name, original_service_name, username, email, encrypted_password, encryption_salt, url, notes
               FROM passwords WHERE user_id = ? AND search_tag = ?
         ''', (user_id, search_tag))
         row = cursor.fetchone()
         cursor.close()
         if not row:
               raise ValueError("Service not found.")
         enc_service, enc_original, enc_user, enc_email, enc_password, old_salt_b64, enc_url, enc_notes = row
         old_salt = base64.urlsafe_b64decode(old_salt_b64)

         current_service = self.decrypt_field(enc_original, master_password, old_salt)
         current_username = self.decrypt_field(enc_user, master_password, old_salt)
         current_email = self.decrypt_field(enc_email, master_password, old_salt)
         current_url = self.decrypt_field(enc_url, master_password, old_salt)
         current_notes = self.decrypt_field(enc_notes, master_password, old_salt)

         new_service = kwargs.get("service_name", current_service)
         new_username = kwargs.get("service_username", current_username)
         new_email = kwargs.get("service_email", current_email)
         new_url = kwargs.get("url", current_url)
         new_notes = kwargs.get("notes", current_notes)

         encrypted_service = self.encrypt_field(new_service, master_password, salt)
         encrypted_original = encrypted_service
         encrypted_username = self.encrypt_field(new_username, master_password, salt)
         encrypted_email = self.encrypt_field(new_email, master_password, salt)
         encrypted_password = self.encrypt_field(new_password, master_password, salt)
         encrypted_url = self.encrypt_field(new_url, master_password, salt)
         encrypted_notes = self.encrypt_field(new_notes, master_password, salt)

         encryption_key = self.derive_encryption_key(master_password, salt)
         hmac_value = hmac.new(encryption_key, encrypted_password.encode(), hashlib.sha256).digest()

         new_search_tag = self.compute_search_tag(search_key, new_service)

         cursor = conn.execute('''
               UPDATE passwords
               SET service_name = ?, original_service_name = ?, username = ?, email = ?, encrypted_password = ?,
                  encryption_salt = ?, hmac = ?, url = ?, notes = ?, search_tag = ?
               WHERE user_id = ? AND search_tag = ?
         ''', (
               encrypted_service, encrypted_original, encrypted_username, encrypted_email, encrypted_password,
               base64.urlsafe_b64encode(salt).decode(), hmac_value, encrypted_url, encrypted_notes, new_search_tag,
               user_id, search_tag
         ))

         if cursor.rowcount == 0:
               raise ValueError("Service not found.")
         cursor.close()
         conn.commit()

      encrypted_password = None
      encrypted_username = None
      encrypted_email = None
      encrypted_service = None
      encrypted_url = None
      encrypted_notes = None
      return True

      
   def delete_password(self, username: str, master_password: str, service_name: str) -> bool:
      user_id = self.verify_and_get_user_id(username, master_password)

      with sqlite3.connect(self.db_path, timeout=30) as conn:
         search_key = self.derive_search_key(master_password, self._get_user_search_salt(conn, user_id))
         search_tag = self.compute_search_tag(search_key, service_name)

         cursor = conn.execute(
               'DELETE FROM passwords WHERE user_id = ? AND search_tag = ?',
               (user_id, search_tag)
         )

         if cursor.rowcount == 0:
               raise ValueError("Service not found.")
         cursor.close()
         conn.commit()
      return True

      
   def get_password(self, username: str, master_password: str, service_name: str) -> dict:
      user_id = self.verify_and_get_user_id(username, master_password)

      with sqlite3.connect(self.db_path, timeout=30) as conn:
         cur = conn.execute("SELECT search_salt FROM users WHERE id = ?", (user_id,))
         row = cur.fetchone()
         cur.close()
         if not row or not row[0]:
               raise ValueError("Service not found.")
         search_salt = row[0]

         search_key = self.derive_search_key(master_password, search_salt)
         search_tag = self.compute_search_tag(search_key, service_name)

         cursor = conn.execute('''
               SELECT service_name, original_service_name, username, email, encrypted_password, encryption_salt, hmac, url, notes, created_at
               FROM passwords WHERE user_id = ? AND search_tag = ?
         ''', (user_id, search_tag))
         result = cursor.fetchone()
         cursor.close()
         if not result:
               raise ValueError('Service not found.')



         enc_service, enc_original, enc_user, enc_email, enc_password, salt_b64, hmac_value, enc_url, enc_notes, enc_created = result
         salt = base64.urlsafe_b64decode(salt_b64)

         encryption_key = self.derive_encryption_key(master_password, salt)

         if not hmac.compare_digest(hmac.new(encryption_key, enc_password.encode(), hashlib.sha256).digest(), hmac_value):
            raise ValueError("Service not found.")

         dec_original = self.decrypt_field(enc_original, master_password, salt)

         if dec_original.strip().lower() != service_name.strip().lower():
               raise ValueError('Service not found.')

         dec_service = self.decrypt_field(enc_service, master_password, salt)

         return {
               'service_name': dec_service,
               'username': self.decrypt_field(enc_user, master_password, salt),
               'email': self.decrypt_field(enc_email, master_password, salt),
               'password': self.decrypt_field(enc_password, master_password, salt),
               'url': self.decrypt_field(enc_url, master_password, salt),
               'notes': self.decrypt_field(enc_notes, master_password, salt),
               'created_at': enc_created
         }

         
   def verify_and_get_user_id(self, username: str, master_password: str) -> int:
      with sqlite3.connect(self.db_path, timeout=30) as conn:
         cursor = conn.execute('SELECT id, master_password_hash FROM users WHERE username = ?', (username,))
         result = cursor.fetchone()
         cursor.close()
         if not result:
            raise ValueError('Invalid credentials.')
         user_id, master_hash = result
         if not self.verify_master_password(master_hash, master_password):
            raise ValueError('Invalid credentials.')

         return user_id
      
   def list_all(self, username: str, master_password: str) -> list:
      user_id = self.verify_and_get_user_id(username, master_password)
      result_list = []

      with sqlite3.connect(self.db_path, timeout=30) as conn:
         cursor = conn.execute('SELECT service_name, encryption_salt FROM passwords WHERE user_id = ?', (user_id,))
         rows = cursor.fetchall()
         cursor.close()

         for enc_service, salt_b64 in rows:
               salt = base64.urlsafe_b64decode(salt_b64)
               service_name = self.decrypt_field(enc_service, master_password, salt)
               result_list.append(service_name)

      return sorted(result_list)

   def change_master_password(self, username: str, old_password: str, new_password: str, batch_size: int = 50) -> bool:
      """
      Change the master password for a user, re-encrypting all stored passwords.
      Note: This operation can be slow for users with many entries.
      """
      logger = logging.getLogger(__name__)
      logger.info(f"Starting master password change for user {username}")
      validate_master_password(new_password)
      user_id = self.verify_and_get_user_id(username, old_password)

      with sqlite3.connect(self.db_path, timeout=30) as conn:

         cursor = conn.execute('''
               SELECT id, service_name, original_service_name, username, email, encrypted_password, encryption_salt, url, notes
               FROM passwords WHERE user_id = ?
         ''', (user_id,))
         rows = cursor.fetchall()
         cursor.close()

         new_hash = self.ph.hash(new_password)
         cursor = conn.execute('UPDATE users SET master_password_hash = ? WHERE id = ?', (new_hash, user_id))
         cursor.close()

         search_salt = self._get_user_search_salt(conn, user_id)
         new_search_key = self.derive_search_key(new_password, search_salt)

         for i, row in enumerate(rows):
            pw_id, enc_service, enc_original, enc_user, enc_email, enc_password, salt_b64, enc_url, enc_notes = row
            old_salt = base64.urlsafe_b64decode(salt_b64)

            service_name = self.decrypt_field(enc_service, old_password, old_salt)
            username_field = self.decrypt_field(enc_user, old_password, old_salt)
            email_field = self.decrypt_field(enc_email, old_password, old_salt)
            password_field = self.decrypt_field(enc_password, old_password, old_salt)
            url_field = self.decrypt_field(enc_url, old_password, old_salt)
            notes_field = self.decrypt_field(enc_notes, old_password, old_salt)

            new_salt = os.urandom(16)
            new_enc_service = self.encrypt_field(service_name, new_password, new_salt)
            new_enc_user = self.encrypt_field(username_field, new_password, new_salt)
            new_enc_email = self.encrypt_field(email_field, new_password, new_salt)
            new_enc_password = self.encrypt_field(password_field, new_password, new_salt)
            new_enc_url = self.encrypt_field(url_field, new_password, new_salt)
            new_enc_notes = self.encrypt_field(notes_field, new_password, new_salt)

            new_encryption_key = self.derive_encryption_key(new_password, new_salt)
            new_hmac = hmac.new(new_encryption_key, new_enc_password.encode(), hashlib.sha256).digest()

            counter = 0
            while True:
               suffix = f"_{counter}" if counter > 0 else ""
               new_search_tag = self.compute_search_tag(new_search_key, service_name + suffix)
               try:
                  cursor = conn.execute('''
                        UPDATE passwords
                        SET service_name = ?, original_service_name = ?, username = ?, email = ?, encrypted_password = ?,
                           encryption_salt = ?, hmac = ?, url = ?, notes = ?, search_tag = ?
                        WHERE id = ?
                  ''', (new_enc_service, new_enc_service, new_enc_user, new_enc_email, new_enc_password,
                        base64.urlsafe_b64encode(new_salt).decode(), new_hmac, new_enc_url, new_enc_notes, new_search_tag, pw_id))
                  cursor.close()
                  break
               except sqlite3.IntegrityError:
                  counter += 1
                  if counter > 10:
                     raise ValueError(f"Unable to resolve search collision for service '{service_name}' after 10 attempts.")

            password_field = None
            username_field = None
            email_field = None
            url_field = None
            notes_field = None
            new_enc_password = None
            new_enc_user = None
            new_enc_email = None
            new_enc_url = None
            new_enc_notes = None

            if (i + 1) % batch_size == 0:
               conn.commit()
               self._key_cache.clear()
               logger.info(f"Committed batch of {batch_size} passwords for user {username}")

         conn.commit()
         logger.info(f"Completed master password change for user {username}")

      old_password = None
      new_password = None
      self._key_cache.clear()
      return True

   def close(self):
      """
      Close the database connection and clear caches.
      """
      self._key_cache.clear()

      