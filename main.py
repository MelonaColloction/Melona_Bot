# ============================================
# melona_bot.py - Melona Bot with HoneyDrop Token
# Complete: PIN Security, Weekly Leaderboard, Daily Airdrop, Registration Toggle
# Added: Admin /userinfo command, winner history tracking
# ============================================

import os
import requests
import json
import sqlite3
import itertools
import asyncio
import hashlib
import secrets
import random
from datetime import datetime, timedelta
from time import time
from collections import defaultdict
from web3 import Web3
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    Application, CommandHandler, MessageHandler, CallbackQueryHandler, 
    filters, ContextTypes
)
from flask import Flask
from threading import Thread

# ============================================
# CONFIGURATIONS (READ FROM ENVIRONMENT)
# ============================================

BOT_TOKEN = os.getenv("BOT_TOKEN")

TRC20_WALLET = os.getenv("TRC20_WALLET")
BNB_WALLET = os.getenv("BNB_WALLET")
TON_WALLET = os.getenv("TON_WALLET")

# ============================================
# TRON API KEYS (18 Separate Accounts)
# ============================================
TRON_API_KEYS = [
    "724cf503-76de-4443-b3f5-ec614355da66", "5f587d81-152d-4e1f-8b15-92a6911cd68e",
    "d373b68c-d29f-43c4-8123-3891603c9d03", "004109ed-bc79-405b-91d1-46ab1953d5f7",
    "8c77b430-d5c6-4032-85b1-46765c180bf8", "009c6768-88f0-4e2b-9a29-83598281942b",
    "3bb42b4e-710f-49d3-925e-a8516e4edd64", "e06f7815-149d-4bd4-af25-7ed22978017c",
    "69231a16-1590-4c54-abba-bf68a39ab25f", "55fd0587-070a-496c-899e-34c22787e435",
    "b301439f-0cbb-48ae-bfa7-aa98ca492f2b", "cac2c719-25f7-4e36-b1af-00f051f38c76",
    "dd8f7447-a6db-46d6-a3cb-801e1ba7990c", "27b2d62e-1b69-4201-93ab-a4e5bc86ff06",
    "395d91c9-5d02-4d18-8b9b-ea674faa2017", "8764bebe-87fa-436e-aed4-7bc12c4ab143",
    "aaa1304f-cc5a-4f0e-85a0-2c7cb1b5711b", "349ebb1d-5f34-4631-adcd-65957fa99b80"
]

# ============================================
# TON (GRAM) API KEYS (4 Separate Accounts)
# ============================================
TON_API_KEYS = [
    "bc98c7400f803a765fd17f6af5c0cfda59a2e5f74b088c23791d525aa801161f",
    "5381ca8d20b400eac70025430cd50218b430fcf8f391406420db5ae923de75d0",
    "658f94c6eed58611ec83ba131d5ca51e0d41cdfa0a32de29a3eb18af24fb22b5",
    "c3e5fdac622a4baf073462a0b2d70023ce4017b56640368744f45d298aab3c60"
]

REQUIRED_MAIN_CHANNEL = os.getenv("MAIN_CHANNEL", "@Melona_collection")
REQUIRED_AIRDROP_CHANNEL = os.getenv("AIRDROP_CHANNEL", "@HoneyDrop_Airdrop")

MARKETING_ADMIN_ID = int(os.getenv("MARKETING_ADMIN_ID", "7312521439"))
FINANCE_ADMIN_ID = int(os.getenv("FINANCE_ADMIN_ID", "7713208330"))

# ============================================
# WEEKLY REWARDS CONFIGURATION
# ============================================
WEEKLY_REWARDS = {
    1: 50000,
    2: 40000,
    3: 30000,
    4: 25000,
    5: 20000,
    range(6, 11): 15000
}

# ============================================
# SYSTEM TOGGLES (Admin Control)
# ============================================
weekly_leaderboard_enabled = True
registration_open = True
daily_airdrop_enabled = True
token_withdrawal_enabled = False

def is_weekly_leaderboard_enabled() -> bool:
    global weekly_leaderboard_enabled
    return weekly_leaderboard_enabled

def set_weekly_leaderboard_enabled(status: bool):
    global weekly_leaderboard_enabled
    weekly_leaderboard_enabled = status

def is_registration_open() -> bool:
    global registration_open
    return registration_open

def set_registration_open(status: bool):
    global registration_open
    registration_open = status

def is_daily_airdrop_enabled() -> bool:
    global daily_airdrop_enabled
    return daily_airdrop_enabled

def set_daily_airdrop_enabled(status: bool):
    global daily_airdrop_enabled
    daily_airdrop_enabled = status

def is_token_withdrawal_enabled() -> bool:
    global token_withdrawal_enabled
    return token_withdrawal_enabled

def set_token_withdrawal_enabled(status: bool):
    global token_withdrawal_enabled
    token_withdrawal_enabled = status

# ============================================
# RATE LIMITING (Anti-Spam)
# ============================================
RATE_LIMIT = {
    "calls": 5,
    "seconds": 10,
    "block_seconds": 60
}

user_rate_limit = defaultdict(list)
blocked_users = {}

# ============================================
# PIN SECURITY SYSTEM
# ============================================
failed_pin_attempts = defaultdict(int)
locked_users = {}

def normalize_pin(pin: str) -> str:
    pin = pin.strip()
    pin = ' '.join(pin.split())
    return pin

def hash_pin(pin: str, salt: str = None) -> tuple:
    if not salt:
        salt = secrets.token_hex(16)
    hashed = hashlib.pbkdf2_hmac('sha256', pin.encode(), salt.encode(), 100000)
    return hashed.hex(), salt

def verify_pin(pin: str, stored_hash: str, salt: str) -> bool:
    hashed, _ = hash_pin(pin, salt)
    return hashed == stored_hash

def validate_pin(pin: str) -> tuple:
    if len(pin) < 5:
        return False, "PIN must be at least 5 characters long."
    if not any(c.isupper() for c in pin):
        return False, "PIN must contain at least ONE capital letter (A-Z)."
    if ' ' in pin:
        return False, "PIN cannot contain spaces."
    return True, "Valid"

def log_failed_pin_attempt(user_id: int, entered_pin: str, action: str = "unknown"):
    with open("pin_failures.log", "a") as f:
        f.write(f"{datetime.now()} - User {user_id} - Action: {action} - Invalid PIN attempt: '{entered_pin}'\n")

def is_rate_limited(user_id: int) -> tuple:
    if user_id in blocked_users:
        block_until = blocked_users[user_id]
        if time() < block_until:
            remaining = int(block_until - time())
            return True, remaining, f"⛔ Blocked for {remaining} seconds"
        else:
            del blocked_users[user_id]
    
    now = time()
    user_rate_limit[user_id] = [t for t in user_rate_limit[user_id] if now - t < RATE_LIMIT["seconds"]]
    
    if len(user_rate_limit[user_id]) >= RATE_LIMIT["calls"]:
        blocked_users[user_id] = now + RATE_LIMIT["block_seconds"]
        user_rate_limit[user_id] = []
        return True, RATE_LIMIT["block_seconds"], f"⛔ Blocked for {RATE_LIMIT['block_seconds']} seconds"
    
    user_rate_limit[user_id].append(now)
    return False, 0, None

def rate_limited(handler_func):
    async def wrapper(update: Update, context: ContextTypes.DEFAULT_TYPE, *args, **kwargs):
        user_id = update.effective_user.id
        if user_id == MARKETING_ADMIN_ID or user_id == FINANCE_ADMIN_ID:
            return await handler_func(update, context, *args, **kwargs)
        is_limited, remaining, message = is_rate_limited(user_id)
        if is_limited:
            if update.callback_query:
                await update.callback_query.answer(message, show_alert=True)
            else:
                await update.message.reply_text(message)
            return
        return await handler_func(update, context, *args, **kwargs)
    return wrapper

# ============================================
# API KEY MANAGERS (Round Robin)
# ============================================
class APIKeyManager:
    def __init__(self, keys):
        self.keys = keys
        self.cycle = itertools.cycle(keys)
    
    def get_next_key(self):
        return next(self.cycle)

tron_key_manager = APIKeyManager(TRON_API_KEYS)
ton_key_manager = APIKeyManager(TON_API_KEYS)

# ============================================
# BRAND AND TOKEN INFO
# ============================================
BOT_NAME = "Melona"
TOKEN_NAME = "HoneyDrop"
TOKEN_SYMBOL = "HONEY"
TOKEN_EMOJI = "🍯"
TOKENS_PER_REFERRAL = 10

# ============================================
# BSC SETUP
# ============================================
BSC_RPC = "https://bsc-dataseed.binance.org/"
w3 = Web3(Web3.HTTPProvider(BSC_RPC))

USDT_CONTRACT_BSC = "0x55d398326f99059fF775485246999027B3197955"
USDT_ABI = json.loads('[{"anonymous":false,"inputs":[{"indexed":true,"name":"from","type":"address"},{"indexed":true,"name":"to","type":"address"},{"indexed":false,"name":"value","type":"uint256"}],"name":"Transfer","type":"event"}]')
usdt_contract = w3.eth.contract(address=USDT_CONTRACT_BSC, abi=USDT_ABI)

# ============================================
# DATABASE
# ============================================
class Database:
    def __init__(self, db_path="melona_bot.db"):
        self.db_path = db_path
        self.init_tables()
    
    def init_tables(self):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    user_id INTEGER PRIMARY KEY,
                    username TEXT,
                    registered_at TIMESTAMP,
                    invited_by INTEGER,
                    balance REAL DEFAULT 0,
                    tokens INTEGER DEFAULT 0,
                    user_pin TEXT,
                    pin_salt TEXT,
                    pin_set_at TIMESTAMP,
                    pending_wallet_address TEXT,
                    pending_wallet_network TEXT,
                    ton_wallet_address TEXT,
                    wallet_address TEXT,
                    wallet_network TEXT,
                    payment_tx_hash TEXT,
                    payment_network TEXT,
                    level TEXT DEFAULT 'Newbie',
                    is_verified BOOLEAN DEFAULT 0,
                    is_marketing_admin BOOLEAN DEFAULT 0
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS withdrawals (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    amount REAL,
                    wallet_address TEXT,
                    wallet_network TEXT,
                    tx_hash TEXT,
                    status TEXT DEFAULT 'pending',
                    requested_at TIMESTAMP
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS token_withdrawals (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    amount INTEGER,
                    ton_wallet_address TEXT,
                    status TEXT DEFAULT 'pending',
                    requested_at TIMESTAMP
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS weekly_referrals (
                    user_id INTEGER PRIMARY KEY,
                    week_start DATE,
                    count INTEGER DEFAULT 0
                )
            """)
            # NEW TABLES FOR WINNER HISTORY
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS airdrop_winners (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    won_at TIMESTAMP,
                    amount INTEGER
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS leaderboard_winners (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    week_start DATE,
                    rank INTEGER,
                    reward INTEGER
                )
            """)
            conn.commit()
    
    def register_marketing_admin_if_needed(self, user_id: int, username: str):
        if user_id == MARKETING_ADMIN_ID:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("INSERT OR IGNORE INTO users (user_id, username, registered_at, is_verified, is_marketing_admin, tokens, level) VALUES (?, ?, ?, 1, 1, 0, '👑 Admin')", (user_id, username, datetime.now()))
                conn.commit()
                return True
        return False
    
    def register_user(self, user_id: int, username: str, tx_hash: str, network: str, invited_by: int = None):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("INSERT OR REPLACE INTO users (user_id, username, registered_at, invited_by, payment_tx_hash, payment_network, is_verified, tokens, level) VALUES (?, ?, ?, ?, ?, ?, 1, 0, '🐣 Newbie')", (user_id, username, datetime.now(), invited_by, tx_hash, network))
            conn.commit()
    
    def update_user_level(self, user_id: int, referral_count: int):
        if referral_count >= 1000:
            level = "👑 Diamond"
        elif referral_count >= 500:
            level = "💎 Platinum"
        elif referral_count >= 100:
            level = "🥇 Gold"
        elif referral_count >= 50:
            level = "🥈 Silver"
        elif referral_count >= 10:
            level = "🥉 Bronze"
        else:
            level = "🐣 Newbie"
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE users SET level = ? WHERE user_id = ?", (level, user_id))
            conn.commit()
    
    def set_user_pin(self, user_id: int, pin: str):
        hashed_pin, salt = hash_pin(pin)
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE users SET user_pin = ?, pin_salt = ?, pin_set_at = ? WHERE user_id = ?", (hashed_pin, salt, datetime.now(), user_id))
            conn.commit()
    
    def verify_user_pin(self, user_id: int, pin: str) -> bool:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT user_pin, pin_salt FROM users WHERE user_id = ?", (user_id,))
            result = cursor.fetchone()
            if not result or not result[0]:
                return False
            return verify_pin(pin, result[0], result[1])
    
    def has_pin(self, user_id: int) -> bool:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT user_pin FROM users WHERE user_id = ?", (user_id,))
            result = cursor.fetchone()
            return result and result[0] is not None
    
    def reset_pin(self, user_id: int):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE users SET user_pin = NULL, pin_salt = NULL, pin_set_at = NULL WHERE user_id = ?", (user_id,))
            conn.commit()
    
    def get_referrer(self, user_id: int) -> int:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT invited_by FROM users WHERE user_id = ?", (user_id,))
            result = cursor.fetchone()
            return result[0] if result else None
    
    def add_balance(self, user_id: int, amount: float):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE users SET balance = balance + ? WHERE user_id = ?", (amount, user_id))
            conn.commit()
    
    def add_tokens_for_referral(self, user_id: int):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE users SET tokens = tokens + ? WHERE user_id = ?", (TOKENS_PER_REFERRAL, user_id))
            conn.commit()
    
    def add_tokens(self, user_id: int, amount: int):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE users SET tokens = tokens + ? WHERE user_id = ?", (amount, user_id))
            conn.commit()
    
    def get_balance(self, user_id: int) -> float:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT balance FROM users WHERE user_id = ?", (user_id,))
            result = cursor.fetchone()
            return result[0] if result else 0
    
    def get_tokens(self, user_id: int) -> int:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT tokens FROM users WHERE user_id = ?", (user_id,))
            result = cursor.fetchone()
            return result[0] if result else 0
    
    def deduct_tokens(self, user_id: int, amount: int) -> bool:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE users SET tokens = tokens - ? WHERE user_id = ? AND tokens >= ?", (amount, user_id, amount))
            conn.commit()
            return cursor.rowcount > 0
    
    def set_wallet_address(self, user_id: int, address: str, network: str):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE users SET wallet_address = ?, wallet_network = ? WHERE user_id = ?", (address, network, user_id))
            conn.commit()
    
    def set_pending_wallet_address(self, user_id: int, address: str, network: str):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE users SET pending_wallet_address = ?, pending_wallet_network = ? WHERE user_id = ?", (address, network, user_id))
            conn.commit()
    
    def get_pending_wallet_address(self, user_id: int):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT pending_wallet_address, pending_wallet_network FROM users WHERE user_id = ?", (user_id,))
            return cursor.fetchone()
    
    def clear_pending_wallet(self, user_id: int):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE users SET pending_wallet_address = NULL, pending_wallet_network = NULL WHERE user_id = ?", (user_id,))
            conn.commit()
    
    def apply_pending_wallet(self, user_id: int) -> bool:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT pending_wallet_address, pending_wallet_network FROM users WHERE user_id = ?", (user_id,))
            result = cursor.fetchone()
            if result and result[0]:
                cursor.execute("UPDATE users SET wallet_address = ?, wallet_network = ?, pending_wallet_address = NULL, pending_wallet_network = NULL WHERE user_id = ?", (result[0], result[1], user_id))
                conn.commit()
                return True
            return False
    
    def set_ton_wallet_address(self, user_id: int, address: str):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE users SET ton_wallet_address = ? WHERE user_id = ?", (address, user_id))
            conn.commit()
    
    def get_ton_wallet_address(self, user_id: int):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT ton_wallet_address FROM users WHERE user_id = ?", (user_id,))
            result = cursor.fetchone()
            return result[0] if result else None
    
    def get_user_wallet(self, user_id: int):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT wallet_address, wallet_network FROM users WHERE user_id = ?", (user_id,))
            return cursor.fetchone()
    
    def add_withdrawal_request(self, user_id: int, amount: float, address: str, network: str):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("INSERT INTO withdrawals (user_id, amount, wallet_address, wallet_network, requested_at) VALUES (?, ?, ?, ?, ?)", (user_id, amount, address, network, datetime.now()))
            conn.commit()
            return cursor.lastrowid
    
    def add_token_withdrawal_request(self, user_id: int, amount: int, address: str):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("INSERT INTO token_withdrawals (user_id, amount, ton_wallet_address, requested_at) VALUES (?, ?, ?, ?)", (user_id, amount, address, datetime.now()))
            conn.commit()
            return cursor.lastrowid
    
    def get_withdrawal(self, request_id: int):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT user_id, amount, wallet_address, wallet_network, status FROM withdrawals WHERE id = ?", (request_id,))
            return cursor.fetchone()
    
    def get_token_withdrawal(self, request_id: int):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT user_id, amount, ton_wallet_address, status FROM token_withdrawals WHERE id = ?", (request_id,))
            return cursor.fetchone()
    
    def update_withdrawal_status(self, request_id: int, status: str):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE withdrawals SET status = ? WHERE id = ?", (status, request_id))
            conn.commit()
    
    def update_token_withdrawal_status(self, request_id: int, status: str):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE token_withdrawals SET status = ? WHERE id = ?", (status, request_id))
            conn.commit()
    
    def deduct_balance(self, user_id: int, amount: float) -> bool:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE users SET balance = balance - ? WHERE user_id = ? AND balance >= ?", (amount, user_id, amount))
            conn.commit()
            return cursor.rowcount > 0
    
    def get_pending_withdrawals(self):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id, user_id, amount, wallet_address, wallet_network, requested_at FROM withdrawals WHERE status = 'pending' ORDER BY requested_at ASC")
            return cursor.fetchall()
    
    def get_pending_token_withdrawals(self):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id, user_id, amount, ton_wallet_address, requested_at FROM token_withdrawals WHERE status = 'pending' ORDER BY requested_at ASC")
            return cursor.fetchall()
    
    def get_stats(self):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM users")
            total_users = cursor.fetchone()[0]
            cursor.execute("SELECT SUM(balance) FROM users")
            total_balance = cursor.fetchone()[0] or 0
            cursor.execute("SELECT SUM(amount) FROM withdrawals WHERE status = 'completed'")
            total_withdrawn = cursor.fetchone()[0] or 0
            cursor.execute("SELECT COUNT(*) FROM withdrawals WHERE status = 'pending'")
            pending_count = cursor.fetchone()[0]
            cursor.execute("SELECT SUM(tokens) FROM users")
            total_tokens = cursor.fetchone()[0] or 0
            return total_users, total_balance, total_withdrawn, pending_count, total_tokens
    
    def user_exists(self, user_id: int) -> bool:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT 1 FROM users WHERE user_id = ?", (user_id,))
            return cursor.fetchone() is not None
    
    def is_marketing_admin(self, user_id: int) -> bool:
        return user_id == MARKETING_ADMIN_ID
    
    def get_user_info(self, user_id: int):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT username, balance, is_marketing_admin, tokens, ton_wallet_address, level FROM users WHERE user_id = ?", (user_id,))
            return cursor.fetchone()
    
    def get_referral_count(self, user_id: int) -> int:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM users WHERE invited_by = ?", (user_id,))
            result = cursor.fetchone()
            return result[0] if result else 0
    
    def get_all_users_by_referrals(self):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT user_id, username, 
                       (SELECT COUNT(*) FROM users WHERE invited_by = u.user_id) as referral_count
                FROM users u
                WHERE referral_count > 0
                ORDER BY referral_count DESC
            """)
            return cursor.fetchall()
    
    def increment_weekly_referral(self, user_id: int):
        today = datetime.now().date()
        week_start = today - timedelta(days=today.weekday())
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("INSERT INTO weekly_referrals (user_id, week_start, count) VALUES (?, ?, 1) ON CONFLICT(user_id) DO UPDATE SET count = count + 1", (user_id, week_start))
            conn.commit()
    
    def get_weekly_leaderboard(self):
        today = datetime.now().date()
        week_start = today - timedelta(days=today.weekday())
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT user_id, count FROM weekly_referrals WHERE week_start = ? ORDER BY count DESC LIMIT 10", (week_start,))
            return cursor.fetchall()
    
    def get_previous_week_winners(self):
        today = datetime.now().date()
        last_week_start = today - timedelta(days=today.weekday() + 7)
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT user_id, count FROM weekly_referrals WHERE week_start = ? ORDER BY count DESC LIMIT 10", (last_week_start,))
            return cursor.fetchall()
    
    def reset_weekly_referrals(self):
        today = datetime.now().date()
        week_start = today - timedelta(days=today.weekday())
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM weekly_referrals WHERE week_start < ?", (week_start,))
            conn.commit()
    
    def get_active_users_for_airdrop(self, limit: int = 10):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT user_id FROM users 
                WHERE (SELECT COUNT(*) FROM users WHERE invited_by = u.user_id) > 0
                ORDER BY RANDOM()
                LIMIT ?
            """, (limit,))
            return cursor.fetchall()
    
    # ========== METHODS FOR PENDING WITHDRAWAL CHECK ==========
    def has_pending_withdrawal(self, user_id: int) -> bool:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT 1 FROM withdrawals WHERE user_id = ? AND status = 'pending'", (user_id,))
            return cursor.fetchone() is not None
    
    def has_pending_token_withdrawal(self, user_id: int) -> bool:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT 1 FROM token_withdrawals WHERE user_id = ? AND status = 'pending'", (user_id,))
            return cursor.fetchone() is not None

    # ========== METHODS FOR WINNER HISTORY ==========
    def record_airdrop_winner(self, user_id: int, amount: int):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("INSERT INTO airdrop_winners (user_id, won_at, amount) VALUES (?, ?, ?)", (user_id, datetime.now(), amount))
            conn.commit()

    def get_airdrop_wins_count(self, user_id: int) -> int:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM airdrop_winners WHERE user_id = ?", (user_id,))
            return cursor.fetchone()[0]

    def record_leaderboard_winner(self, user_id: int, week_start: str, rank: int, reward: int):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("INSERT INTO leaderboard_winners (user_id, week_start, rank, reward) VALUES (?, ?, ?, ?)", (user_id, week_start, rank, reward))
            conn.commit()

    def get_leaderboard_wins_count(self, user_id: int) -> int:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM leaderboard_winners WHERE user_id = ?", (user_id,))
            return cursor.fetchone()[0]

    def get_current_week_leaderboard_rank(self, user_id: int):
        today = datetime.now().date()
        week_start = today - timedelta(days=today.weekday())
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT user_id, count FROM weekly_referrals WHERE week_start = ? ORDER BY count DESC", (week_start,))
            rows = cursor.fetchall()
            for rank, (uid, count) in enumerate(rows, 1):
                if uid == user_id:
                    return rank, count
        return None, 0

db = Database()

# ============================================
# WEEKLY REWARD FUNCTION
# ============================================
async def process_weekly_rewards(context: ContextTypes.DEFAULT_TYPE):
    if not is_weekly_leaderboard_enabled():
        return
    
    winners = db.get_previous_week_winners()
    if not winners:
        return
    
    today = datetime.now().date()
    week_start = today - timedelta(days=today.weekday())
    
    reward_list = []
    for i, (user_id, count) in enumerate(winners, 1):
        if i == 1:
            reward = 50000
        elif i == 2:
            reward = 40000
        elif i == 3:
            reward = 30000
        elif i == 4:
            reward = 25000
        elif i == 5:
            reward = 20000
        else:
            reward = 15000
        
        db.add_tokens(user_id, reward)
        db.record_leaderboard_winner(user_id, week_start.isoformat(), i, reward)
        reward_list.append((user_id, reward, count))
        
        try:
            await context.bot.send_message(chat_id=user_id, text=f"🏆 Weekly Leaderboard Reward! You ranked #{i} with {count} referrals! 🍯 You received {reward} HONEY!")
        except:
            pass
    
    report = "🏆 Weekly Leaderboard Winners\n\n"
    for i, (user_id, reward, count) in enumerate(reward_list, 1):
        user_info = db.get_user_info(user_id)
        username = user_info[0] if user_info else str(user_id)
        report += f"{i}. @{username} - {count} referrals → {reward} HONEY\n"
    
    await context.bot.send_message(chat_id=FINANCE_ADMIN_ID, text=report)
    db.reset_weekly_referrals()

# ============================================
# DAILY SURPRISE AIRDROP (200 HONEY to 10 users = 2,000 total)
# ============================================
async def daily_surprise_airdrop(context: ContextTypes.DEFAULT_TYPE):
    if not is_daily_airdrop_enabled():
        return
    
    winners = db.get_active_users_for_airdrop(10)
    if not winners:
        return
    
    for (user_id,) in winners:
        db.add_tokens(user_id, 200)
        db.record_airdrop_winner(user_id, 200)
        try:
            await context.bot.send_message(chat_id=user_id, text="🎁 Surprise Airdrop! You've been randomly selected as one of today's winners! 🍯 You received 200 HONEY!")
        except:
            pass
    
    await context.bot.send_message(chat_id=FINANCE_ADMIN_ID, text=f"🎁 Daily Surprise Airdrop Completed! 10 users received 200 HONEY each. Total: 2,000 HONEY")

# ============================================
# CHANNEL MEMBERSHIP CHECK
# ============================================
async def is_member_of_main_channel(update: Update, context: ContextTypes.DEFAULT_TYPE) -> bool:
    if not REQUIRED_MAIN_CHANNEL:
        return True
    try:
        chat_member = await context.bot.get_chat_member(chat_id=REQUIRED_MAIN_CHANNEL, user_id=update.effective_user.id)
        return chat_member.status in ["member", "administrator", "creator"]
    except:
        return False

async def is_member_of_airdrop_channel(update: Update, context: ContextTypes.DEFAULT_TYPE) -> bool:
    if not REQUIRED_AIRDROP_CHANNEL:
        return True
    try:
        chat_member = await context.bot.get_chat_member(chat_id=REQUIRED_AIRDROP_CHANNEL, user_id=update.effective_user.id)
        return chat_member.status in ["member", "administrator", "creator"]
    except:
        return False

async def is_member_of_all_channels(update: Update, context: ContextTypes.DEFAULT_TYPE) -> tuple:
    is_main = await is_member_of_main_channel(update, context)
    is_airdrop = await is_member_of_airdrop_channel(update, context)
    return is_main, is_airdrop

async def check_membership_and_continue(update: Update, context: ContextTypes.DEFAULT_TYPE, action_name="use this bot") -> bool:
    is_main, is_airdrop = await is_member_of_all_channels(update, context)
    if not is_main or not is_airdrop:
        keyboard = []
        if not is_main:
            keyboard.append([InlineKeyboardButton("🔗 Join Main Channel", url="https://t.me/Melona_collection")])
        if not is_airdrop:
            keyboard.append([InlineKeyboardButton("🍯 Join HoneyDrop Channel", url="https://t.me/HoneyDrop_Airdrop")])
        keyboard.append([InlineKeyboardButton("✅ I've Joined Both", callback_data="check_membership_continue")])
        await update.message.reply_text(
            f"🔒 You must be a member of both channels to {action_name}:\n\n👉 Main Channel: {REQUIRED_MAIN_CHANNEL}\n🍯 Airdrop Channel: {REQUIRED_AIRDROP_CHANNEL}",
            reply_markup=InlineKeyboardMarkup(keyboard)
        )
        return False
    return True

def is_finance_admin(user_id: int) -> bool:
    return user_id == FINANCE_ADMIN_ID

user_states = {}

def detect_network_from_address(address: str) -> str:
    if address.startswith("T") and len(address) == 34:
        return "TRC20"
    elif address.startswith("0x") and len(address) == 42:
        return "BNB"
    elif address.startswith(("UQ", "EQ")) and len(address) >= 30:
        return "TON"
    return None

def is_valid_ton_address(address: str) -> bool:
    return address.startswith(("UQ", "EQ")) and len(address) >= 30

# ============================================
# ADMIN TOGGLE COMMANDS
# ============================================
@rate_limited
async def close_registration(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_finance_admin(update.effective_user.id):
        await update.message.reply_text("⛔ Unauthorized! Only Finance Admin can use this command.")
        return
    
    set_registration_open(False)
    set_weekly_leaderboard_enabled(False)
    set_daily_airdrop_enabled(False)
    
    await update.message.reply_text(
        "🔒 **New User Registration has been CLOSED!**\n\n"
        "The following features have been automatically disabled:\n"
        "❌ Weekly Leaderboard\n"
        "❌ Daily Surprise Airdrop\n\n"
        "✅ Existing users can still:\n"
        "• Withdraw USD balance\n"
        "• Withdraw HONEY tokens\n"
        "• Check their balance and stats\n\n"
        "Use /open_registration to reopen."
    )

@rate_limited
async def open_registration(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_finance_admin(update.effective_user.id):
        await update.message.reply_text("⛔ Unauthorized! Only Finance Admin can use this command.")
        return
    
    set_registration_open(True)
    set_weekly_leaderboard_enabled(True)
    set_daily_airdrop_enabled(True)
    
    await update.message.reply_text(
        "🔓 **New User Registration has been OPENED!**\n\n"
        "The following features have been automatically enabled:\n"
        "✅ Weekly Leaderboard\n"
        "✅ Daily Surprise Airdrop\n\n"
        "Use /close_registration to close."
    )

@rate_limited
async def registration_status(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_finance_admin(update.effective_user.id):
        await update.message.reply_text("⛔ Unauthorized!")
        return
    
    status = "✅ OPEN" if is_registration_open() else "❌ CLOSED"
    await update.message.reply_text(f"📋 **Registration Status:** {status}")

@rate_limited
async def system_status(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_finance_admin(update.effective_user.id):
        await update.message.reply_text("⛔ Unauthorized!")
        return
    
    status_text = (
        f"📊 **Melona System Status**\n\n"
        f"🔓 Registration: {'✅ OPEN' if is_registration_open() else '❌ CLOSED'}\n"
        f"🏆 Weekly Leaderboard: {'✅ ACTIVE' if is_weekly_leaderboard_enabled() else '❌ INACTIVE'}\n"
        f"🎁 Daily Airdrop: {'✅ ACTIVE' if is_daily_airdrop_enabled() else '❌ INACTIVE'}\n"
        f"🪙 Token Withdrawal: {'✅ ENABLED' if is_token_withdrawal_enabled() else '❌ DISABLED'}\n\n"
        f"📢 After registration closes, users can only withdraw funds."
    )
    await update.message.reply_text(status_text)

@rate_limited
async def enable_leaderboard(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_finance_admin(update.effective_user.id):
        await update.message.reply_text("⛔ Unauthorized!")
        return
    set_weekly_leaderboard_enabled(True)
    await update.message.reply_text("🏆 Weekly Leaderboard ENABLED!")

@rate_limited
async def disable_leaderboard(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_finance_admin(update.effective_user.id):
        await update.message.reply_text("⛔ Unauthorized!")
        return
    set_weekly_leaderboard_enabled(False)
    await update.message.reply_text("❌ Weekly Leaderboard DISABLED!")

@rate_limited
async def leaderboard_status(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_finance_admin(update.effective_user.id):
        await update.message.reply_text("⛔ Unauthorized!")
        return
    status = "✅ ENABLED" if is_weekly_leaderboard_enabled() else "❌ DISABLED"
    await update.message.reply_text(f"🏆 Weekly Leaderboard Status: {status}")

@rate_limited
async def enable_token_withdrawal(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_finance_admin(update.effective_user.id):
        await update.message.reply_text("⛔ Unauthorized!")
        return
    set_token_withdrawal_enabled(True)
    await update.message.reply_text(f"✅ HONEY withdrawal ENABLED!")

@rate_limited
async def disable_token_withdrawal(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_finance_admin(update.effective_user.id):
        await update.message.reply_text("⛔ Unauthorized!")
        return
    set_token_withdrawal_enabled(False)
    await update.message.reply_text(f"❌ HONEY withdrawal DISABLED!")

# ============================================
# PAYMENT VERIFICATION
# ============================================
async def verify_trc20(tx_hash: str, expected_amount: float = 10):
    for attempt in range(len(TRON_API_KEYS)):
        current_key = tron_key_manager.get_next_key()
        try:
            url = f"https://api.trongrid.io/v1/transactions/{tx_hash}/trc20"
            headers = {"TRON-PRO-API-KEY": current_key}
            response = requests.get(url, headers=headers, timeout=30)
            if response.status_code == 200:
                data = response.json()
                for tx in data.get("data", []):
                    if tx.get("token_info", {}).get("symbol") == "USDT":
                        amount = float(tx.get("value", 0)) / 1000000
                        if amount >= expected_amount:
                            return True, amount
                return False, 0
            elif response.status_code == 429:
                continue
            else:
                return False, 0
        except:
            continue
    return False, 0

async def verify_bsc(tx_hash: str, expected_amount: float = 10):
    try:
        tx_receipt = w3.eth.get_transaction_receipt(tx_hash)
        if not tx_receipt or tx_receipt.status != 1:
            return False, 0
        for log in tx_receipt.logs:
            try:
                event = usdt_contract.events.Transfer().process_log(log)
                if event.args.to.lower() == BNB_WALLET.lower():
                    amount = event.args.value / 10**18
                    if amount >= expected_amount:
                        return True, amount
            except:
                continue
        return False, 0
    except:
        return False, 0

async def verify_ton(tx_hash: str, expected_amount: float = 10):
    for attempt in range(len(TON_API_KEYS)):
        current_key = ton_key_manager.get_next_key()
        base_url = "https://toncenter.com/api/v2/"
        headers = {"X-API-Key": current_key}
        try:
            url = f"{base_url}getTransactions"
            params = {"hash": tx_hash}
            response = requests.get(url, params=params, headers=headers, timeout=30)
            data = response.json()
            if data.get("ok") and data.get("result"):
                for tx in data["result"]:
                    out_msgs = tx.get("out_msgs", [])
                    for msg in out_msgs:
                        if msg.get("destination") == TON_WALLET:
                            amount = msg.get("value", 0) / 10**9
                            if amount >= expected_amount:
                                return True, amount
                return False, 0
            elif response.status_code == 429:
                continue
            else:
                return False, 0
        except:
            continue
    return False, 0

# ============================================
# BOT HANDLERS
# ============================================
@rate_limited
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    user_id = user.id
    args = context.args
    
    # Check registration status for new users
    if not db.user_exists(user_id) and not is_registration_open():
        await update.message.reply_text(
            "🔒 **Registration is currently CLOSED!**\n\n"
            "The Melona Bot registration period has ended.\n"
            "Thank you for your interest!\n\n"
            "📢 Existing users can still withdraw their funds.\n"
            "🍯 HONEY token is available on major exchanges."
        )
        return
    
    if user_id == MARKETING_ADMIN_ID and not db.user_exists(user_id):
        db.register_marketing_admin_if_needed(user_id, user.username)
        await update.message.reply_text(f"👑 Welcome Marketing Admin! You have been registered for FREE.")
        return
    
    if args and args[0].startswith("ref_"):
        referrer_id = int(args[0].split("_")[1])
        if referrer_id != user_id and not db.get_referrer(user_id):
            user_states[user_id] = {"referrer": referrer_id}
    
    if db.user_exists(user_id):
        user_info = db.get_user_info(user_id)
        balance = user_info[1] if user_info else 0
        tokens = user_info[3] if user_info else 0
        level = user_info[5] if user_info else "🐣 Newbie"
        has_pin = db.has_pin(user_id)
        pin_status = "🔐 PIN: Set" if has_pin else "🔐 PIN: Not set"
        
        is_main, is_airdrop = await is_member_of_all_channels(update, context)
        if not is_main or not is_airdrop:
            keyboard = []
            if not is_main:
                keyboard.append([InlineKeyboardButton("🔗 Join Main Channel", url="https://t.me/Melona_collection")])
            if not is_airdrop:
                keyboard.append([InlineKeyboardButton("🍯 Join HoneyDrop Channel", url="https://t.me/HoneyDrop_Airdrop")])
            keyboard.append([InlineKeyboardButton("✅ I've Joined Both", callback_data="recheck_membership")])
            await update.message.reply_text(f"{pin_status}\n\n⚠️ You left a required channel!", reply_markup=InlineKeyboardMarkup(keyboard))
            return
        
        await update.message.reply_text(
            f"✅ Already registered!\n{pin_status}\n💰 USD: {balance}\n🍯 HONEY: {tokens}\n📊 Level: {level}\n\n"
            f"Commands:\n/invite - Referral link\n/balance - USD balance\n/token - HONEY balance\n"
            f"/leaderboard - Top referrers\n/mystats - Your stats\n/withdraw - USD payout\n"
            f"/withdraw_token - HONEY payout\n/change_wallet - Change wallet address"
        )
        return
    
    is_main, is_airdrop = await is_member_of_all_channels(update, context)
    if not is_main or not is_airdrop:
        keyboard = []
        if not is_main:
            keyboard.append([InlineKeyboardButton("🔗 Join Main Channel", url="https://t.me/Melona_collection")])
        if not is_airdrop:
            keyboard.append([InlineKeyboardButton("🍯 Join HoneyDrop Channel", url="https://t.me/HoneyDrop_Airdrop")])
        keyboard.append([InlineKeyboardButton("✅ I've Joined Both", callback_data="check_membership")])
        await update.message.reply_text("🔒 Join our channels first!", reply_markup=InlineKeyboardMarkup(keyboard))
        return
    
    keyboard = InlineKeyboardMarkup([[InlineKeyboardButton("💰 Payment Guide", callback_data="payment_guide")]])
    await update.message.reply_text(
        f"🍈 Welcome to Melona Bot!\n\n🍯 Earn HONEY tokens + $5 USD per referral!\n\n"
        f"To register: Send $10 USDT (TRC20, BNB, or TON) and send the transaction hash.\n\n"
        f"After registration:\n• Earn $5 USD per referral\n• Earn 10 HONEY per referral\n\n"
        f"🏆 Top referrers each week win up to 50,000 HONEY!",
        reply_markup=keyboard
    )

@rate_limited
async def recheck_membership(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    user_id = query.from_user.id
    is_main, is_airdrop = await is_member_of_all_channels(update, context)
    if is_main and is_airdrop:
        user_info = db.get_user_info(user_id)
        balance = user_info[1] if user_info else 0
        tokens = user_info[3] if user_info else 0
        level = user_info[5] if user_info else "🐣 Newbie"
        await query.edit_message_text(f"✅ Welcome back!\n💰 USD: {balance}\n🍯 HONEY: {tokens}\n📊 Level: {level}")
    else:
        keyboard = []
        if not is_main:
            keyboard.append([InlineKeyboardButton("🔗 Join Main Channel", url="https://t.me/Melona_collection")])
        if not is_airdrop:
            keyboard.append([InlineKeyboardButton("🍯 Join HoneyDrop Channel", url="https://t.me/HoneyDrop_Airdrop")])
        keyboard.append([InlineKeyboardButton("✅ I've Joined Both", callback_data="recheck_membership")])
        await query.edit_message_text("❌ Still not a member.", reply_markup=InlineKeyboardMarkup(keyboard))

@rate_limited
async def check_membership_continue(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    is_main, is_airdrop = await is_member_of_all_channels(update, context)
    if is_main and is_airdrop:
        await query.edit_message_text("✅ Membership confirmed! Please use the command again.")
    else:
        keyboard = []
        if not is_main:
            keyboard.append([InlineKeyboardButton("🔗 Join Main Channel", url="https://t.me/Melona_collection")])
        if not is_airdrop:
            keyboard.append([InlineKeyboardButton("🍯 Join HoneyDrop Channel", url="https://t.me/HoneyDrop_Airdrop")])
        keyboard.append([InlineKeyboardButton("✅ I've Joined Both", callback_data="check_membership_continue")])
        await query.edit_message_text("❌ Still not a member.", reply_markup=InlineKeyboardMarkup(keyboard))

@rate_limited
async def check_membership(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    is_main, is_airdrop = await is_member_of_all_channels(update, context)
    if is_main and is_airdrop:
        keyboard = InlineKeyboardMarkup([[InlineKeyboardButton("💰 Payment Guide", callback_data="payment_guide")]])
        await query.edit_message_text("✅ Membership confirmed! Click below.", reply_markup=keyboard)
    else:
        keyboard = []
        if not is_main:
            keyboard.append([InlineKeyboardButton("🔗 Join Main Channel", url="https://t.me/Melona_collection")])
        if not is_airdrop:
            keyboard.append([InlineKeyboardButton("🍯 Join HoneyDrop Channel", url="https://t.me/HoneyDrop_Airdrop")])
        keyboard.append([InlineKeyboardButton("✅ I've Joined Both", callback_data="check_membership")])
        await query.edit_message_text("❌ Still not a member.", reply_markup=InlineKeyboardMarkup(keyboard))

@rate_limited
async def payment_guide(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    keyboard = [[InlineKeyboardButton("TRC20", callback_data="select_net_TRC20"), InlineKeyboardButton("BNB", callback_data="select_net_BNB"), InlineKeyboardButton("TON (Gram)", callback_data="select_net_TON")]]
    await query.edit_message_text(
        "💰 Select Network:\n\n• TRC20 - TRON (USDT) - Low fee\n• BNB - BSC (BEP20) - Widely supported\n• TON (Gram) - TON - Very low fee",
        reply_markup=InlineKeyboardMarkup(keyboard)
    )

@rate_limited
async def select_network(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    network = query.data.replace("select_net_", "")
    wallets = {"TRC20": TRC20_WALLET, "BNB": BNB_WALLET, "TON": TON_WALLET}
    network_display = "TON (Gram)" if network == "TON" else network
    await query.edit_message_text(
        f"🔑 Network: {network_display}\n\nSend $10 USDT to:\n`{wallets[network]}`\n\nAfter sending, click below and send your transaction hash.",
        reply_markup=InlineKeyboardMarkup([
            [InlineKeyboardButton("✅ I have the hash", callback_data=f"send_hash_{network}")],
            [InlineKeyboardButton("🔙 Back", callback_data="payment_guide")]
        ])
    )

@rate_limited
async def receive_tx_hash(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    network = query.data.replace("send_hash_", "")
    user_states[query.from_user.id] = {"pending_network": network}
    await query.edit_message_text(f"Send your transaction hash for {network}:")

@rate_limited
async def handle_tx_hash(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    if user_id == MARKETING_ADMIN_ID:
        await update.message.reply_text("👑 Admin registered for free.")
        return
    if db.user_exists(user_id):
        await update.message.reply_text("✅ Already registered!")
        return
    if not is_registration_open():
        await update.message.reply_text("🔒 Registration is CLOSED!")
        return
    if not await check_membership_and_continue(update, context, "register"):
        return
    if user_id not in user_states or "pending_network" not in user_states[user_id]:
        await update.message.reply_text("Select a network from Payment Guide first.")
        return
    
    network = user_states[user_id]["pending_network"]
    tx_hash = update.message.text.strip()
    await update.message.reply_text(f"Verifying transaction on {network}...")
    
    if network == "TRC20":
        is_valid, amount = await verify_trc20(tx_hash)
    elif network == "BNB":
        is_valid, amount = await verify_bsc(tx_hash)
    else:
        is_valid, amount = await verify_ton(tx_hash)
    
    if is_valid:
        referrer_id = user_states[user_id].get("referrer")
        db.register_user(user_id, update.effective_user.username, tx_hash, network, referrer_id)
        
        if referrer_id:
            db.add_balance(referrer_id, 5)
            db.add_tokens_for_referral(referrer_id)
            db.increment_weekly_referral(referrer_id)
            await context.bot.send_message(referrer_id, f"🎉 You earned $5 USD and {TOKENS_PER_REFERRAL} HONEY for a new referral!")
            new_count = db.get_referral_count(referrer_id)
            db.update_user_level(referrer_id, new_count)
        
        del user_states[user_id]
        await ask_for_pin_with_confirm(update, context)
        keyboard = InlineKeyboardMarkup([[InlineKeyboardButton("✅ Set Wallet Address", callback_data="set_wallet")]])
        await update.message.reply_text(
            f"✅ Registration Successful!\n💰 Amount: {amount} USDT\n🌐 Network: {network}\n\nNow set your security PIN above!\nThen set your wallet address.",
            reply_markup=keyboard
        )
    else:
        await update.message.reply_text("❌ Transaction not found or amount less than 10 USDT.")

@rate_limited
async def set_wallet(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    if not db.user_exists(user_id):
        await update.message.reply_text("Register first with /start")
        return
    if not await check_membership_and_continue(update, context, "set wallet"):
        return
    query = update.callback_query
    await query.answer()
    user_states[user_id] = {"setting_wallet": True}
    await query.edit_message_text("Send your wallet address (TRC20, BSC, or TON (Gram)):")

@rate_limited
async def handle_wallet(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    if user_id in user_states and user_states[user_id].get("setting_wallet"):
        address = update.message.text.strip()
        network = detect_network_from_address(address)
        if network:
            db.set_wallet_address(user_id, address, network)
            del user_states[user_id]["setting_wallet"]
            network_display = "TON (Gram)" if network == "TON" else network
            await update.message.reply_text(f"✅ Your {network_display} wallet saved!\n\nUse /invite for referral link.\nUse /leaderboard to see top referrers!")
        else:
            await update.message.reply_text("❌ Invalid address.")

@rate_limited
async def invite(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    if not db.user_exists(user_id):
        await update.message.reply_text("Register first with /start")
        return
    if not await check_membership_and_continue(update, context, "get referral link"):
        return
    bot_username = (await context.bot.get_me()).username
    await update.message.reply_text(
        f"🔗 Your Referral Link\n\n`https://t.me/{bot_username}?start=ref_{user_id}`\n\n• Earn $5 USD per referral\n• Earn 10 HONEY per referral"
    )

@rate_limited
async def balance(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    if not db.user_exists(user_id):
        await update.message.reply_text("Register first with /start")
        return
    if not await check_membership_and_continue(update, context, "check balance"):
        return
    balance = db.get_balance(user_id)
    await update.message.reply_text(f"💰 USD Balance: {balance} USD")

@rate_limited
async def token_info(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    if not db.user_exists(user_id):
        await update.message.reply_text("Register first with /start")
        return
    if not await check_membership_and_continue(update, context, "check tokens"):
        return
    tokens = db.get_tokens(user_id)
    withdrawal_status = "✅ ENABLED" if is_token_withdrawal_enabled() else "❌ DISABLED"
    await update.message.reply_text(f"🍯 HONEY Balance: {tokens}\n🔓 Withdrawal: {withdrawal_status}")

@rate_limited
async def leaderboard(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    if not db.user_exists(user_id):
        await update.message.reply_text("Register first with /start")
        return
    if not await check_membership_and_continue(update, context, "view leaderboard"):
        return
    
    top_users = db.get_all_users_by_referrals()
    if not top_users:
        await update.message.reply_text("📭 No referrals yet!")
        return
    
    text = "🏆 Top Referrers (All-Time)\n\n"
    for i, (user_id, username, count) in enumerate(top_users[:10], 1):
        medal = "🥇" if i == 1 else "🥈" if i == 2 else "🥉" if i == 3 else "📌"
        name = f"@{username}" if username else f"User {user_id}"
        text += f"{medal} #{i} → {name}: {count} referrals\n"
    
    status_text = "✅ ACTIVE" if is_weekly_leaderboard_enabled() else "❌ INACTIVE"
    text += f"\n📊 Weekly Leaderboard: {status_text}\n🏆 Weekly Rewards: 1st:50k | 2nd:40k | 3rd:30k | 4th:25k | 5th:20k | 6-10th:15k HONEY"
    await update.message.reply_text(text)

@rate_limited
async def my_stats(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    if not db.user_exists(user_id):
        await update.message.reply_text("Register first with /start")
        return
    if not await check_membership_and_continue(update, context, "view stats"):
        return
    
    with sqlite3.connect("melona_bot.db") as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT username, balance, tokens,
                   (SELECT COUNT(*) FROM users WHERE invited_by = ?) as referral_count,
                   level
            FROM users WHERE user_id = ?
        """, (user_id, user_id))
        result = cursor.fetchone()
    
    if not result:
        return
    
    username, balance, tokens, referral_count, level = result
    
    cursor.execute("""
        SELECT COUNT(*) + 1 FROM users u
        WHERE (SELECT COUNT(*) FROM users WHERE invited_by = u.user_id) > ?
    """, (referral_count,))
    rank = cursor.fetchone()[0] if referral_count > 0 else "N/A"
    
    has_pin = db.has_pin(user_id)
    pin_status = "✅ Set" if has_pin else "❌ Not set"
    
    wallet = db.get_user_wallet(user_id)
    wallet_address = wallet[0] if wallet else "Not set"
    wallet_network = wallet[1] if wallet else "N/A"
    
    await update.message.reply_text(
        f"📊 Your Stats\n\n👤 @{username or 'N/A'}\n🔐 PIN: {pin_status}\n🏆 Rank: #{rank}\n📊 Level: {level}\n"
        f"👥 Referrals: {referral_count}\n💰 USD: {balance}\n🍯 HONEY: {tokens}\n💳 USD Wallet: {wallet_address} ({wallet_network})"
    )

# ===================== WITHDRAW FUNCTIONS (WITH PENDING CHECK) =====================
@rate_limited
async def withdraw(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    if not db.user_exists(user_id):
        await update.message.reply_text("Register first with /start")
        return
    if not await check_membership_and_continue(update, context, "withdraw"):
        return
    if not db.has_pin(user_id):
        await update.message.reply_text("❌ PIN required!")
        return
    # Check for pending withdrawal request
    if db.has_pending_withdrawal(user_id):
        await update.message.reply_text("⚠️ You already have a pending withdrawal request. Please wait until it is processed.")
        return
    balance = db.get_balance(user_id)
    if balance < 5:
        await update.message.reply_text(f"❌ Minimum 5 USD. Balance: {balance} USD")
        return
    wallet = db.get_user_wallet(user_id)
    if not wallet:
        await update.message.reply_text("Set wallet address first.", reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("✅ Set Wallet", callback_data="set_wallet")]]))
        return
    user_states[user_id] = {"awaiting_pin_for_withdraw": True, "withdraw_amount": balance, "withdraw_wallet": wallet}
    await update.message.reply_text(f"🔐 Verify PIN to withdraw {balance} USD to:\n`{wallet[0]}`")

@rate_limited
async def withdraw_token(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    if not await check_membership_and_continue(update, context, "withdraw tokens"):
        return
    if not is_token_withdrawal_enabled():
        await update.message.reply_text(f"❌ HONEY withdrawal is DISABLED.")
        return
    if not db.user_exists(user_id):
        await update.message.reply_text("Register first with /start")
        return
    if not db.has_pin(user_id):
        await update.message.reply_text("❌ PIN required!")
        return
    # Check for pending token withdrawal request
    if db.has_pending_token_withdrawal(user_id):
        await update.message.reply_text("⚠️ You already have a pending token withdrawal request. Please wait until it is processed.")
        return
    tokens = db.get_tokens(user_id)
    if tokens < 10:
        await update.message.reply_text(f"❌ Minimum 10 HONEY. Balance: {tokens}")
        return
    ton_wallet = db.get_ton_wallet_address(user_id)
    if not ton_wallet:
        await update.message.reply_text("Set TON wallet address with /set_ton_wallet")
        return
    user_states[user_id] = {"awaiting_pin_for_token_withdraw": True, "token_amount": tokens, "ton_wallet": ton_wallet}
    await update.message.reply_text(f"🔐 Verify PIN to withdraw {tokens} HONEY to:\n`{ton_wallet}`")

async def verify_pin_for_withdraw(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    message_id = update.message.message_id
    pin = normalize_pin(update.message.text.strip())
    if user_id not in user_states or not user_states[user_id].get("awaiting_pin_for_withdraw"):
        return
    await context.bot.delete_message(chat_id=user_id, message_id=message_id)
    if db.verify_user_pin(user_id, pin):
        amount = user_states[user_id].get("withdraw_amount", 0)
        wallet = user_states[user_id].get("withdraw_wallet")
        del user_states[user_id]
        req_id = db.add_withdrawal_request(user_id, amount, wallet[0], wallet[1])
        await context.bot.send_message(
            FINANCE_ADMIN_ID,
            f"🆕 Withdrawal #{req_id}\nUser: {user_id}\nAmount: {amount} USD\nWallet: {wallet[0]}\nNetwork: {wallet[1]}",
            reply_markup=InlineKeyboardMarkup([
                [InlineKeyboardButton("✅ Approve", callback_data=f"approve_{req_id}"),
                 InlineKeyboardButton("❌ Reject", callback_data=f"reject_{req_id}")]
            ])
        )
        await update.message.reply_text(f"✅ Withdrawal request #{req_id} submitted.")
    else:
        log_failed_pin_attempt(user_id, pin, "withdraw")
        failed_pin_attempts[user_id] += 1
        remaining = 5 - failed_pin_attempts[user_id]
        if remaining <= 0:
            await update.message.reply_text("❌ Too many failed attempts! Account locked.")
            del user_states[user_id]
        else:
            await update.message.reply_text(f"❌ Incorrect PIN! {remaining}/5 attempts remaining")

async def verify_pin_for_token_withdraw(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    message_id = update.message.message_id
    pin = normalize_pin(update.message.text.strip())
    if user_id not in user_states or not user_states[user_id].get("awaiting_pin_for_token_withdraw"):
        return
    await context.bot.delete_message(chat_id=user_id, message_id=message_id)
    if db.verify_user_pin(user_id, pin):
        tokens = user_states[user_id].get("token_amount", 0)
        ton_wallet = user_states[user_id].get("ton_wallet")
        del user_states[user_id]
        req_id = db.add_token_withdrawal_request(user_id, tokens, ton_wallet)
        await context.bot.send_message(
            FINANCE_ADMIN_ID,
            f"🍯 Token Withdrawal #{req_id}\nUser: {user_id}\nAmount: {tokens} HONEY\nWallet: {ton_wallet}",
            reply_markup=InlineKeyboardMarkup([
                [InlineKeyboardButton("✅ Approve", callback_data=f"approve_token_{req_id}"),
                 InlineKeyboardButton("❌ Reject", callback_data=f"reject_token_{req_id}")]
            ])
        )
        await update.message.reply_text(f"✅ Token withdrawal #{req_id} submitted.")
    else:
        log_failed_pin_attempt(user_id, pin, "token_withdraw")
        failed_pin_attempts[user_id] += 1
        remaining = 5 - failed_pin_attempts[user_id]
        if remaining <= 0:
            await update.message.reply_text("❌ Too many failed attempts! Account locked.")
            del user_states[user_id]
        else:
            await update.message.reply_text(f"❌ Incorrect PIN! {remaining}/5 attempts remaining")

@rate_limited
async def set_ton_wallet(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    if not db.user_exists(user_id):
        await update.message.reply_text("Register first with /start")
        return
    if not is_token_withdrawal_enabled():
        await update.message.reply_text(f"❌ HONEY withdrawal is DISABLED. Wait for admin to enable.")
        return
    if not await check_membership_and_continue(update, context, "set TON wallet"):
        return
    user_states[user_id] = {"setting_ton_wallet": True}
    await update.message.reply_text(f"Send your TON (Gram) wallet address (starts with UQ or EQ):")

@rate_limited
async def handle_ton_wallet(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    if user_id in user_states and user_states[user_id].get("setting_ton_wallet"):
        address = update.message.text.strip()
        if not is_valid_ton_address(address):
            await update.message.reply_text("❌ Invalid TON address. Must start with UQ or EQ.")
            return
        db.set_ton_wallet_address(user_id, address)
        del user_states[user_id]["setting_ton_wallet"]
        tokens = db.get_tokens(user_id)
        await update.message.reply_text(f"✅ TON wallet saved!\n🍯 HONEY Balance: {tokens}")

@rate_limited
async def change_wallet_request(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    if not db.user_exists(user_id):
        await update.message.reply_text("❌ Register first.")
        return
    if not db.has_pin(user_id):
        await update.message.reply_text("❌ No PIN set!")
        return
    user_states[user_id] = {"awaiting_new_wallet": True}
    await update.message.reply_text("🔄 Change Withdrawal Wallet Address\n\nSend your NEW wallet address (TRC20, BSC, or TON):")

async def process_new_wallet(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    message_id = update.message.message_id
    address = update.message.text.strip()
    if user_id not in user_states or not user_states[user_id].get("awaiting_new_wallet"):
        return
    network = detect_network_from_address(address)
    if not network:
        await update.message.reply_text("❌ Invalid address.")
        return
    await context.bot.delete_message(chat_id=user_id, message_id=message_id)
    db.set_pending_wallet_address(user_id, address, network)
    del user_states[user_id]["awaiting_new_wallet"]
    user_states[user_id] = {"verifying_wallet_change": True}
    await update.message.reply_text(f"🔐 Verify PIN to change wallet to:\n`{address}`")

async def verify_pin_for_wallet_change(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    message_id = update.message.message_id
    pin = normalize_pin(update.message.text.strip())
    if user_id not in user_states or not user_states[user_id].get("verifying_wallet_change"):
        return
    await context.bot.delete_message(chat_id=user_id, message_id=message_id)
    if db.verify_user_pin(user_id, pin):
        if db.apply_pending_wallet(user_id):
            new_wallet, network = db.get_user_wallet(user_id)
            network_display = "TON (Gram)" if network == "TON" else network
            await update.message.reply_text(f"✅ Wallet updated to {network_display}: `{new_wallet}`")
        else:
            await update.message.reply_text("❌ Error updating wallet.")
        del user_states[user_id]
    else:
        log_failed_pin_attempt(user_id, pin, "wallet_change")
        failed_pin_attempts[user_id] += 1
        remaining = 5 - failed_pin_attempts[user_id]
        if remaining <= 0:
            await update.message.reply_text("❌ Too many failed attempts! Account locked.")
            del user_states[user_id]
        else:
            await update.message.reply_text(f"❌ Incorrect PIN! {remaining}/5 attempts remaining")

# ============================================
# ADMIN HANDLERS (Withdrawals)
# ============================================
@rate_limited
async def admin_reset_pin(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_finance_admin(update.effective_user.id):
        await update.message.reply_text("⛔ Unauthorized!")
        return
    args = context.args
    if len(args) < 1:
        await update.message.reply_text("Usage: /reset_pin @username")
        return
    username = args[0].replace("@", "")
    with sqlite3.connect("melona_bot.db") as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT user_id FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()
    if not result:
        await update.message.reply_text(f"❌ User @{username} not found!")
        return
    user_id = result[0]
    db.reset_pin(user_id)
    await update.message.reply_text(f"✅ PIN reset for @{username}")
    try:
        await context.bot.send_message(chat_id=user_id, text="🔐 Your PIN has been reset by admin. Please set a new PIN.")
    except:
        pass

@rate_limited
async def list_pending_withdrawals(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_finance_admin(update.effective_user.id):
        await update.message.reply_text("⛔ Unauthorized!")
        return
    pending = db.get_pending_withdrawals()
    if not pending:
        await update.message.reply_text("📭 No pending USD withdrawals.")
        return
    text = "💰 Pending USD Withdrawals:\n\n"
    for req in pending:
        text += f"🔹 #{req[0]} | User: {req[1]} | Amount: {req[2]} USD | Network: {req[4]}\n"
    await update.message.reply_text(text)

@rate_limited
async def list_pending_token_withdrawals(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_finance_admin(update.effective_user.id):
        await update.message.reply_text("⛔ Unauthorized!")
        return
    pending = db.get_pending_token_withdrawals()
    if not pending:
        await update.message.reply_text(f"📭 No pending HONEY withdrawals.")
        return
    text = f"🍯 Pending HONEY Withdrawals:\n\n"
    for req in pending:
        text += f"🔹 #{req[0]} | User: {req[1]} | Amount: {req[2]} HONEY\n"
        text += f"   Wallet: `{req[3][:20]}...`\n\n"
    await update.message.reply_text(text)

@rate_limited
async def stats(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_finance_admin(update.effective_user.id):
        await update.message.reply_text("⛔ Unauthorized!")
        return
    total_users, total_balance, total_withdrawn, pending_count, total_tokens = db.get_stats()
    await update.message.reply_text(
        f"📊 Melona Statistics\n\n👥 Users: {total_users}\n💰 USD Balance: {total_balance} USD\n"
        f"💸 USD Withdrawn: {total_withdrawn} USD\n🍯 HONEY Tokens: {total_tokens}\n"
        f"⏳ Pending USD: {pending_count}\n🔓 Token Withdrawal: {'ENABLED' if is_token_withdrawal_enabled() else 'DISABLED'}"
    )

@rate_limited
async def approve_withdrawal(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_finance_admin(update.effective_user.id):
        await update.callback_query.answer("Unauthorized!", show_alert=True)
        return
    query = update.callback_query
    await query.answer()
    req_id = int(query.data.split("_")[1])
    req = db.get_withdrawal(req_id)
    if not req or req[4] != "pending":
        await query.edit_message_text("❌ Invalid or already processed.")
        return
    user_id, amount, address, network, status = req
    if db.deduct_balance(user_id, amount):
        db.update_withdrawal_status(req_id, "completed")
        await context.bot.send_message(user_id, f"✅ Withdrawal of {amount} USD approved!\nTracking ID: {req_id}")
        await query.edit_message_text(f"✅ Withdrawal #{req_id} approved. {amount} USD deducted.")
    else:
        await query.edit_message_text("❌ Insufficient balance.")

@rate_limited
async def reject_withdrawal(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_finance_admin(update.effective_user.id):
        await update.callback_query.answer("Unauthorized!", show_alert=True)
        return
    query = update.callback_query
    await query.answer()
    req_id = int(query.data.split("_")[1])
    req = db.get_withdrawal(req_id)
    if req and req[4] == "pending":
        db.update_withdrawal_status(req_id, "rejected")
        await context.bot.send_message(req[0], "❌ Your withdrawal has been rejected.")
        await query.edit_message_text(f"❌ Withdrawal #{req_id} rejected.")

@rate_limited
async def approve_token_withdrawal(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_finance_admin(update.effective_user.id):
        await update.callback_query.answer("Unauthorized!", show_alert=True)
        return
    query = update.callback_query
    await query.answer()
    req_id = int(query.data.split("_")[2])
    req = db.get_token_withdrawal(req_id)
    if not req or req[3] != "pending":
        await query.edit_message_text("❌ Invalid or already processed.")
        return
    user_id, amount, ton_wallet, status = req
    if db.deduct_tokens(user_id, amount):
        db.update_token_withdrawal_status(req_id, "completed")
        await context.bot.send_message(user_id, f"✅ HONEY withdrawal of {amount} tokens approved!\nTracking ID: {req_id}")
        await query.edit_message_text(f"✅ Token withdrawal #{req_id} approved. {amount} HONEY deducted.")
    else:
        await query.edit_message_text("❌ Insufficient balance.")

@rate_limited
async def reject_token_withdrawal(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_finance_admin(update.effective_user.id):
        await update.callback_query.answer("Unauthorized!", show_alert=True)
        return
    query = update.callback_query
    await query.answer()
    req_id = int(query.data.split("_")[2])
    req = db.get_token_withdrawal(req_id)
    if req and req[3] == "pending":
        db.update_token_withdrawal_status(req_id, "rejected")
        await context.bot.send_message(req[0], f"❌ Your HONEY withdrawal has been rejected.")
        await query.edit_message_text(f"❌ Token withdrawal #{req_id} rejected.")

# ============================================
# NEW ADMIN COMMAND: USERINFO
# ============================================
@rate_limited
async def userinfo(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not (is_finance_admin(update.effective_user.id) or update.effective_user.id == MARKETING_ADMIN_ID):
        await update.message.reply_text("⛔ Unauthorized! Only admins can use this command.")
        return
    
    args = context.args
    if len(args) < 1:
        await update.message.reply_text("Usage: /userinfo <user_id>\nExample: /userinfo 123456789")
        return
    
    try:
        target_id = int(args[0])
    except ValueError:
        await update.message.reply_text("❌ Invalid user ID. Please enter a numeric ID.")
        return
    
    if not db.user_exists(target_id):
        await update.message.reply_text(f"❌ User {target_id} not found in database.")
        return
    
    user_info = db.get_user_info(target_id)
    if not user_info:
        await update.message.reply_text("❌ Error fetching user info.")
        return
    
    username, balance, is_admin, tokens, ton_wallet, level = user_info
    referral_count = db.get_referral_count(target_id)
    has_pin = db.has_pin(target_id)
    wallet = db.get_user_wallet(target_id)
    wallet_address = wallet[0] if wallet else "Not set"
    wallet_network = wallet[1] if wallet else "N/A"
    
    leaderboard_wins = db.get_leaderboard_wins_count(target_id)
    airdrop_wins = db.get_airdrop_wins_count(target_id)
    current_rank, current_week_count = db.get_current_week_leaderboard_rank(target_id)
    rank_text = f"#{current_rank} (with {current_week_count} referrals)" if current_rank else "Not in top 10 this week"
    
    with sqlite3.connect("melona_bot.db") as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT registered_at FROM users WHERE user_id = ?", (target_id,))
        reg_date = cursor.fetchone()
    reg_date_str = reg_date[0] if reg_date else "Unknown"
    
    message = (
        f"📋 **User Information**\n\n"
        f"🆔 ID: `{target_id}`\n"
        f"👤 Username: @{username or 'No username'}\n"
        f"📅 Registered: {reg_date_str}\n"
        f"🏅 Level: {level}\n"
        f"🔐 PIN: {'✅ Set' if has_pin else '❌ Not set'}\n\n"
        f"💰 USD Balance: {balance} USD\n"
        f"🍯 HONEY Balance: {tokens}\n"
        f"👥 Total Referrals: {referral_count}\n\n"
        f"🏆 Leaderboard Wins (All time): {leaderboard_wins}\n"
        f"📊 Current Week Rank: {rank_text}\n"
        f"🎁 Airdrop Wins (All time): {airdrop_wins}\n\n"
        f"💳 Withdrawal Wallet: {wallet_address} ({wallet_network})\n"
        f"🪙 TON Wallet for HONEY: {ton_wallet or 'Not set'}"
    )
    await update.message.reply_text(message, parse_mode="Markdown")

# ============================================
# PIN SETUP HANDLERS
# ============================================
async def ask_for_pin_with_confirm(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    user_states[user_id] = {"setting_pin": True, "pin_confirm": False}
    await update.message.reply_text(
        "🔐 Set your Security PIN\n\nRequirements:\n• At least 5 characters\n• Must contain at least ONE capital letter (A-Z)\n\n⚠️ This PIN can NEVER be changed!\n\nExamples: Melona123, HoneyDrop2024\n\nEnter your PIN:"
    )

async def save_pin_with_confirm(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    message_id = update.message.message_id
    pin = normalize_pin(update.message.text.strip())
    if user_id not in user_states:
        return
    if user_states[user_id].get("setting_pin") and not user_states[user_id].get("pin_confirm"):
        valid, error = validate_pin(pin)
        if not valid:
            await update.message.reply_text(f"❌ {error}\n\nTry again:")
            return
        user_states[user_id]["temp_pin"] = pin
        user_states[user_id]["pin_confirm"] = True
        await context.bot.delete_message(chat_id=user_id, message_id=message_id)
        await update.message.reply_text("🔄 Confirm your PIN\n\nEnter your PIN again to confirm:")
        return
    elif user_states[user_id].get("pin_confirm"):
        temp_pin = user_states[user_id].get("temp_pin", "")
        pin_normalized = normalize_pin(pin)
        if pin_normalized == temp_pin:
            db.set_user_pin(user_id, temp_pin)
            del user_states[user_id]
            await context.bot.delete_message(chat_id=user_id, message_id=message_id)
            confirm_msg = await update.message.reply_text("✅ PIN set successfully!\n🔒 _This message will self-destruct in 10 seconds..._", parse_mode="Markdown")
            await asyncio.sleep(10)
            await context.bot.delete_message(chat_id=user_id, message_id=confirm_msg.message_id)
        else:
            await update.message.reply_text("❌ PINs do not match! Start over.")
            del user_states[user_id]

# ============================================
# KEEP ALIVE
# ============================================
flask_app = Flask('')

@flask_app.route('/')
def home():
    return f"🍈 Melona Bot is alive! | 🍯 HoneyDrop"

def run():
    flask_app.run(host='0.0.0.0', port=int(os.environ.get("PORT", 8080)))

def keep_alive():
    t = Thread(target=run)
    t.start()

keep_alive()

# ============================================
# MAIN FUNCTION
# ============================================
def main():
    app = Application.builder().token(BOT_TOKEN).build()
    
    # PIN handlers
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, save_pin_with_confirm))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, verify_pin_for_withdraw))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, verify_pin_for_token_withdraw))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, verify_pin_for_wallet_change))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, process_new_wallet))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_ton_wallet))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_wallet))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_tx_hash))
    
    # Commands
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("invite", invite))
    app.add_handler(CommandHandler("balance", balance))
    app.add_handler(CommandHandler("token", token_info))
    app.add_handler(CommandHandler("leaderboard", leaderboard))
    app.add_handler(CommandHandler("mystats", my_stats))
    app.add_handler(CommandHandler("withdraw", withdraw))
    app.add_handler(CommandHandler("withdraw_token", withdraw_token))
    app.add_handler(CommandHandler("set_ton_wallet", set_ton_wallet))
    app.add_handler(CommandHandler("change_wallet", change_wallet_request))
    
    # Admin commands
    app.add_handler(CommandHandler("enable_token", enable_token_withdrawal))
    app.add_handler(CommandHandler("disable_token", disable_token_withdrawal))
    app.add_handler(CommandHandler("pending", list_pending_withdrawals))
    app.add_handler(CommandHandler("pending_tokens", list_pending_token_withdrawals))
    app.add_handler(CommandHandler("stats", stats))
    app.add_handler(CommandHandler("reset_pin", admin_reset_pin))
    app.add_handler(CommandHandler("enable_leaderboard", enable_leaderboard))
    app.add_handler(CommandHandler("disable_leaderboard", disable_leaderboard))
    app.add_handler(CommandHandler("leaderboard_status", leaderboard_status))
    app.add_handler(CommandHandler("close_registration", close_registration))
    app.add_handler(CommandHandler("open_registration", open_registration))
    app.add_handler(CommandHandler("registration_status", registration_status))
    app.add_handler(CommandHandler("system_status", system_status))
    # NEW ADMIN COMMAND
    app.add_handler(CommandHandler("userinfo", userinfo))
    
    # Callbacks
    app.add_handler(CallbackQueryHandler(recheck_membership, pattern="recheck_membership"))
    app.add_handler(CallbackQueryHandler(check_membership_continue, pattern="check_membership_continue"))
    app.add_handler(CallbackQueryHandler(check_membership, pattern="check_membership"))
    app.add_handler(CallbackQueryHandler(payment_guide, pattern="payment_guide"))
    app.add_handler(CallbackQueryHandler(select_network, pattern="select_net_"))
    app.add_handler(CallbackQueryHandler(receive_tx_hash, pattern="send_hash_"))
    app.add_handler(CallbackQueryHandler(set_wallet, pattern="set_wallet"))
    app.add_handler(CallbackQueryHandler(approve_withdrawal, pattern="approve_"))
    app.add_handler(CallbackQueryHandler(reject_withdrawal, pattern="reject_"))
    app.add_handler(CallbackQueryHandler(approve_token_withdrawal, pattern="approve_token_"))
    app.add_handler(CallbackQueryHandler(reject_token_withdrawal, pattern="reject_token_"))
    
    # Schedules
    job_queue = app.job_queue
    if job_queue:
        job_queue.run_daily(process_weekly_rewards, time=datetime.time(hour=0, minute=0, second=0), days_of_week=(0,))
        job_queue.run_daily(daily_surprise_airdrop, time=datetime.time(hour=12, minute=0, second=0))
        print("📅 Weekly rewards scheduled for Monday 00:00 UTC")
        print("🎁 Daily airdrop scheduled for 12:00 UTC")
    
    print(f"🍈 Melona Bot is running!")
    print(f"   Main Channel: {REQUIRED_MAIN_CHANNEL}")
    print(f"   Airdrop Channel: {REQUIRED_AIRDROP_CHANNEL}")
    print(f"   Registration: {'OPEN' if is_registration_open() else 'CLOSED'}")
    print(f"   Weekly Leaderboard: {'ENABLED' if is_weekly_leaderboard_enabled() else 'DISABLED'}")
    print(f"   Daily Airdrop: {'ENABLED' if is_daily_airdrop_enabled() else 'DISABLED'}")
    print(f"   Token Withdrawal: {'ENABLED' if is_token_withdrawal_enabled() else 'DISABLED'}")
    
    if os.environ.get("RAILWAY_ENVIRONMENT"):
        port = int(os.environ.get("PORT", 8080))
        app.run_webhook(
            listen="0.0.0.0",
            port=port,
            url_path=f"/webhook/{BOT_TOKEN}",
            webhook_url=f"{os.environ['PUBLIC_URL']}/webhook/{BOT_TOKEN}"
        )
    else:
        app.run_polling(allowed_updates=Update.ALL_TYPES)

if __name__ == "__main__":
    main()