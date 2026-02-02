import requests
from gatet import Tele
import traceback
import html
import os
import json
import time
import threading
import re
from telebot import TeleBot
from hit_sender import send  


# ==============================
# CONFIG FILE
# ==============================
CONFIG_FILE = "config.json"
DEFAULT_CONFIG = {
    "allowed_groups": [
    -1003530017927,
],
    "require_approval": True,
    "only_group": True,                 # if True: users can use only in allowed groups
    "maintenance": False,               # if True: bot locked for users (admin can still use)
    "user_cooldown_sec": 7,
    "group_cooldown_sec": 1,

    "free_daily_credits": 1,            # /daily gives this amount
    "daily_cooldown_sec": 24 * 3600,    # 24h

    "spam_ban_threshold": 10,           # auto-ban after N spam hits
    "block_forwarded": True,            # block forwarded messages (non-admin)
    "block_links": True,                # block http/https links (non-admin)

    "rules_text": "• No spam\n• No forwarded messages\n• No links\n• Use commands properly\n• Respect admins"
}

# ==============================
# BASIC CONFIG
# ==============================
MAX_CARDS = 10
checker_name = "@buik100"

ADMIN_IDS = [
    7078867529,
    7415233736,   # owner/admin id m   1696442023,   # second admin
]

LOG_CHANNEL = -1003871702658

# ==============================
# LOAD TOKEN
# ==============================
with open("token.txt", "r", encoding="utf-8") as f:
    TOKEN = f.read().strip()

bot = TeleBot(TOKEN, parse_mode="HTML")

# ==============================
# THREAD SAFETY
# ==============================
DB_LOCK = threading.Lock()

# ==============================
# DB
# ==============================
CREDITS_FILE = "credits.json"
DEFAULT_CREDITS = 1

# ==============================
# HELPERS
# ==============================
def esc(s):
    return (str(s) if s is not None else "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

def now_ts():
    return int(time.time())

def as_pre(text: str) -> str:
    return f"<pre>{text}</pre>"

def is_admin(uid: int) -> bool:
    return uid in ADMIN_IDS

def format_bool(b) -> str:
    return "YES" if bool(b) else "NO"

def send_log(text):
    try:
        bot.send_message(LOG_CHANNEL, text, parse_mode="HTML")
    except:
        pass
        
# ================= BIN LOOKUP =================
BIN_CACHE = {}

def get_bin_info(cc):
    bin6 = cc.split("|", 1)[0][:6]

    if bin6 in BIN_CACHE:
        return BIN_CACHE[bin6]

    info = {
        "bank": "UNKNOWN",
        "country": "UNKNOWN",
        "flag": "🏳️"
    }

    try:
        r = requests.get(
            f"https://bins.antipublic.cc/bins/{bin6}",
            timeout=8,
            headers={
                "User-Agent": "Mozilla/5.0 (BIN Lookup)"
            }
        )
        r.raise_for_status()

        d = r.json()
        info["bank"] = d.get("bank", info["bank"])
        info["country"] = d.get("country", info["country"])
        info["flag"] = d.get("country_flag", info["flag"])

    except Exception as e:
        print(f"[BIN ERROR] {bin6} -> {repr(e)}")

    BIN_CACHE[bin6] = info
    return info

# ==============================
# JSON IO (SAFE)
# ==============================
def _safe_read_json(path, default):
    if not os.path.exists(path):
        return default
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except:
        return default

def _safe_write_json(path, data):
    """
    Writes temp file safely, then atomic replace
    - Has fallbacks so bot never crashes
    """
    tmp = path + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        os.replace(tmp, path)
    except FileNotFoundError:
        # fallback: direct write
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
        except:
            pass
    except Exception:
        # last fallback
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
        except:
            pass

def load_config():
    cfg = _safe_read_json(CONFIG_FILE, DEFAULT_CONFIG.copy())
    for k, v in DEFAULT_CONFIG.items():
        cfg.setdefault(k, v)
    _safe_write_json(CONFIG_FILE, cfg)
    return cfg

def save_config(cfg):
    _safe_write_json(CONFIG_FILE, cfg)

def load_db():
    with DB_LOCK:
        return _safe_read_json(CREDITS_FILE, {})

def save_db(db):
    with DB_LOCK:
        _safe_write_json(CREDITS_FILE, db)

def set_plan_for_user(u: dict):
    # simple auto plan: if credits >= 1000 => VIP else FREE
    try:
        u["plan"] = "VIP" if int(u.get("credits", 0)) >= 1000 else "FREE"
    except:
        u["plan"] = "FREE"

def ensure_user(user_id):
    uid = str(user_id)
    db = load_db()

    if uid not in db:
        db[uid] = {
            "credits": DEFAULT_CREDITS,
            "approved": False,
            "banned": False,
            "created_at": now_ts(),
            "last_daily": 0,
            "checks": 0,
            "spam": 0,
            "plan": "FREE"
        }
        set_plan_for_user(db[uid])
        save_db(db)
        return db

    # ensure keys exist (only save if changed)
    changed = False
    defaults = {
        "credits": DEFAULT_CREDITS,
        "approved": False,
        "banned": False,
        "created_at": now_ts(),
        "last_daily": 0,
        "checks": 0,
        "spam": 0,
        "plan": "FREE"
    }
    for k, v in defaults.items():
        if k not in db[uid]:
            db[uid][k] = v
            changed = True

    # refresh plan
    before_plan = db[uid].get("plan")
    set_plan_for_user(db[uid])
    if db[uid].get("plan") != before_plan:
        changed = True

    if changed:
        save_db(db)

    return db

# ==============================
# COOLDOWN
# ==============================
LAST_USER = {}
LAST_GROUP = {}

def hit_cooldown(message):
    cfg = load_config()
    now = time.time()

    uid = message.from_user.id
    gid = message.chat.id

    # group cooldown (only in groups)
    if message.chat.type in ["group", "supergroup"]:
        if now - LAST_GROUP.get(gid, 0) < int(cfg.get("group_cooldown_sec", 1)):
            return f"Group cooldown: {cfg.get('group_cooldown_sec', 1)}s"
        LAST_GROUP[gid] = now

    # user cooldown (all chats)
    if now - LAST_USER.get(uid, 0) < int(cfg.get("user_cooldown_sec", 7)):
        return f"User cooldown: {cfg.get('user_cooldown_sec', 7)}s"
    LAST_USER[uid] = now

    return None

# ==============================
# SPAM / SECURITY
# ==============================
def contains_link(text: str) -> bool:
    t = (text or "").lower()
    return ("http://" in t) or ("https://" in t) or ("t.me/" in t)

def _add_spam_hit(user_id: int, reason: str = ""):
    cfg = load_config()
    db = ensure_user(user_id)
    uid = str(user_id)

    db[uid]["spam"] = int(db[uid].get("spam", 0)) + 1

    threshold = int(cfg.get("spam_ban_threshold", 10))
    if db[uid]["spam"] >= threshold:
        db[uid]["banned"] = True
        save_db(db)
        send_log(f"⛔ Auto-banned <code>{uid}</code> (spam={db[uid]['spam']}) Reason: {esc(reason)}")
        return

    save_db(db)

def spam_guard(message) -> bool:
    """
    Returns True if message is allowed, False if blocked (and counts spam for non-admin).
    """
    cfg = load_config()
    if is_admin(message.from_user.id):
        return True

    # forwarded block
    if cfg.get("block_forwarded", True):
        if getattr(message, "forward_from", None) or getattr(message, "forward_from_chat", None) or getattr(message, "forward_sender_name", None):
            _add_spam_hit(message.from_user.id, reason="Forwarded message blocked")
            bot.reply_to(message, "❌ Forwarded messages are not allowed.")
            return False

    # link block
    if cfg.get("block_links", True):
        if contains_link(message.text or ""):
            _add_spam_hit(message.from_user.id, reason="Link blocked")
            bot.reply_to(message, "❌ Links are not allowed.")
            return False

    return True

# ==============================
# ACCESS CONTROL (Group for users, Private for owner/admin)
# ==============================
def guard_access(message):
    cfg = load_config()

    # maintenance
    if cfg.get("maintenance", False) and not is_admin(message.from_user.id):
        bot.reply_to(message, "🛠 Bot is under maintenance. Please try later.")
        return False

    # private
    if message.chat.type == "private":
        if is_admin(message.from_user.id):
            return True

        if not cfg.get("only_group", True):
            db = ensure_user(message.from_user.id)
            u = db[str(message.from_user.id)]
            if u.get("banned"):
                bot.reply_to(message, "⛔ You are banned.")
                return False
            if cfg.get("require_approval", True) and not u.get("approved"):
                bot.reply_to(message, "⛔ Approval required. Use /request in the allowed group.")
                return False
            return True

        bot.reply_to(message, "❌ This bot is group-only for users. (Owner can use in private)")
        return False

    # groups only
    if message.chat.type not in ["group", "supergroup"]:
        bot.reply_to(message, "❌ Unsupported chat type.")
        return False

    # allowed groups
    if message.chat.id not in cfg.get("allowed_groups", []):
        bot.reply_to(message, "❌ Not allowed in this group.")
        return False

    # admin always ok
    if is_admin(message.from_user.id):
        return True

    # user checks
    db = ensure_user(message.from_user.id)
    u = db[str(message.from_user.id)]

    if u.get("banned"):
        bot.reply_to(message, "⛔ You are banned.")
        return False

    if cfg.get("require_approval", True) and not u.get("approved"):
        bot.reply_to(message, "⛔ Approval required. Use /request.")
        return False

    return True

def spend_credit(message, cost):
    db = ensure_user(message.from_user.id)
    uid = str(message.from_user.id)
    u = db[uid]

    if int(u.get("credits", 0)) < int(cost):
        bot.reply_to(message, "❌ No credits left.")
        return None

    u["credits"] = int(u.get("credits", 0)) - int(cost)
    set_plan_for_user(u)
    db[uid] = u
    save_db(db)
    return u["credits"]

# ✅ FIXED: spend_credit_or_block (DICT-BASED DB)
def spend_credit_or_block(message, cost=1):
    db = ensure_user(message.from_user.id)
    uid = str(message.from_user.id)
    u = db[uid]

    credits = int(u.get("credits", 0))
    cost = int(cost)

    if credits < cost:
        bot.reply_to(
            message,
            f"❌ <b>Not enough credits!</b>\n"
            f"💳 Required: {cost}\n"
            f"💰 Your credits: {credits}",
            parse_mode="HTML"
        )
        return None

    u["credits"] = credits - cost
    set_plan_for_user(u)
    db[uid] = u
    save_db(db)
    return u["credits"]

# ==============================
# ADMIN HELPERS
# ==============================
def admin_only(message):
    if not is_admin(message.from_user.id):
        bot.reply_to(message, "❌ Admin only.")
        return False
    return True

def parse_args(message):
    return (message.text or "").split()

# ==============================
# STARTUP: ensure files exist
# ==============================
load_config()
save_db(load_db())
send_log("✅ LOG TEST OK")

# ==============================
# BASIC UTIL COMMANDS
# ==============================
@bot.message_handler(commands=["ping"])
def ping_cmd(message):
    if not guard_access(message): return
    if not spam_guard(message): return
    bot.reply_to(message, "✅ Pong!")

@bot.message_handler(commands=["myid"])
def myid_cmd(message):
    if not guard_access(message): return
    if not spam_guard(message): return
    bot.reply_to(
        message,
        as_pre(
            f"USER ID : {message.from_user.id}\n"
            f"CHAT ID : {message.chat.id}\n"
            f"TYPE    : {message.chat.type}"
        ),
        parse_mode="HTML"
    )

@bot.message_handler(commands=["showid"])
def showid_cmd(message):
    if not admin_only(message): return
    title = getattr(message.chat, "title", "N/A")
    bot.reply_to(
        message,
        as_pre(
            f"CHAT TYPE : {message.chat.type}\n"
            f"TITLE     : {title}\n"
            f"CHAT ID   : {message.chat.id}"
        ),
        parse_mode="HTML"
    )

# ==============================
# START / HELP (FULL)
# ==============================
@bot.message_handler(commands=["start", "help", "cmds"])
def start_cmd(message):
    if not guard_access(message): return
    if not spam_guard(message): return

    db = ensure_user(message.from_user.id)
    u = db[str(message.from_user.id)]
    set_plan_for_user(u)
    save_db(db)

    cfg = load_config()
    username = message.from_user.username or "NoUsername"

    text = (
    "┏━━ WELCOME ━━┓\n"
    f"User        : @{username}\n"
    f"Plan        : {u.get('plan','FREE')}\n"
    f"Credits     : {u.get('credits',0)}\n"
    f"Approved    : {format_bool(u.get('approved'))}\n"
    f"Banned      : {format_bool(u.get('banned'))}\n"
    f"Chat ID     : {message.chat.id}\n"
    f"Chat Type   : {message.chat.type}\n"
    "\n"
    "┏━━ SETTINGS ━━┓\n"
    f"Only Group        : {format_bool(cfg.get('only_group', True))}\n"
    f"Require Approval  : {format_bool(cfg.get('require_approval', True))}\n"
    f"Maintenance       : {format_bool(cfg.get('maintenance', False))}\n"
    f"User Cooldown     : {cfg.get('user_cooldown_sec')}s\n"
    f"Group Cooldown    : {cfg.get('group_cooldown_sec')}s\n"
    f"Daily Credits     : {cfg.get('free_daily_credits')} (every 24h)\n"
    "\n"
    "┏━━ USER COMMANDS ━━┓\n"
    "/cvv      - Demo action (uses 1 credit)\n"
    "/daily    - Claim daily credits\n"
    "/status   - Your status\n"
    "/info     - Your info\n"
    "/rules    - Group rules\n"
    "/request  - Request approval/credits\n"
    "\n"
    "┏━━ OWNER/ADMIN ━━┓\n"
    "/approve user_id\n"
    "/unapprove user_id\n"
    "/vip user_id      - Give VIP (private allow)\n"
    "/unvip user_id    - Remove VIP\n"
    "/addcredits user_id amount\n"
    "/setcredits user_id amount\n"
    "/ban user_id\n"
    "/unban user_id\n"
    "/userinfo user_id\n"
    "/stats\n"
    "/addgroup chat_id\n"
    "/delgroup chat_id\n"
    "/listgroups\n"
    "/toggleapproval\n"
    "/onlygroup on|off\n"
    "/maintenance on|off\n"
    "/setcooldown user|group seconds\n"
    "/setlog chat_id\n"
    "/setname @botname\n"
    "\n"
    f"Bot : {checker_name}\n"
    "┗━━━━━━━━━━━━━━━━━━┛"
)
    bot.reply_to(message, as_pre(text), parse_mode="HTML")

# ==============================
# RULES
# ==============================
@bot.message_handler(commands=["rules"])
def rules_cmd(message):
    if not guard_access(message): return
    if not spam_guard(message): return
    cfg = load_config()
    bot.reply_to(message, as_pre("RULES:\n" + str(cfg.get("rules_text", ""))), parse_mode="HTML")

# ==============================
# INFO / STATUS
# ==============================
@bot.message_handler(commands=["info"])
def info_cmd(message):
    if not guard_access(message): return
    if not spam_guard(message): return

    db = ensure_user(message.from_user.id)
    u = db[str(message.from_user.id)]
    set_plan_for_user(u)
    save_db(db)

    username = message.from_user.username or "NoUsername"
    text = (
        "┏━━ YOUR INFO ━━┓\n"
        f"User     : @{username}\n"
        f"Plan     : {u.get('plan','FREE')}\n"
        f"Credits  : {u.get('credits',0)}\n"
        f"Approved : {format_bool(u.get('approved'))}\n"
        f"Banned   : {format_bool(u.get('banned'))}\n"
        f"Checks   : {u.get('checks',0)}\n"
        f"Spam     : {u.get('spam',0)}\n"
        "┗━━━━━━━━━━━━━━━━━━┛"
    )
    bot.reply_to(message, as_pre(text), parse_mode="HTML")

@bot.message_handler(commands=["status", "me"])
def status_cmd(message):
    if not guard_access(message): return
    if not spam_guard(message): return

    cd = hit_cooldown(message)
    if cd:
        bot.reply_to(message, f"⏳ {cd}")
        return

    db = ensure_user(message.from_user.id)
    u = db[str(message.from_user.id)]
    set_plan_for_user(u)
    save_db(db)

    username = message.from_user.username or "NoUsername"
    text = (
        "┏━━ STATUS ━━┓\n"
        f"User    : @{username}\n"
        f"Plan    : {u.get('plan','FREE')}\n"
        f"Credits : {u.get('credits',0)}\n"
        f"Chat    : {message.chat.id}\n"
        "┗━━━━━━━━━━━━━━━━━━┛"
    )
    bot.reply_to(message, as_pre(text), parse_mode="HTML")

# ==============================
# DAILY CREDITS
# ==============================
@bot.message_handler(commands=["daily"])
def daily_cmd(message):
    if not guard_access(message): return
    if not spam_guard(message): return

    db = ensure_user(message.from_user.id)
    uid = str(message.from_user.id)
    u = db[uid]

    cooldown = 24 * 3600   # 1 day
    amount = 50            # 50 credits

    last = int(u.get("last_daily", 0))
    now = now_ts()
    remain = cooldown - (now - last)

    if remain > 0:
        hrs = remain // 3600
        mins = (remain % 3600) // 60
        bot.reply_to(
            message,
            f"⏳ Daily already claimed.\nTry again in {hrs}h {mins}m."
        )
        return

    u["credits"] = int(u.get("credits", 0)) + amount
    u["last_daily"] = now

    db[uid] = u
    save_db(db)

    bot.reply_to(
        message,
        f"✅ Daily claimed!\n➕ {amount} credits\n💳 Total: {u['credits']}"
    )
# ==============================
# REQUEST
# ==============================
@bot.message_handler(commands=["request"])
def request_cmd(message):
    cfg = load_config()
    if message.chat.type not in ["group", "supergroup"]:
        bot.reply_to(message, "❌ Use /request in the allowed group.")
        return
    if message.chat.id not in cfg.get("allowed_groups", []):
        bot.reply_to(message, "❌ Not allowed in this group.")
        return

    if not spam_guard(message): return

    cd = hit_cooldown(message)
    if cd:
        bot.reply_to(message, f"⏳ {cd}")
        return

    uid = message.from_user.id
    username = message.from_user.username or "NoUsername"

    bot.reply_to(message, "✅ Request sent to admin.")

    admin_text = as_pre(
        "┏━━ NEW REQUEST ━━┓\n"
        f"User    : @{username}\n"
        f"User ID : {uid}\n"
        f"Group   : {message.chat.id}\n"
        "\n"
        "Quick Actions:\n"
        f"/approve {uid}\n"
        f"/addcredits {uid} 5\n"
        "┗━━━━━━━━━━━━━━━━━━┛"
    )

    for admin_id in ADMIN_IDS:
        try:
            bot.send_message(admin_id, admin_text, parse_mode="HTML")
        except:
            pass

    send_log(f"📩 Request from @{esc(username)} (<code>{uid}</code>) in <code>{message.chat.id}</code>")

# ==============================
# DEMO /CHK (SAFE PLACEHOLDER)
# ==============================
@bot.message_handler(commands=["chk"])
def chk_cmd(message):
    if not guard_access(message): return
    if not spam_guard(message): return

    cd = hit_cooldown(message)
    if cd:
        bot.reply_to(message, f"⏳ {cd}")
        return

    remaining = spend_credit(message, 1)
    if remaining is None:
        return

    db = ensure_user(message.from_user.id)
    uid = str(message.from_user.id)
    db[uid]["checks"] = int(db[uid].get("checks", 0)) + 1
    save_db(db)

    username = message.from_user.username or "NoUsername"
    text = (
        "┏━━ CHK (DEMO) ━━┓\n"
        f"User      : @{username}\n"
        f"Cost      : 1 credit\n"
        f"Remaining : {remaining}\n"
        f"Checks    : {db[uid].get('checks', 0)}\n"
        "\n"
        "This is a demo command.\n"
        "Access / cooldown / credits are working.\n"
        "┗━━━━━━━━━━━━━━━━━━┛"
    )
    bot.reply_to(message, as_pre(text), parse_mode="HTML")

# ==============================
# ADMIN: USER MANAGEMENT
# ==============================
@bot.message_handler(commands=["userinfo"])
def userinfo_cmd(message):
    if not admin_only(message): return
    args = parse_args(message)
    if len(args) != 2:
        bot.reply_to(message, "Usage: /userinfo user_id")
        return
    target = args[1]

    db = load_db()
    u = db.get(str(target))
    if not u:
        bot.reply_to(message, "❌ User not found.")
        return

    text = (
        "┏━━ USER INFO ━━┓\n"
        f"ID       : {target}\n"
        f"Plan     : {u.get('plan','FREE')}\n"
        f"Credits  : {u.get('credits',0)}\n"
        f"Approved : {format_bool(u.get('approved'))}\n"
        f"Banned   : {format_bool(u.get('banned'))}\n"
        f"Checks   : {u.get('checks',0)}\n"
        f"Spam     : {u.get('spam',0)}\n"
        "┗━━━━━━━━━━━━━━━━━━┛"
    )
    bot.reply_to(message, as_pre(text), parse_mode="HTML")

@bot.message_handler(commands=["approve"])
def approve_cmd(message):
    if not admin_only(message): return
    args = parse_args(message)
    if len(args) != 2:
        bot.reply_to(message, "Usage: /approve user_id")
        return
    target = args[1]

    db = ensure_user(target)
    uid = str(target)
    db[uid]["approved"] = True
    db[uid].setdefault("credits", DEFAULT_CREDITS)
    db[uid]["banned"] = False
    set_plan_for_user(db[uid])
    save_db(db)

    bot.reply_to(message, f"✅ Approved: {uid}")
    try:
        bot.send_message(int(uid), "✅ You have been approved by admin.")
    except:
        pass

@bot.message_handler(commands=["unapprove"])
def unapprove_cmd(message):
    if not admin_only(message): return
    args = parse_args(message)
    if len(args) != 2:
        bot.reply_to(message, "Usage: /unapprove user_id")
        return
    target = args[1]

    db = ensure_user(target)
    uid = str(target)
    db[uid]["approved"] = False
    save_db(db)

    bot.reply_to(message, f"✅ Unapproved: {uid}")
    try:
        bot.send_message(int(uid), "⚠️ You have been unapproved by admin.")
    except:
        pass

@bot.message_handler(commands=["ban"])
def ban_cmd(message):
    if not admin_only(message): return
    args = parse_args(message)
    if len(args) != 2:
        bot.reply_to(message, "Usage: /ban user_id")
        return
    target = args[1]

    db = ensure_user(target)
    uid = str(target)
    db[uid]["banned"] = True
    save_db(db)

    bot.reply_to(message, f"⛔ Banned: {uid}")

@bot.message_handler(commands=["unban"])
def unban_cmd(message):
    if not admin_only(message): return
    args = parse_args(message)
    if len(args) != 2:
        bot.reply_to(message, "Usage: /unban user_id")
        return
    target = args[1]

    db = ensure_user(target)
    uid = str(target)
    db[uid]["banned"] = False
    save_db(db)

    bot.reply_to(message, f"✅ Unbanned: {uid}")

@bot.message_handler(commands=["addcredits"])
def addcredits_cmd(message):
    if not admin_only(message): return
    args = parse_args(message)
    if len(args) != 3:
        bot.reply_to(message, "Usage: /addcredits user_id amount")
        return
    target, amt = args[1], args[2]
    try:
        amt = int(amt)
        if amt <= 0:
            raise ValueError
    except:
        bot.reply_to(message, "❌ amount must be a positive number")
        return

    db = ensure_user(target)
    uid = str(target)
    db[uid]["credits"] = int(db[uid].get("credits", 0)) + amt
    set_plan_for_user(db[uid])
    save_db(db)

    bot.reply_to(message, f"✅ Added {amt} credits to {uid}. Now: {db[uid]['credits']}")

@bot.message_handler(commands=["setcredits"])
def setcredits_cmd(message):
    if not admin_only(message): return
    args = parse_args(message)
    if len(args) != 3:
        bot.reply_to(message, "Usage: /setcredits user_id amount")
        return
    target, amt = args[1], args[2]
    try:
        amt = int(amt)
        if amt < 0:
            raise ValueError
    except:
        bot.reply_to(message, "❌ amount must be >= 0")
        return

    db = ensure_user(target)
    uid = str(target)
    db[uid]["credits"] = amt
    set_plan_for_user(db[uid])
    save_db(db)

    bot.reply_to(message, f"✅ Set credits for {uid} to {amt}")

# ==============================
# ADMIN: SETTINGS
# ==============================
@bot.message_handler(commands=["toggleapproval"])
def toggleapproval_cmd(message):
    if not admin_only(message): return
    cfg = load_config()
    cfg["require_approval"] = not bool(cfg.get("require_approval", True))
    save_config(cfg)
    bot.reply_to(message, f"✅ require_approval = {cfg['require_approval']}")

@bot.message_handler(commands=["onlygroup"])
def onlygroup_cmd(message):
    if not admin_only(message): return
    args = parse_args(message)
    if len(args) != 2 or args[1].lower() not in ["on", "off"]:
        bot.reply_to(message, "Usage: /onlygroup on|off")
        return
    cfg = load_config()
    cfg["only_group"] = True if args[1].lower() == "on" else False
    save_config(cfg)
    bot.reply_to(message, f"✅ only_group = {cfg['only_group']}")

@bot.message_handler(commands=["maintenance"])
def maintenance_cmd(message):
    if not admin_only(message): return
    args = parse_args(message)
    if len(args) != 2 or args[1].lower() not in ["on", "off"]:
        bot.reply_to(message, "Usage: /maintenance on|off")
        return
    cfg = load_config()
    cfg["maintenance"] = True if args[1].lower() == "on" else False
    save_config(cfg)
    bot.reply_to(message, f"✅ maintenance = {cfg['maintenance']}")

@bot.message_handler(commands=["setcooldown"])
def setcooldown_cmd(message):
    if not admin_only(message): return
    args = parse_args(message)
    if len(args) != 3:
        bot.reply_to(message, "Usage: /setcooldown user|group seconds")
        return
    mode = args[1].lower().strip()
    try:
        secs = int(args[2])
        if secs < 0 or secs > 3600:
            raise ValueError
    except:
        bot.reply_to(message, "❌ seconds must be 0~3600")
        return

    cfg = load_config()
    if mode == "user":
        cfg["user_cooldown_sec"] = secs
    elif mode == "group":
        cfg["group_cooldown_sec"] = secs
    else:
        bot.reply_to(message, "❌ mode must be user or group")
        return
    save_config(cfg)
    bot.reply_to(message, f"✅ cooldown updated: {mode} = {secs}s")

@bot.message_handler(commands=["setlog"])
def setlog_cmd(message):
    if not admin_only(message): return
    global LOG_CHANNEL
    args = parse_args(message)
    if len(args) != 2:
        bot.reply_to(message, "Usage: /setlog chat_id")
        return
    try:
        LOG_CHANNEL = int(args[1])
    except:
        bot.reply_to(message, "❌ chat_id must be number")
        return
    bot.reply_to(message, f"✅ LOG_CHANNEL updated: {LOG_CHANNEL}")

@bot.message_handler(commands=["setname"])
def setname_cmd(message):
    if not admin_only(message): return
    global checker_name
    args = parse_args(message)
    if len(args) != 2:
        bot.reply_to(message, "Usage: /setname @botname")
        return
    checker_name = args[1].strip()
    bot.reply_to(message, f"✅ checker_name updated: {checker_name}")

# ==============================
# GROUP LIST / ADD / DEL
# ==============================
@bot.message_handler(commands=["listgroups"])
def listgroups_cmd(message):
    if not admin_only(message): return
    cfg = load_config()
    groups = cfg.get("allowed_groups", [])
    text = "Allowed Groups:\n" + "\n".join([str(g) for g in groups]) if groups else "Allowed Groups: NONE"
    bot.reply_to(message, as_pre(text), parse_mode="HTML")

@bot.message_handler(commands=["addgroup"])
def addgroup_cmd(message):
    if not admin_only(message): return
    args = parse_args(message)
    if len(args) != 2:
        bot.reply_to(message, "Usage: /addgroup chat_id")
        return
    try:
        gid = int(args[1])
    except:
        bot.reply_to(message, "❌ chat_id must be number")
        return
    cfg = load_config()
    if gid not in cfg["allowed_groups"]:
        cfg["allowed_groups"].append(gid)
    save_config(cfg)
    bot.reply_to(message, f"✅ Added group: {gid}")

@bot.message_handler(commands=["delgroup"])
def delgroup_cmd(message):
    if not admin_only(message): return
    args = parse_args(message)
    if len(args) != 2:
        bot.reply_to(message, "Usage: /delgroup chat_id")
        return
    try:
        gid = int(args[1])
    except:
        bot.reply_to(message, "❌ chat_id must be number")
        return
    cfg = load_config()
    if gid in cfg["allowed_groups"]:
        cfg["allowed_groups"].remove(gid)
        save_config(cfg)
        bot.reply_to(message, f"✅ Removed group: {gid}")
    else:
        bot.reply_to(message, "❌ Group not in allowed list.")

# ==============================
# STATS
# ==============================
@bot.message_handler(commands=["stats"])
def stats_cmd(message):
    if not admin_only(message): return
    db = load_db()
    total_users = len(db)
    total_credits = sum(int(u.get("credits", 0)) for u in db.values())
    total_checks = sum(int(u.get("checks", 0)) for u in db.values())
    total_banned = sum(1 for u in db.values() if u.get("banned"))
    total_approved = sum(1 for u in db.values() if u.get("approved"))

    text = (
        "┏━━ BOT STATS ━━┓\n"
        f"Users     : {total_users}\n"
        f"Approved  : {total_approved}\n"
        f"Banned    : {total_banned}\n"
        f"Checks    : {total_checks}\n"
        f"CreditsΣ  : {total_credits}\n"
        "┗━━━━━━━━━━━━━━━━━━┛"
    )
    bot.reply_to(message, as_pre(text), parse_mode="HTML")
    
# ===== PUT THIS OUTSIDE HANDLER (top-level) =====
def bar(done, total, size=8):
    if total <= 0:
        return "<code>[□□□□□□□□]</code> 0/0"

    filled = int(size * done / total)
    return "<code>[{}{}]</code> {}/{}".format(
        "■" * filled,
        "□" * (size - filled),
        done,
        total
    )

def h(x):
    """Escape dynamic text so Telegram HTML parse won't break."""
    return html.escape(str(x), quote=False)


def h(x):
    return html.escape(str(x), quote=False)
    
    # ==============================
# PRIVATE ACCESS HARD GUARD (VIP ALLOWED)
# ==============================
# ==============================
# ADMIN: SET VIP
# ==============================
# ==============================
# ADMIN: SET VIP
# ==============================
@bot.message_handler(commands=["vip"])
def set_vip(message):
    if not is_admin(message.from_user.id):
        bot.reply_to(message, "⛔ Admin only command.")
        return

    parts = message.text.split()
    if len(parts) != 2 or not parts[1].isdigit():
        bot.reply_to(message, "Usage: /vip user_id")
        return

    user_id = parts[1]

    db = ensure_user(user_id)
    u = db[str(user_id)]

    u["plan"] = "VIP"
    u["approved"] = True
    u["banned"] = False

    save_db(db)

    bot.reply_to(
        message,
        f"✅ User {user_id} is now VIP."
    )

@bot.message_handler(commands=["cvv"])
def cvv_handler(message):
    if not guard_access(message):
        return

    try:
        text = message.text or ""
        cards = re.findall(
            r"\d{15,16}[\s|:/]\d{1,2}[\s|:/]\d{2,4}[\s|:/]\d{3,4}",
            text
        )

        if not cards:
            bot.reply_to(message, "❌ <b>No valid cards found!</b>", parse_mode="HTML")
            return

        cc_list = [re.sub(r"[\s:/]+", "|", c) for c in cards[:MAX_CARDS]]
        card_count = len(cc_list)

        remaining = spend_credit_or_block(message, cost=card_count)
        if remaining is None:
            return

        header = (
    "<b>VIP STRIPE GATE</b>\n"
    "──────────────\n"
    f"Cards : <code>{card_count}</code>\n"
    "──────────────\n\n"
)

        msg = bot.reply_to(message, bar(0, card_count), parse_mode="HTML")

        results = []

        for i, cc in enumerate(cc_list, start=1):
            start_t = time.time()

            # BIN SAFE
            try:
                bin_data = get_bin_info(cc) or {}
            except Exception:
                bin_data = {}

            bank = h(bin_data.get("bank", "N/A"))
            country = h(bin_data.get("country", "N/A"))
            flag = h(bin_data.get("flag", ""))

            try:
                resp_raw = str(Tele(cc))  # keep original
                resp = resp_raw.strip()

                # ✅ EXACT CHARGED: only when the whole line is "Payment Successful!" or "Donation Successful!"
                # - case-insensitive
                # - allows optional ! or .
                if re.search(r'(?im)^\s*(payment|donation)\s+successful\s*[!.]?\s*$', resp):
                    status = "CHARGED $1.00🔥"

                elif re.search(r'(?i)\binsufficient\b|\blow funds\b', resp):
                    status = "LOW FUNDS 🔥"

                elif re.search(r'(?i)\bincorrect_cvc\b|\bsecurity code\b|\bcvc\b', resp):
                    status = "CCN LIVE ✅"

                elif re.search(r'(?i)\brequires_action\b|\b3ds\b', resp):
                    status = "3DS 🛡️"

                else:
                    status = "DECLINED ❌"

            except Exception as e:
                print("TELE ERROR:", repr(e))
                traceback.print_exc()
                status = "ERROR ⚠️"

            t = round(time.time() - start_t, 2)

            results.append(
                f"<code>{h(cc)}</code>\n"
                f"➜ {h(status)}\n"
                f"{bank} | {country} {flag} | {t}s\n"
            )

            try:
                bot.edit_message_text(
                    chat_id=message.chat.id,
                    message_id=msg.message_id,
                    text=bar(i, card_count),
                    parse_mode="HTML"
                )
            except:
                pass

        username = message.from_user.username or "NoUsername"

        final_text = (
    header
    + "\n".join(results)
    + "\n\n"
    "✨✨ <b>PREMIUM ACCESS</b> ✨✨\n"
    "━━━━━━━━━━━━━━━━━━\n"
    f"👤 @{h(username)}\n"
    f"👑 <b>VIP / PREMIUM USER</b>\n"
    f"💳 Credits : <code>{h(remaining)}</code>\n"
    "━━━━━━━━━━━━━━━━━━\n"
    f"🤖 <b>{h(checker_name)}</b> • Secure System"
)

        if len(final_text) > 3800:
            try:
                bot.edit_message_text(
                    chat_id=message.chat.id,
                    message_id=msg.message_id,
                    text=header + "<b>Result too long… sending in parts</b>",
                    parse_mode="HTML"
                )
            except:
                pass

            chunk = ""
            for block in results:
                if len(chunk) + len(block) > 3500:
                    bot.send_message(message.chat.id, chunk, parse_mode="HTML")
                    chunk = ""
                chunk += block + "\n"

            if chunk.strip():
                bot.send_message(message.chat.id, chunk, parse_mode="HTML")

            bot.send_message(
                message.chat.id,
                f"👤 @{h(username)} 👑 <b>PREMIUM</b>\n"
                f"💳 <b>Credits</b> : <code>{h(remaining)}</code>\n"
                f"🤖 <b>{h(checker_name)}</b>",
                parse_mode="HTML"
            )
            return

        bot.edit_message_text(
            chat_id=message.chat.id,
            message_id=msg.message_id,
            text=final_text,
            parse_mode="HTML"
        )

    except Exception as e:
        bot.reply_to(message, f"❌ Error: <code>{h(e)}</code>", parse_mode="HTML")

# ================= MAIN =================
if __name__ == "__main__":
    print("Bot is running...")
    while True:
        try:
            bot.polling(non_stop=True, timeout=30)
        except Exception as e:
            print("Polling error:", e)
            time.sleep(5)