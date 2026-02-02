import requests
import random

# ================= HTML ESCAPE =================
def escape_html(s):
    if s is None:
        return ""
    return (str(s)
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;"))

# ================= MASK CARD =================
def mask_card(cc):
    """
    4242424242424242|12|27|123
    -> 424242******4242|12|27|***
    """
    try:
        parts = str(cc).split("|")
        num = parts[0]
        mm = parts[1] if len(parts) > 1 else "MM"
        yy = parts[2] if len(parts) > 2 else "YY"
        cvv = parts[3] if len(parts) > 3 else "***"
        masked_num = num[:6] + "*" * (len(num) - 10) + num[-4:]
        return f"{masked_num}|{mm}|{yy}|***"
    except:
        return "***MASKED***"

# ================= SEND RESULT =================
def send(cc, last, username, time_taken, remaining):
    ii = (str(cc)[:6] if cc else "")
    cents = random.randint(50, 99)

    bank = "Unknown"
    country = "Unknown"
    emj = "🏳️"

    # ===== BIN LOOKUP =====
    try:
        r = requests.get(f"https://bins.antipublic.cc/bins/{ii}", timeout=10)
        r.raise_for_status()
        data = r.json()
        bank = data.get("bank", bank)
        country = data.get("country", country)
        emj = data.get("country_flag", emj)
    except Exception as e:
        print("BIN API ERROR:", e)

    # ===== RESULT ICON =====
    u = (last or "").upper()
    if any(x in u for x in ("CHARGED", "DONATION SUCCESSFUL")):
        icon = "🟢"
    elif any(x in u for x in ("DECLINED", "DEAD", "INSUFFICIENT")):
        icon = "🔴"
    else:
        icon = "🟡"

    # ===== ESCAPE OUTPUT =====
    last_e = escape_html(last)
    bank_e = escape_html(bank)
    country_e = escape_html(country)
    user_e = escape_html(username or "NoUsername")
    taken_e = escape_html(str(time_taken))
    rem_e = escape_html(str(remaining))
    ii_e = escape_html(ii)

    masked_cc = escape_html(mask_card(cc))

    # ===== FINAL MESSAGE =====
    msg = (
        "━━━━━━━━━━━━━━━━━━━━\n"
        f"{icon} <b>RESULT</b> : <b>{last_e}</b>\n"
        f"💸 <b>AMOUNT</b> : <code>0.{cents:02d}$</code>\n"
        f"⏱ <b>TIME</b> : <code>{taken_e}s</code>\n"
        "━━━━━━━━━━━━━━━━━━━━\n\n"
        "💳 <b>CARD</b>\n"
        f"<code>{masked_cc}</code>\n\n"
        "🏦 <b>BIN INFO</b>\n"
        f"• <b>Bank</b> : {bank_e}\n"
        f"• <b>Country</b> : {country_e} {emj}\n"
        f"• <b>BIN</b> : <code>{ii_e}</code>\n\n"
        "━━━━━━━━━━━━━━━━━━━━\n"
        f"👤 @{user_e} 👑 <b>PREMIUM</b>\n"
        f"💳 <b>Credits</b> : <code>{rem_e}</code>\n"
        "🤖 <b>@buik100</b>"
    )

    return msg