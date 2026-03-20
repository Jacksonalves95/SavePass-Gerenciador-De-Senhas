"""
SavePass - Gerenciador de Senhas Seguro
Desenvolvido por Jackson Alves © 2026
"""

import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import json
import os
import re
import base64
import hashlib
import hmac
import secrets
import string
from datetime import datetime
from pathlib import Path
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet

# ─────────────────────────────────────────────
#  PATHS & CONSTANTS
# ─────────────────────────────────────────────
BASE_DIR   = Path(__file__).parent
DATA_DIR   = BASE_DIR / "data"
USERS_FILE = DATA_DIR / "users.json"
LOGO_FILE  = BASE_DIR / "logosavepass1.jpg"

DATA_DIR.mkdir(exist_ok=True)

MAX_CREDENTIALS = 10

# ─────────────────────────────────────────────
#  PALETTE
# ─────────────────────────────────────────────
C = {
    "bg":          "#0A0D14",
    "panel":       "#0F1420",
    "card":        "#141926",
    "border":      "#1E2840",
    "border2":     "#253050",
    "accent":      "#2563EB",
    "accent2":     "#3B82F6",
    "accent_glow": "#1D4ED8",
    "danger":      "#EF4444",
    "success":     "#10B981",
    "warn":        "#F59E0B",
    "text":        "#E2E8F0",
    "text2":       "#94A3B8",
    "text3":       "#64748B",
    "header":      "#0D1117",
    "input_bg":    "#0D1117",
    "hover":       "#1E293B",
    "white":       "#FFFFFF",
}

FONT_TITLE  = ("Segoe UI", 22, "bold")
FONT_HEADER = ("Segoe UI", 13, "bold")
FONT_BODY   = ("Segoe UI", 10)
FONT_SMALL  = ("Segoe UI", 9)
FONT_MICRO  = ("Segoe UI", 8)
FONT_MONO   = ("Consolas", 10)
FONT_LOGO   = ("Segoe UI Black", 28, "bold")

# ─────────────────────────────────────────────
#  CRYPTO HELPERS
# ─────────────────────────────────────────────
def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480_000,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))


def encrypt_value(value: str, key: bytes) -> str:
    return Fernet(key).encrypt(value.encode()).decode()


def decrypt_value(token: str, key: bytes) -> str:
    return Fernet(key).decrypt(token.encode()).decode()


def hash_password(password: str) -> dict:
    salt = secrets.token_bytes(32)
    key  = derive_key(password, salt)
    tag  = hmac.new(key, b"savepass_auth", hashlib.sha256).digest()
    return {
        "salt": base64.b64encode(salt).decode(),
        "tag":  base64.b64encode(tag).decode(),
    }


def verify_password(password: str, stored: dict) -> bool:
    try:
        salt = base64.b64decode(stored["salt"])
        key  = derive_key(password, salt)
        tag  = hmac.new(key, b"savepass_auth", hashlib.sha256).digest()
        return hmac.compare_digest(tag, base64.b64decode(stored["tag"]))
    except Exception:
        return False


def get_user_key(password: str, salt_b64: str) -> bytes:
    salt = base64.b64decode(salt_b64)
    return derive_key(password, salt)


# ─────────────────────────────────────────────
#  USER STORE
# ─────────────────────────────────────────────
def load_users() -> dict:
    if USERS_FILE.exists():
        with open(USERS_FILE, "r") as f:
            return json.load(f)
    return {}


def save_users(users: dict):
    with open(USERS_FILE, "w") as f:
        json.dump(users, f, indent=2)


def validate_email(email: str) -> bool:
    return bool(re.match(r"^[\w\.\+\-]+@[\w\-]+\.[a-zA-Z]{2,}$", email))


def validate_password_strength(pwd: str) -> tuple[bool, str]:
    if len(pwd) < 8:
        return False, "Mínimo 8 caracteres"
    if not re.search(r"[A-Z]", pwd):
        return False, "Precisa de letra maiúscula"
    if not re.search(r"[a-z]", pwd):
        return False, "Precisa de letra minúscula"
    if not re.search(r"\d", pwd):
        return False, "Precisa de número"
    if not re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?]", pwd):
        return False, "Precisa de caractere especial"
    return True, "Senha forte ✓"


def generate_strong_password(length: int = 16) -> str:
    alphabet = string.ascii_letters + string.digits + "!@#$%&*"
    while True:
        pwd = "".join(secrets.choice(alphabet) for _ in range(length))
        ok, _ = validate_password_strength(pwd)
        if ok:
            return pwd


# ─────────────────────────────────────────────
#  CUSTOM WIDGETS
# ─────────────────────────────────────────────
class RoundedFrame(tk.Canvas):
    def __init__(self, parent, width, height, radius=12, bg=C["card"],
                 border_color=C["border"], border_width=1, **kw):
        super().__init__(parent, width=width, height=height,
                         bg=parent.cget("bg"), highlightthickness=0, **kw)
        self._draw(width, height, radius, bg, border_color, border_width)

    def _draw(self, w, h, r, fill, bc, bw):
        self.delete("all")
        # shadow
        self.create_rounded_rect(4, 4, w+2, h+2, r, fill="#060810", outline="")
        # border
        self.create_rounded_rect(0, 0, w, h, r, fill=bc, outline="")
        # fill
        self.create_rounded_rect(bw, bw, w-bw, h-bw, r-bw, fill=fill, outline="")

    def create_rounded_rect(self, x1, y1, x2, y2, r, **kw):
        pts = [
            x1+r, y1,  x2-r, y1,
            x2,   y1,  x2,   y1+r,
            x2,   y2-r, x2, y2,
            x2-r, y2,  x1+r, y2,
            x1,   y2,  x1,   y2-r,
            x1,   y1+r, x1, y1,
        ]
        return self.create_polygon(pts, smooth=True, **kw)


class StyledEntry(tk.Frame):
    def __init__(self, parent, placeholder="", show="", width=280, **kw):
        super().__init__(parent, bg=C["input_bg"],
                         highlightbackground=C["border"],
                         highlightcolor=C["accent"],
                         highlightthickness=1, bd=0)
        self.show_char = show
        self._placeholder = placeholder
        self._showing = (show == "")

        self.entry = tk.Entry(
            self, bg=C["input_bg"], fg=C["text2"],
            insertbackground=C["accent"],
            relief="flat", bd=0, font=FONT_BODY, width=width // 8,
            show=show,
        )
        self.entry.pack(fill="x", padx=10, pady=8)

        if placeholder:
            self._set_placeholder()
            self.entry.bind("<FocusIn>",  self._on_focus_in)
            self.entry.bind("<FocusOut>", self._on_focus_out)

    def _set_placeholder(self):
        self.entry.insert(0, self._placeholder)
        self.entry.config(fg=C["text3"])

    def _on_focus_in(self, e):
        if self.entry.get() == self._placeholder:
            self.entry.delete(0, "end")
            self.entry.config(fg=C["text"], show=self.show_char)

    def _on_focus_out(self, e):
        if not self.entry.get():
            self.entry.config(show="")
            self._set_placeholder()

    def get(self):
        val = self.entry.get()
        return "" if val == self._placeholder else val

    def set(self, val):
        self.entry.delete(0, "end")
        self.entry.config(fg=C["text"], show=self.show_char)
        self.entry.insert(0, val)

    def clear(self):
        self.entry.delete(0, "end")
        if self._placeholder:
            self._set_placeholder()


class IconButton(tk.Label):
    def __init__(self, parent, text, command=None,
                 fg=C["text"], bg=C["card"], font=FONT_BODY,
                 hover_fg=C["accent2"], **kw):
        super().__init__(parent, text=text, fg=fg, bg=bg,
                         font=font, cursor="hand2", **kw)
        self._fg = fg
        self._hfg = hover_fg
        self._bg = bg
        self._command = command
        self.bind("<Enter>",  lambda e: self.config(fg=self._hfg))
        self.bind("<Leave>",  lambda e: self.config(fg=self._fg))
        if command:
            self.bind("<Button-1>", lambda e: command())


class PrimaryButton(tk.Frame):
    def __init__(self, parent, text, command=None, width=200, height=38,
                 color=C["accent"], hover=C["accent2"], **kw):
        super().__init__(parent, bg=parent.cget("bg"))
        self.btn = tk.Label(
            self, text=text, bg=color, fg=C["white"],
            font=("Segoe UI", 10, "bold"), cursor="hand2",
            width=width // 8, pady=8,
        )
        self.btn.pack()
        self._color = color
        self._hover = hover
        self._command = command
        for w in (self, self.btn):
            w.bind("<Enter>",    lambda e: self.btn.config(bg=self._hover))
            w.bind("<Leave>",    lambda e: self.btn.config(bg=self._color))
            w.bind("<Button-1>", lambda e: command() if command else None)


class StrengthBar(tk.Frame):
    def __init__(self, parent, **kw):
        super().__init__(parent, bg=C["card"], **kw)
        self.bars = []
        bar_frame = tk.Frame(self, bg=C["card"])
        bar_frame.pack(side="left")
        for _ in range(5):
            b = tk.Frame(bar_frame, width=28, height=5, bg=C["border"])
            b.pack(side="left", padx=2)
            self.bars.append(b)
        self.label = tk.Label(self, text="", fg=C["text3"],
                              bg=C["card"], font=FONT_MICRO)
        self.label.pack(side="left", padx=(8, 0))

    def update(self, password: str):
        score = 0
        colors = []
        if len(password) >= 8:  score += 1
        if re.search(r"[A-Z]", password): score += 1
        if re.search(r"[a-z]", password): score += 1
        if re.search(r"\d", password):    score += 1
        if re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?]", password): score += 1

        palettes = ["#EF4444", "#F97316", "#F59E0B", "#84CC16", "#10B981"]
        labels   = ["Muito fraca", "Fraca", "Razoável", "Boa", "Forte"]

        for i, b in enumerate(self.bars):
            b.config(bg=palettes[score-1] if i < score else C["border"])
        self.label.config(
            text=labels[score-1] if score > 0 else "",
            fg=palettes[score-1] if score > 0 else C["text3"],
        )


# ─────────────────────────────────────────────
#  TOOLTIP
# ─────────────────────────────────────────────
class Tooltip:
    def __init__(self, widget, text):
        self.widget = widget
        self.text = text
        self.tip = None
        widget.bind("<Enter>", self.show)
        widget.bind("<Leave>", self.hide)

    def show(self, e=None):
        x = self.widget.winfo_rootx() + 20
        y = self.widget.winfo_rooty() + self.widget.winfo_height() + 4
        self.tip = tk.Toplevel(self.widget)
        self.tip.wm_overrideredirect(True)
        self.tip.geometry(f"+{x}+{y}")
        lbl = tk.Label(self.tip, text=self.text, bg="#1E293B", fg=C["text"],
                       font=FONT_MICRO, padx=8, pady=4,
                       relief="flat", bd=0)
        lbl.pack()

    def hide(self, e=None):
        if self.tip:
            self.tip.destroy()
            self.tip = None


# ─────────────────────────────────────────────
#  NOTIFICATION TOAST
# ─────────────────────────────────────────────
class Toast:
    def __init__(self, root, message, kind="info"):
        colors = {"info": C["accent"], "success": C["success"],
                  "error": C["danger"], "warn": C["warn"]}
        icons  = {"info": "ℹ", "success": "✓", "error": "✕", "warn": "⚠"}
        bg = colors.get(kind, C["accent"])

        self.w = tk.Toplevel(root)
        self.w.wm_overrideredirect(True)
        sw = root.winfo_screenwidth()
        self.w.geometry(f"320x54+{sw-340}+30")
        self.w.attributes("-topmost", True)

        frame = tk.Frame(self.w, bg=C["panel"],
                         highlightbackground=bg, highlightthickness=1)
        frame.pack(fill="both", expand=True)

        tk.Label(frame, text=icons[kind], bg=bg, fg=C["white"],
                 font=("Segoe UI", 14), width=3).pack(side="left")
        tk.Label(frame, text=message, bg=C["panel"], fg=C["text"],
                 font=FONT_SMALL, anchor="w").pack(side="left", padx=10)

        root.after(3000, self.w.destroy)


# ─────────────────────────────────────────────
#  LOGIN SCREEN
# ─────────────────────────────────────────────
class LoginScreen(tk.Frame):
    def __init__(self, parent, on_login, on_register):
        super().__init__(parent, bg=C["bg"])
        self.on_login = on_login
        self.on_register = on_register
        self._build()

    def _build(self):
        # Full-screen canvas for background grid
        self.canvas = tk.Canvas(self, bg=C["bg"], highlightthickness=0)
        self.canvas.place(relwidth=1, relheight=1)
        self.after(100, self._draw_grid)

        # Center container
        center = tk.Frame(self, bg=C["bg"])
        center.place(relx=0.5, rely=0.5, anchor="center")

        # Logo area
        logo_frame = tk.Frame(center, bg=C["bg"])
        logo_frame.pack(pady=(0, 30))

        try:
            from PIL import Image, ImageTk
            # ── LOGO TELA DE LOGIN ─────────────────────────────────────
            # Ajuste LOGIN_LOGO_MAX_W e LOGIN_LOGO_MAX_H conforme necessário.
            # A imagem será redimensionada proporcionalmente (sem distorção)
            # para caber dentro desse limite.
            LOGIN_LOGO_MAX_W = 220   # largura máxima em pixels
            LOGIN_LOGO_MAX_H = 100   # altura máxima em pixels
            # ──────────────────────────────────────────────────────────
            img = Image.open(LOGO_FILE)
            img.thumbnail((LOGIN_LOGO_MAX_W, LOGIN_LOGO_MAX_H), Image.LANCZOS)
            self._logo_img = ImageTk.PhotoImage(img)
            tk.Label(logo_frame, image=self._logo_img, bg=C["bg"]).pack()
        except Exception:
            self._draw_text_logo(logo_frame)

        # Card
        card = tk.Frame(center, bg=C["card"],
                        highlightbackground=C["border"],
                        highlightthickness=1)
        card.pack(ipadx=40, ipady=30)

        tk.Label(card, text="Bem-vindo de volta",
                 bg=C["card"], fg=C["text"],
                 font=FONT_HEADER).pack(pady=(20, 4))
        tk.Label(card, text="Entre com suas credenciais para continuar",
                 bg=C["card"], fg=C["text3"],
                 font=FONT_SMALL).pack(pady=(0, 20))

        # Separator
        tk.Frame(card, height=1, bg=C["border"]).pack(fill="x", padx=30, pady=(0, 20))

        # Fields
        field_frame = tk.Frame(card, bg=C["card"])
        field_frame.pack(padx=30)

        tk.Label(field_frame, text="Usuário", bg=C["card"],
                 fg=C["text2"], font=FONT_SMALL).pack(anchor="w")
        self.user_entry = StyledEntry(field_frame, placeholder="Seu nome de usuário", width=300)
        self.user_entry.pack(fill="x", pady=(4, 12))

        tk.Label(field_frame, text="Senha", bg=C["card"],
                 fg=C["text2"], font=FONT_SMALL).pack(anchor="w")

        pwd_row = tk.Frame(field_frame, bg=C["card"])
        pwd_row.pack(fill="x", pady=(4, 0))
        self.pwd_entry = StyledEntry(pwd_row, placeholder="Sua senha", show="•", width=260)
        self.pwd_entry.pack(side="left", fill="x", expand=True)
        self._pwd_visible = False
        self.eye_btn = tk.Label(pwd_row, text="👁", bg=C["card"],
                                fg=C["text3"], font=("Segoe UI", 12),
                                cursor="hand2")
        self.eye_btn.pack(side="left", padx=(6, 0))
        self.eye_btn.bind("<Button-1>", self._toggle_pwd)

        # Login btn
        tk.Frame(card, height=1, bg=C["border"]).pack(fill="x", padx=30, pady=(24, 0))

        btn_frame = tk.Frame(card, bg=C["card"])
        btn_frame.pack(pady=20, padx=30)

        PrimaryButton(btn_frame, "Entrar →", self._do_login, width=300).pack(fill="x")

        link = tk.Label(btn_frame, text="Criar nova conta",
                        bg=C["card"], fg=C["accent"],
                        font=FONT_SMALL, cursor="hand2")
        link.pack(pady=(12, 0))
        link.bind("<Button-1>", lambda e: self.on_register())
        link.bind("<Enter>",    lambda e: link.config(fg=C["accent2"]))
        link.bind("<Leave>",    lambda e: link.config(fg=C["accent"]))

        # Bind Enter key
        self.user_entry.entry.bind("<Return>", lambda e: self._do_login())
        self.pwd_entry.entry.bind("<Return>",  lambda e: self._do_login())

        # Footer
        tk.Label(self, text="© 2026 Jackson Alves  •  SavePass",
                 bg=C["bg"], fg=C["text3"],
                 font=FONT_MICRO).place(relx=0.5, rely=0.97, anchor="center")

    def _draw_text_logo(self, parent):
        row = tk.Frame(parent, bg=C["bg"])
        row.pack()
        tk.Label(row, text="Save", bg=C["bg"], fg=C["white"],
                 font=FONT_LOGO).pack(side="left")
        tk.Label(row, text="Pass", bg=C["bg"], fg=C["accent"],
                 font=FONT_LOGO).pack(side="left")
        tk.Label(parent, text="Seu cofre de senhas pessoal",
                 bg=C["bg"], fg=C["text3"],
                 font=FONT_SMALL).pack()

    def _draw_grid(self):
        w = self.winfo_width() or 1200
        h = self.winfo_height() or 700
        self.canvas.delete("grid")
        for x in range(0, w, 60):
            self.canvas.create_line(x, 0, x, h, fill="#111827",
                                    tags="grid", width=1)
        for y in range(0, h, 60):
            self.canvas.create_line(0, y, w, y, fill="#111827",
                                    tags="grid", width=1)
        # Glow dot
        cx, cy = w // 2, h // 2
        for r, alpha in [(240, "#0D1529"), (160, "#0F1B35"),
                         (100, "#112040"), (60, "#152550")]:
            self.canvas.create_oval(cx-r, cy-r, cx+r, cy+r,
                                    fill=alpha, outline="", tags="grid")

    def _toggle_pwd(self, e=None):
        self._pwd_visible = not self._pwd_visible
        self.pwd_entry.entry.config(
            show="" if self._pwd_visible else "•"
        )
        self.eye_btn.config(
            fg=C["accent"] if self._pwd_visible else C["text3"]
        )

    def _do_login(self):
        user = self.user_entry.get().strip()
        pwd  = self.pwd_entry.get()
        if not user or not pwd:
            messagebox.showwarning("Atenção", "Preencha usuário e senha.", parent=self)
            return
        self.on_login(user, pwd)


# ─────────────────────────────────────────────
#  REGISTER SCREEN
# ─────────────────────────────────────────────
class RegisterScreen(tk.Frame):
    def __init__(self, parent, on_register, on_back):
        super().__init__(parent, bg=C["bg"])
        self.on_register = on_register
        self.on_back = on_back
        self._build()

    def _build(self):
        # Background accent line
        accent = tk.Frame(self, height=3, bg=C["accent"])
        accent.pack(fill="x", side="top")

        center = tk.Frame(self, bg=C["bg"])
        center.place(relx=0.5, rely=0.5, anchor="center")

        # Header
        hdr = tk.Frame(center, bg=C["bg"])
        hdr.pack(fill="x", pady=(0, 20))

        back_btn = tk.Label(hdr, text="← Voltar", bg=C["bg"],
                            fg=C["text3"], font=FONT_SMALL, cursor="hand2")
        back_btn.pack(side="left")
        back_btn.bind("<Button-1>", lambda e: self.on_back())
        back_btn.bind("<Enter>",    lambda e: back_btn.config(fg=C["accent"]))
        back_btn.bind("<Leave>",    lambda e: back_btn.config(fg=C["text3"]))

        tk.Label(hdr, text="Criar Conta", bg=C["bg"],
                 fg=C["text"], font=FONT_HEADER).pack(side="left", padx=20)

        # Card
        card = tk.Frame(center, bg=C["card"],
                        highlightbackground=C["border"],
                        highlightthickness=1)
        card.pack(ipadx=40, ipady=20)

        tk.Label(card, text="Registre-se no SavePass",
                 bg=C["card"], fg=C["text"],
                 font=("Segoe UI", 12, "bold")).pack(pady=(20, 4))
        tk.Label(card, text="Preencha os dados abaixo para criar sua conta segura",
                 bg=C["card"], fg=C["text3"],
                 font=FONT_SMALL).pack(pady=(0, 16))

        tk.Frame(card, height=1, bg=C["border"]).pack(fill="x", padx=30, pady=(0, 16))

        fields = tk.Frame(card, bg=C["card"])
        fields.pack(padx=30)

        # Username
        tk.Label(fields, text="Nome de usuário *", bg=C["card"],
                 fg=C["text2"], font=FONT_SMALL).pack(anchor="w")
        self.user_e = StyledEntry(fields, placeholder="mínimo 3 caracteres", width=320)
        self.user_e.pack(fill="x", pady=(4, 12))

        # Email
        tk.Label(fields, text="E-mail *", bg=C["card"],
                 fg=C["text2"], font=FONT_SMALL).pack(anchor="w")
        self.email_e = StyledEntry(fields, placeholder="seu@email.com", width=320)
        self.email_e.pack(fill="x", pady=(4, 12))

        # Password
        tk.Label(fields, text="Senha *", bg=C["card"],
                 fg=C["text2"], font=FONT_SMALL).pack(anchor="w")
        pwd_row = tk.Frame(fields, bg=C["card"])
        pwd_row.pack(fill="x", pady=(4, 4))
        self.pwd_e = StyledEntry(pwd_row, placeholder="Mín. 8 chars, maiúsc, nº, especial", show="•", width=270)
        self.pwd_e.pack(side="left", fill="x", expand=True)

        gen_btn = tk.Label(pwd_row, text="⚡", bg=C["card"],
                           fg=C["warn"], font=("Segoe UI", 14),
                           cursor="hand2")
        gen_btn.pack(side="left", padx=6)
        gen_btn.bind("<Button-1>", self._generate_password)
        Tooltip(gen_btn, "Gerar senha forte")

        self.strength = StrengthBar(fields)
        self.strength.pack(anchor="w", pady=(2, 8))
        self.pwd_e.entry.bind("<KeyRelease>",
                              lambda e: self.strength.update(self.pwd_e.get()))

        # Confirm password
        tk.Label(fields, text="Confirmar Senha *", bg=C["card"],
                 fg=C["text2"], font=FONT_SMALL).pack(anchor="w")
        self.confirm_e = StyledEntry(fields, placeholder="Repita a senha", show="•", width=320)
        self.confirm_e.pack(fill="x", pady=(4, 8))

        self.match_lbl = tk.Label(fields, text="", bg=C["card"],
                                   fg=C["text3"], font=FONT_MICRO)
        self.match_lbl.pack(anchor="w", pady=(0, 8))
        self.confirm_e.entry.bind("<KeyRelease>", self._check_match)

        # Terms note
        tk.Label(fields,
                 text="✓  Dados salvos criptografados localmente — somente você tem acesso",
                 bg=C["card"], fg=C["success"],
                 font=FONT_MICRO).pack(anchor="w", pady=(0, 4))

        tk.Frame(card, height=1, bg=C["border"]).pack(fill="x", padx=30, pady=(8, 0))

        PrimaryButton(card, "Criar Conta →", self._do_register, width=340).pack(
            pady=20, padx=30, fill="x"
        )

        tk.Label(self, text="© 2026 Jackson Alves  •  SavePass",
                 bg=C["bg"], fg=C["text3"],
                 font=FONT_MICRO).place(relx=0.5, rely=0.97, anchor="center")

    def _generate_password(self, e=None):
        pwd = generate_strong_password(18)
        self.pwd_e.set(pwd)
        self.confirm_e.set(pwd)
        self.strength.update(pwd)
        self.match_lbl.config(text="✓ Senhas idênticas", fg=C["success"])
        Toast(self.winfo_toplevel(), "Senha forte gerada!", "success")

    def _check_match(self, e=None):
        p1, p2 = self.pwd_e.get(), self.confirm_e.get()
        if not p2:
            self.match_lbl.config(text="")
        elif p1 == p2:
            self.match_lbl.config(text="✓ Senhas idênticas", fg=C["success"])
        else:
            self.match_lbl.config(text="✕ Senhas diferentes", fg=C["danger"])

    def _do_register(self):
        user  = self.user_e.get().strip()
        email = self.email_e.get().strip()
        pwd   = self.pwd_e.get()
        conf  = self.confirm_e.get()

        if not user or not email or not pwd:
            messagebox.showwarning("Campos obrigatórios",
                                   "Preencha todos os campos.", parent=self)
            return
        if len(user) < 3:
            messagebox.showwarning("Usuário inválido",
                                   "Usuário deve ter ao menos 3 caracteres.", parent=self)
            return
        if not validate_email(email):
            messagebox.showwarning("E-mail inválido",
                                   "Insira um e-mail válido.", parent=self)
            return
        ok, msg = validate_password_strength(pwd)
        if not ok:
            messagebox.showwarning("Senha fraca", msg, parent=self)
            return
        if pwd != conf:
            messagebox.showwarning("Senhas diferentes",
                                   "As senhas não coincidem.", parent=self)
            return

        users = load_users()
        if user in users:
            messagebox.showerror("Usuário existente",
                                 "Este nome de usuário já está em uso.", parent=self)
            return

        stored = hash_password(pwd)
        users[user] = {
            "email":       email,
            "hash":        stored,
            "created_at":  datetime.now().isoformat(),
            "credentials": [],
            "settings": {
                "auto_lock_minutes": 10,
                "show_password_strength": True,
                "theme": "dark",
            },
            "display_name": "",
        }
        save_users(users)
        messagebox.showinfo("Conta criada!", f"Bem-vindo, {user}!\nFaça login para continuar.")
        self.on_register()


# ─────────────────────────────────────────────
#  MAIN APP
# ─────────────────────────────────────────────
class MainApp(tk.Frame):
    def __init__(self, parent, username: str, password: str, on_logout):
        super().__init__(parent, bg=C["bg"])
        self.username  = username
        self.password  = password
        self.on_logout = on_logout
        self._user_key = None
        self._load_user()
        self._build()

    def _load_user(self):
        users = load_users()
        self._user_data = users[self.username]
        self._user_key  = get_user_key(self.password,
                                       self._user_data["hash"]["salt"])

    def _save_user(self):
        users = load_users()
        users[self.username] = self._user_data
        save_users(users)

    # ── BUILD ──────────────────────────────────
    def _build(self):
        # Top header bar
        self._build_header()
        # Body
        body = tk.Frame(self, bg=C["bg"])
        body.pack(fill="both", expand=True, padx=0, pady=0)
        # Left sidebar
        self._build_sidebar(body)
        # Right main panel
        self._build_main(body)
        # Footer
        tk.Frame(self, height=1, bg=C["border"]).pack(fill="x")
        footer = tk.Frame(self, bg=C["header"], height=28)
        footer.pack(fill="x")
        footer.pack_propagate(False)
        tk.Label(footer, text="© 2026 Jackson Alves  •  SavePass  •  Todos os dados criptografados localmente",
                 bg=C["header"], fg=C["text3"],
                 font=FONT_MICRO).pack(side="left", padx=14, pady=6)
        tk.Label(footer,
                 text=f"Logado como: {self.username}",
                 bg=C["header"], fg=C["text3"],
                 font=FONT_MICRO).pack(side="right", padx=14, pady=6)

    def _build_header(self):
        header = tk.Frame(self, bg=C["header"], height=52)
        header.pack(fill="x")
        header.pack_propagate(False)

        # Logo left
        logo_frame = tk.Frame(header, bg=C["header"])
        logo_frame.pack(side="left", padx=16)

        try:
            from PIL import Image, ImageTk
            # ── LOGO DO CABEÇALHO (interna, canto superior esquerdo) ───
            # Ajuste HEADER_LOGO_MAX_W e HEADER_LOGO_MAX_H conforme necessário.
            # A imagem será redimensionada proporcionalmente (sem distorção).
            HEADER_LOGO_MAX_W = 120   # largura máxima em pixels
            HEADER_LOGO_MAX_H =  36   # altura máxima em pixels
            # ──────────────────────────────────────────────────────────
            img = Image.open(LOGO_FILE)
            img.thumbnail((HEADER_LOGO_MAX_W, HEADER_LOGO_MAX_H), Image.LANCZOS)
            self._header_logo = ImageTk.PhotoImage(img)
            tk.Label(logo_frame, image=self._header_logo,
                     bg=C["header"]).pack(pady=8)
        except Exception:
            row = tk.Frame(logo_frame, bg=C["header"])
            row.pack(pady=8)
            tk.Label(row, text="Save", bg=C["header"],
                     fg=C["white"], font=("Segoe UI Black", 13, "bold")).pack(side="left")
            tk.Label(row, text="Pass", bg=C["header"],
                     fg=C["accent"], font=("Segoe UI Black", 13, "bold")).pack(side="left")

        # Separator
        tk.Frame(header, width=1, bg=C["border"]).pack(side="left", fill="y", pady=10)

        # Nav right
        nav = tk.Frame(header, bg=C["header"])
        nav.pack(side="right", padx=16)

        buttons = [
            ("⚙  Configurações", self._open_settings),
            ("👤  Conta",         self._open_account),
            ("↩  Sair",          self._do_logout),
        ]
        for text, cmd in buttons:
            sep = "danger" if "Sair" in text else "normal"
            fg  = C["danger"] if sep == "danger" else C["text2"]
            hfg = C["danger"] if sep == "danger" else C["accent2"]
            btn = tk.Label(nav, text=text, bg=C["header"],
                           fg=fg, font=FONT_SMALL, cursor="hand2",
                           padx=10)
            btn.pack(side="left")
            btn.bind("<Enter>",    lambda e, b=btn, h=hfg: b.config(fg=h))
            btn.bind("<Leave>",    lambda e, b=btn, f=fg:  b.config(fg=f))
            btn.bind("<Button-1>", lambda e, c=cmd: c())
            tk.Frame(nav, width=1, bg=C["border"]).pack(
                side="left", fill="y", pady=12)

        # Username badge
        display = self._user_data.get("display_name") or self.username
        initials = display[:2].upper()
        badge = tk.Frame(header, bg=C["accent"], width=32, height=32)
        badge.pack(side="right", pady=10, padx=(0, 8))
        badge.pack_propagate(False)
        tk.Label(badge, text=initials, bg=C["accent"],
                 fg=C["white"], font=("Segoe UI", 9, "bold")).place(
            relx=0.5, rely=0.5, anchor="center")

        # Accent bottom line
        tk.Frame(self, height=2, bg=C["accent"]).pack(fill="x")

    def _build_sidebar(self, parent):
        sidebar = tk.Frame(parent, bg=C["panel"], width=370)
        sidebar.pack(side="left", fill="y")
        sidebar.pack_propagate(False)

        # Separator right
        tk.Frame(parent, width=1, bg=C["border"]).pack(side="left", fill="y")

        # ── Wallet ─────────────────────────────
        wallet_hdr = tk.Frame(sidebar, bg=C["panel"])
        wallet_hdr.pack(fill="x", padx=16, pady=(16, 8))

        tk.Label(wallet_hdr, text="🗂  Carteira de Credenciais",
                 bg=C["panel"], fg=C["text"],
                 font=("Segoe UI", 10, "bold")).pack(side="left")

        count = len(self._user_data.get("credentials", []))
        self.count_badge = tk.Label(
            wallet_hdr,
            text=f"{count}/{MAX_CREDENTIALS}",
            bg=C["accent"], fg=C["white"],
            font=FONT_MICRO, padx=6, pady=2,
        )
        self.count_badge.pack(side="right")

        tk.Frame(sidebar, height=1, bg=C["border"]).pack(fill="x", padx=16)

        # Scroll frame for credentials
        scroll_container = tk.Frame(sidebar, bg=C["panel"])
        scroll_container.pack(fill="both", expand=True, padx=0, pady=0)

        self.cred_canvas = tk.Canvas(scroll_container, bg=C["panel"],
                                     highlightthickness=0)
        scrollbar = tk.Scrollbar(scroll_container, orient="vertical",
                                 command=self.cred_canvas.yview)
        self.cred_frame = tk.Frame(self.cred_canvas, bg=C["panel"])

        self.cred_frame.bind("<Configure>",
            lambda e: self.cred_canvas.configure(
                scrollregion=self.cred_canvas.bbox("all")))

        self.cred_canvas.create_window((0, 0), window=self.cred_frame, anchor="nw")
        self.cred_canvas.configure(yscrollcommand=scrollbar.set)

        self.cred_canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        self.cred_canvas.bind("<MouseWheel>",
            lambda e: self.cred_canvas.yview_scroll(int(-1*(e.delta/120)), "units"))

        self._refresh_wallet()

    def _build_main(self, parent):
        main = tk.Frame(parent, bg=C["bg"])
        main.pack(side="left", fill="both", expand=True)

        # ── Cabeçalho da seção ─────────────────
        top = tk.Frame(main, bg=C["bg"])
        top.pack(fill="x", padx=20, pady=(16, 0))

        tk.Label(top, text="＋  Cadastro de Credenciais",
                 bg=C["bg"], fg=C["text"],
                 font=("Segoe UI", 11, "bold")).pack(side="left")
        tk.Label(top, text="Adicione logins para acessar rapidamente",
                 bg=C["bg"], fg=C["text3"],
                 font=FONT_SMALL).pack(side="right")

        tk.Frame(main, height=1, bg=C["border"]).pack(fill="x", padx=20, pady=(8, 12))

        # ── Formulário compacto ────────────────
        form = tk.Frame(main, bg=C["card"],
                        highlightbackground=C["border"],
                        highlightthickness=1)
        form.pack(fill="x", padx=20)

        f = tk.Frame(form, bg=C["card"])
        f.pack(fill="x", padx=16, pady=14)

        # Linha 1 — Sistema | Login
        r1 = tk.Frame(f, bg=C["card"])
        r1.pack(fill="x", pady=(0, 10))

        c1 = tk.Frame(r1, bg=C["card"])
        c1.pack(side="left", fill="x", expand=True, padx=(0, 6))
        tk.Label(c1, text="Sistema", bg=C["card"],
                 fg=C["text2"], font=FONT_SMALL).pack(anchor="w")
        self.sys_e = StyledEntry(c1, placeholder="Gmail, Netflix, GitHub…", width=200)
        self.sys_e.pack(fill="x", pady=(3, 0))

        c2 = tk.Frame(r1, bg=C["card"])
        c2.pack(side="left", fill="x", expand=True, padx=(6, 0))
        tk.Label(c2, text="Login / Usuário", bg=C["card"],
                 fg=C["text2"], font=FONT_SMALL).pack(anchor="w")
        self.login_e = StyledEntry(c2, placeholder="Email ou usuário do sistema", width=200)
        self.login_e.pack(fill="x", pady=(3, 0))

        # Linha 2 — Senha | Categoria
        r2 = tk.Frame(f, bg=C["card"])
        r2.pack(fill="x", pady=(0, 10))

        c3 = tk.Frame(r2, bg=C["card"])
        c3.pack(side="left", fill="x", expand=True, padx=(0, 6))
        tk.Label(c3, text="Senha", bg=C["card"],
                 fg=C["text2"], font=FONT_SMALL).pack(anchor="w")
        pwd_row = tk.Frame(c3, bg=C["card"])
        pwd_row.pack(fill="x", pady=(3, 0))
        self.cred_pwd_e = StyledEntry(pwd_row, placeholder="Senha do sistema", show="•", width=160)
        self.cred_pwd_e.pack(side="left", fill="x", expand=True)
        gen2 = tk.Label(pwd_row, text="⚡", bg=C["card"],
                        fg=C["warn"], font=("Segoe UI", 12), cursor="hand2")
        gen2.pack(side="left", padx=(5, 0))
        gen2.bind("<Button-1>", self._gen_cred_pwd)
        Tooltip(gen2, "Gerar senha forte")

        c4 = tk.Frame(r2, bg=C["card"])
        c4.pack(side="left", fill="x", expand=True, padx=(6, 0))
        tk.Label(c4, text="Categoria", bg=C["card"],
                 fg=C["text2"], font=FONT_SMALL).pack(anchor="w")
        self.cat_var = tk.StringVar(value="Geral")
        cats = ["Geral", "Trabalho", "Social", "Banco", "Streaming", "Dev", "Outro"]
        cat_menu = ttk.Combobox(c4, textvariable=self.cat_var,
                                values=cats, state="readonly",
                                font=FONT_SMALL, width=16)
        cat_menu.pack(anchor="w", pady=(3, 0))
        self._style_combobox(cat_menu)

        # Linha 3 — Barra de força + Anotação (inline compacta)
        r3 = tk.Frame(f, bg=C["card"])
        r3.pack(fill="x", pady=(0, 10))

        self.cred_strength = StrengthBar(r3)
        self.cred_strength.pack(side="left")
        self.cred_pwd_e.entry.bind(
            "<KeyRelease>",
            lambda e: self.cred_strength.update(self.cred_pwd_e.get())
        )

        note_frame = tk.Frame(r3, bg=C["card"])
        note_frame.pack(side="right", fill="x", expand=True, padx=(12, 0))
        tk.Label(note_frame, text="Anotação (opcional)", bg=C["card"],
                 fg=C["text2"], font=FONT_SMALL).pack(anchor="w")
        self.note_e = tk.Text(note_frame, height=2, bg=C["input_bg"],
                              fg=C["text2"], relief="flat",
                              font=FONT_SMALL, insertbackground=C["accent"],
                              highlightbackground=C["border"],
                              highlightthickness=1, padx=6, pady=4)
        self.note_e.pack(fill="x", pady=(3, 0))

        # Linha 4 — Botão salvar
        r4 = tk.Frame(f, bg=C["card"])
        r4.pack(fill="x")
        PrimaryButton(r4, "💾  Salvar Credencial",
                      self._save_credential, width=220).pack(side="left")
        tk.Label(r4, text=f"Máx. {MAX_CREDENTIALS} credenciais por conta",
                 bg=C["card"], fg=C["text3"],
                 font=FONT_MICRO).pack(side="right", pady=6)

        # ── Stats ─────────────────────────────
        stats_frame = tk.Frame(main, bg=C["bg"])
        stats_frame.pack(fill="x", padx=20, pady=(14, 0))
        self._build_stats(stats_frame)

    def _style_combobox(self, cb):
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("TCombobox",
                        fieldbackground=C["input_bg"],
                        background=C["input_bg"],
                        foreground=C["text"],
                        selectbackground=C["accent"],
                        selectforeground=C["white"],
                        bordercolor=C["border"],
                        arrowcolor=C["text3"])

    def _build_stats(self, parent):
        self.stats_frame = parent
        self._refresh_stats()

    def _refresh_stats(self):
        for w in self.stats_frame.winfo_children():
            w.destroy()

        creds = self._user_data.get("credentials", [])
        cats  = {}
        for c in creds:
            k = c.get("category", "Geral")
            cats[k] = cats.get(k, 0) + 1

        cards_data = [
            ("🔑", "Credenciais", f"{len(creds)}/{MAX_CREDENTIALS}",
             C["accent"]),
            ("📂", "Categorias", str(len(cats)), C["success"]),
            ("📅", "Última adição",
             creds[-1]["created_at"][:10] if creds else "—",
             C["warn"]),
            ("🛡", "Criptografia", "AES-256", C["text3"]),
        ]

        for icon, label, value, color in cards_data:
            c = tk.Frame(self.stats_frame, bg=C["card"],
                         highlightbackground=C["border"],
                         highlightthickness=1, width=160, height=70)
            c.pack(side="left", padx=(0, 12), pady=4)
            c.pack_propagate(False)

            tk.Label(c, text=icon, bg=C["card"],
                     fg=color, font=("Segoe UI", 16)).place(x=12, y=10)
            tk.Label(c, text=value, bg=C["card"],
                     fg=C["white"], font=("Segoe UI", 13, "bold")).place(x=44, y=8)
            tk.Label(c, text=label, bg=C["card"],
                     fg=C["text3"], font=FONT_MICRO).place(x=44, y=30)

    # ── WALLET ─────────────────────────────────
    def _refresh_wallet(self):
        for w in self.cred_frame.winfo_children():
            w.destroy()

        creds = self._user_data.get("credentials", [])

        if not creds:
            tk.Label(self.cred_frame,
                     text="Nenhuma credencial\nsalva ainda.",
                     bg=C["panel"], fg=C["text3"],
                     font=FONT_SMALL, justify="center").pack(pady=40)
            return

        for i, cred in enumerate(creds):
            self._build_cred_card(i, cred)

        count = len(creds)
        self.count_badge.config(text=f"{count}/{MAX_CREDENTIALS}",
                                 bg=C["danger"] if count >= MAX_CREDENTIALS else C["accent"])

    def _build_cred_card(self, index: int, cred: dict):
        cat_colors = {
            "Trabalho":   "#7C3AED",
            "Banco":      "#059669",
            "Social":     "#DB2777",
            "Streaming":  "#DC2626",
            "Dev":        "#0891B2",
            "Geral":      C["accent"],
            "Outro":      C["text3"],
        }
        cat   = cred.get("category", "Geral")
        color = cat_colors.get(cat, C["accent"])

        # Try to decrypt login for display
        try:
            login_display = decrypt_value(cred["login"], self._user_key)
        except Exception:
            login_display = "••••••"

        card = tk.Frame(self.cred_frame, bg=C["card"],
                        highlightbackground=C["border"],
                        highlightthickness=1)
        card.pack(fill="x", padx=10, pady=5)

        # Color strip
        tk.Frame(card, width=4, bg=color).pack(side="left", fill="y")

        body = tk.Frame(card, bg=C["card"])
        body.pack(side="left", fill="x", expand=True, padx=10, pady=10)

        # Row 1: system name + category tag
        row1 = tk.Frame(body, bg=C["card"])
        row1.pack(fill="x")
        tk.Label(row1, text=cred["system"], bg=C["card"],
                 fg=C["white"], font=("Segoe UI", 10, "bold")).pack(side="left")
        cat_lbl = tk.Label(row1, text=cat, bg=color, fg=C["white"],
                           font=FONT_MICRO, padx=6, pady=1)
        cat_lbl.pack(side="right")

        # Row 2: login
        row2 = tk.Frame(body, bg=C["card"])
        row2.pack(fill="x", pady=(4, 2))
        tk.Label(row2, text="Login:", bg=C["card"],
                 fg=C["text3"], font=FONT_MICRO).pack(side="left")
        tk.Label(row2, text=login_display, bg=C["card"],
                 fg=C["text2"], font=FONT_MONO).pack(side="left", padx=4)

        # Row 3: password masked + eye icon
        row3 = tk.Frame(body, bg=C["card"])
        row3.pack(fill="x")
        tk.Label(row3, text="Senha:", bg=C["card"],
                 fg=C["text3"], font=FONT_MICRO).pack(side="left")

        pwd_var  = tk.StringVar(value="••••••••")
        showing  = [False]
        pwd_lbl  = tk.Label(row3, textvariable=pwd_var, bg=C["card"],
                             fg=C["text2"], font=FONT_MONO)
        pwd_lbl.pack(side="left", padx=4)

        def toggle_pwd(idx=index, var=pwd_var, s=showing):
            if not s[0]:
                try:
                    raw = decrypt_value(
                        self._user_data["credentials"][idx]["password"],
                        self._user_key
                    )
                    var.set(raw)
                    s[0] = True
                    eye.config(fg=C["accent"])
                except Exception:
                    Toast(self.winfo_toplevel(), "Erro ao descriptografar", "error")
            else:
                var.set("••••••••")
                s[0] = False
                eye.config(fg=C["text3"])

        eye = tk.Label(row3, text="👁", bg=C["card"],
                       fg=C["text3"], font=("Segoe UI", 10),
                       cursor="hand2")
        eye.pack(side="left")
        eye.bind("<Button-1>", lambda e, t=toggle_pwd: t())

        # Copy password button
        def copy_pwd(idx=index):
            try:
                raw = decrypt_value(
                    self._user_data["credentials"][idx]["password"],
                    self._user_key
                )
                self.winfo_toplevel().clipboard_clear()
                self.winfo_toplevel().clipboard_append(raw)
                Toast(self.winfo_toplevel(), "Senha copiada!", "success")
            except Exception:
                Toast(self.winfo_toplevel(), "Erro ao copiar", "error")

        copy_btn = tk.Label(row3, text="⧉", bg=C["card"],
                            fg=C["text3"], font=("Segoe UI", 11),
                            cursor="hand2")
        copy_btn.pack(side="left", padx=(4, 0))
        copy_btn.bind("<Button-1>", lambda e, c=copy_pwd: c())
        Tooltip(copy_btn, "Copiar senha")

        # Notes
        note = cred.get("note", "")
        if note:
            tk.Label(body, text=f"📝 {note}", bg=C["card"],
                     fg=C["text3"], font=FONT_MICRO, anchor="w").pack(fill="x", pady=(4, 0))

        # Delete button
        del_btn = tk.Label(card, text="✕", bg=C["card"],
                           fg=C["text3"], font=FONT_SMALL,
                           cursor="hand2")
        del_btn.pack(side="right", padx=8)
        del_btn.bind("<Enter>",    lambda e: del_btn.config(fg=C["danger"]))
        del_btn.bind("<Leave>",    lambda e: del_btn.config(fg=C["text3"]))
        del_btn.bind("<Button-1>", lambda e, i=index: self._delete_credential(i))

        # Hover effect
        for w in [card, body, row1, row2, row3]:
            w.bind("<Enter>", lambda e, c=card: c.config(
                highlightbackground=C["accent_glow"]))
            w.bind("<Leave>", lambda e, c=card: c.config(
                highlightbackground=C["border"]))

    # ── CREDENTIAL ACTIONS ─────────────────────
    def _gen_cred_pwd(self, e=None):
        pwd = generate_strong_password(16)
        self.cred_pwd_e.set(pwd)
        self.cred_strength.update(pwd)
        Toast(self.winfo_toplevel(), "Senha gerada!", "success")

    def _save_credential(self):
        system = self.sys_e.get().strip()
        login  = self.login_e.get().strip()
        pwd    = self.cred_pwd_e.get()
        note   = self.note_e.get("1.0", "end").strip()
        cat    = self.cat_var.get()

        if not system or not login or not pwd:
            Toast(self.winfo_toplevel(),
                  "Preencha sistema, login e senha", "warn")
            return

        creds = self._user_data.get("credentials", [])
        if len(creds) >= MAX_CREDENTIALS:
            Toast(self.winfo_toplevel(),
                  f"Limite de {MAX_CREDENTIALS} credenciais atingido", "error")
            return

        enc_login = encrypt_value(login,  self._user_key)
        enc_pwd   = encrypt_value(pwd,    self._user_key)

        creds.append({
            "system":     system,
            "login":      enc_login,
            "password":   enc_pwd,
            "category":   cat,
            "note":       note,
            "created_at": datetime.now().isoformat(),
        })
        self._user_data["credentials"] = creds
        self._save_user()

        self.sys_e.clear()
        self.login_e.clear()
        self.cred_pwd_e.clear()
        self.note_e.delete("1.0", "end")
        self.cat_var.set("Geral")
        self.cred_strength.update("")

        self._refresh_wallet()
        self._refresh_stats()
        Toast(self.winfo_toplevel(), f"'{system}' salvo com sucesso!", "success")

    def _delete_credential(self, index: int):
        creds = self._user_data.get("credentials", [])
        name  = creds[index]["system"]
        if messagebox.askyesno("Confirmar exclusão",
                               f"Remover credencial '{name}'?",
                               parent=self):
            creds.pop(index)
            self._user_data["credentials"] = creds
            self._save_user()
            self._refresh_wallet()
            self._refresh_stats()
            Toast(self.winfo_toplevel(), f"'{name}' removido", "info")

    # ── SETTINGS ───────────────────────────────
    def _open_settings(self):
        win = tk.Toplevel(self)
        win.title("Configurações — SavePass")
        win.configure(bg=C["bg"])
        win.geometry("420x360")
        win.resizable(False, False)
        win.grab_set()

        tk.Frame(win, height=3, bg=C["accent"]).pack(fill="x")
        tk.Label(win, text="⚙  Configurações",
                 bg=C["bg"], fg=C["text"],
                 font=FONT_HEADER).pack(pady=(16, 4), padx=20, anchor="w")
        tk.Frame(win, height=1, bg=C["border"]).pack(fill="x", padx=20, pady=8)

        sett = self._user_data.get("settings", {})
        frame = tk.Frame(win, bg=C["bg"])
        frame.pack(fill="x", padx=20)

        # Setting 1: Auto-lock
        tk.Label(frame, text="🔒  Bloqueio automático (minutos)",
                 bg=C["bg"], fg=C["text"], font=FONT_BODY).pack(anchor="w", pady=(0, 4))
        lock_var = tk.IntVar(value=sett.get("auto_lock_minutes", 10))
        lock_vals = [5, 10, 15, 30, 60, 0]
        lock_labels = ["5 min", "10 min", "15 min", "30 min", "1 hora", "Nunca"]
        lock_menu = ttk.Combobox(frame, textvariable=lock_var,
                                 values=lock_vals, state="readonly",
                                 font=FONT_SMALL, width=14)
        lock_menu.set(f"{sett.get('auto_lock_minutes', 10)} min")
        lock_menu.pack(anchor="w")

        tk.Frame(frame, height=1, bg=C["border"]).pack(fill="x", pady=12)

        # Setting 2: Show strength
        tk.Label(frame, text="💪  Exibir indicador de força de senha",
                 bg=C["bg"], fg=C["text"], font=FONT_BODY).pack(anchor="w", pady=(0, 4))
        strength_var = tk.BooleanVar(
            value=sett.get("show_password_strength", True))
        row = tk.Frame(frame, bg=C["bg"])
        row.pack(anchor="w")
        for label, val in [("Sim", True), ("Não", False)]:
            rb = tk.Radiobutton(row, text=label, variable=strength_var,
                                value=val, bg=C["bg"], fg=C["text"],
                                selectcolor=C["accent"],
                                activebackground=C["bg"],
                                font=FONT_SMALL)
            rb.pack(side="left", padx=(0, 12))

        tk.Frame(frame, height=1, bg=C["border"]).pack(fill="x", pady=12)

        # Setting 3: Clipboard clear
        tk.Label(frame, text="📋  Limpar área de transferência ao sair",
                 bg=C["bg"], fg=C["text"], font=FONT_BODY).pack(anchor="w", pady=(0, 4))
        clip_var = tk.BooleanVar(value=sett.get("clear_clipboard", True))
        row2 = tk.Frame(frame, bg=C["bg"])
        row2.pack(anchor="w")
        for label, val in [("Sim", True), ("Não", False)]:
            rb = tk.Radiobutton(row2, text=label, variable=clip_var,
                                value=val, bg=C["bg"], fg=C["text"],
                                selectcolor=C["accent"],
                                activebackground=C["bg"],
                                font=FONT_SMALL)
            rb.pack(side="left", padx=(0, 12))

        def save_settings():
            self._user_data["settings"]["show_password_strength"] = strength_var.get()
            self._user_data["settings"]["clear_clipboard"] = clip_var.get()
            self._save_user()
            win.destroy()
            Toast(self.winfo_toplevel(), "Configurações salvas!", "success")

        PrimaryButton(win, "Salvar Configurações", save_settings, width=200).pack(pady=20)

    def _open_account(self):
        win = tk.Toplevel(self)
        win.title("Minha Conta — SavePass")
        win.configure(bg=C["bg"])
        win.geometry("460x560")
        win.resizable(False, False)
        win.grab_set()

        tk.Frame(win, height=3, bg=C["success"]).pack(fill="x")
        tk.Label(win, text="👤  Minha Conta",
                 bg=C["bg"], fg=C["text"],
                 font=FONT_HEADER).pack(pady=(16, 4), padx=20, anchor="w")
        tk.Frame(win, height=1, bg=C["border"]).pack(fill="x", padx=20, pady=(0, 12))

        # Scrollable frame so content never gets cut
        canvas  = tk.Canvas(win, bg=C["bg"], highlightthickness=0)
        sb      = tk.Scrollbar(win, orient="vertical", command=canvas.yview)
        inner   = tk.Frame(canvas, bg=C["bg"])
        inner.bind("<Configure>",
                   lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=inner, anchor="nw")
        canvas.configure(yscrollcommand=sb.set)
        canvas.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        frame = inner

        fpad = dict(padx=20)

        # Display name
        tk.Label(frame, text="Nome de exibição", bg=C["bg"],
                 fg=C["text2"], font=FONT_SMALL).pack(anchor="w", **fpad)
        name_e = StyledEntry(frame, placeholder="Como quer ser chamado?", width=400)
        name_e.pack(fill="x", padx=20, pady=(4, 12))
        if self._user_data.get("display_name"):
            name_e.set(self._user_data["display_name"])

        # Username (readonly)
        tk.Label(frame, text="Usuário (não editável)", bg=C["bg"],
                 fg=C["text2"], font=FONT_SMALL).pack(anchor="w", **fpad)
        user_lbl = tk.Label(frame, text=self.username, bg=C["input_bg"],
                             fg=C["text3"], font=FONT_MONO,
                             anchor="w", padx=10, pady=8,
                             highlightbackground=C["border"],
                             highlightthickness=1)
        user_lbl.pack(fill="x", padx=20, pady=(4, 12))

        # Email
        tk.Label(frame, text="E-mail", bg=C["bg"],
                 fg=C["text2"], font=FONT_SMALL).pack(anchor="w", **fpad)
        email_e = StyledEntry(frame, width=400)
        email_e.pack(fill="x", padx=20, pady=(4, 12))
        email_e.set(self._user_data.get("email", ""))

        tk.Frame(frame, height=1, bg=C["border"]).pack(fill="x", padx=20, pady=(4, 12))

        # Change password section
        tk.Label(frame, text="Alterar Senha",
                 bg=C["bg"], fg=C["text"],
                 font=("Segoe UI", 10, "bold")).pack(anchor="w", padx=20, pady=(0, 8))

        tk.Label(frame, text="Senha atual", bg=C["bg"],
                 fg=C["text2"], font=FONT_SMALL).pack(anchor="w", **fpad)
        cur_pwd_e = StyledEntry(frame, placeholder="Digite a senha atual", show="•", width=400)
        cur_pwd_e.pack(fill="x", padx=20, pady=(4, 10))

        tk.Label(frame, text="Nova senha", bg=C["bg"],
                 fg=C["text2"], font=FONT_SMALL).pack(anchor="w", **fpad)
        new_pwd_e = StyledEntry(frame, placeholder="Nova senha (mín. 8 chars)", show="•", width=400)
        new_pwd_e.pack(fill="x", padx=20, pady=(4, 6))

        tk.Label(frame,
                 text="  Deixe os campos de senha em branco se não quiser alterá-la.",
                 bg=C["bg"], fg=C["text3"], font=FONT_MICRO).pack(anchor="w", padx=20, pady=(0, 16))

        tk.Frame(frame, height=1, bg=C["border"]).pack(fill="x", padx=20, pady=(0, 12))

        def save_account():
            new_name  = name_e.get().strip()
            new_email = email_e.get().strip()
            cur_pwd   = cur_pwd_e.get()
            new_pwd   = new_pwd_e.get()

            if new_email and not validate_email(new_email):
                Toast(win, "E-mail inválido", "error")
                return

            if new_name:
                self._user_data["display_name"] = new_name

            if new_email:
                self._user_data["email"] = new_email

            if cur_pwd or new_pwd:
                if not verify_password(cur_pwd, self._user_data["hash"]):
                    Toast(win, "Senha atual incorreta", "error")
                    return
                ok, msg = validate_password_strength(new_pwd)
                if not ok:
                    Toast(win, msg, "error")
                    return
                self._user_data["hash"] = hash_password(new_pwd)
                self.password = new_pwd
                self._user_key = get_user_key(new_pwd,
                                              self._user_data["hash"]["salt"])

            self._save_user()
            win.destroy()
            Toast(self.winfo_toplevel(), "Conta atualizada com sucesso!", "success")

        btn_outer = tk.Frame(frame, bg=C["bg"])
        btn_outer.pack(fill="x", padx=20, pady=(0, 20))
        PrimaryButton(btn_outer, "💾  Salvar Alterações", save_account,
                      width=200, color=C["success"], hover="#059669").pack(side="left")
        cancel_lbl = tk.Label(btn_outer, text="Cancelar", bg=C["bg"],
                              fg=C["text3"], font=FONT_SMALL, cursor="hand2")
        cancel_lbl.pack(side="right", padx=(0, 4))
        cancel_lbl.bind("<Button-1>", lambda e: win.destroy())
        cancel_lbl.bind("<Enter>",    lambda e: cancel_lbl.config(fg=C["danger"]))
        cancel_lbl.bind("<Leave>",    lambda e: cancel_lbl.config(fg=C["text3"]))

    # ── LOGOUT ─────────────────────────────────
    def _do_logout(self):
        if messagebox.askyesno("Sair", "Deseja sair da sua conta?",
                               parent=self):
            if self._user_data.get("settings", {}).get("clear_clipboard", True):
                try:
                    self.winfo_toplevel().clipboard_clear()
                except Exception:
                    pass
            self.on_logout()


# ─────────────────────────────────────────────
#  APP CONTROLLER
# ─────────────────────────────────────────────
class SavePassApp:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("SavePass — Gerenciador de Senhas")
        self.root.geometry("1100x680")
        self.root.minsize(900, 600)
        self.root.configure(bg=C["bg"])

        # Centered on screen
        self.root.update_idletasks()
        sw = self.root.winfo_screenwidth()
        sh = self.root.winfo_screenheight()
        x  = (sw - 1100) // 2
        y  = (sh - 680)  // 2
        self.root.geometry(f"1100x680+{x}+{y}")

        self._current_frame = None
        self.show_login()

    def _switch(self, frame):
        if self._current_frame:
            self._current_frame.destroy()
        self._current_frame = frame
        frame.pack(fill="both", expand=True)

    def show_login(self):
        self._switch(LoginScreen(self.root, self._handle_login,
                                 self.show_register))

    def show_register(self):
        self._switch(RegisterScreen(self.root, self.show_login,
                                    self.show_login))

    def _handle_login(self, username: str, password: str):
        users = load_users()
        if username not in users:
            messagebox.showerror("Usuário não encontrado",
                                 "Nenhuma conta com este nome de usuário.",
                                 parent=self.root)
            return
        if not verify_password(password, users[username]["hash"]):
            messagebox.showerror("Senha incorreta",
                                 "Senha inválida. Tente novamente.",
                                 parent=self.root)
            return
        self._switch(MainApp(self.root, username, password, self.show_login))

    def run(self):
        self.root.mainloop()


# ─────────────────────────────────────────────
#  ENTRY POINT
# ─────────────────────────────────────────────
if __name__ == "__main__":
    app = SavePassApp()
    app.run()
