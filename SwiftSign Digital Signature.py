import base64
import os
import tkinter as tk
from tkinter import ttk, messagebox, filedialog, scrolledtext, simpledialog
import json
from datetime import datetime
import hashlib
import threading
from collections import deque, OrderedDict
import time
import webbrowser
from PIL import Image, ImageTk
from ttkthemes import ThemedStyle
from ecdsa import SigningKey, VerifyingKey, NIST256p, BadSignatureError
from cryptography.hazmat.primitives.asymmetric import rsa, dh, padding as asym_padding
from cryptography.hazmat.primitives import hashes, serialization, hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
import hmac as std_hmac
import subprocess

# --- Drag and Drop Support ---
try:
    from tkinterdnd2 import DND_FILES, TkinterDnD
    DND_SUPPORT = True
except ImportError:
    DND_SUPPORT = False
    class TkinterDnD:
        @staticmethod
        def Tk(*args, **kwargs):
            return tk.Tk(*args, **kwargs)
    print("Warning: tkinterdnd2 library not found. Drag and drop functionality will be disabled. Install with 'pip install tkinterdnd2'.")

# --- Helper to parse DND file strings ---
def parse_dnd_files(widget, dnd_string):
    try:
        filepaths = widget.tk.splitlist(dnd_string)
        return [fp for fp in filepaths if fp]
    except tk.TclError:
        return [f.strip() for f in dnd_string.replace('} {', '\n').replace('{', '').replace('}', '').splitlines() if f.strip()]

# --- DH Class (Integrated) ---
class OptimizedDH:
    """
    Optimized implementation of Diffie-Hellman, adapted for key generation,
    and HMAC-based "license signing" and verification.
    """
    def __init__(self, cache_size=10):
        self._key_cache = OrderedDict()
        self._shared_secret_cache = OrderedDict()
        self._cache_size = cache_size

    def _cache_key(self, key_type, key_path, key_obj):
        cache_key = f"{key_type}:{key_path}"
        if len(self._key_cache) >= self._cache_size:
            self._key_cache.popitem(last=False)
        self._key_cache[cache_key] = key_obj

    def _get_key(self, key_type, key_path, use_cache=True):
        if not use_cache: return None
        cache_key = f"{key_type}:{key_path}"
        if cache_key in self._key_cache:
            key_obj = self._key_cache.pop(cache_key)
            self._key_cache[cache_key] = key_obj
            return key_obj
        return None

    def _cache_shared_secret(self, cache_key, derived_key):
        if len(self._shared_secret_cache) >= self._cache_size:
            self._shared_secret_cache.popitem(last=False)
        self._shared_secret_cache[cache_key] = derived_key
        
    def _get_cached_shared_secret(self, cache_key):
        if cache_key in self._shared_secret_cache:
            derived_key = self._shared_secret_cache.pop(cache_key)
            self._shared_secret_cache[cache_key] = derived_key
            return derived_key
        return None

    def _derive_hkdf_key(self, shared_material):
        return HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"dh-license-hmac-key",
            backend=default_backend()
        ).derive(shared_material)

    def generate_dh_keys(self, paths, key_size=2048, generator=2, cache=True, password=None):
        if key_size < 2048:
            return False, "Key size must be at least 2048 bits for DH."
        params_path, priv_key_path, pub_key_path = paths
        encryption_algorithm = serialization.NoEncryption() 
        try:
            parameters = dh.generate_parameters(generator=generator, key_size=key_size, backend=default_backend())
            private_key = parameters.generate_private_key()
            public_key = private_key.public_key()
            with open(params_path, "wb") as f:
                f.write(parameters.parameter_bytes(serialization.Encoding.PEM, serialization.ParameterFormat.PKCS3))
            with open(priv_key_path, "wb") as f:
                f.write(private_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, encryption_algorithm))
            with open(pub_key_path, "wb") as f:
                f.write(public_key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
            if cache:
                self._cache_key('params', params_path, parameters) 
                self._cache_key('public', pub_key_path, public_key)
                shared_key_material = private_key.exchange(public_key)
                derived_hmac_key = self._derive_hkdf_key(shared_key_material)
                secret_cache_key = f"{priv_key_path}:{pub_key_path}"
                self._cache_shared_secret(secret_cache_key, derived_hmac_key)
            return True, (params_path, priv_key_path, pub_key_path)
        except Exception as e:
            return False, f"DH key generation failed: {str(e)}"

    def _load_dh_private_key(self, path, cache, password_provider=None):
        cached_key = self._get_key('private', path, cache)
        if cached_key: return cached_key
        with open(path, "rb") as f:
            key_data = f.read()
        try:
            key = serialization.load_pem_private_key(key_data, password=None, backend=default_backend())
        except Exception as e:
            raise ValueError(f"Failed to load DH private key '{os.path.basename(path)}': {str(e)}. Keys are no longer expected to be encrypted.") from e
        if not isinstance(key, dh.DHPrivateKey):
            raise ValueError("Invalid key type: Not a DH private key.")
        if cache: self._cache_key('private', path, key)
        return key

    def _load_dh_public_key(self, path, cache):
        cached_key = self._get_key('public', path, cache)
        if cached_key: return cached_key
        with open(path, "rb") as f:
            key = serialization.load_pem_public_key(f.read(), backend=default_backend())
        if not isinstance(key, dh.DHPublicKey):
            raise ValueError("Invalid key type: Not a DH public key.")
        if cache: self._cache_key('public', path, key)
        return key

    def _get_derived_hmac_key(self, private_key_path, public_key_path, cache, password_provider=None):
        secret_cache_key = f"{private_key_path}:{public_key_path}"
        cached_secret = self._get_cached_shared_secret(secret_cache_key)
        if cached_secret: return cached_secret
        private_key = self._load_dh_private_key(private_key_path, cache, password_provider=None) 
        public_key = self._load_dh_public_key(public_key_path, cache)
        shared_key_material = private_key.exchange(public_key)
        derived_hmac_key = self._derive_hkdf_key(shared_key_material)
        if cache: self._cache_shared_secret(secret_cache_key, derived_hmac_key)
        return derived_hmac_key

    def _derive_public_key_path(self, private_key_path):
        dir_name, base_name = os.path.split(private_key_path)
        if base_name.endswith('.pem'): base_name = base_name[:-4]
        if 'private' in base_name:
            public_base = base_name.replace('private', 'public')
        else:
            public_base = base_name + ".pub" 
        return os.path.join(dir_name, public_base + '.pem')

    def _derive_private_key_path(self, public_key_path):
        dir_name, base_name = os.path.split(public_key_path)
        if base_name.endswith('.pem'): base_name = base_name[:-4]
        if 'public' in base_name:
            private_base = base_name.replace('public', 'private')
        elif base_name.endswith('.pub'):
            private_base = base_name[:-4] 
        else:
            private_base = base_name 
        return os.path.join(dir_name, private_base + '.pem')

    def sign_dh(self, private_key_path, data_string, public_key_path_for_exchange=None, cache=True):
        try:
            if public_key_path_for_exchange is None:
                public_key_path_for_exchange = self._derive_public_key_path(private_key_path)
                if not os.path.exists(public_key_path_for_exchange):
                     return False, f"Could not derive or find public key for exchange: {public_key_path_for_exchange}. DH signing requires both private and public keys to derive a shared secret."
            derived_hmac_key = self._get_derived_hmac_key(private_key_path, public_key_path_for_exchange, cache, password_provider=None) 
            h = hmac.HMAC(derived_hmac_key, hashes.SHA256(), backend=default_backend())
            h.update(data_string.encode('utf-8'))
            signature = h.finalize()
            return True, base64.b64encode(signature).decode('utf-8')
        except Exception as e:
            return False, f"DH (HMAC) signing failed: {str(e)}"

    def verify_dh(self, public_key_path_signer, data_string, signature_b64, cache=True, dh_params_path=None):
        """
        Verifies an HMAC-SHA256 signature derived from a DH key exchange.
        Note: This scheme is unconventional for "digital signatures" as it requires
        the verifier to have access to the signer's private key (or a key pair
        that can reproduce the original shared secret). This method assumes the
        signer's private key path can be derived from public_key_path_signer.
        Optionally validates public key parameters against a provided DH parameters file.
        """
        try:
            public_key = self._load_dh_public_key(public_key_path_signer, cache)

            if dh_params_path and os.path.exists(dh_params_path):
                try:
                    with open(dh_params_path, "rb") as f_params:
                        explicit_parameters = serialization.load_pem_parameters(f_params.read(), backend=default_backend())
                    if not isinstance(explicit_parameters, dh.DHParameters):
                        return False, "Invalid DH parameters file format (not DHParameter type)."
                    pk_params_numbers = public_key.parameters().parameter_numbers()
                    explicit_params_numbers = explicit_parameters.parameter_numbers()
                    if pk_params_numbers.p != explicit_params_numbers.p or \
                       pk_params_numbers.g != explicit_params_numbers.g:
                        return False, ("DH parameters in public key do not match those in the provided parameters file. "
                                       "Please ensure consistency.")
                except Exception as e:
                    return False, f"Error loading or comparing DH parameters file '{os.path.basename(dh_params_path)}': {str(e)}"
            elif dh_params_path and not os.path.exists(dh_params_path):
                 return False, f"Provided DH parameters file not found: {os.path.basename(dh_params_path)}"
            derived_private_key_path_signer = self._derive_private_key_path(public_key_path_signer)
            if not os.path.exists(derived_private_key_path_signer):
                 return False, f"DH (HMAC) Verification Error: Could not find the signer's private key file ('{os.path.basename(derived_private_key_path_signer)}'), which is derived from the public key file ('{os.path.basename(public_key_path_signer)}') and is required for this verification scheme."
            derived_hmac_key = self._get_derived_hmac_key(derived_private_key_path_signer, public_key_path_signer, cache, password_provider=None) 
            h = hmac.HMAC(derived_hmac_key, hashes.SHA256(), backend=default_backend())
            h.update(data_string.encode('utf-8'))
            expected_signature = h.finalize()
            decoded_signature = base64.b64decode(signature_b64.encode('utf-8'))
            if std_hmac.compare_digest(decoded_signature, expected_signature):
                return True, "DH (HMAC) Signature VALID"
            else:
                return False, "DH (HMAC) Signature INVALID: Verification failed."
        except Exception as e:
            return False, f"DH (HMAC) verification error: {str(e)}"

    def clear_cache(self):
        self._key_cache.clear()
        self._shared_secret_cache.clear()

# --- Custom ElGamal (RSA-PSS based) Implementation ---
class ElGamal:
    @staticmethod
    def generate_private_key(key_size=2048, backend=None):
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=backend or default_backend()
        )
        return key
    @staticmethod
    def sign(private_key, data_bytes, hash_algorithm=None):
        signature = private_key.sign(
            data_bytes,
            asym_padding.PSS(
                mgf=asym_padding.MGF1(hashes.SHA256()),
                salt_length=asym_padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return signature
    @staticmethod
    def verify(public_key, signature, data_bytes, hash_algorithm=None):
        try:
            public_key.verify(
                signature,
                data_bytes,
                asym_padding.PSS(
                    mgf=asym_padding.MGF1(hashes.SHA256()),
                    salt_length=asym_padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except InvalidSignature:
            raise

# --- Styling Class ---
class AppStyles:
    DEFAULT_COLORS = {
        'primary': '#5b5b5b', 
        'primary_hover': '#2980b9', 
        'primary_active': '#2c3e50',
        'secondary': '#2ecc71', 
        'warning': '#f39c12', 
        'danger': '#e74c3c',
        'light': '#ecf0f1', 
        'dark': '#2c3e50', 
        'white': '#ffffff', 
        'black': '#000000',
        'gray': '#f5f5f5', 
        'frame_border': '#d9d9d9',
        'success_bg': '#d4edda', 
        'success_fg': '#155724',
        'error_bg': '#f8d7da', 
        'error_fg': '#721c24',
        'info_bg': '#cce5ff', 
        'info_fg': '#004085', 
        'highlight': '#3498db'
    }
    DARK_MODE_COLORS = {
        'primary': '#28a745', 
        'primary_hover': '#2f9ee6', 
        'primary_active': '#1a7cad',
        'secondary': '#2ecc71', 
        'warning': '#f39c12', 
        'danger': '#e74c3c',
        'light': '#4a4a4a', 
        'dark': '#e0e0e0', 
        'white': '#3b3b3b', 
        'black': '#ffffff',
        'gray': '#3a3a3a', 
        'frame_border': '#555555',
        'success_bg': '#103a16', 
        'success_fg': '#d4edda',
        'error_bg': '#5c1c24', 
        'error_fg': '#f8d7da',
        'info_bg': '#003366', 
        'info_fg': '#cce5ff', 
        'highlight': '#5fa8db'
    }
    COLORS = DEFAULT_COLORS.copy()
    FONTS = {
        'header': ('Helvetica', 30, 'bold'), 
        'subheader': ('Helvetica', 13, 'normal'),
        'body': ('Helvetica', 12), 
        'body_bold': ('Helvetica', 12, 'bold'),
        'medium': ('Helvetica', 11),
        'small': ('Helvetica', 10), 
        'tiny': ('Helvetica', 8)
    }
    @staticmethod
    def update_theme(dark_mode_enabled: bool):
        AppStyles.COLORS.clear()
        AppStyles.COLORS.update(AppStyles.DARK_MODE_COLORS if dark_mode_enabled else AppStyles.DEFAULT_COLORS)
    @staticmethod
    def apply(root):
        style = ttk.Style(root)
        is_dark_mode = AppStyles.COLORS['white'] == AppStyles.DARK_MODE_COLORS['white']
        try:
            themed_style = ThemedStyle(root)
            theme = "equilux" if is_dark_mode else "arc"
            themed_style.set_theme(theme)
            style = themed_style
        except tk.TclError: 
            print("ThemedStyle not available or theme engine missing. Using default ttk styles.")
            pass 

        # --- Standard TButton Styling ---
        style.configure('TButton', font=AppStyles.FONTS['body'], padding=5,background=AppStyles.COLORS['light'], foreground=AppStyles.COLORS['black'])
        style.map('TButton',background=[('active', AppStyles.COLORS['dark']), ('!active', AppStyles.COLORS['light'])],foreground=[('active', AppStyles.COLORS['black']), ('!active', AppStyles.COLORS['black'])])
        if is_dark_mode:
            primary_bg_normal = AppStyles.COLORS['primary']         
            primary_fg_normal = '#ffffff' 
            primary_bg_active = AppStyles.COLORS['primary_active']
            primary_fg_active = AppStyles.COLORS['black'] 
        else: 
            primary_bg_normal = AppStyles.COLORS['light'] 
            primary_fg_normal = '#00bc8c'                 
            primary_bg_active = AppStyles.COLORS['primary_active'] 
            primary_fg_active = '#077bff'                  
        style.configure('Primary.TButton', font=AppStyles.FONTS['body'], padding=5,background=primary_bg_normal, foreground=primary_fg_normal)
        style.map('Primary.TButton',background=[('active', primary_bg_active), ('!active', primary_bg_normal)],foreground=[('active', primary_fg_active), ('!active', primary_fg_normal)])
        style.configure('TLabel', font=AppStyles.FONTS['body'], background=AppStyles.COLORS['white'], foreground=AppStyles.COLORS['dark'])
        style.configure('Header.TLabel', font=AppStyles.FONTS['header'], background=AppStyles.COLORS['white'], foreground=AppStyles.COLORS['dark'])
        style.configure('Subheader.TLabel', font=AppStyles.FONTS['subheader'], background=AppStyles.COLORS['white'], foreground=AppStyles.COLORS['dark'])
        style.configure('Success.TLabel', background=AppStyles.COLORS['success_bg'], foreground=AppStyles.COLORS['success_fg'], font=AppStyles.FONTS['body_bold'], padding=10)
        style.configure('Error.TLabel', background=AppStyles.COLORS['error_bg'], foreground=AppStyles.COLORS['error_fg'], font=AppStyles.FONTS['body_bold'], padding=10)
        style.configure('Info.TLabel', background=AppStyles.COLORS['info_bg'], foreground=AppStyles.COLORS['info_fg'], font=AppStyles.FONTS['body_bold'], padding=10)
        style.configure('Warning.TLabel', background=AppStyles.COLORS['warning'], foreground=AppStyles.COLORS['black'], font=AppStyles.FONTS['body'], padding=5) # Added for DH warning
        style.configure('TFrame', background=AppStyles.COLORS['white'])
        style.configure('AboutScrollable.TFrame', background=AppStyles.COLORS['gray'])
        style.configure('TNotebook', background=AppStyles.COLORS['white'])
        style.configure('TNotebook.Tab', font=AppStyles.FONTS['body'], padding=[10, 5],background=AppStyles.COLORS['light'], foreground=AppStyles.COLORS['dark'])
        style.map('TNotebook.Tab',background=[('selected', AppStyles.COLORS['white']), ('!selected', AppStyles.COLORS['light'])],foreground=[('selected', AppStyles.COLORS['primary']), ('!selected', AppStyles.COLORS['dark'])])
        style.configure('TEntry', fieldbackground=AppStyles.COLORS['white'], foreground=AppStyles.COLORS['black'], insertbackground=AppStyles.COLORS['black'])
        style.configure('TCombobox', fieldbackground=AppStyles.COLORS['white'], foreground=AppStyles.COLORS['black'])
        root.option_add('*TCombobox*Listbox.background', AppStyles.COLORS['white'])
        root.option_add('*TCombobox*Listbox.foreground', AppStyles.COLORS['black'])
        root.option_add('*TCombobox*Listbox.selectBackground', AppStyles.COLORS['highlight'])
        root.option_add('*TCombobox*Listbox.selectForeground', AppStyles.COLORS['white'])
        style.configure('TLabelframe', background=AppStyles.COLORS['white'], relief=tk.GROOVE, borderwidth=1)
        style.configure('TLabelframe.Label', background=AppStyles.COLORS['white'], foreground=AppStyles.COLORS['dark'], font=AppStyles.FONTS['body_bold'])
        style.configure('About.TLabelframe', background=AppStyles.COLORS['gray'], bordercolor=AppStyles.COLORS['frame_border'], relief=tk.GROOVE, borderwidth=1)
        style.configure('About.TLabelframe.Label', background=AppStyles.COLORS['gray'], foreground=AppStyles.COLORS['dark'], font=AppStyles.FONTS['body_bold'])
        style.configure('TCheckbutton', background=AppStyles.COLORS['white'], foreground=AppStyles.COLORS['dark'], font=AppStyles.FONTS['body'])
        style.map('TCheckbutton',background=[('active', AppStyles.COLORS['white'])],indicatorcolor=[('selected', AppStyles.COLORS['primary']), ('!selected', AppStyles.COLORS['dark'])],foreground=[('disabled', AppStyles.COLORS['gray'])])
        style.configure("Treeview", background=AppStyles.COLORS['white'], foreground=AppStyles.COLORS['black'], fieldbackground=AppStyles.COLORS['white'], rowheight=25)
        style.map("Treeview", background=[('selected', AppStyles.COLORS['highlight'])], foreground=[('selected', AppStyles.COLORS['white'])])
        style.configure("Treeview.Heading", font=AppStyles.FONTS['body_bold'], background=AppStyles.COLORS['light'], foreground=AppStyles.COLORS['black'])
        style.map("Treeview.Heading", background=[('active', AppStyles.COLORS['primary_hover'])])

# --- Animated Label for status messages ---
class AnimatedLabel(tk.Label):
    def __init__(self, parent, animations_enabled_func, *args, **kwargs):
        super().__init__(parent, *args, **kwargs)
        self._alpha = 0
        self._fade_duration = 300
        self._fade_steps = 10
        self._fade_delay = self._fade_duration // self._fade_steps
        self.animations_enabled_func = animations_enabled_func
        self._after_id = None
        self._text_color_target = kwargs.get('foreground', AppStyles.COLORS['dark'])

    def _stop_fade(self):
        if self._after_id:
            self.after_cancel(self._after_id)
            self._after_id = None

    def fade_in(self):
        self._stop_fade()
        self._text_color_target = self.cget('foreground')
        if not self.animations_enabled_func():
            self.config(fg=self._text_color_target)
            self._alpha = 1
            return
        self._alpha = 0
        self._fade(1)

    def fade_out(self):
        self._stop_fade()
        if not self.animations_enabled_func():
            self.config(fg=self.cget('bg'))
            self._alpha = 0
            return
        self._alpha = 1
        self._fade(-1)

    def _fade(self, direction):
        if not self.animations_enabled_func():
            self._alpha = 1 if direction > 0 else 0
            self.config(fg=self._get_faded_color(True))
            return
        target_alpha = 1 if direction > 0 else 0
        if (direction > 0 and self._alpha >= 1) or (direction < 0 and self._alpha <= 0):
            self._alpha = target_alpha
            self.config(fg=self._get_faded_color(True))
            return
        self._alpha += direction * (1 / self._fade_steps)
        self._alpha = max(0, min(1, self._alpha))
        self.config(fg=self._get_faded_color())
        self._after_id = self.after(self._fade_delay, lambda: self._fade(direction))

    def _get_faded_color(self, force_final_color=False):
        current_alpha = self._alpha
        if force_final_color:
            current_alpha = 1.0 if (self._alpha >= 0.5 and self._alpha <=1.0) else 0.0
        
        def color_to_rgb(color_str):
            try:
                if color_str.startswith('#'):
                    return tuple(int(color_str[i:i+2], 16) for i in (1, 3, 5))
                r, g, b = self.winfo_rgb(color_str) 
                return r // 256, g // 256, b // 256
            except tk.TclError: 
                 is_dark_mode = AppStyles.COLORS['white'] == AppStyles.DARK_MODE_COLORS['white']
                 default_fg_rgb = (224, 224, 224) if is_dark_mode else (44, 62, 80) 
                 default_bg_rgb = (59, 59, 59) if is_dark_mode else (255, 255, 255)  
                 if color_str == self._text_color_target: return default_fg_rgb
                 if color_str == self.cget('bg'): return default_bg_rgb
                 return default_fg_rgb 
            except ValueError: 
                 is_dark_mode = AppStyles.COLORS['white'] == AppStyles.DARK_MODE_COLORS['white']
                 return (44, 62, 80) if not is_dark_mode else (224, 224, 224)
        base_fg_rgb = color_to_rgb(self._text_color_target)
        bg_rgb = color_to_rgb(self.cget('bg'))
        r = int(bg_rgb[0] + (base_fg_rgb[0] - bg_rgb[0]) * current_alpha)
        g = int(bg_rgb[1] + (base_fg_rgb[1] - bg_rgb[1]) * current_alpha)
        b = int(bg_rgb[2] + (base_fg_rgb[2] - bg_rgb[2]) * current_alpha)
        return f'#{r:02x}{g:02x}{b:02x}'

    def update_style(self):
        self.config(bg=AppStyles.COLORS['white']) 
        self._text_color_target = AppStyles.COLORS['dark']
        if self._alpha > 0:
             self.config(fg=self._get_faded_color(self._alpha >= 1.0))
        else:
             self.config(fg=self.cget('bg'))

# --- Status Bar ---
class StatusBar(ttk.Frame):
    def __init__(self, parent, animations_enabled_func):
        super().__init__(parent, style='TFrame')
        self.animations_enabled_func = animations_enabled_func
        self.message_var = tk.StringVar()
        self.message_label = AnimatedLabel(self, self.animations_enabled_func, textvariable=self.message_var, anchor='w', font=AppStyles.FONTS['body'], bg=AppStyles.COLORS['white'], fg=AppStyles.COLORS['dark'])
        self.message_label.pack(side='left', fill='x', expand=True, padx=5, pady=2)
        self.progress_label = ttk.Label(self, text="0%")
        self.progress_bar = ttk.Progressbar(self, orient='horizontal', mode='determinate', length=150)
        self.hide_progress()
        self.update_style()

    def update_style(self):
        self.config(style='TFrame') 
        self.message_label.update_style() 
        self.progress_label.config(style='TLabel', background=AppStyles.COLORS['white'], foreground=AppStyles.COLORS['dark'])

    def set_message(self, message, status='info'):
        self.message_var.set(message)
        color_map = {
            'info': AppStyles.COLORS['dark'], 'success': AppStyles.COLORS['secondary'],
            'error': AppStyles.COLORS['danger'], 'warning': AppStyles.COLORS['warning']
        }
        new_fg_color = color_map.get(status, AppStyles.COLORS['dark'])
        self.message_label.config(foreground=new_fg_color)
        self.message_label._text_color_target = new_fg_color
        if self.animations_enabled_func():
            self.message_label.fade_in()
        else:
            self.message_label.config(fg=new_fg_color)
            self.message_label._alpha = 1

    def show_progress(self):
        if not self.progress_label.winfo_ismapped():
            self.progress_label.pack(side='right', padx=(0, 5), pady=2)
        if not self.progress_bar.winfo_ismapped():
            self.progress_bar.pack(side='right', padx=5, pady=2)

    def hide_progress(self):
        self.progress_bar.pack_forget()
        self.progress_label.pack_forget()

    def set_progress(self, value, text_override=None):
        if not self.progress_bar.winfo_ismapped(): self.show_progress()
        self.progress_bar['value'] = value
        self.progress_label.config(text=text_override if text_override else f"{int(value)}%")
        if value >= 100 and not text_override:
            self.after(2000, self.hide_progress)

# --- File Selector ---
class FileSelector(ttk.Frame):
    def __init__(self, parent, label_text="Select File", on_file_selected=None, filetypes=None, mode='open', defaultextension=None, animations_enabled_func=lambda: True, initialdir_func=None, select_directory=False):
        super().__init__(parent, style='TFrame')
        self.on_file_selected = on_file_selected
        self.filetypes = filetypes or [("All files", "*.*")]
        self.mode = mode 
        self.defaultextension = defaultextension
        self.animations_enabled_func = animations_enabled_func
        self.initialdir_func = initialdir_func
        self.select_directory = select_directory
        self.columnconfigure(1, weight=1)
        self.label = ttk.Label(self, text=label_text)
        self.label.grid(row=0, column=0, padx=5, pady=5, sticky='w')
        self.file_path = tk.StringVar()
        self.entry = ttk.Entry(self, textvariable=self.file_path, width=50)
        self.entry.grid(row=0, column=1, padx=5, pady=5, sticky='ew')
        self.browse_button = ttk.Button(self, text="Browse", command=self._browse_file)
        self.browse_button.grid(row=0, column=2, padx=5, pady=5)
        self.entry.bind('<FocusIn>', lambda e: self._animate_focus(True))
        self.entry.bind('<FocusOut>', lambda e: self._animate_focus(False))
        if DND_SUPPORT:
            self.entry.drop_target_register(DND_FILES)
            self.entry.dnd_bind('<<Drop>>', self._on_drop)
        self.update_style()

    def _on_drop(self, event):
        if not DND_SUPPORT: return
        filepaths = parse_dnd_files(self.entry, event.data)
        if filepaths:
            selected_path = filepaths[0]
            if self.select_directory:
                if os.path.isfile(selected_path):
                    selected_path = os.path.dirname(selected_path)
                elif not os.path.isdir(selected_path):
                    messagebox.showwarning("Drag & Drop Error", f"Dropped item '{selected_path}' is not a valid file or directory.", parent=self.winfo_toplevel())
                    return
            self.file_path.set(selected_path)
            if self.on_file_selected:
                self.on_file_selected(selected_path)
            if self.animations_enabled_func():
                original_fg = self.entry.cget('foreground')
                self.entry.config(foreground=AppStyles.COLORS['highlight'])
                self.entry.after(500, lambda: self.entry.config(foreground=original_fg if self.entry != self.focus_get() else AppStyles.COLORS['highlight']))

    def _animate_focus(self, focus_in):
        if not self.animations_enabled_func():
            self.entry.config(foreground=AppStyles.COLORS['black'])
            return
        self.entry.config(foreground=AppStyles.COLORS['highlight'] if focus_in else AppStyles.COLORS['black'])

    def update_style(self):
        self.config(style='TFrame')
        self.label.config(style='TLabel')
        self.entry.config(style='TEntry') 
        self.browse_button.config(style='TButton')
        self._animate_focus(self.entry == self.focus_get())

    def _browse_file(self):
        initial_dir = self.initialdir_func() if self.initialdir_func else os.path.expanduser("~")
        filepath = None
        title_base = self.label.cget('text').replace(':', '')
        if self.select_directory:
            filepath = filedialog.askdirectory(parent=self, initialdir=initial_dir, title=f"Select {title_base}")
        elif self.mode == 'save':
            filepath = filedialog.asksaveasfilename(filetypes=self.filetypes, defaultextension=self.defaultextension, parent=self, initialdir=initial_dir, title=f"Save {title_base}")
        else:
            filepath = filedialog.askopenfilename(filetypes=self.filetypes, parent=self, initialdir=initial_dir, title=f"Open {title_base}")
        if filepath:
            self.file_path.set(filepath)
            if self.on_file_selected: self.on_file_selected(filepath)
            if self.animations_enabled_func():
                original_fg = self.entry.cget('foreground')
                self.entry.config(foreground=AppStyles.COLORS['highlight'])
                self.entry.after(500, lambda: self.entry.config(foreground=original_fg if self.entry != self.focus_get() else AppStyles.COLORS['highlight']))
    def get_path(self): return self.file_path.get()
    def set_path(self, path): self.file_path.set(path)

# --- Result Display ---
class ResultDisplay(ttk.Frame):
    def __init__(self, parent):
        super().__init__(parent, style='TFrame')
        self.status_var = tk.StringVar(value="No operation performed yet.")
        self.status_label = ttk.Label(self, textvariable=self.status_var, anchor='w', style='Info.TLabel')
        self.status_label.pack(side='top', fill='x', padx=10, pady=(10,1))
        self.result_text = scrolledtext.ScrolledText(self, height=8, width=60, wrap=tk.WORD, relief=tk.SOLID, borderwidth=1)
        self.result_text.pack(side='top', fill='both', expand=True, padx=10, pady=5)
        self.result_text.config(state='disabled')
        self.update_style()

    def update_style(self):
        self.config(style='TFrame')
        current_style = self.status_label.cget("style") 
        self.status_label.configure(style=current_style or 'Info.TLabel') 
        self.result_text.config(background=AppStyles.COLORS['white'], foreground=AppStyles.COLORS['black'],insertbackground=AppStyles.COLORS['black'], selectbackground=AppStyles.COLORS['highlight'], selectforeground=AppStyles.COLORS['white'])
        try:
            self.result_text.tag_configure("sel", background=AppStyles.COLORS['highlight'], foreground=AppStyles.COLORS['white'])
            self.result_text.tag_configure("error", foreground=AppStyles.COLORS['black'])
            self.result_text.tag_configure("success", foreground=AppStyles.COLORS['black'])
        except tk.TclError: 
            pass

    def _update_display(self, message, details, style_name):
        self.status_var.set(message)
        self.status_label.configure(style=style_name)
        self.result_text.config(state='normal')
        self.result_text.delete(1.0, tk.END)
        if details: self.result_text.insert(tk.END, details)
        self.result_text.config(state='disabled')
    def set_success(self, message, details=""): self._update_display(message, details, 'Success.TLabel')
    def set_error(self, message, details=""): self._update_display(message, details, 'Error.TLabel')
    def set_info(self, message, details=""): self._update_display(message, details, 'Info.TLabel')
    def clear(self): self._update_display("No operation performed yet.", "", 'Info.TLabel')
    def append_text(self, text, tag=None):
        self.result_text.config(state='normal')
        if tag:
            self.result_text.insert(tk.END, text, (tag,))
        else:
            self.result_text.insert(tk.END, text)
        self.result_text.yview(tk.END)
        self.result_text.config(state='disabled')

# --- Undo Manager ---
class UndoManager:
    def __init__(self, max_history=20):
        self.undo_stack = deque(maxlen=max_history)
        self.redo_stack = deque(maxlen=max_history)

    def add_action(self, action_type: str, data: dict):
        action = {'type': action_type, 'data': data, 'timestamp': time.time()}
        self.undo_stack.append(action)
        self.redo_stack.clear()

    def undo(self):
        if not self.undo_stack: return None
        action = self.undo_stack.pop()
        self.redo_stack.append(action)
        return action

    def redo(self):
        if not self.redo_stack: return None
        action = self.redo_stack.pop()
        self.undo_stack.append(action)
        return action

    def can_undo(self): return len(self.undo_stack) > 0
    def can_redo(self): return len(self.redo_stack) > 0

# --- Settings Panel ---
class SettingsPanel(tk.Toplevel):
    def __init__(self, parent_for_toplevel, 
                 actual_ui_container,    
                 app_settings_dict,      
                 app_apply_settings_cb,  
                 app_settings_tk_vars,   
                 app_revert_tk_vars_cb,  
                 is_modal_dialog=True,
                 app_base_dir=""):
        super().__init__(parent_for_toplevel) 
        self.actual_ui_container = actual_ui_container if actual_ui_container else self 
        self.app_settings_dict = app_settings_dict 
        self.app_apply_settings_cb = app_apply_settings_cb
        self.app_revert_tk_vars_cb = app_revert_tk_vars_cb
        self.is_modal_dialog = is_modal_dialog
        self.app_base_dir = app_base_dir
        self.key_dir_var = app_settings_tk_vars['key_dir']
        self.default_algo_var = app_settings_tk_vars['default_algo']
        self.animations_var = app_settings_tk_vars['animations']
        self.dark_mode_var = app_settings_tk_vars['dark_mode']
        if not self.is_modal_dialog:
            self.withdraw() 
        if self.is_modal_dialog:
            self.title("Settings")
            self.geometry("600x450")
            try:
                icon_path = os.path.join(self.app_base_dir, "icons", "icon.ico")
                if os.path.exists(icon_path): self.iconbitmap(icon_path)
                else: print(f"Icon file not found for settings window: {icon_path}")
            except Exception as e: 
                print(f"Could not set settings window icon: {e}")
            if parent_for_toplevel: self.transient(parent_for_toplevel)
            self.grab_set()
            self.protocol("WM_DELETE_WINDOW", self.destroy) 
        self.create_widgets()
        self.update_widget_styles()

    def create_widgets(self):
        ui_parent = self.actual_ui_container
        self.main_frame = ttk.Frame(ui_parent, padding="10", style='TFrame')
        self.main_frame.pack(fill='both', expand=True)
        self.general_frame = ttk.LabelFrame(self.main_frame, text="General Settings", padding="10", style='TLabelframe')
        self.general_frame.pack(fill='x', pady=5)
        self.general_frame.columnconfigure(1, weight=1)
        self.key_dir_label = ttk.Label(self.general_frame, text="Default Key Directory:")
        self.key_dir_label.grid(row=0, column=0, sticky='w', pady=3, padx=2)
        self.key_dir_entry = ttk.Entry(self.general_frame, textvariable=self.key_dir_var, width=40)
        self.key_dir_entry.grid(row=0, column=1, sticky='ew', padx=5)
        self.key_dir_button = ttk.Button(self.general_frame, text="Browse", command=self._browse_key_dir)
        self.key_dir_button.grid(row=0, column=2, padx=5)
        self.default_algo_label = ttk.Label(self.general_frame, text="Default Algorithm:")
        self.default_algo_label.grid(row=1, column=0, sticky='w', pady=3, padx=2)
        self.algo_combo = ttk.Combobox(self.general_frame, textvariable=self.default_algo_var,values=["ECC", "RSA", "ElGamal", "Diffie-Hellman"], state='readonly')
        self.algo_combo.grid(row=1, column=1, sticky='w', padx=5)
        self.ui_frame = ttk.LabelFrame(self.main_frame, text="UI Settings", padding="10", style='TLabelframe')
        self.ui_frame.pack(fill='x', pady=5)
        self.animations_check = ttk.Checkbutton(self.ui_frame, text="Enable UI animations", variable=self.animations_var, style='TCheckbutton')
        self.animations_check.grid(row=0, column=0, sticky='w', columnspan=2, pady=2)
        self.dark_mode_check = ttk.Checkbutton(self.ui_frame, text="Dark mode", variable=self.dark_mode_var, style='TCheckbutton')
        self.dark_mode_check.grid(row=1, column=0, sticky='w', columnspan=2, pady=2)
        self.button_frame = ttk.Frame(self.main_frame, style='TFrame')
        self.button_frame.pack(fill='x', pady=15, side='bottom')
        self.save_button = ttk.Button(self.button_frame, text="Save", command=self.save_and_apply_settings, style='Primary.TButton')
        self.save_button.pack(side='right', padx=5)
        cancel_command = self.destroy if self.is_modal_dialog else self.app_revert_tk_vars_cb
        self.cancel_button = ttk.Button(self.button_frame, text="Cancel", command=cancel_command)
        self.cancel_button.pack(side='right', padx=5)

    def update_widget_styles(self):
        container_to_style = self.actual_ui_container
        if isinstance(container_to_style, tk.Toplevel): 
            container_to_style.configure(bg=AppStyles.COLORS['white'])
        self.main_frame.configure(style='TFrame')
        self.general_frame.configure(style='TLabelframe')
        self.ui_frame.configure(style='TLabelframe')
        self.button_frame.configure(style='TFrame')
        self.key_dir_label.configure(style='TLabel')
        self.default_algo_label.configure(style='TLabel')
        self.key_dir_entry.configure(style='TEntry')
        self.algo_combo.configure(style='TCombobox')
        self.option_add('*TCombobox*Listbox.background', AppStyles.COLORS['white'])
        self.option_add('*TCombobox*Listbox.foreground', AppStyles.COLORS['black'])
        self.option_add('*TCombobox*Listbox.selectBackground', AppStyles.COLORS['highlight'])
        self.option_add('*TCombobox*Listbox.selectForeground', AppStyles.COLORS['white'])
        self.animations_check.configure(style='TCheckbutton')
        self.dark_mode_check.configure(style='TCheckbutton')
        self.key_dir_button.configure(style='TButton')
        self.save_button.configure(style='Primary.TButton')
        self.cancel_button.configure(style='TButton')

    def _browse_key_dir(self):
        dialog_parent = self.winfo_toplevel()
        dir_path = filedialog.askdirectory(parent=dialog_parent, title="Select Default Key Directory", initialdir=self.key_dir_var.get() or os.path.expanduser("~"))
        if dir_path: self.key_dir_var.set(dir_path)

    def save_and_apply_settings(self):
        if self.app_apply_settings_cb:
            self.app_apply_settings_cb() 
        msg_box_parent = self if self.is_modal_dialog and self.winfo_viewable() else self.master.winfo_toplevel()
        messagebox.showinfo("Settings Saved", "Settings saved successfully. Some changes may require an application restart to fully apply.", parent=msg_box_parent)
        if self.is_modal_dialog:
            self.destroy() 

# --- Main Application ---
class CryptoLicenseSystem:
    def __init__(self, root):
        self.root = root
        self.app_base_dir = os.path.dirname(os.path.abspath(__file__))
        try:
            icon_path = os.path.join(self.app_base_dir, "icons", "icon.ico")
            if os.path.exists(icon_path): self.root.iconbitmap(icon_path)
            else: print(f"Icon file not found: {icon_path}")
        except Exception as e: print(f"Could not set window icon: {e}")
        self.root.title("SwiftSign Digital Signature")
        self.root.geometry("1300x700")
        self.root.minsize(1300, 700) 
        self.settings = self.load_app_settings()
        self.settings_key_dir_var = tk.StringVar()
        self.settings_default_algo_var = tk.StringVar()
        self.settings_animations_var = tk.BooleanVar()
        self.settings_dark_mode_var = tk.BooleanVar()
        self._load_settings_into_tk_vars() 
        AppStyles.update_theme(self.settings.get('dark_mode', False))
        self.undo_manager = UndoManager(max_history=20)
        self.current_algorithm = tk.StringVar(value=self.settings.get('default_algorithm', 'ECC'))
        self.default_key_dir = self.settings.get('default_key_dir', os.path.join(os.path.expanduser("~"), "CryptoLicense_Keys"))
        os.makedirs(self.default_key_dir, exist_ok=True)
        self.logo_label = None 
        self.logo_photoimage = None
        self.title_font_config = AppStyles.FONTS['header']
        self.subtitle_font_config = AppStyles.FONTS['subheader']
        AppStyles.apply(self.root)
        self.dh_optimized_instance = OptimizedDH() 
        self.crypto_engines = {
            'ECC': self.ecc_engine(),
            'RSA': self.rsa_engine(),
            'ElGamal': self.elgamal_engine(), 
            'Diffie-Hellman': self.create_optimized_dh_engine(self.dh_optimized_instance)
        }
        self.settings_dialog_instance = None 
        self.settings_tab_panel_instance = None 
        self.batch_sign_files = []
        self.batch_verify_files = []
        self.create_menu()
        self.create_main_ui()
        self.refresh_ui_styles()
        self.root.bind_all('<Control-z>', lambda e: self.undo_action())
        self.root.bind_all('<Control-y>', lambda e: self.redo_action())
        self.root.bind_all('<Control-s>', lambda e: self.open_settings())
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        self.root.after(200, self.start_header_animations)
        
    def _get_settings_tk_vars_as_dict(self):
        return {
            'key_dir': self.settings_key_dir_var,
            'default_algo': self.settings_default_algo_var,
            'animations': self.settings_animations_var,
            'dark_mode': self.settings_dark_mode_var,
        }

    def _load_settings_into_tk_vars(self):
        self.settings_key_dir_var.set(self.settings.get('default_key_dir', os.path.join(os.path.expanduser("~"), "SwiftSign_Keys")))
        self.settings_default_algo_var.set(self.settings.get('default_algorithm', 'ECC'))
        self.settings_animations_var.set(self.settings.get('enable_animations', True))
        self.settings_dark_mode_var.set(self.settings.get('dark_mode', False))

    def are_animations_enabled(self): return self.settings.get('enable_animations', True)
    def get_default_key_dir(self): return self.settings.get('default_key_dir', self.default_key_dir)

    def _update_logo_image(self):
        if not hasattr(self, 'logo_label') or not self.logo_label or not self.logo_label.winfo_exists():
            return
        is_dark_mode = self.settings.get('dark_mode', False)
        logo_filename_light_theme = "logo darkimage1.png"
        logo_filename_dark_theme = "logo lightimag2.png"
        logo_path_light_theme = os.path.join(self.app_base_dir, "images", logo_filename_light_theme)
        logo_path_dark_theme = os.path.join(self.app_base_dir, "images", logo_filename_dark_theme)
        if is_dark_mode:
            primary_logo_path = logo_path_dark_theme
            fallback_logo_path = logo_path_light_theme
            primary_logo_filename = logo_filename_dark_theme
            fallback_logo_filename = logo_filename_light_theme
        else:
            primary_logo_path = logo_path_light_theme
            fallback_logo_path = logo_path_dark_theme
            primary_logo_filename = logo_filename_light_theme
            fallback_logo_filename = logo_filename_dark_theme
        logo_path_to_load = primary_logo_path
        if not os.path.exists(logo_path_to_load):
            print(f"Warning: Primary logo image file not found at {primary_logo_path}. Trying the other mode's logo path if it exists.")
            logo_path_to_load = fallback_logo_path
            if not os.path.exists(logo_path_to_load):
                print(f"Warning: Fallback logo image file not found at {fallback_logo_path}. No logo will be displayed.")
                self.logo_label.config(image=None, bg=AppStyles.COLORS['white'])
                self.logo_photoimage = None
                return
        new_photoimage = None
        try:
            logo_img_pil = Image.open(logo_path_to_load).resize((190,100), Image.Resampling.LANCZOS)
            new_photoimage = ImageTk.PhotoImage(logo_img_pil)
        except Exception as e:
            error_message = f"Could not load logo from '{logo_path_to_load}': {type(e).__name__} - {e}"
            print(f"Warning: {error_message}")
        self.logo_photoimage = new_photoimage
        self.logo_label.config(image=self.logo_photoimage, bg=AppStyles.COLORS['white'])
        if self.logo_photoimage: self.logo_label.image = self.logo_photoimage
        else: self.logo_label.image = None

    def create_menu(self):
        self.menubar = tk.Menu(self.root)
        file_menu = tk.Menu(self.menubar, tearoff=0)
        file_menu.add_command(label="Key Generation", command=lambda: self.notebook.select(self.keygen_frame_outer))
        file_menu.add_command(label="License Signing", command=lambda: self.notebook.select(self.sign_frame_outer))
        file_menu.add_command(label="License Verification", command=lambda: self.notebook.select(self.verify_frame_outer))
        file_menu.add_command(label="Batch Operations", command=lambda: self.notebook.select(self.batch_ops_tab_outer_frame))
        file_menu.add_command(label="Search", command=lambda: self.notebook.select(self.search_frame_outer))
        file_menu.add_separator()
        file_menu.add_command(label="Settings...", command=self.open_settings, accelerator="Ctrl+S")
        file_menu.add_separator()
        file_menu.add_command(label="Reset", command=self.reset_application)
        file_menu.add_command(label="Exit", command=self.on_close)
        self.menubar.add_cascade(label="File", menu=file_menu)
        edit_menu = tk.Menu(self.menubar, tearoff=0)
        edit_menu.add_command(label="Undo", command=self.undo_action, accelerator="Ctrl+Z", state='disabled')
        edit_menu.add_command(label="Redo", command=self.redo_action, accelerator="Ctrl+Y", state='disabled')
        self.menubar.add_cascade(label="Edit", menu=edit_menu)
        self.edit_menu = edit_menu
        self._update_undo_redo_menu_state()
        help_menu = tk.Menu(self.menubar, tearoff=0)
        help_menu.add_command(label="Documentation", command=self.show_documentation)
        help_menu.add_command(label="Submit Feedback", command=self.show_feedback_form)
        help_menu.add_command(label="About", command=lambda: self.notebook.select(self.about_outer_frame)) 
        self.menubar.add_cascade(label="Help", menu=help_menu)
        self.root.config(menu=self.menubar)

    def _update_undo_redo_menu_state(self):
        if hasattr(self, 'edit_menu'):
            self.edit_menu.entryconfigure("Undo", state='normal' if self.undo_manager.can_undo() else 'disabled')
            self.edit_menu.entryconfigure("Redo", state='normal' if self.undo_manager.can_redo() else 'disabled')

    def create_main_ui(self):
        self.main_frame = ttk.Frame(self.root, padding="20 20 20 20", style='TFrame')
        self.main_frame.pack(fill='both', expand=True)
        welcome_frame = ttk.Frame(self.main_frame, style='TFrame')
        welcome_frame.pack(fill='x', pady=(0, 10))
        self.logo_label = tk.Label(welcome_frame, borderwidth=0) 
        self._update_logo_image() 
        self.logo_label.pack(side='left', padx=80) 
        title_frame = ttk.Frame(welcome_frame, style='TFrame')
        title_frame.pack(side='left', fill='x', expand=False)
        self.app_title_label = ttk.Label(title_frame, text="SwiftSign Digital Signature", style='Header.TLabel')
        self.app_title_label.config(font=(self.title_font_config[0], 1, self.title_font_config[2]))
        self.app_title_label.pack(side='top')
        self.app_subtitle_label = ttk.Label(title_frame, text="Generate and authenticate digital signatures using ECC, RSA, ElGamal, and Diffie-Hellman Algorithms.", style='Subheader.TLabel')
        self.app_subtitle_label.config(font=(self.subtitle_font_config[0], 1, self.subtitle_font_config[2]))
        self.app_subtitle_label.pack(side='top', pady=5)
        self.notebook = ttk.Notebook(self.main_frame, style='TNotebook')
        self.notebook.pack(fill='both', expand=True, pady=10)
        self.keygen_frame_outer, self.keygen_frame_content = self._create_tab_frame(self.notebook, "Key Generation")
        self.create_keygen_tab_content(self.keygen_frame_content)
        self.sign_frame_outer, self.sign_frame_content = self._create_tab_frame(self.notebook, "License Signing")
        self.create_sign_tab_content(self.sign_frame_content)
        self.verify_frame_outer, self.verify_frame_content = self._create_tab_frame(self.notebook, "License Verification")
        self.create_verify_tab_content(self.verify_frame_content)
        self.batch_ops_tab_outer_frame, self.batch_ops_tab_content_parent = self._create_tab_frame(self.notebook, "Batch Operations", is_batch_ops_tab=True)
        self.create_batch_ops_tab_content(self.batch_ops_tab_content_parent)
        self.search_frame_outer, self.search_frame_content = self._create_tab_frame(self.notebook, "Search")
        self.create_search_tab_content(self.search_frame_content)
        self.settings_tab_outer_frame, self.settings_tab_content_frame = self._create_tab_frame(self.notebook, "Settings")
        self.create_settings_tab_content(self.settings_tab_content_frame)
        self.about_outer_frame, self.about_content_parent_frame = self._create_tab_frame(self.notebook, "About", is_about_tab=True)
        self.create_about_tab_content(self.about_content_parent_frame)
        self.status_bar = StatusBar(self.root, self.are_animations_enabled)
        self.status_bar.pack(side='bottom', fill='x')
        self.status_bar.set_message("Ready", status='info')

    def start_header_animations(self):
        if not (hasattr(self, 'app_title_label') and self.app_title_label and self.app_title_label.winfo_exists()): return
        self._animate_label_font_size(self.app_title_label, self.title_font_config, 450, 25,on_complete=lambda: self.root.after(100, self.start_subtitle_animation_delayed))

    def start_subtitle_animation_delayed(self):
        if not (hasattr(self, 'app_subtitle_label') and self.app_subtitle_label and self.app_subtitle_label.winfo_exists()): return
        self._animate_label_font_size(self.app_subtitle_label, self.subtitle_font_config, 400, 20)

    def _animate_label_font_size(self, widget, target_font_config, duration_ms, steps, current_step=0, on_complete=None):
        if not widget or not widget.winfo_exists():
            if on_complete: on_complete()
            return
        target_font_family, target_font_size, target_font_weight = target_font_config
        if not self.are_animations_enabled():
            widget.config(font=(target_font_family, target_font_size, target_font_weight))
            if on_complete: on_complete()
            return
        if current_step > steps:
            widget.config(font=(target_font_family, target_font_size, target_font_weight))
            if on_complete: on_complete()
            return
        start_font_size = 1 
        progress = current_step / steps
        eased_progress = 1 - (1 - progress) ** 2
        current_font_size = max(1, int(start_font_size + (target_font_size - start_font_size) * eased_progress))
        widget.config(font=(target_font_family, current_font_size, target_font_weight))
        delay_per_step = duration_ms // steps or 1
        self.root.after(delay_per_step, lambda: self._animate_label_font_size(widget, target_font_config, duration_ms, steps, current_step + 1, on_complete))

    def load_app_settings(self):
        settings_path = os.path.join(os.path.expanduser("~"), ".swiftsign_settings.json")
        defaults = {
            'default_key_dir': os.path.join(os.path.expanduser("~"), "SwiftSign_Keys"),
            'default_algorithm': 'ECC', 'enable_animations': True, 'dark_mode': False,
            'last_search_dir_keys': ''
        }
        if os.path.exists(settings_path):
            try:
                with open(settings_path, 'r') as f: loaded_settings = json.load(f)
                final_settings = {}
                for key, value in defaults.items():
                    final_settings[key] = loaded_settings.get(key, value)
                return final_settings
            except json.JSONDecodeError: print("Warning: Settings file corrupted, loading defaults.")
        return defaults

    def save_app_settings(self):
        settings_path = os.path.join(os.path.expanduser("~"), ".swiftsign_settings.json")
        current_settings_to_save = {
            'default_key_dir': self.settings.get('default_key_dir'),
            'default_algorithm': self.settings.get('default_algorithm'),
            'enable_animations': self.settings.get('enable_animations'),
            'dark_mode': self.settings.get('dark_mode'),
            'last_search_dir_keys': self.search_dir_keys_var.get() if hasattr(self, 'search_dir_keys_var') else ''
        }
        try:
            with open(settings_path, 'w') as f: json.dump(current_settings_to_save, f, indent=2)
        except Exception as e: messagebox.showwarning("Settings Error", f"Could not save settings: {e}", parent=self.root)

    def apply_and_save_settings(self):
        self.settings['default_key_dir'] = self.settings_key_dir_var.get()
        self.settings['default_algorithm'] = self.settings_default_algo_var.get()
        self.settings['enable_animations'] = self.settings_animations_var.get()
        self.settings['dark_mode'] = self.settings_dark_mode_var.get()
        if hasattr(self, 'search_dir_keys_var'): self.settings['last_search_dir_keys'] = self.search_dir_keys_var.get()
        AppStyles.update_theme(self.settings.get('dark_mode', False))
        AppStyles.apply(self.root) 
        self.default_key_dir = self.settings.get('default_key_dir', self.default_key_dir)
        os.makedirs(self.default_key_dir, exist_ok=True)
        new_default_algo = self.settings.get('default_algorithm', 'ECC')
        if self.current_algorithm.get() != new_default_algo:
            self.current_algorithm.set(new_default_algo)
            self._update_algorithm_selection(new_default_algo) 
        self.refresh_ui_styles()
        self.save_app_settings() 

    def _update_algorithm_selection(self, algorithm):
        algo_values = list(self.crypto_engines.keys())
        if algorithm in algo_values:
            idx = algo_values.index(algorithm)
            for combo_attr in ['keygen_algo_combo', 'sign_algo_combo', 'verify_algo_combo', 
                               'batch_ops_algo_combo']:
                if hasattr(self, combo_attr): getattr(self, combo_attr).current(idx)
            self.current_algorithm.set(algorithm)
            is_verify_tab_fully_initialized = (
                hasattr(self, 'dh_params_selector_frame') and self.dh_params_selector_frame and
                hasattr(self, 'dh_verify_warning_label') and self.dh_verify_warning_label and
                hasattr(self, 'verify_pubkey_selector') and self.verify_pubkey_selector and
                self.verify_pubkey_selector.master
            )
            if is_verify_tab_fully_initialized:
                if algorithm == 'Diffie-Hellman':
                    self.dh_verify_warning_label.pack(side='top', fill='x', padx=10, pady=5)
                else:
                    self.dh_verify_warning_label.pack_forget()
                if algorithm == 'Diffie-Hellman':
                    self.dh_params_selector_frame.pack(fill='x', pady=1, after=self.verify_pubkey_selector)
                else:
                    self.dh_params_selector_frame.pack_forget()

    def refresh_ui_styles(self):
        self.root.configure(bg=AppStyles.COLORS['white'])
        self.main_frame.configure(style='TFrame')
        if hasattr(self, 'logo_label') and self.logo_label and self.logo_label.winfo_exists(): self._update_logo_image()
        if hasattr(self, 'app_title_label') and self.app_title_label.winfo_exists():
            welcome_frame = self.app_title_label.master.master
            title_frame = self.app_title_label.master
            if welcome_frame.winfo_exists(): welcome_frame.configure(style='TFrame')
            if title_frame.winfo_exists(): title_frame.configure(style='TFrame')
            self.app_title_label.configure(style='Header.TLabel')
            self.app_subtitle_label.configure(style='Subheader.TLabel')
        self.notebook.configure(style='TNotebook')
        for i in range(self.notebook.index("end")): 
            tab_id = self.notebook.tabs()[i]
            tab_frame_outer = self.notebook.nametowidget(tab_id)
            if hasattr(tab_frame_outer, 'update_style_recursive'):
                tab_frame_outer.update_style_recursive()
        self.status_bar.update_style()
        is_dark_mode = AppStyles.COLORS['white'] == AppStyles.DARK_MODE_COLORS['white']
        menu_bg = AppStyles.COLORS['light'] if not is_dark_mode else AppStyles.COLORS['dark'] 
        menu_fg = AppStyles.COLORS['dark'] if not is_dark_mode else AppStyles.COLORS['light']
        active_bg = AppStyles.COLORS['primary']
        active_fg = AppStyles.COLORS['black'] if is_dark_mode else AppStyles.COLORS['white']

    def reset_application(self):
        if not messagebox.askyesno("Confirm Reset", "Reset all inputs and clear history?", parent=self.root): return
        default_algo = self.settings.get('default_algorithm', 'ECC')
        self.current_algorithm.set(default_algo)
        self._update_algorithm_selection(default_algo)
        selectors_to_clear = ['keygen_path_selector', 'sign_privkey_selector', 'verify_pubkey_selector', 'license_file_selector', 'license_data_selector', 'dh_params_selector','batch_sign_priv_key_selector','batch_sign_output_dir_selector', 'batch_verify_pub_key_selector']
        for sel_attr in selectors_to_clear:
            if hasattr(self, sel_attr) and getattr(self, sel_attr): getattr(self, sel_attr).set_path("")
        results_to_clear = ['keygen_result_display', 'sign_result_display', 'verify_result_display', 'batch_ops_result_display', 'search_results_display']
        for res_attr in results_to_clear:
            if hasattr(self, res_attr): getattr(self, res_attr).clear()
        string_vars_to_clear = ['customer_name', 'customer_email', 'expiry_date', 'hardware_id', 'search_term_var']
        for var_attr in string_vars_to_clear:
             if hasattr(self, var_attr) and getattr(self, var_attr): getattr(self, var_attr).set("")
        if hasattr(self, 'batch_sign_files_list'): self.batch_sign_files_list.delete(0, tk.END)
        if hasattr(self, 'batch_verify_files_tree'):
            for item in self.batch_verify_files_tree.get_children(): self.batch_verify_files_tree.delete(item)
        if hasattr(self, 'search_results_tree'):
            for item in self.search_results_tree.get_children(): self.search_results_tree.delete(item)
        self.batch_sign_files.clear()
        self.batch_verify_files.clear()
        self.undo_manager.undo_stack.clear(); self.undo_manager.redo_stack.clear()
        self._update_undo_redo_menu_state()
        self.status_bar.set_message("Application reset.", status='info')
        self.notebook.select(0)

    def undo_action(self):
        action = self.undo_manager.undo()
        if not action: self.status_bar.set_message("Nothing to undo", status='info'); return
        action_type = action['type']
        if action_type == 'key_generation' and hasattr(self, 'keygen_result_display'):
            self.keygen_result_display.clear(); self.status_bar.set_message("Undo: Keygen result cleared", status='info')
        elif action_type == 'sign' and hasattr(self, 'sign_result_display'):
            self.sign_result_display.clear(); self.status_bar.set_message("Undo: Signing result cleared", status='info')
        elif action_type == 'verify' and hasattr(self, 'verify_result_display'):
            self.verify_result_display.clear(); self.status_bar.set_message("Undo: Verification result cleared", status='info')
        elif action_type.startswith('batch_') and hasattr(self, 'batch_ops_result_display'):
            self.batch_ops_result_display.clear(); self.status_bar.set_message(f"Undo: Batch operation ({action_type}) result cleared", status='info')
        self._update_undo_redo_menu_state()

    def redo_action(self):
        action = self.undo_manager.redo()
        if not action: self.status_bar.set_message("Nothing to redo", status='info'); return
        action_type, data = action['type'], action['data']
        details_str = data.get('details_str', 'Action redone, details not fully restored.')
        target_display = None
        if action_type == 'key_generation': target_display = self.keygen_result_display
        elif action_type == 'sign': target_display = self.sign_result_display
        elif action_type == 'verify': target_display = self.verify_result_display
        elif action_type.startswith('batch_'): target_display = self.batch_ops_result_display
        if target_display:
            is_valid = data.get('is_valid', False)
            if 'error' in data:
                 target_display.set_error(f"{action_type.replace('_', ' ').title()} (Redone - Error)", data['error'])
                 self.status_bar.set_message(f"Redo: {action_type} (Error) restored", status='error')
            elif action_type.endswith('verify') and not is_valid:
                 target_display.set_error(f"{action_type.replace('_', ' ').title()} INVALID (Redone)", details_str)
                 self.status_bar.set_message(f"Redo: {action_type} (INVALID) restored", status='error')
            else:
                 target_display.set_success(f"{action_type.replace('_', ' ').title()} (Redone)", details_str)
                 self.status_bar.set_message(f"Redo: {action_type} restored", status='success' if is_valid or not action_type.endswith('verify') else 'info')
        self._update_undo_redo_menu_state()

    def open_settings(self):
        if self.settings_dialog_instance and self.settings_dialog_instance.winfo_exists():
            self.settings_dialog_instance.deiconify(); self.settings_dialog_instance.lift(); self.settings_dialog_instance.focus_set()
            return
        self.settings_dialog_instance = SettingsPanel(
            parent_for_toplevel=self.root, actual_ui_container=None, app_settings_dict=self.settings,
            app_apply_settings_cb=self.apply_and_save_settings, app_settings_tk_vars=self._get_settings_tk_vars_as_dict(),
            app_revert_tk_vars_cb=self._load_settings_into_tk_vars, is_modal_dialog=True,
            app_base_dir=self.app_base_dir)

    def show_documentation(self):
        doc_url = "https://github.com/rayder54321/SwiftSign-Digital-Signature-program" 
        try: webbrowser.open(doc_url, new=2)
        except Exception as e: messagebox.showerror("Error", f"Could not open documentation: {e}", parent=self.root)

    def show_feedback_form(self):
        feedback_window = tk.Toplevel(self.root)
        feedback_window.title("Submit Feedback")
        feedback_window.geometry("450x350")
        try:
            icon_path = os.path.join(self.app_base_dir, "icons", "icon.ico")
            if os.path.exists(icon_path): feedback_window.iconbitmap(icon_path)
            else: print(f"Icon file not found for feedback window: {icon_path}")
        except Exception as e: 
            print(f"Could not set feedback window icon: {e}")
        feedback_window.transient(self.root)
        feedback_window.grab_set()
        if AppStyles.COLORS['white'] == AppStyles.DARK_MODE_COLORS['white']:feedback_window.configure(bg=AppStyles.COLORS['white'])
        main_frame = ttk.Frame(feedback_window, padding=10)
        main_frame.pack(fill='both', expand=True)
        ttk.Label(main_frame, text="We appreciate your feedback!", font=AppStyles.FONTS['body_bold']).pack(pady=(0,10))
        type_frame = ttk.Frame(main_frame)
        type_frame.pack(fill='x', pady=5)
        ttk.Label(type_frame, text="Feedback Type:").pack(side='left', padx=(0,5))
        feedback_type_var = tk.StringVar(value="General")
        feedback_type_combo = ttk.Combobox(type_frame, textvariable=feedback_type_var, values=["General", "Bug Report", "Feature Request", "Compliment"], state="readonly")
        feedback_type_combo.pack(side='left', fill='x', expand=True)
        ttk.Label(main_frame, text="Your Email (Optional):").pack(anchor='w', pady=(5,0))
        email_var = tk.StringVar()
        email_entry = ttk.Entry(main_frame, textvariable=email_var)
        email_entry.pack(fill='x', pady=(0,5))
        ttk.Label(main_frame, text="Description:").pack(anchor='w', pady=(5,0))
        desc_text = scrolledtext.ScrolledText(main_frame, height=8, width=50, wrap=tk.WORD)
        desc_text.pack(fill='both', expand=True, pady=(0,10))
        desc_text.configure(bg=AppStyles.COLORS['white'], fg=AppStyles.COLORS['black'], insertbackground=AppStyles.COLORS['black'])

        def submit():
            self._submit_feedback(feedback_type_var, desc_text, email_var, feedback_window)
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill='x', pady=(5,0))
        submit_button = ttk.Button(button_frame, text="Submit Feedback", command=submit, style="Primary.TButton")
        submit_button.pack(side='right')
        cancel_button = ttk.Button(button_frame, text="Cancel", command=feedback_window.destroy)
        cancel_button.pack(side='right', padx=5)
        AppStyles.apply(feedback_window)
        main_frame.configure(style='TFrame')
        type_frame.configure(style='TFrame')
        button_frame.configure(style='TFrame')
        for child in main_frame.winfo_children() + type_frame.winfo_children() + button_frame.winfo_children():
            if isinstance(child, ttk.Label): child.configure(style='TLabel')
            if isinstance(child, ttk.Entry): child.configure(style='TEntry')
            if isinstance(child, ttk.Combobox): child.configure(style='TCombobox')
            if isinstance(child, ttk.Button) and child != submit_button : child.configure(style='TButton')

    def _submit_feedback(self, type_var, desc_text_widget, email_var, window_to_destroy):
        feedback_type = type_var.get()
        description = desc_text_widget.get(1.0, tk.END).strip()
        email = email_var.get().strip()
        if not description:
            messagebox.showerror("Error", "Description cannot be empty.", parent=window_to_destroy)
            return
        print(f"--- Feedback Submitted (Simulated) ---")
        print(f"Timestamp: {datetime.now().isoformat()}")
        print(f"Type: {feedback_type}")
        print(f"Email: {email if email else 'N/A'}")
        print(f"Description:\n{description}")
        print(f"------------------------------------")
        self.status_bar.set_message("Feedback submitted successfully (simulation).", status='success')
        messagebox.showinfo("Feedback Submitted", "Thank you for your feedback! (This is a simulated submission)", parent=window_to_destroy)
        window_to_destroy.destroy()

    def _create_tab_frame(self, parent_notebook, text_label, is_about_tab=False, is_batch_ops_tab=False):
        outer_frame = ttk.Frame(parent_notebook, style='TFrame')
        parent_notebook.add(outer_frame, text=text_label)
        if is_about_tab or is_batch_ops_tab:
            content_frame_for_canvas_host = outer_frame 
        else:
            content_frame_for_canvas_host = ttk.Frame(outer_frame, padding="10 10 10 10", style='TFrame')
            content_frame_for_canvas_host.pack(fill='both', expand=True)

        def update_style_recursive_closure(widget_to_update=content_frame_for_canvas_host): 
            is_settings_tab_content = hasattr(self, 'settings_tab_content_frame') and widget_to_update == self.settings_tab_content_frame
            try: current_style = widget_to_update.cget("style")
            except tk.TclError: current_style = None
            if isinstance(widget_to_update, (ttk.Frame, ttk.LabelFrame, ttk.Combobox, ttk.Entry, ttk.Button, ttk.Checkbutton, ttk.Label, ttk.Progressbar, ttk.Scrollbar, ttk.Treeview)):
                if hasattr(widget_to_update, 'update_style'):
                    widget_to_update.update_style()
                else:
                    base_style_name = widget_to_update.winfo_class().replace('Tk', 'T')
                    if base_style_name == "TLabelFrame":
                        is_about_lf = current_style and "About.TLabelframe" in current_style
                        if not is_settings_tab_content and not is_about_lf : 
                            widget_to_update.configure(style='TLabelframe')
                            for child in widget_to_update.winfo_children():
                                if child.winfo_class() == 'TLabel' and child.master == widget_to_update: # Ensure it's the direct Label child of LabelFrame
                                    child.configure(style='TLabelframe.Label'); break
                        elif is_about_lf:
                             widget_to_update.configure(style='About.TLabelframe')
                             for child in widget_to_update.winfo_children():
                                if child.winfo_class() == 'TLabel' and child.master == widget_to_update:
                                    child.configure(style='About.TLabelframe.Label'); break
                    elif widget_to_update is getattr(self, 'about_scrollable_frame', None) or \
                         widget_to_update is getattr(self, 'scrollable_batch_ops_frame', None) :
                        style_to_set = 'AboutScrollable.TFrame' if widget_to_update is getattr(self, 'about_scrollable_frame', None) else 'TFrame'
                        widget_to_update.configure(style=style_to_set)
                    elif base_style_name == "TCombobox": widget_to_update.configure(style='TCombobox')
                    elif isinstance(widget_to_update, ttk.Label): widget_to_update.configure(style=current_style or 'TLabel') 
                    elif isinstance(widget_to_update, ttk.Checkbutton): widget_to_update.configure(style='TCheckbutton')
                    elif isinstance(widget_to_update, ttk.Button): 
                        if current_style == 'Primary.TButton': widget_to_update.configure(style='Primary.TButton')
                        else: widget_to_update.configure(style='TButton')
                    elif isinstance(widget_to_update, ttk.Treeview): widget_to_update.configure(style='Treeview') 
                    elif isinstance(widget_to_update, ttk.Widget) and not is_settings_tab_content: 
                        try: widget_to_update.configure(style=base_style_name)
                        except tk.TclError: pass 
            elif isinstance(widget_to_update, (tk.Canvas, scrolledtext.ScrolledText, tk.Listbox, tk.Entry)):
                if hasattr(widget_to_update, 'update_style'): 
                    widget_to_update.update_style()
                else:
                    base_tk_bg_color = AppStyles.COLORS['white']
                    base_tk_fg_color = AppStyles.COLORS['black']
                    base_tk_highlight_bg = AppStyles.COLORS['frame_border']
                    base_tk_insert_bg = AppStyles.COLORS['black']
                    base_tk_select_bg = AppStyles.COLORS['highlight']
                    base_tk_select_fg = AppStyles.COLORS['white']
                    if isinstance(widget_to_update, tk.Canvas):
                        current_canvas_bg = base_tk_bg_color 
                        if widget_to_update is getattr(self, 'about_frame_canvas', None):
                            current_canvas_bg = AppStyles.COLORS['gray']
                        widget_to_update.config(
                            background=current_canvas_bg, 
                            highlightbackground=base_tk_highlight_bg if widget_to_update.cget('highlightthickness') != '0' else current_canvas_bg
                        )
                    elif isinstance(widget_to_update, (scrolledtext.ScrolledText, tk.Listbox, tk.Entry)):
                         widget_to_update.config(background=base_tk_bg_color, foreground=base_tk_fg_color)
                         try:
                            widget_to_update.config(
                                insertbackground=base_tk_insert_bg, 
                                selectbackground=base_tk_select_bg, 
                                selectforeground=base_tk_select_fg
                            )
                         except tk.TclError: pass
            
            if not is_settings_tab_content:
                for child in widget_to_update.winfo_children():
                    update_style_recursive_closure(child)
            elif self.settings_tab_panel_instance:
                self.settings_tab_panel_instance.update_widget_styles()
        content_frame_for_canvas_host.update_style_recursive = lambda: update_style_recursive_closure(content_frame_for_canvas_host)
        if outer_frame is not content_frame_for_canvas_host:
            outer_frame.update_style_recursive = lambda: update_style_recursive_closure(content_frame_for_canvas_host)
        return outer_frame, content_frame_for_canvas_host

    def create_keygen_tab_content(self, parent_frame): 
        self.keygen_frame = parent_frame 
        algo_frame = ttk.Frame(self.keygen_frame, style='TFrame')
        algo_frame.pack(fill='x', pady=5)
        ttk.Label(algo_frame, text="Select Algorithm:").grid(row=0, column=0, padx=5, pady=3, sticky='w')
        self.keygen_algo_combo = ttk.Combobox(algo_frame, textvariable=self.current_algorithm, values=list(self.crypto_engines.keys()), state='readonly', width=15)
        self.keygen_algo_combo.grid(row=0, column=1, padx=5, pady=5, sticky='w')
        self.keygen_algo_combo.bind('<<ComboboxSelected>>', lambda e: self._update_algorithm_selection(self.current_algorithm.get()))
        output_frame = ttk.LabelFrame(self.keygen_frame, text="Output Directory", padding=10, style='TLabelframe')
        output_frame.pack(fill='x', pady=5)
        self.keygen_path_selector = FileSelector(output_frame, "Save Directory:", mode='open', animations_enabled_func=self.are_animations_enabled, initialdir_func=self.get_default_key_dir, select_directory=True)
        self.keygen_path_selector.pack(fill='x', pady=2)
        button_frame = ttk.Frame(self.keygen_frame, style='TFrame')
        button_frame.pack(pady=15)
        ttk.Button(button_frame, text="Generate Keys", style='Primary.TButton', command=self.generate_keys).pack(side='left', padx=5)
        self.keygen_result_display = ResultDisplay(self.keygen_frame)
        self.keygen_result_display.pack(fill='both', expand=True, pady=5)
        self._update_algorithm_selection(self.current_algorithm.get())

    def create_search_tab_content(self, parent_frame):
        self.search_frame = parent_frame
        search_frame_content = ttk.Frame(self.search_frame, padding="10", style='TFrame')
        search_frame_content.pack(fill='both', expand=True)
        search_input_frame = ttk.LabelFrame(search_frame_content, text="Search Criteria (Keys Only)", padding=10, style='TLabelframe')
        search_input_frame.pack(fill='x', pady=5)
        search_input_frame.columnconfigure(1, weight=1)
        ttk.Label(search_input_frame, text="Search Term:").grid(row=0, column=0, padx=5, pady=3, sticky='w')
        self.search_term_var = tk.StringVar()
        search_entry = ttk.Entry(search_input_frame, textvariable=self.search_term_var)
        search_entry.grid(row=0, column=1, padx=5, pady=3, sticky='ew')
        ttk.Label(search_input_frame, text="Search Type:").grid(row=1, column=0, padx=5, pady=3, sticky='w')
        self.search_type_var = tk.StringVar(value="Keys")
        search_type_combo = ttk.Combobox(search_input_frame, textvariable=self.search_type_var, values=["Keys"], state='readonly')
        search_type_combo.grid(row=1, column=1, padx=5, pady=3, sticky='w')
        self.search_dir_keys_frame = ttk.Frame(search_input_frame, style='TFrame')
        self.search_dir_keys_var = tk.StringVar(value=self.settings.get('last_search_dir_keys', self.get_default_key_dir()))
        self.search_dir_keys_selector = FileSelector(self.search_dir_keys_frame, "Search Directory (Keys):", select_directory=True, initialdir_func=self.get_default_key_dir)
        self.search_dir_keys_selector.pack(fill='x', expand=True)
        self.search_dir_keys_selector.set_path(self.search_dir_keys_var.get())
        self.search_dir_keys_frame.grid(row=2, column=0, columnspan=3, sticky='ew', pady=2)
        self._update_search_dir_visibility()
        search_button_frame = ttk.Frame(search_frame_content, style='TFrame')
        search_button_frame.pack(pady=10)
        ttk.Button(search_button_frame, text="Search Keys", style='Primary.TButton', command=self.perform_search).pack() # Renamed button
        search_results_lf = ttk.LabelFrame(search_frame_content, text="Search Results", padding=10, style='TLabelframe')
        search_results_lf.pack(fill='both', expand=True, pady=5)
        search_results_tree_frame = ttk.Frame(search_results_lf, style='TFrame')
        search_results_tree_frame.pack(fill='both', expand=True)
        self.search_results_tree = ttk.Treeview(search_results_tree_frame, columns=("name", "type", "path", "modified"), show="headings")
        self.search_results_tree.heading("name", text="Name")
        self.search_results_tree.heading("type", text="Type")
        self.search_results_tree.heading("path", text="Path")
        self.search_results_tree.heading("modified", text="Last Modified")
        self.search_results_tree.column("name", width=150, anchor='w')
        self.search_results_tree.column("type", width=100, anchor='w')
        self.search_results_tree.column("path", width=300, anchor='w')
        self.search_results_tree.column("modified", width=150, anchor='w')
        search_results_tree_scroll_y = ttk.Scrollbar(search_results_tree_frame, orient='vertical', command=self.search_results_tree.yview)
        search_results_tree_scroll_y.pack(side='right', fill='y')
        self.search_results_tree.config(yscrollcommand=search_results_tree_scroll_y.set)
        search_results_tree_scroll_x = ttk.Scrollbar(search_results_lf, orient='horizontal', command=self.search_results_tree.xview)
        search_results_tree_scroll_x.pack(side='bottom', fill='x')
        self.search_results_tree.config(xscrollcommand=search_results_tree_scroll_x.set)
        self.search_results_tree.pack(side='left', fill='both', expand=True)
        self.search_results_tree.bind("<Double-1>", self.on_search_result_double_click)
        self.search_results_display = ResultDisplay(search_frame_content)
        self.search_results_display.pack(fill='x', pady=5)
        self._update_algorithm_selection(self.current_algorithm.get())

    def create_sign_tab_content(self, parent_frame):
        self.sign_frame = parent_frame
        algo_frame = ttk.Frame(self.sign_frame, style='TFrame')
        algo_frame.pack(fill='x', pady=3)
        ttk.Label(algo_frame, text="Select Algorithm:").grid(row=0, column=0, padx=5, pady=3, sticky='w')
        self.sign_algo_combo = ttk.Combobox(algo_frame, textvariable=self.current_algorithm, values=list(self.crypto_engines.keys()), state='readonly', width=15)
        self.sign_algo_combo.grid(row=0, column=1, padx=5, pady=3, sticky='w')
        self.sign_algo_combo.bind('<<ComboboxSelected>>', lambda e: self._update_algorithm_selection(self.current_algorithm.get()))
        input_frame = ttk.LabelFrame(self.sign_frame, text="Input", padding=5, style='TLabelframe')
        input_frame.pack(fill='x', pady=3)
        self.sign_privkey_selector = FileSelector(input_frame, "Private Key:", filetypes=[("PEM files", "*.pem"), ("Key files", "*.key"), ("All files", "*.*")], mode='open', animations_enabled_func=self.are_animations_enabled, initialdir_func=self.get_default_key_dir)
        self.sign_privkey_selector.pack(fill='x', pady=2)
        details_frame = ttk.LabelFrame(self.sign_frame, text="License Details", padding=10, style='TLabelframe')
        details_frame.pack(fill='x', pady=3)
        details_frame.columnconfigure(1, weight=1)
        self.customer_name = tk.StringVar(); ttk.Label(details_frame, text="Customer:").grid(row=0, column=0, sticky='w', padx=2, pady=2); ttk.Entry(details_frame, textvariable=self.customer_name).grid(row=0, column=1, padx=5, pady=2, sticky='ew')
        self.customer_email = tk.StringVar(); ttk.Label(details_frame, text="Email:").grid(row=1, column=0, sticky='w', padx=2, pady=2); ttk.Entry(details_frame, textvariable=self.customer_email).grid(row=1, column=1, padx=5, pady=2, sticky='ew')
        self.expiry_date = tk.StringVar(); ttk.Label(details_frame, text="Expiry (DD/MM/YYYY):").grid(row=2, column=0, sticky='w', padx=2, pady=2); ttk.Entry(details_frame, textvariable=self.expiry_date).grid(row=2, column=1, padx=5, pady=2, sticky='ew')
        self.hardware_id = tk.StringVar(); ttk.Label(details_frame, text="Hardware ID:").grid(row=3, column=0, sticky='w', padx=2, pady=2); ttk.Entry(details_frame, textvariable=self.hardware_id).grid(row=3, column=1, padx=5, pady=2, sticky='ew')
        button_frame = ttk.Frame(self.sign_frame, style='TFrame')
        button_frame.pack(pady=3)
        ttk.Button(button_frame, text="Sign License", style='Primary.TButton', command=self.sign_license).pack(side='left', padx=5)
        ttk.Button(button_frame, text="Preview License", style='Primary.TButton', command=self.preview_license).pack(side='left', padx=5)
        self.sign_result_display = ResultDisplay(self.sign_frame)
        self.sign_result_display.pack(fill='both', expand=False, pady=1)
        self._update_algorithm_selection(self.current_algorithm.get())

    def create_verify_tab_content(self, parent_frame): 
        self.verify_frame = parent_frame
        algo_frame = ttk.Frame(self.verify_frame, style='TFrame')
        algo_frame.pack(fill='x', pady=3)
        ttk.Label(algo_frame, text="Select Algorithm:").grid(row=0, column=0, padx=5, pady=3, sticky='w')
        self.verify_algo_combo = ttk.Combobox(algo_frame, textvariable=self.current_algorithm, values=list(self.crypto_engines.keys()), state='readonly', width=15)
        self.verify_algo_combo.grid(row=0, column=1, padx=5, pady=1, sticky='w')
        self.verify_algo_combo.bind('<<ComboboxSelected>>', lambda e: self._update_algorithm_selection(self.current_algorithm.get()))
        dh_warning_text = ("Note: Diffie-Hellman verification in this application requires access to the signer's "
                           "private key for HMAC calculation, which is unconventional for general digital signatures. "
                           "Ensure the signer's private key (derived from the public key path) is available. "
                           "Optionally, provide the DH parameters file for validation.")
        self.dh_verify_warning_label = ttk.Label(self.verify_frame, text=dh_warning_text, style='Warning.TLabel', wraplength=500, justify='left')
        self.input_frame_verify_tab = ttk.LabelFrame(self.verify_frame, text="Input", padding=5, style='TLabelframe')
        self.input_frame_verify_tab.pack(fill='x', pady=1)
        self.verify_pubkey_selector = FileSelector(self.input_frame_verify_tab, "Public Key:", filetypes=[("PEM files", "*.pem"), ("Public key files", "*.pub"), ("All files", "*.*")], mode='open', animations_enabled_func=self.are_animations_enabled, initialdir_func=self.get_default_key_dir)
        self.verify_pubkey_selector.pack(fill='x', pady=1)
        self.dh_params_selector_frame = ttk.Frame(self.input_frame_verify_tab, style='TFrame')
        self.dh_params_selector = FileSelector(self.dh_params_selector_frame, "DH Parameters File:",filetypes=[("PEM files", "*.pem"), ("DH Param files", "*.dh"), ("All files", "*.*")],mode='open', animations_enabled_func=self.are_animations_enabled,initialdir_func=self.get_default_key_dir)
        self.dh_params_selector.pack(fill='x', expand=True)
        self.license_file_selector = FileSelector(self.input_frame_verify_tab, "License Signature File:", filetypes=[("Signature files", "*.sig;*.ecc;*.rsa;*.elgamal;*.dh"), ("All files", "*.*")], mode='open', animations_enabled_func=self.are_animations_enabled)
        self.license_file_selector.pack(fill='x', pady=1)
        self.license_data_selector = FileSelector(self.input_frame_verify_tab, "License Data File (JSON/Text):", filetypes=[("Text files", "*.txt"),("JSON files", "*.json"), ("All files", "*.*")], mode='open', animations_enabled_func=self.are_animations_enabled)
        self.license_data_selector.pack(fill='x', pady=1)
        button_frame = ttk.Frame(self.verify_frame, style='TFrame')
        button_frame.pack(pady=10)
        ttk.Button(button_frame, text="Verify License", style='Primary.TButton', command=self.verify_license).pack(side='left', padx=5)
        self.verify_result_display = ResultDisplay(self.verify_frame)
        self.verify_result_display.pack(fill='both', expand=True, pady=1)
        self._update_algorithm_selection(self.current_algorithm.get())

    def create_batch_ops_tab_content(self, parent_canvas_host_frame):
        batch_canvas = tk.Canvas(parent_canvas_host_frame, borderwidth=0, highlightthickness=0, bg=AppStyles.COLORS['white'])
        batch_scrollbar = ttk.Scrollbar(parent_canvas_host_frame, orient="vertical", command=batch_canvas.yview)
        self.scrollable_batch_ops_frame = ttk.Frame(batch_canvas, padding="5", style='TFrame')
        scrollable_window_id = batch_canvas.create_window((0, 0), window=self.scrollable_batch_ops_frame, anchor="nw")

        def _on_canvas_configure_batch(event):
            canvas_width = event.width
            if batch_canvas.winfo_exists() and scrollable_window_id:
                try: batch_canvas.itemconfig(scrollable_window_id, width=canvas_width)
                except tk.TclError: pass
            if self.scrollable_batch_ops_frame.winfo_exists():
                 self.scrollable_batch_ops_frame.update_idletasks()

        def _on_scrollable_frame_configure_batch(event):
            if batch_canvas.winfo_exists():
                try: batch_canvas.configure(scrollregion=batch_canvas.bbox("all"))
                except tk.TclError: pass
        batch_canvas.bind("<Configure>", _on_canvas_configure_batch)
        self.scrollable_batch_ops_frame.bind("<Configure>", _on_scrollable_frame_configure_batch)
        batch_canvas.configure(yscrollcommand=batch_scrollbar.set)
        batch_canvas.pack(side="left", fill="both", expand=True)
        batch_scrollbar.pack(side="right", fill="y")
        self.batch_ops_frame = self.scrollable_batch_ops_frame 
        algo_frame = ttk.Frame(self.batch_ops_frame, style='TFrame')
        algo_frame.pack(fill='x', pady=5)
        ttk.Label(algo_frame, text="Select Algorithm for Batch:").grid(row=0, column=0, padx=3, pady=5, sticky='w')
        self.batch_ops_algo_combo = ttk.Combobox(algo_frame, textvariable=self.current_algorithm, values=list(self.crypto_engines.keys()), state='readonly', width=15)
        self.batch_ops_algo_combo.grid(row=0, column=1, padx=5, pady=5, sticky='w')
        self.batch_ops_algo_combo.bind('<<ComboboxSelected>>', lambda e: self._update_algorithm_selection(self.current_algorithm.get()))
        sign_lf = ttk.LabelFrame(self.batch_ops_frame, text="Batch Sign Licenses", padding=10)
        sign_lf.pack(fill='x', pady=10)
        self.batch_sign_priv_key_selector = FileSelector(sign_lf, "Private Key:", filetypes=[("PEM files", "*.pem"), ("All files", "*.*")], initialdir_func=self.get_default_key_dir)
        self.batch_sign_priv_key_selector.pack(fill='x', pady=2)
        self.batch_sign_output_dir_selector = FileSelector(sign_lf, "Output Directory for Signatures:", select_directory=True, initialdir_func=self.get_default_key_dir)
        self.batch_sign_output_dir_selector.pack(fill='x', pady=2)
        ttk.Label(sign_lf, text="Data Files to Sign (JSON, one per license):").pack(anchor='w', pady=(5,0))
        sign_files_frame = ttk.Frame(sign_lf)
        sign_files_frame.pack(fill='x', pady=2)
        self.batch_sign_files_list = tk.Listbox(sign_files_frame, selectmode=tk.EXTENDED, height=5)
        self.batch_sign_files_list.pack(side='left', fill='x', expand=True)
        sign_scroll = ttk.Scrollbar(sign_files_frame, orient='vertical', command=self.batch_sign_files_list.yview)
        sign_scroll.pack(side='right', fill='y')
        self.batch_sign_files_list.config(yscrollcommand=sign_scroll.set)
        if DND_SUPPORT:
            self.batch_sign_files_list.drop_target_register(DND_FILES)
            self.batch_sign_files_list.dnd_bind('<<Drop>>', lambda e: self._on_drop_to_listbox(e, self.batch_sign_files_list, self.batch_sign_files))
        sign_buttons_frame = ttk.Frame(sign_lf)
        sign_buttons_frame.pack(fill='x', pady=5)
        ttk.Button(sign_buttons_frame, text="Add Data Files", command=self._add_batch_sign_files).pack(side='left')
        ttk.Button(sign_buttons_frame, text="Remove Selected", command=lambda: self._remove_selected_from_listbox(self.batch_sign_files_list, self.batch_sign_files)).pack(side='left', padx=5)
        ttk.Button(sign_buttons_frame, text="Clear All", command=lambda: self._clear_listbox(self.batch_sign_files_list, self.batch_sign_files)).pack(side='left', padx=5)
        ttk.Button(sign_lf, text="Start Batch Signing", command=self.start_batch_signing, style="Primary.TButton").pack(pady=10)
        verify_lf = ttk.LabelFrame(self.batch_ops_frame, text="Batch Verify Licenses", padding=10)
        verify_lf.pack(fill='x', pady=10)
        self.batch_verify_pub_key_selector = FileSelector(verify_lf, "Public Key:", filetypes=[("PEM files", "*.pem"), ("PUB files", "*.pub"), ("All files", "*.*")], initialdir_func=self.get_default_key_dir)
        self.batch_verify_pub_key_selector.pack(fill='x', pady=2)
        ttk.Label(verify_lf, text="License Files to Verify (Data + Signature pairs):").pack(anchor='w', pady=(5,0))
        verify_files_frame = ttk.Frame(verify_lf) 
        verify_files_frame.pack(fill='x', expand=True, pady=2)
        self.batch_verify_files_tree = ttk.Treeview(verify_files_frame, columns=("data_file", "sig_file"), show="headings", height=5)
        self.batch_verify_files_tree.heading("data_file", text="Data File")
        self.batch_verify_files_tree.heading("sig_file", text="Signature File")
        self.batch_verify_files_tree.column("data_file", width=200, anchor='w')
        self.batch_verify_files_tree.column("sig_file", width=200, anchor='w')
        self.batch_verify_files_tree.pack(side='left', fill='both', expand=True)
        verify_scroll = ttk.Scrollbar(verify_files_frame, orient='vertical', command=self.batch_verify_files_tree.yview)
        verify_scroll.pack(side='right', fill='y')
        self.batch_verify_files_tree.config(yscrollcommand=verify_scroll.set)
        verify_buttons_frame = ttk.Frame(verify_lf)
        verify_buttons_frame.pack(fill='x', pady=5)
        ttk.Button(verify_buttons_frame, text="Add License Pair", command=self._add_batch_verify_pair).pack(side='left')
        ttk.Button(verify_buttons_frame, text="Remove Selected", command=self._remove_selected_from_treeview).pack(side='left', padx=5)
        ttk.Button(verify_buttons_frame, text="Clear All", command=self._clear_treeview).pack(side='left', padx=5)
        ttk.Button(verify_lf, text="Start Batch Verification", command=self.start_batch_verification, style="Primary.TButton").pack(pady=10)
        self.batch_ops_result_display = ResultDisplay(self.batch_ops_frame)
        self.batch_ops_result_display.pack(fill='both', expand=True, pady=10)
        self._update_algorithm_selection(self.current_algorithm.get())

    def _on_drop_to_listbox(self, event, listbox_widget, file_list_storage):
        if not DND_SUPPORT: return
        filepaths = parse_dnd_files(listbox_widget, event.data)
        for fp in filepaths:
            if fp not in file_list_storage:
                listbox_widget.insert(tk.END, os.path.basename(fp))
                file_list_storage.append(fp)

    def _add_batch_sign_files(self):
        files = filedialog.askopenfilenames(title="Select Data Files to Sign", filetypes=[("JSON files", "*.json"), ("Text files", "*.txt"), ("All files", "*.*")],parent=self.root)
        if files:
            for f in files:
                if f not in self.batch_sign_files:
                    self.batch_sign_files_list.insert(tk.END, os.path.basename(f))
                    self.batch_sign_files.append(f)
    
    def _remove_selected_from_listbox(self, listbox_widget, file_list_storage):
        selected_indices = list(listbox_widget.curselection())
        selected_indices.sort(reverse=True)
        for i in selected_indices:
            listbox_widget.delete(i)
            del file_list_storage[i]

    def _clear_listbox(self, listbox_widget, file_list_storage):
        listbox_widget.delete(0, tk.END)
        file_list_storage.clear()

    def _add_batch_verify_pair(self):
        data_file = filedialog.askopenfilename(title="Select License Data File",filetypes=[("JSON files", "*.json"), ("Text files", "*.txt"), ("All files", "*.*")],parent=self.root)
        if not data_file: return
        sig_file = filedialog.askopenfilename(title="Select Corresponding Signature File",filetypes=[("Signature files", "*.sig;*.ecc;*.rsa;*.elgamal;*.dh"), ("All files", "*.*")],parent=self.root, initialdir=os.path.dirname(data_file))
        if not sig_file: return
        pair = (data_file, sig_file)
        if pair not in self.batch_verify_files:
            self.batch_verify_files_tree.insert("", tk.END, values=(os.path.basename(data_file), os.path.basename(sig_file)))
            self.batch_verify_files.append(pair)

    def _remove_selected_from_treeview(self):
        selected_items = self.batch_verify_files_tree.selection()
        if not selected_items: return
        indices_to_remove = []
        for item_id in selected_items:
            try:
                all_items = self.batch_verify_files_tree.get_children('')
                idx = all_items.index(item_id)
                indices_to_remove.append(idx)
            except ValueError:
                pass 
        indices_to_remove.sort(reverse=True)
        for idx in indices_to_remove:
            if 0 <= idx < len(self.batch_verify_files):
                del self.batch_verify_files[idx]
        for item_id in selected_items:
            self.batch_verify_files_tree.delete(item_id)

    def _clear_treeview(self):
        for item in self.batch_verify_files_tree.get_children():
            self.batch_verify_files_tree.delete(item)
        self.batch_verify_files.clear()

    # --- Search Functionality ---
    def perform_search(self):
        term = self.search_term_var.get().lower()
        search_type = "Keys"
        for item in self.search_results_tree.get_children():
            self.search_results_tree.delete(item)
        self.search_results_display.set_info("Searching for keys...", "")
        self.status_bar.set_message("Searching for keys...", status='info')

        def do_search_thread():
            results = []
            try:
                search_dir = self.search_dir_keys_var.get()
                if not search_dir or not os.path.isdir(search_dir):
                    self.root.after(0, lambda: self.search_results_display.set_error("Search Error", "Key directory not specified or invalid."))
                    self.root.after(0, lambda: self.status_bar.set_message("Search Error: Invalid key directory.", status='error'))
                    return
                self.settings['last_search_dir_keys'] = search_dir 
                for root_dir, _, files in os.walk(search_dir):
                    for fname in files:
                        if term in fname.lower() and (fname.lower().endswith(".pem") or fname.lower().endswith(".key") or fname.lower().endswith(".pub") or fname.lower().endswith(".dh")):
                            fpath = os.path.join(root_dir, fname)
                            ftype = "Private Key" if "private" in fname.lower() else "Public Key" if "public" in fname.lower() or ".pub" in fname.lower() else "DH Parameters" if "params" in fname.lower() and ".pem" in fname.lower() else "Key"
                            try: fmod = datetime.fromtimestamp(os.path.getmtime(fpath)).strftime('%Y-%m-%d %H:%M:%S')
                            except: fmod = "N/A"
                            results.append((fname, ftype, fpath, fmod))
                
                def update_ui_with_results():
                    if results:
                        for res in results:
                            self.search_results_tree.insert("", tk.END, values=res)
                        self.search_results_display.set_success(f"{len(results)} key(s) found.", "")
                        self.status_bar.set_message(f"{len(results)} key(s) found.", status='success')
                    else:
                        self.search_results_display.set_info("No keys found.", f"No key files matched '{term}' in the specified directory.")
                        self.status_bar.set_message("No keys found.", status='info')
                self.root.after(0, update_ui_with_results)
            except Exception as e:
                self.root.after(0, lambda: self.search_results_display.set_error("Search Error", str(e)))
                self.root.after(0, lambda: self.status_bar.set_message(f"Search Error: {type(e).__name__}", status='error'))
        threading.Thread(target=do_search_thread, daemon=True).start()

    def _update_search_dir_visibility(self, event=None):
        if hasattr(self, 'search_dir_keys_frame') and self.search_dir_keys_frame:
            self.search_dir_keys_frame.grid(row=2, column=0, columnspan=3, sticky='ew', pady=2)
        if hasattr(self, 'search_dir_licenses_frame') and self.search_dir_licenses_frame and self.search_dir_licenses_frame.winfo_exists():
            self.search_dir_licenses_frame.grid_forget()

    def on_search_result_double_click(self, event):
        item_id = self.search_results_tree.focus()
        if not item_id: return
        item_values = self.search_results_tree.item(item_id, "values")
        if item_values and len(item_values) > 2:
            file_path = item_values[2]
            if os.path.exists(file_path):
                try:
                    if os.name == 'nt':
                        os.startfile(os.path.dirname(file_path)) 
                    elif os.name == 'posix': 
                        if hasattr(os, 'uname') and os.uname().sysname == 'Darwin':
                            subprocess.call(['open', '-R', file_path])
                        else: # Linux
                            try: subprocess.call(['xdg-open', os.path.dirname(file_path)])
                            except FileNotFoundError:
                                messagebox.showinfo("Open Folder", f"Could not automatically open folder. Path: {os.path.dirname(file_path)}", parent=self.root)
                    self.status_bar.set_message(f"Opened folder for: {os.path.basename(file_path)}", status='info')
                except Exception as e:
                    messagebox.showerror("Error", f"Could not open file location: {e}", parent=self.root)
            else:
                messagebox.showwarning("File Not Found", f"The file '{file_path}' no longer exists.", parent=self.root)

    def create_settings_tab_content(self, parent_frame): 
        self.settings_tab_content_frame = parent_frame 
        self.settings_tab_panel_instance = SettingsPanel(
            parent_for_toplevel=self.root, actual_ui_container=self.settings_tab_content_frame, 
            app_settings_dict=self.settings, app_apply_settings_cb=self.apply_and_save_settings,
            app_settings_tk_vars=self._get_settings_tk_vars_as_dict(),
            app_revert_tk_vars_cb=self._load_settings_into_tk_vars, is_modal_dialog=False,
            app_base_dir=self.app_base_dir)

    def create_about_tab_content(self, parent_canvas_host_frame):
        self.about_frame_canvas = tk.Canvas(parent_canvas_host_frame, borderwidth=0, highlightthickness=0)
        scrollbar = ttk.Scrollbar(parent_canvas_host_frame, orient="vertical", command=self.about_frame_canvas.yview)
        self.about_scrollable_frame = ttk.Frame(self.about_frame_canvas, padding="10", style='AboutScrollable.TFrame')
        self.scrollable_window_id = self.about_frame_canvas.create_window((0, 0), window=self.about_scrollable_frame, anchor="nw")

        def _on_canvas_configure(event):
            canvas_width = event.width
            if self.about_frame_canvas.winfo_exists() and self.scrollable_window_id:
                 try: self.about_frame_canvas.itemconfig(self.scrollable_window_id, width=canvas_width)
                 except tk.TclError: pass
            if hasattr(self, 'about_scrollable_frame') and self.about_scrollable_frame.winfo_exists():
                wraplength_col1 = canvas_width - 30 if canvas_width > 30 else 1 
                wraplength_col2 = (canvas_width / 2) - 30 if (canvas_width / 2) > 30 else 1
                if hasattr(self, 'app_info_text_label') and self.app_info_text_label.winfo_exists():
                    self.app_info_text_label.config(wraplength=wraplength_col1)
                if hasattr(self, 'features_text_label') and self.features_text_label.winfo_exists():
                    self.features_text_label.config(wraplength=wraplength_col2)
                if hasattr(self, 'contact_text_label') and self.contact_text_label.winfo_exists():
                    self.contact_text_label.config(wraplength=wraplength_col2)
            if hasattr(self, 'about_scrollable_frame') and self.about_scrollable_frame.winfo_exists():
                self.about_scrollable_frame.update_idletasks()

        def _on_scrollable_frame_configure(event):
            if self.about_frame_canvas.winfo_exists():
                try: self.about_frame_canvas.configure(scrollregion=self.about_frame_canvas.bbox("all"))
                except tk.TclError: pass
        self.about_frame_canvas.bind("<Configure>", _on_canvas_configure)
        self.about_scrollable_frame.bind("<Configure>", _on_scrollable_frame_configure)
        self.about_frame_canvas.configure(yscrollcommand=scrollbar.set)
        self.about_frame_canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        self.about_section_labelframes = []
        section1_lf = ttk.LabelFrame(self.about_scrollable_frame, text="Application Information", padding=5, style='About.TLabelframe')
        section1_lf.pack(fill='x', padx=0, pady=5); 
        self.about_section_labelframes.append(section1_lf)
        app_info_text = ("SwiftSign Digital Signature \n\nVersion: 4.0 \nDeveloped by: Mohamed Nassar, Ahmed El Shaboury and Ahmed Maged \n\n"
                         "This program is developed as part of the graduation project for the Department of Cyber Security and Data Analytics, Faculty of Electronic Engineering, Menoufia University.\n"
                         " \n"
                         "SwiftSign Digital Signature program is a secure and versatile tool designed for generating and verifying digital signatures with a focus on licensing applications and it provides a robust platform for ensuring the authenticity and integrity of digital licenses by advanced cryptographic techniques also the application supports a variety of cryptographic algorithms each tailored to provide secure key generation, signing, and verification capabilities: \n"
                         " \n"
                         "- ECC: ECDSA with the NIST256p curve and SHA-256 hash function for efficient and secure signatures.\n"
                         "- RSA: Utilizes RSASSA-PSS with 2048-bit keys and SHA-256 hash function.\n"
                         "- ElGamal: A non-standard implementation based on RSA-PSS with SHA-256, adapted for signing and verification.\n"
                         "- Diffie-Hellman: Employs DH key exchange to derive a shared secret, used with HMAC-SHA256 for signing and verification.\n")
        self.app_info_text_label = ttk.Label(section1_lf, text=app_info_text,font=AppStyles.FONTS['medium'], justify='left', style='TLabel')
        self.app_info_text_label.pack(fill='x', padx=0, pady=5)
        sections_container = ttk.Frame(self.about_scrollable_frame, style='AboutScrollable.TFrame')
        sections_container.pack(fill='x', padx=0, pady=5)
        sections_container.columnconfigure(0, weight=1); sections_container.columnconfigure(1, weight=1)   
        section3_lf = ttk.LabelFrame(sections_container, text="Features", padding=10, style='About.TLabelframe')
        section3_lf.grid(row=0, column=0, padx=10, pady=5, sticky='nsew'); self.about_section_labelframes.append(section3_lf)
        features_text = ("- Key Pair Generation: Create public and private key pairs for all algorithms.\n"
                         "- License Signing: Digitally sign license data using the selected algorithm.\n"
                         "- Signature Verification: Validate the authenticity and integrity of licenses.\n"
                         "- Batch Processing: Sign or verify multiple files simultaneously.\n"
                         "- Search Functionality: Locate keys or license files.\n"
                         "- Drag & Drop: Easily select files for operations.\n"
                         "- User-Friendly Interface: Navigate easily through different tabs.\n"
                         "- Undo/Redo Functionality: Revert or reapply actions.\n"
                         "- Customizable Settings: Adjust defaults, UI preferences (dark mode, animations).\n"
                         "- Feedback Mechanism: Submit feedback directly through the app.\n")
        self.features_text_label = ttk.Label(section3_lf, text=features_text,font=AppStyles.FONTS['small'], justify='left', style='TLabel')
        self.features_text_label.pack(fill='x', padx=5, pady=5)
        section4_lf = ttk.LabelFrame(sections_container, text="Contact & Support", padding=10, style='About.TLabelframe')
        section4_lf.grid(row=0, column=1, padx=10, pady=5, sticky='nsew'); self.about_section_labelframes.append(section4_lf)
        contact_text = ("For additional information, support, or to contribute to the project, please visit our GitHub repository:\n\n"
                        "- https://github.com/rayder54321/SwiftSign-Digital-Signature-program\n"
                        "- Documentation: Find detailed guides and setup instructions in the repository’s README file.\n"
                        "- Issue Reporting: Submit bugs or feature requests via GitHub Issues.\n"
                        "- Requirements: Python 3.8+, libraries in README (incl. tkinterdnd2 for DND).\n")
        self.contact_text_label = ttk.Label(section4_lf, text=contact_text, font=AppStyles.FONTS['small'], justify='left', style='TLabel')
        self.contact_text_label.pack(fill='x', padx=5, pady=5)
        def update_about_tab_styles_recursive_closure(widget_to_update=self.about_scrollable_frame):
            if not self.about_frame_canvas.winfo_exists(): return 
            self.about_frame_canvas.config(background=AppStyles.COLORS['gray'], highlightbackground=AppStyles.COLORS['frame_border'])
            self.about_scrollable_frame.configure(style='AboutScrollable.TFrame')
            sections_container.configure(style='AboutScrollable.TFrame') 
            for lf in self.about_section_labelframes:
                if lf.winfo_exists(): 
                    lf.configure(style='About.TLabelframe')
                    for child in lf.winfo_children():
                        if child.winfo_exists(): 
                            if isinstance(child, ttk.Label):
                                child.configure(style='TLabel', background=AppStyles.COLORS['gray'], foreground=AppStyles.COLORS['dark'])
                            elif isinstance(child, ttk.Frame): 
                                child.configure(style='AboutScrollable.TFrame')
        parent_canvas_host_frame.update_style_recursive = update_about_tab_styles_recursive_closure

    def _execute_threaded_operation(self, operation_func, success_message_base, error_message_prefix, result_display_widget, progress_message_base, action_type=None, custom_success_handler=None, is_batch=False, total_batch_items=0):
        if not is_batch or (is_batch and result_display_widget.status_var.get().startswith("No operation")):
             result_display_widget.clear()
             result_display_widget.set_info(f"{progress_message_base}...", "Operation in progress.")

        def task_wrapper():
            self.status_bar.show_progress()
            if not is_batch:
                self.status_bar.set_progress(0); self.status_bar.set_message(f"{progress_message_base} (0%)...", status='info')
            try:
                if not is_batch: self.root.after(50, lambda: self.status_bar.set_progress(10))
                if is_batch:
                    num_successful = 0
                    num_failed = 0
                    for i, success, payload in operation_func():
                        progress_percent = int(((i + 1) / total_batch_items) * 100)
                        self.root.after(0, lambda p=progress_percent, current=i+1: self.status_bar.set_progress(p, text_override=f"Processing {current}/{total_batch_items}"))
                        item_name = payload.get("item_name", f"Item {i+1}")
                        if success:
                            num_successful += 1
                            self.root.after(0, lambda item=item_name, det=payload.get("details", "OK"): result_display_widget.append_text(f"SUCCESS: {item} - {det}\n", tag="success")) 
                        else:
                            num_failed += 1
                            self.root.after(0, lambda item=item_name, err=payload.get("error", "Failed"): result_display_widget.append_text(f"FAILED: {item} - {err}\n", tag="error")) 
                    final_message = f"Batch {progress_message_base} complete. Successful: {num_successful}, Failed: {num_failed}."
                    overall_status_for_bar = 'success' if num_failed == 0 else 'error'
                    overall_status_for_display_label = 'Success.TLabel' if num_failed == 0 else 'Error.TLabel'
                    self.root.after(0, lambda: self.status_bar.set_message(final_message, status=overall_status_for_bar))
                    self.root.after(0, lambda: result_display_widget.status_var.set(final_message)) 
                    self.root.after(0, lambda: result_display_widget.status_label.configure(style=overall_status_for_display_label))
                    self.root.after(0, lambda: self.status_bar.set_progress(100)) 
                    if action_type: self.undo_manager.add_action(action_type, {'details_str': final_message, 'summary': {'success': num_successful, 'failed': num_failed}})
                else:
                    self.root.after(50, lambda: self.status_bar.set_message(f"{progress_message_base} (10%)...", status='info'))
                    success, result_payload = operation_func()
                    self.root.after(0, lambda: self.status_bar.set_progress(100))
                    if success:
                        undo_data = {}
                        if action_type:
                            undo_data['details_str'] = result_payload if isinstance(result_payload, str) else result_payload.get('details','')
                            if isinstance(result_payload, dict): undo_data['is_valid'] = result_payload.get('is_valid', False) 
                            self.undo_manager.add_action(action_type, undo_data)
                        if custom_success_handler: self.root.after(0, lambda: custom_success_handler(result_payload))
                        else:
                            self.root.after(0, lambda: self.status_bar.set_message(success_message_base, status='success'))
                            self.root.after(0, lambda: result_display_widget.set_success(success_message_base, undo_data.get('details_str','Operation successful.')))
                    else: 
                        error_detail = result_payload if isinstance(result_payload, str) else "Unknown error"
                        self.root.after(0, lambda: self.status_bar.set_message(f"{error_message_prefix}: {error_detail}", status='error'))
                        self.root.after(0, lambda: result_display_widget.set_error(error_message_prefix, error_detail))
                        if action_type: self.undo_manager.add_action(action_type, {'error': error_detail})
            except Exception as e: 
                self.root.after(0, lambda: self.status_bar.set_progress(100)) 
                err_type_name = type(e).__name__
                err_msg_detail = str(e)
                suggestion = ""
                if isinstance(e, PermissionError):
                    err_msg_detail = f"Permission denied for '{getattr(e, 'filename', 'file/directory')}'."
                    suggestion = "Check read/write permissions. Try running as administrator or changing file/folder permissions."
                elif isinstance(e, FileNotFoundError):
                    err_msg_detail = f"File not found: '{getattr(e, 'filename', 'file/directory')}'."
                    suggestion = "Please check the path and ensure the file exists."
                elif isinstance(e, json.JSONDecodeError):
                    err_msg_detail = f"Invalid JSON data: {e.msg} at line {e.lineno} col {e.colno} (in '{getattr(e, 'doc', 'unknown JSON file')}')."
                    suggestion = "Check the JSON file for syntax errors. It might be corrupted."
                elif isinstance(e, (BadSignatureError, InvalidSignature)):
                    algo = self.current_algorithm.get() 
                    err_msg_detail = f"{algo} signature verification failed. The signature is invalid or does not match the data/key."
                    suggestion = "Ensure you are using the correct public key, data file, and signature file. The data might have been tampered with or the key is wrong."
                elif isinstance(e, UnsupportedAlgorithm) or "Unsupported" in str(e) or "Unknown algorithm" in str(e):
                    algo = self.current_algorithm.get()
                    err_msg_detail = f"Unsupported cryptographic algorithm or operation for {algo}."
                    suggestion = f"The key or data might be incompatible with {algo}, or a required library feature/format is missing."
                elif isinstance(e, (ValueError, TypeError)) and ("PEM" in str(e) or "key" in str(e) or "ASN.1" in str(e) or "password" in str(e).lower() or "decrypt" in str(e).lower()):
                    algo = self.current_algorithm.get()
                    err_msg_detail = f"Invalid key format, data, or password for {algo}: {str(e)}."
                    suggestion = "Ensure the key file is a valid PEM-encoded key and not corrupted. If password-protected, ensure the password is correct."
                elif isinstance(e, IsADirectoryError):
                    err_msg_detail = f"Expected a file but found a directory: '{getattr(e, 'filename', 'path')}'."
                    suggestion = "Please select a file, not a directory, for this operation."
                elif isinstance(e, NotADirectoryError):
                    err_msg_detail = f"Expected a directory but found a file: '{getattr(e, 'filename', 'path')}'."
                    suggestion = "Please select a directory for this operation."
                full_error_details = f"{err_msg_detail}\n\nSuggestion: {suggestion}" if suggestion else err_msg_detail
                self.root.after(0, lambda: self.status_bar.set_message(f"{error_message_prefix}: {err_type_name}", status='error'))
                self.root.after(0, lambda: result_display_widget.set_error(f"{error_message_prefix} ({err_type_name})", full_error_details))
                if action_type and not is_batch: self.undo_manager.add_action(action_type, {'error': full_error_details})
            finally:
                if not is_batch: 
                    self.root.after(1000, self.status_bar.hide_progress) 
                self.root.after(0, self._update_undo_redo_menu_state)
        threading.Thread(target=task_wrapper, daemon=True).start()

    def ecc_engine(self): return {'name': 'ECC', 'generate': self.generate_ecc_keys, 'sign': self.sign_ecc, 'verify': self.verify_ecc}
    def rsa_engine(self): return {'name': 'RSA', 'generate': self.generate_rsa_keys, 'sign': self.sign_rsa, 'verify': self.verify_rsa}
    def elgamal_engine(self): return {'name': 'ElGamal', 'generate': self.generate_elgamal_keys, 'sign': self.sign_elgamal, 'verify': self.verify_elgamal}
    def create_optimized_dh_engine(self, dh_instance):
        return {
            'generate': lambda paths, password: dh_instance.generate_dh_keys(paths, password=None), 
            'sign': lambda priv_key, data_str: dh_instance.sign_dh(priv_key, data_str), 
            'verify': lambda pub_key, data_str, sig_b64, dh_params_path=None: dh_instance.verify_dh(pub_key, data_str, sig_b64, dh_params_path=dh_params_path),
            'name': 'Diffie-Hellman', 'description': 'DH for key agreement, adapted for HMAC-SHA256 signatures.'
        }
    
    def generate_keys(self):
        def do_generate():
            save_dir = self.keygen_path_selector.get_path()
            if not save_dir: return False, "Please select a save directory."
            if not os.path.isdir(save_dir):
                try: os.makedirs(save_dir, exist_ok=True)
                except OSError as e: return False, f"Invalid/inaccessible directory: {save_dir}. Error: {e}"
            algorithm = self.current_algorithm.get()
            engine = self.crypto_engines[algorithm]
            password = None
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            priv_key_filename = f"{algorithm.lower()}_private_{timestamp}.pem"
            pub_key_filename = f"{algorithm.lower()}_public_{timestamp}.pem"
            _priv_key_path = os.path.join(save_dir, priv_key_filename)
            _pub_key_path = os.path.join(save_dir, pub_key_filename)
            paths_for_engine = [_priv_key_path, _pub_key_path, None]
            if algorithm == 'Diffie-Hellman': 
                params_filename_dh = f"dh_params_{timestamp}.pem" 
                _params_path_dh = os.path.join(save_dir, params_filename_dh)
                paths_for_engine = (_params_path_dh, _priv_key_path, _pub_key_path)
            self.root.after(0, lambda: self.status_bar.set_progress(30)); 
            success, generated_files_info = engine['generate'](paths_for_engine, password=password) 
            self.root.after(0, lambda: self.status_bar.set_progress(70)); 
            if success:
                details = f"=== {algorithm} Key Generation Successful ===\n\n"
                if algorithm == 'Diffie-Hellman':
                    if isinstance(generated_files_info, tuple) and len(generated_files_info) == 3:
                        details += f"Parameters saved to: {os.path.basename(generated_files_info[0])}\n"
                        details += f"Private Key saved to: {os.path.basename(generated_files_info[1])}\n"
                        details += f"Public Key saved to: {os.path.basename(generated_files_info[2])}\n"
                    else: 
                        details += f"Generated files: {generated_files_info} (Unexpected format for DH)\n"
                else:
                    if isinstance(generated_files_info, tuple) and len(generated_files_info) == 2:
                        details += f"Private Key saved to: {os.path.basename(generated_files_info[0])}\n"
                        details += f"Public Key saved to: {os.path.basename(generated_files_info[1])}\n"
                    else: 
                        details += f"Generated files: {generated_files_info} (Unexpected format for {algorithm})\n"
                details += "\nIMPORTANT: Keep the private key secure and backed up!"
                return True, details
            return False, generated_files_info 
        self._execute_threaded_operation(do_generate, "Keys Generated Successfully", "Key Generation Error", self.keygen_result_display, "Generating keys", action_type='key_generation')

    def preview_license(self):
        customer_name_str = self.customer_name.get().strip()
        customer_email_str = self.customer_email.get().strip()
        expiry_input_str = self.expiry_date.get().strip()
        hardware_id_str = self.hardware_id.get().strip() or "N/A"
        algorithm = self.current_algorithm.get()
        if not all([customer_name_str, customer_email_str, expiry_input_str]):
            self.sign_result_display.set_error("Preview Error", "Please fill mandatory license details (Customer, Email, Expiry Date).")
            self.status_bar.set_message("Preview Error: Missing license details.", status='error')
            return
        try:
            expiry_dt_obj = datetime.strptime(expiry_input_str, "%d/%m/%Y")
            expiry_iso_format_str = expiry_dt_obj.strftime("%Y-%m-%d")
        except ValueError:
            self.sign_result_display.set_error("Preview Error", "Invalid Expiry Date format. Use DD/MM/YYYY.")
            self.status_bar.set_message("Preview Error: Invalid expiry date.", status='error')
            return
        license_data_preview = {
            "algorithm": algorithm, "customer": customer_name_str, "email": customer_email_str,
            "expiry_date": expiry_iso_format_str, "hardware_id": hardware_id_str,
            "issued_at": datetime.now().isoformat(), 
            "_preview_note": "This is a preview of the license data. No signature has been generated or saved."
        }
        license_str_preview = json.dumps(license_data_preview, indent=2)
        self.sign_result_display.set_info("License Preview Generated", license_str_preview)
        self.status_bar.set_message("License preview generated successfully.", status='info')

    def sign_license(self):
        def do_sign():
            priv_key_file = self.sign_privkey_selector.get_path()
            if not priv_key_file or not os.path.exists(priv_key_file): return False, f"Private key file not found or not selected: {priv_key_file}"
            customer_name_str = self.customer_name.get().strip()
            customer_email_str = self.customer_email.get().strip()
            expiry_input_str = self.expiry_date.get().strip()
            if not all([customer_name_str, customer_email_str, expiry_input_str]):
                return False, "Please fill mandatory license details (Customer, Email, Expiry Date)."
            try:
                expiry_dt_obj = datetime.strptime(expiry_input_str, "%d/%m/%Y")
                expiry_iso_format_str = expiry_dt_obj.strftime("%Y-%m-%d")
            except ValueError: return False, "Invalid Expiry Date format. Use DD/MM/YYYY."
            algorithm = self.current_algorithm.get()
            license_data = {
                "algorithm": algorithm, "customer": customer_name_str, "email": customer_email_str, 
                "expiry_date": expiry_iso_format_str, "hardware_id": self.hardware_id.get().strip() or "N/A", 
                "issued_at": datetime.now().isoformat()
            }
            license_str = json.dumps(license_data, indent=2)
            self.root.after(0, lambda: self.status_bar.set_progress(20)); 
            default_license_data_name = f"license_{license_data['customer'].replace(' ','_')}_{datetime.now().strftime('%Y%m%d')}.json"
            license_data_file = filedialog.asksaveasfilename(initialfile=default_license_data_name, defaultextension=".json", filetypes=[("JSON files", "*.json"), ("Text Files", "*.txt"), ("All Files", "*.*")], title="Save License Data File", parent=self.root, initialdir=os.path.dirname(priv_key_file) or self.get_default_key_dir())
            if not license_data_file: return False, "License data file saving cancelled."
            with open(license_data_file, "w", encoding='utf-8') as f: f.write(license_str)
            self.root.after(0, lambda: self.status_bar.set_progress(50)); 
            engine = self.crypto_engines[algorithm]
            success, signature_b64 = engine['sign'](priv_key_file, license_str) 
            if not success: return False, signature_b64 
            sig_ext = "dh" if algorithm == "Diffie-Hellman" else algorithm.lower().replace('-', '')
            default_sig_name = f"license_sig_{license_data['customer'].replace(' ','_')}_{datetime.now().strftime('%Y%m%d')}.{sig_ext}" 
            license_signature_file = filedialog.asksaveasfilename(
                initialfile=default_sig_name, defaultextension=f".{sig_ext}", 
                filetypes=[(f"{algorithm} Signature Files (*.{sig_ext})", f"*.{sig_ext}"), ("All Files", "*.*")], 
                title="Save License Signature File", parent=self.root, 
                initialdir=os.path.dirname(license_data_file) or self.get_default_key_dir()
            )
            if not license_signature_file: return False, "License signature file saving cancelled."
            with open(license_signature_file, "w", encoding='utf-8') as f: f.write(signature_b64)
            details = (f"=== License Signed Successfully with {algorithm} ===\n\nLicense data: {os.path.basename(license_data_file)}\nSignature: {os.path.basename(license_signature_file)}\n\nFull Data Path: {license_data_file}\nFull Sig Path: {license_signature_file}\n\nDetails:\n{license_str}")
            return True, details
        self._execute_threaded_operation(do_sign, "License Signed Successfully", "License Signing Error", self.sign_result_display, "Signing license", action_type='sign')

    def verify_license(self):
        def do_verify():
            pub_key_file = self.verify_pubkey_selector.get_path()
            sig_file = self.license_file_selector.get_path()
            data_file = self.license_data_selector.get_path()
            if not all([pub_key_file, sig_file, data_file]): return False, "Please select Public Key, Signature, and Data File."
            for f_path, name in [(pub_key_file, "Public key"), (sig_file, "Signature"), (data_file, "Data")]:
                if not os.path.exists(f_path): return False, f"{name} file not found: {os.path.basename(f_path)}"
            algorithm = self.current_algorithm.get()
            dh_params_file_path = None
            if algorithm == 'Diffie-Hellman':
                if hasattr(self, 'dh_params_selector') and self.dh_params_selector.winfo_exists():
                    dh_params_file_path = self.dh_params_selector.get_path()
                    if not dh_params_file_path:
                        dh_params_file_path = None
                    elif dh_params_file_path and not os.path.exists(dh_params_file_path):
                        return False, f"DH Parameters file specified but not found: {os.path.basename(dh_params_file_path)}"
            self.root.after(0, lambda: self.status_bar.set_progress(20)); 
            with open(data_file, "r", encoding='utf-8') as f: license_data_str = f.read()
            with open(sig_file, "r", encoding='utf-8') as f: signature_b64 = f.read().strip()
            parsed_license_data = None
            try:
                parsed_license_data = json.loads(license_data_str)
                original_algo = parsed_license_data.get("algorithm", "Unknown")
                if original_algo != "Unknown" and original_algo != algorithm:
                    self.root.after(0, lambda: messagebox.showwarning("Algorithm Mismatch", f"License data indicates it was signed with '{original_algo}', but you selected '{algorithm}' for verification. Results may be incorrect if these do not match the key type.", parent=self.root))
            except json.JSONDecodeError as je:
                print(f"Note: Data file '{os.path.basename(data_file)}' is not valid JSON ({je}). Proceeding with raw data verification.")
            self.root.after(0, lambda: self.status_bar.set_progress(50)); 
            engine = self.crypto_engines[algorithm]
            is_valid, verification_message = engine['verify'](pub_key_file, license_data_str, signature_b64, dh_params_path=dh_params_file_path)
            details = f"=== License Verification using {algorithm} ===\n\n"
            details += f"Public Key: {os.path.basename(pub_key_file)}\n"
            if algorithm == 'Diffie-Hellman' and dh_params_file_path:
                details += f"DH Parameters File (for validation): {os.path.basename(dh_params_file_path)}\n"
            details += f"Data File: {os.path.basename(data_file)}\n"
            details += f"Signature File: {os.path.basename(sig_file)}\n\n"
            if parsed_license_data:
                details += f"License Content (from {os.path.basename(data_file)}):\n{json.dumps(parsed_license_data, indent=2)}\n\n"
            else: 
                details += f"Raw Data Content (from {os.path.basename(data_file)} - first 200 chars):\n{license_data_str[:200]}{'...' if len(license_data_str) > 200 else ''}\n\n"
            details += f"Verification Result: {verification_message}"
            return True, {'is_valid': is_valid, 'details': details}

        def handle_verification_success(result_payload):
            is_valid, details_str = result_payload['is_valid'], result_payload['details']
            if is_valid: self.status_bar.set_message("Verification: License IS VALID", status='success'); self.verify_result_display.set_success("License VALID", details_str)
            else: self.status_bar.set_message("Verification: License IS INVALID or Error", status='error'); self.verify_result_display.set_error("License INVALID or Error", details_str)
        self._execute_threaded_operation(do_verify, "Verification Completed", "Verification Error", self.verify_result_display, "Verifying license", action_type='verify', custom_success_handler=handle_verification_success)

    # --- Batch Operations ---
    def start_batch_signing(self):
        priv_key_file = self.batch_sign_priv_key_selector.get_path()
        output_dir = self.batch_sign_output_dir_selector.get_path()
        data_files = list(self.batch_sign_files) 
        if not priv_key_file or not os.path.exists(priv_key_file):
            messagebox.showerror("Error", "Please select a valid private key for batch signing.", parent=self.root)
            return
        if not output_dir or not os.path.isdir(output_dir):
            messagebox.showerror("Error", "Please select a valid output directory for signatures.", parent=self.root)
            return
        if not data_files:
            messagebox.showinfo("Info", "No data files selected for batch signing.", parent=self.root)
            return
        algorithm = self.current_algorithm.get()
        engine = self.crypto_engines[algorithm]
        self.batch_ops_result_display.clear()
        self.batch_ops_result_display.set_info(f"Starting Batch Signing ({len(data_files)} files)...", "")

        def do_batch_sign():
            for i, data_file_path in enumerate(data_files):
                item_name = os.path.basename(data_file_path)
                try:
                    with open(data_file_path, "r", encoding='utf-8') as f:
                        data_str = f.read()
                    try:
                        parsed_data = json.loads(data_str)
                        if "algorithm" not in parsed_data:
                            parsed_data["algorithm"] = algorithm
                        if "issued_at" not in parsed_data: 
                             parsed_data["issued_at"] = datetime.now().isoformat()
                        data_to_sign_str = json.dumps(parsed_data, indent=2)
                    except json.JSONDecodeError:
                        data_to_sign_str = data_str
                    success, signature_b64_or_err = engine['sign'](priv_key_file, data_to_sign_str)
                    if success:
                        sig_ext = "dh" if algorithm == "Diffie-Hellman" else algorithm.lower().replace('-', '')
                        base_data_name = os.path.splitext(os.path.basename(data_file_path))[0]
                        sig_filename = f"{base_data_name}.{sig_ext}"
                        sig_output_path = os.path.join(output_dir, sig_filename)
                        with open(sig_output_path, "w", encoding='utf-8') as f:
                            f.write(signature_b64_or_err)
                        yield i, True, {"item_name": item_name, "details": f"Signed to {sig_filename}"}
                    else:
                        yield i, False, {"item_name": item_name, "error": signature_b64_or_err}
                except Exception as e:
                    yield i, False, {"item_name": item_name, "error": f"Exception: {type(e).__name__} - {str(e)}"}
        self._execute_threaded_operation(do_batch_sign, "Batch Signing Completed", "Batch Signing Error", self.batch_ops_result_display, "Signing", action_type='batch_sign', is_batch=True, total_batch_items=len(data_files))

    def start_batch_verification(self):
        pub_key_file = self.batch_verify_pub_key_selector.get_path()
        file_pairs = list(self.batch_verify_files) 
        if not pub_key_file or not os.path.exists(pub_key_file):
            messagebox.showerror("Error", "Please select a valid public key for batch verification.", parent=self.root)
            return
        if not file_pairs:
            messagebox.showinfo("Info", "No license (data + signature) pairs selected for batch verification.", parent=self.root)
            return
        algorithm = self.current_algorithm.get()
        engine = self.crypto_engines[algorithm]
        self.batch_ops_result_display.clear()
        self.batch_ops_result_display.set_info(f"Starting Batch Verification ({len(file_pairs)} pairs)...", "")

        def do_batch_verify():
            dh_params_path_for_batch = None 
            for i, (data_file_path, sig_file_path) in enumerate(file_pairs):
                item_name = f"{os.path.basename(data_file_path)} + {os.path.basename(sig_file_path)}"
                try:
                    if not os.path.exists(data_file_path):
                        yield i, False, {"item_name": item_name, "error": f"Data file not found: {os.path.basename(data_file_path)}"}
                        continue
                    if not os.path.exists(sig_file_path):
                        yield i, False, {"item_name": item_name, "error": f"Signature file not found: {os.path.basename(sig_file_path)}"}
                        continue
                    with open(data_file_path, "r", encoding='utf-8') as f_data:
                        data_str = f_data.read()
                    with open(sig_file_path, "r", encoding='utf-8') as f_sig:
                        sig_b64 = f_sig.read().strip()
                    is_valid, verify_msg = engine['verify'](pub_key_file, data_str, sig_b64, dh_params_path=dh_params_path_for_batch)
                    if is_valid:
                        yield i, True, {"item_name": item_name, "details": verify_msg}
                    else:
                        yield i, False, {"item_name": item_name, "error": verify_msg}
                except Exception as e:
                    yield i, False, {"item_name": item_name, "error": f"Exception: {type(e).__name__} - {str(e)}"}
        self._execute_threaded_operation(do_batch_verify, "Batch Verification Completed", "Batch Verification Error",self.batch_ops_result_display, "Verifying",action_type='batch_verify', is_batch=True, total_batch_items=len(file_pairs))

    # --- RSA Methods ---
    def generate_rsa_keys(self, paths, password=None): 
        priv_key_path, pub_key_path, _ = paths
        encryption_algorithm = serialization.NoEncryption()
        try:
            private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
            public_key = private_key.public_key()
            with open(priv_key_path, "wb") as f: f.write(private_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, encryption_algorithm))
            with open(pub_key_path, "wb") as f: f.write(public_key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
            return True, (priv_key_path, pub_key_path)
        except Exception as e: return False, f"RSA key generation failed: {str(e)}"

    def _load_rsa_private_key(self, private_key_path):
        with open(private_key_path, "rb") as f:
            key_data = f.read()
        try:
            return serialization.load_pem_private_key(key_data, password=None, backend=default_backend())
        except Exception as e:
            raise ValueError(f"Failed to load RSA private key '{os.path.basename(private_key_path)}': {str(e)}. Keys are no longer expected to be encrypted.") from e
    
    def sign_rsa(self, private_key_path, data_string):
        try:
            private_key = self._load_rsa_private_key(private_key_path)
            signature = private_key.sign(data_string.encode('utf-8'), asym_padding.PSS(mgf=asym_padding.MGF1(hashes.SHA256()), salt_length=asym_padding.PSS.MAX_LENGTH), hashes.SHA256())
            return True, base64.b64encode(signature).decode('utf-8')
        except Exception as e: return False, f"RSA signing failed: {str(e)}"

    def verify_rsa(self, public_key_path, data_string, signature_b64, dh_params_path=None):
        try:
            with open(public_key_path, "rb") as f: public_key = serialization.load_pem_public_key(f.read(), backend=default_backend())
            public_key.verify(base64.b64decode(signature_b64), data_string.encode('utf-8'), asym_padding.PSS(mgf=asym_padding.MGF1(hashes.SHA256()), salt_length=asym_padding.PSS.MAX_LENGTH), hashes.SHA256())
            return True, "RSA Signature VALID"
        except (InvalidSignature, BadSignatureError): return False, "RSA Signature INVALID: Verification failed." 
        except Exception as e: return False, f"RSA verification error: {str(e)}"

    # --- ElGamal (RSA-PSS based) Methods ---
    def generate_elgamal_keys(self, paths, password=None): 
        priv_key_path, pub_key_path, _ = paths
        encryption_algorithm = serialization.NoEncryption()
        try:
            private_key = ElGamal.generate_private_key(key_size=2048, backend=default_backend()) 
            public_key = private_key.public_key()
            with open(priv_key_path, "wb") as f: f.write(private_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, encryption_algorithm))
            with open(pub_key_path, "wb") as f: f.write(public_key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
            return True, (priv_key_path, pub_key_path)
        except Exception as e: return False, f"ElGamal (RSA-based) key generation failed: {str(e)}"

    def _load_elgamal_private_key(self, private_key_path): 
        return self._load_rsa_private_key(private_key_path) 

    def sign_elgamal(self, private_key_path, data_string):
        try:
            private_key_obj = self._load_elgamal_private_key(private_key_path) 
            signature = ElGamal.sign(private_key_obj, data_string.encode('utf-8')) 
            return True, base64.b64encode(signature).decode('utf-8')
        except Exception as e: return False, f"ElGamal (RSA-based) signing failed: {str(e)}"

    def verify_elgamal(self, public_key_path, data_string, signature_b64, dh_params_path=None):
        try:
            with open(public_key_path, "rb") as f: public_key_obj = serialization.load_pem_public_key(f.read(), backend=default_backend())
            ElGamal.verify(public_key_obj, base64.b64decode(signature_b64), data_string.encode('utf-8')) 
            return True, "ElGamal (RSA-based) Signature VALID"
        except (InvalidSignature, BadSignatureError): return False, "ElGamal (RSA-based) Signature INVALID: Verification failed."
        except Exception as e: return False, f"ElGamal (RSA-based) verification error: {str(e)}"

    # --- ECC Methods ---
    def generate_ecc_keys(self, paths, password=None): 
        priv_key_path, pub_key_path, _ = paths
        try:
            private_key = SigningKey.generate(curve=NIST256p)
            public_key = private_key.verifying_key
            with open(priv_key_path, "wb") as f: f.write(private_key.to_pem()) 
            with open(pub_key_path, "wb") as f: f.write(public_key.to_pem())
            return True, (priv_key_path, pub_key_path)
        except Exception as e: return False, f"ECC key generation failed: {str(e)}"

    def sign_ecc(self, private_key_path, data_string):
        try:
            with open(private_key_path, "rb") as f: private_key = SigningKey.from_pem(f.read(), hashfunc=hashlib.sha256)
            signature = private_key.sign(data_string.encode('utf-8'), hashfunc=hashlib.sha256)
            return True, base64.b64encode(signature).decode('utf-8')
        except Exception as e: return False, f"ECC signing failed: {str(e)}"

    def verify_ecc(self, public_key_path, data_string, signature_b64, dh_params_path=None):
        try:
            with open(public_key_path, "rb") as f: public_key = VerifyingKey.from_pem(f.read(), hashfunc=hashlib.sha256)
            public_key.verify(base64.b64decode(signature_b64), data_string.encode('utf-8'), hashfunc=hashlib.sha256)
            return True, "ECC Signature VALID"
        except BadSignatureError: return False, "ECC Signature INVALID: Verification failed."
        except Exception as e: return False, f"ECC verification error: {str(e)}"

    def on_close(self):
        if hasattr(self, 'search_dir_keys_var'): self.settings['last_search_dir_keys'] = self.search_dir_keys_var.get()
        self.save_app_settings()
        if messagebox.askokcancel("Quit", "Exit SwiftSign Digital Signature ?", parent=self.root):
            self.dh_optimized_instance.clear_cache() 
            if self.settings_dialog_instance and self.settings_dialog_instance.winfo_exists():
                self.settings_dialog_instance.destroy()
            if self.settings_tab_panel_instance and self.settings_tab_panel_instance.winfo_exists():
                self.settings_tab_panel_instance.destroy() 
            self.root.destroy()

if __name__ == '__main__':
    if DND_SUPPORT:
        root = TkinterDnD.Tk()
    else:
        root = tk.Tk()    
    app = CryptoLicenseSystem(root)
    root.mainloop()
