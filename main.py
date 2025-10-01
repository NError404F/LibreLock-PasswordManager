import customtkinter as ctk
from utils import PasswordManager
import logging

logging.basicConfig(
    filename="app.log",
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s"
)
logger = logging.getLogger(__name__)

def mask_sensitive(s: str, head=2) -> str:
    if not s:
        return "N/A"
    if len(s) <= head:
        return "*" * len(s)
    return s[:head] + "*" * (len(s) - head)

CLIPBOARD_CLEAR_MS = 30_000

class Popup(ctk.CTkToplevel):
    """Simple modal popup (info / success / error)."""
    def __init__(self, parent, title: str, message: str, kind: str = "info"):
        super().__init__(parent)
        self.title(title)
        self.geometry("420x200")
        self.resizable(False, False)

        try:
            self.grab_set()
            self.focus_force()
        except tk.TclError:
            pass

        palette = {
            "info": "#66b2ff",
            "success": "#2db94d",
            "error": "#ff5c5c",
            "warning": "#ff9f43"
        }
        color = palette.get(kind, palette["info"])

        container = ctk.CTkFrame(self, corner_radius=12)
        container.pack(expand=True, fill="both", padx=20, pady=20)

        label = ctk.CTkLabel(container, text=message, wraplength=360, text_color=color, font=("Arial", 13))
        label.pack(expand=True, pady=(8, 10))

        btn = ctk.CTkButton(container, text="OK", command=self.destroy)
        btn.pack(pady=(0, 6))

class LibreLockApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("LibreLock - Secure Password Manager")
        self.geometry("980x640")
        self.minsize(860, 520)
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("dark-blue")

        self.pm = PasswordManager()

        self.current_user = None
        self.current_master_password = None

        self._build_login_screen()

    def _clear_root(self):
        for w in self.winfo_children():
            w.destroy()

    def _clear_content(self):
        for w in self.content_frame.winfo_children():
            w.destroy()

    def _show_popup(self, title, message, kind="info"):
        Popup(self, title, message, kind)

    def _copy_to_clipboard(self, value: str):
        if not value:
            self._show_popup("Nothing to copy", "Empty value cannot be copied.", "warning")
            return
        try:
            self.clipboard_clear()
            self.clipboard_append(value)

            self.after(CLIPBOARD_CLEAR_MS, self._clear_clipboard_if_still(value))
            self._show_popup("Copied", "Value copied to clipboard. It will be cleared in 30 seconds.", "success")
        except Exception as e:
            logger.exception("Clipboard error")
            self._show_popup("Clipboard Error", str(e), "error")

    def _clear_clipboard_if_still(self, expected_value):
        def _fn():
            try:
                current = self.clipboard_get()
                if current == expected_value:
                    self.clipboard_clear()
                    logger.debug("Clipboard cleared automatically")
            except Exception:
                pass
        return _fn


    def _build_login_screen(self):
        self._clear_root()
        wrapper = ctk.CTkFrame(self, corner_radius=12, fg_color="#151515")
        wrapper.pack(expand=True, fill="both", padx=180, pady=80)

        title = ctk.CTkLabel(wrapper, text="🔐 LibreLock", font=("Segoe UI", 28, "bold"))
        title.pack(pady=(18, 12))

        self.login_username = ctk.CTkEntry(wrapper, placeholder_text="Username")
        self.login_username.pack(fill="x", padx=30, pady=8)

        self.login_password = ctk.CTkEntry(wrapper, placeholder_text="Master password", show="*")
        self.login_password.pack(fill="x", padx=30, pady=8)

        btn_frame = ctk.CTkFrame(wrapper, fg_color="transparent")
        btn_frame.pack(fill="x", padx=30, pady=(12, 20))

        login_btn = ctk.CTkButton(btn_frame, text="Login", command=self._action_login)
        login_btn.pack(side="left", expand=True, fill="x", padx=(0, 6))

        register_btn = ctk.CTkButton(btn_frame, text="Register", fg_color="#2d7d46", hover_color="#1f4d2a", command=self._action_register)
        register_btn.pack(side="left", expand=True, fill="x", padx=(6, 0))

    def _build_dashboard(self):
        self._clear_root()

        sidebar = ctk.CTkFrame(self, width=220, corner_radius=0)
        sidebar.pack(side="left", fill="y")

        profile_lbl = ctk.CTkLabel(sidebar, text=f"👤 {self.current_user}", font=("Segoe UI", 14, "bold"))
        profile_lbl.pack(pady=(18, 12))

        ctk.CTkButton(sidebar, text="➕ Add Password", command=self._build_add_screen).pack(fill="x", padx=14, pady=8)
        ctk.CTkButton(sidebar, text="📜 View / Search", command=self._build_list_screen).pack(fill="x", padx=14, pady=8)
        ctk.CTkButton(sidebar, text="🔑 Change Master Password", command=self._build_change_master).pack(fill="x", padx=14, pady=8)
        ctk.CTkButton(sidebar, text="🚪 Logout", fg_color="#a83232", hover_color="#7a2222", command=self._action_logout).pack(fill="x", padx=14, pady=(30, 8))

        self.content_frame = ctk.CTkFrame(self, corner_radius=10)
        self.content_frame.pack(expand=True, fill="both", padx=18, pady=18)

        welcome = ctk.CTkLabel(self.content_frame, text="Welcome to LibreLock", font=("Segoe UI", 20, "bold"))
        welcome.pack(pady=24)

        quick_actions = ctk.CTkFrame(self.content_frame, fg_color="transparent")
        quick_actions.pack(fill="x", padx=16)

        ctk.CTkButton(quick_actions, text="Add New", width=120, command=self._build_add_screen).pack(side="left", padx=6)
        ctk.CTkButton(quick_actions, text="View All", width=120, command=self._build_list_screen).pack(side="left", padx=6)

    def _build_add_screen(self):
        self._clear_content()
        hdr = ctk.CTkLabel(self.content_frame, text="Add New Entry", font=("Segoe UI", 18, "bold"))
        hdr.pack(pady=(6, 12))

        form = ctk.CTkFrame(self.content_frame, fg_color="transparent")
        form.pack(fill="x", padx=12)

        self.add_service = ctk.CTkEntry(form, placeholder_text="Service (required)")
        self.add_service.pack(fill="x", pady=6)

        self.add_username = ctk.CTkEntry(form, placeholder_text="Username (optional)")
        self.add_username.pack(fill="x", pady=6)

        self.add_email = ctk.CTkEntry(form, placeholder_text="Email (optional)")
        self.add_email.pack(fill="x", pady=6)

        self.add_password_field = ctk.CTkEntry(form, placeholder_text="Password (required)", show="*")
        self.add_password_field.pack(fill="x", pady=6)

        self.add_url = ctk.CTkEntry(form, placeholder_text="URL (optional)")
        self.add_url.pack(fill="x", pady=6)

        ctk.CTkLabel(form, text="Notes (optional):").pack(anchor="w", pady=(8, 2))
        self.add_notes = ctk.CTkTextbox(form, height=100)
        self.add_notes.pack(fill="both", pady=(0, 6))

        actions = ctk.CTkFrame(self.content_frame, fg_color="transparent")
        actions.pack(fill="x", padx=12, pady=8)
        ctk.CTkButton(actions, text="Save", fg_color="#2d7d46", command=self._action_add_password).pack(side="left", padx=6)
        ctk.CTkButton(actions, text="Cancel", fg_color="#444444", command=lambda: self._build_dashboard()).pack(side="left")

    def _build_list_screen(self):
        self._clear_content()
        hdr = ctk.CTkLabel(self.content_frame, text="Stored Services", font=("Segoe UI", 18, "bold"))
        hdr.pack(pady=(6, 12))

        search_frame = ctk.CTkFrame(self.content_frame, fg_color="transparent")
        search_frame.pack(fill="x", padx=8)

        ctk.CTkLabel(search_frame, text="Search:").pack(side="left", padx=(4, 8))
        self.search_var = ctk.StringVar()
        search_entry = ctk.CTkEntry(search_frame, textvariable=self.search_var, placeholder_text="type to filter")
        search_entry.pack(side="left", fill="x", expand=True, padx=(0, 8))
        search_entry.bind("<KeyRelease>", lambda e: self._refresh_service_buttons())

        refresh_btn = ctk.CTkButton(search_frame, text="Refresh", width=88, command=self._refresh_service_buttons)
        refresh_btn.pack(side="left")

        self.services_container = ctk.CTkScrollableFrame(self.content_frame, height=420)
        self.services_container.pack(expand=True, fill="both", padx=8, pady=(10, 6))

        self._refresh_service_buttons()

    def _refresh_service_buttons(self):

        for w in self.services_container.winfo_children():
            w.destroy()

        try:
            services = self.pm.list_all(self.current_user, self.current_master_password)
        except Exception as e:
            logger.exception("list_all failed")
            self._show_popup("Error", str(e), "error")
            return

        q = getattr(self, "search_var", ctk.StringVar()).get().strip().lower() if hasattr(self, "search_var") else ""
        filtered = [s for s in services if q in s.lower()]

        if not filtered:
            ctk.CTkLabel(self.services_container, text="No services found.", fg_color="transparent").pack(pady=10)
            return

        for svc in filtered:
            row = ctk.CTkFrame(self.services_container, fg_color="#101010", corner_radius=8)
            row.pack(fill="x", padx=8, pady=6)

            lbl = ctk.CTkLabel(row, text=svc, anchor="w")
            lbl.pack(side="left", padx=(12, 6), pady=8, fill="x", expand=True)

            view_btn = ctk.CTkButton(row, text="View", width=86, command=lambda s=svc: self._open_details_popup(s))
            view_btn.pack(side="right", padx=(6, 12))

    def _open_details_popup(self, service_name: str):
        try:
            data = self.pm.get_password(self.current_user, self.current_master_password, service_name)
        except Exception as e:
            logger.exception("get_password failed")
            self._show_popup("Error", str(e), "error")
            return

        pop = ctk.CTkToplevel(self)
        pop.title(f"Details — {service_name}")
        pop.geometry("560x420")
        pop.resizable(False, False)
        pop.grab_set()
        pop.focus_force()

        frame = ctk.CTkFrame(pop, corner_radius=10)
        frame.pack(expand=True, fill="both", padx=12, pady=12)

        ctk.CTkLabel(frame, text=data["service_name"], font=("Segoe UI", 16, "bold")).pack(anchor="w", pady=(6, 4))

        info_frame = ctk.CTkFrame(frame, fg_color="transparent")
        info_frame.pack(fill="x", pady=(6, 6))

        def _row(label_text, value, copy_cb):
            r = ctk.CTkFrame(info_frame, fg_color="transparent")
            r.pack(fill="x", pady=4)
            ctk.CTkLabel(r, text=label_text, width=10, anchor="w").pack(side="left", padx=(6,8))
            val_lbl = ctk.CTkEntry(r, width=1)
            val_lbl.insert(0, value or "")

            val_lbl.configure(state="disabled")
            val_lbl.pack(side="left", fill="x", expand=True, padx=(0,8))
            ctk.CTkButton(r, text="Copy", width=80, command=lambda: copy_cb(value)).pack(side="right", padx=(0,6))

        _row("Username:", data.get("username", ""), lambda v: self._copy_to_clipboard(v))
        _row("Email:", data.get("email", ""), lambda v: self._copy_to_clipboard(v))
        _row("Password:", data.get("password", ""), lambda v: self._copy_to_clipboard(v))
        _row("URL:", data.get("url", ""), lambda v: self._copy_to_clipboard(v))


        ctk.CTkLabel(frame, text="Notes:", anchor="w").pack(anchor="w", padx=6, pady=(10,2))
        notes_box = ctk.CTkTextbox(frame, height=110)
        notes_box.insert("0.0", data.get("notes", "") or "")
        notes_box.configure(state="disabled")
        notes_box.pack(fill="both", padx=6, pady=(0,8))

        action_row = ctk.CTkFrame(frame, fg_color="transparent")
        action_row.pack(fill="x", pady=(6, 4))
        ctk.CTkButton(action_row, text="Edit", fg_color="#ffb84d", command=lambda: [pop.destroy(), self._build_edit_screen(service_name)]).pack(side="left", padx=6)
        ctk.CTkButton(action_row, text="Delete", fg_color="#ff5c5c", command=lambda: [pop.destroy(), self._confirm_delete(service_name)]).pack(side="right", padx=6)

    def _build_edit_screen(self, service_name: str):
        self._clear_content()
        hdr = ctk.CTkLabel(self.content_frame, text=f"Edit — {service_name}", font=("Segoe UI", 18, "bold"))
        hdr.pack(pady=(6, 12))

        try:
            data = self.pm.get_password(self.current_user, self.current_master_password, service_name)
        except Exception as e:
            logger.exception("get_password failed")
            self._show_popup("Error", str(e), "error")
            return

        form = ctk.CTkFrame(self.content_frame, fg_color="transparent")
        form.pack(fill="x", padx=12)

        ctk.CTkLabel(form, text="New password (leave blank to keep current):").pack(anchor="w", pady=(6,2))
        self.edit_password_field = ctk.CTkEntry(form, placeholder_text="New password", show="*")
        self.edit_password_field.pack(fill="x", pady=6)

        ctk.CTkLabel(form, text="URL:").pack(anchor="w", pady=(6,2))
        self.edit_url = ctk.CTkEntry(form)
        self.edit_url.insert(0, data.get("url") or "")
        self.edit_url.pack(fill="x", pady=6)

        ctk.CTkLabel(form, text="Notes:").pack(anchor="w", pady=(6,2))
        self.edit_notes = ctk.CTkTextbox(form, height=120)
        self.edit_notes.insert("0.0", data.get("notes") or "")
        self.edit_notes.pack(fill="both", pady=(0,6))

        actions = ctk.CTkFrame(self.content_frame, fg_color="transparent")
        actions.pack(fill="x", padx=12, pady=8)
        ctk.CTkButton(actions, text="Save Changes", fg_color="#2d7d46", command=lambda: self._action_update(service_name)).pack(side="left", padx=6)
        ctk.CTkButton(actions, text="Cancel", fg_color="#444444", command=lambda: self._build_list_screen()).pack(side="left")

    def _confirm_delete(self, service_name: str):
        def _do_delete():
            try:
                self.pm.delete_password(self.current_user, self.current_master_password, service_name)
                self._show_popup("Deleted", f"'{service_name}' removed.", "success")
                self._build_list_screen()
            except Exception as e:
                logger.exception("delete_password failed")
                self._show_popup("Error", str(e), "error")

        confirm = Popup(self, "Confirm delete", f"Delete '{service_name}'? This action cannot be undone.", "warning")

        for w in confirm.winfo_children():

            for child in w.winfo_children():
                if isinstance(child, ctk.CTkButton):
                    child.configure(text="Delete", fg_color="#ff5c5c", command=lambda: [confirm.destroy(), _do_delete()])
                    break
            break 

    def _build_change_master(self):
        self._clear_content()
        hdr = ctk.CTkLabel(self.content_frame, text="Change Master Password", font=("Segoe UI", 18, "bold"))
        hdr.pack(pady=(6, 12))

        form = ctk.CTkFrame(self.content_frame, fg_color="transparent")
        form.pack(fill="x", padx=12)

        self.change_old = ctk.CTkEntry(form, placeholder_text="Current master password", show="*")
        self.change_old.pack(fill="x", pady=6)
        self.change_new = ctk.CTkEntry(form, placeholder_text="New master password (min 12 chars)", show="*")
        self.change_new.pack(fill="x", pady=6)

        actions = ctk.CTkFrame(self.content_frame, fg_color="transparent")
        actions.pack(fill="x", padx=12, pady=8)
        ctk.CTkButton(actions, text="Change", fg_color="#2d7d46", command=self._action_change_master).pack(side="left", padx=6)
        ctk.CTkButton(actions, text="Cancel", fg_color="#444444", command=lambda: self._build_dashboard()).pack(side="left")

    def _action_register(self):
        username = self.login_username.get().strip()
        password = self.login_password.get().strip()
        if not username or not password:
            self._show_popup("Invalid", "Username and password required.", "warning")
            return
        try:
            self.pm.register_user(username, password)
            self._show_popup("Success", "Registration complete. Please log in.", "success")
        except Exception as e:
            logger.exception("register failed")
            self._show_popup("Error", str(e), "error")

    def _action_login(self):
        username = self.login_username.get().strip()
        password = self.login_password.get().strip()
        if not username or not password:
            self._show_popup("Invalid", "Enter username and password.", "warning")
            return
        try:
            self.pm.verify_and_get_user_id(username, password)
            self.current_user = username
            self.current_master_password = password
            logger.info("Login: %s", mask_sensitive(username))
            self._build_dashboard()
        except Exception as e:
            logger.exception("login failed")
            self._show_popup("Login failed", str(e), "error")

    def _action_logout(self):
        self.current_user = None
        self.current_master_password = None
        self._build_login_screen()

    def _action_add_password(self):
        svc = self.add_service.get().strip()
        pw = self.add_password_field.get().strip()
        if not svc or not pw:
            self._show_popup("Invalid", "Service and password are required.", "warning")
            return
        try:
            self.pm.add_password(
                self.current_user,
                self.current_master_password,
                svc,
                self.add_username.get().strip(),
                self.add_email.get().strip(),
                pw,
                url=self.add_url.get().strip(),
                notes=self.add_notes.get("0.0", "end").strip()
            )
            logger.info("Added service %s for %s", mask_sensitive(svc), self.current_user)
            self._show_popup("Saved", f"'{svc}' saved successfully.", "success")
            self._build_list_screen()
        except Exception as e:
            logger.exception("add_password failed")
            self._show_popup("Error", str(e), "error")

    def _action_update(self, service_name: str):
        new_pw = self.edit_password_field.get().strip()
        new_url = self.edit_url.get().strip()
        new_notes = self.edit_notes.get("0.0", "end").strip()

        try:
            if not new_pw:
                existing = self.pm.get_password(self.current_user, self.current_master_password, service_name)
                new_pw = existing.get("password", "")
            self.pm.update_password(
                self.current_user,
                self.current_master_password,
                service_name,
                new_pw,
                url=new_url,
                notes=new_notes
            )
            logger.info("Updated service %s for %s", mask_sensitive(service_name), self.current_user)
            self._show_popup("Updated", f"'{service_name}' updated.", "success")
            self._build_list_screen()
        except Exception as e:
            logger.exception("update_password failed")
            self._show_popup("Error", str(e), "error")

    def _action_change_master(self):
        old = self.change_old.get().strip()
        new = self.change_new.get().strip()
        if not old or not new:
            self._show_popup("Invalid", "Both old and new password are required.", "warning")
            return
        try:
            self.pm.change_master_password(self.current_user, old, new)
            self.current_master_password = new
            self._show_popup("Success", "Master password updated.", "success")
            self._build_dashboard()
        except Exception as e:
            logger.exception("change_master_password failed")
            self._show_popup("Error", str(e), "error")

if __name__ == "__main__":
    app = LibreLockApp()
    app.mainloop()
