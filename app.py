import sqlite3
import secrets
import string
import tkinter as tk
from tkinter import ttk, messagebox
from pathlib import Path
from crypto_utils import derive_key, encrypt_text, decrypt_text, hash_master_password, verify_master_password

DB_PATH = Path(__file__).with_name("password_manager.db")


class PasswordManager:
    def __init__(self, root):
        self.root = root
        self.root.title("Password Manager")
        self.root.geometry("900x600")
        self.root.minsize(780, 520)
        self.master_password = None
        self.key = None
        self.init_db()
        self.show_login()

    def connect(self):
        return sqlite3.connect(DB_PATH)

    def init_db(self):
        with self.connect() as con:
            con.execute("""CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                master_hash TEXT NOT NULL,
                salt TEXT NOT NULL
            )""")
            con.execute("""CREATE TABLE IF NOT EXISTS credentials (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                website TEXT NOT NULL,
                username TEXT NOT NULL,
                password TEXT NOT NULL,
                notes TEXT DEFAULT ''
            )""")

    def clear(self):
        for w in self.root.winfo_children():
            w.destroy()

    def show_login(self):
        self.clear()
        frame = ttk.Frame(self.root, padding=40)
        frame.place(relx=.5, rely=.5, anchor="center")

        ttk.Label(frame, text="Password Manager", font=("Arial", 24, "bold")).grid(row=0, column=0, columnspan=2, pady=(0, 8))
        ttk.Label(frame, text="Your credentials are encrypted before storage.").grid(row=1, column=0, columnspan=2, pady=(0, 25))

        with self.connect() as con:
            user = con.execute("SELECT master_hash, salt FROM users WHERE id=1").fetchone()

        if user is None:
            ttk.Label(frame, text="Create a master password", font=("Arial", 13, "bold")).grid(row=2, column=0, columnspan=2, pady=8)
            ttk.Label(frame, text="Master password").grid(row=3, column=0, sticky="e", padx=8, pady=8)
            self.master_entry = ttk.Entry(frame, show="*", width=30)
            self.master_entry.grid(row=3, column=1, pady=8)
            ttk.Label(frame, text="Confirm password").grid(row=4, column=0, sticky="e", padx=8, pady=8)
            self.confirm_entry = ttk.Entry(frame, show="*", width=30)
            self.confirm_entry.grid(row=4, column=1, pady=8)
            ttk.Button(frame, text="Create Vault", command=self.create_master).grid(row=5, column=0, columnspan=2, pady=18)
            self.master_entry.focus()
        else:
            ttk.Label(frame, text="Unlock your vault", font=("Arial", 13, "bold")).grid(row=2, column=0, columnspan=2, pady=8)
            ttk.Label(frame, text="Master password").grid(row=3, column=0, sticky="e", padx=8, pady=8)
            self.master_entry = ttk.Entry(frame, show="*", width=30)
            self.master_entry.grid(row=3, column=1, pady=8)
            ttk.Button(frame, text="Unlock", command=self.login).grid(row=4, column=0, columnspan=2, pady=18)
            self.master_entry.bind("<Return>", lambda e: self.login())
            self.master_entry.focus()

    def create_master(self):
        p = self.master_entry.get()
        c = self.confirm_entry.get()
        if len(p) < 8:
            messagebox.showwarning("Weak password", "Use at least 8 characters.")
            return
        if p != c:
            messagebox.showerror("Error", "Passwords do not match.")
            return
        salt = secrets.token_bytes(16)
        master_hash = hash_master_password(p, salt)
        with self.connect() as con:
            con.execute("INSERT INTO users(id, master_hash, salt) VALUES(1, ?, ?)",
                        (master_hash, salt.hex()))
        self.master_password, self.key = p, derive_key(p, salt)
        self.show_dashboard()

    def login(self):
        p = self.master_entry.get()
        with self.connect() as con:
            user = con.execute("SELECT master_hash, salt FROM users WHERE id=1").fetchone()
        if not user or not verify_master_password(p, bytes.fromhex(user[1]), user[0]):
            messagebox.showerror("Login failed", "Incorrect master password.")
            return
        self.master_password, self.key = p, derive_key(p, bytes.fromhex(user[1]))
        self.show_dashboard()

    def show_dashboard(self):
        self.clear()
        top = ttk.Frame(self.root, padding=12)
        top.pack(fill="x")
        ttk.Label(top, text="Password Vault", font=("Arial", 20, "bold")).pack(side="left")
        ttk.Button(top, text="Generate Password", command=self.generate_password).pack(side="right", padx=5)
        ttk.Button(top, text="Logout", command=self.logout).pack(side="right", padx=5)

        body = ttk.Frame(self.root, padding=12)
        body.pack(fill="both", expand=True)

        self.tree = ttk.Treeview(body, columns=("website", "username"), show="headings")
        self.tree.heading("website", text="Website / Service")
        self.tree.heading("username", text="Username / Email")
        self.tree.column("website", width=350)
        self.tree.column("username", width=350)
        self.tree.pack(fill="both", expand=True)
        self.tree.bind("<Double-1>", lambda e: self.view_credential())

        buttons = ttk.Frame(self.root, padding=12)
        buttons.pack(fill="x")
        ttk.Button(buttons, text="Add", command=self.add_credential).pack(side="left", padx=4)
        ttk.Button(buttons, text="View", command=self.view_credential).pack(side="left", padx=4)
        ttk.Button(buttons, text="Update", command=self.update_credential).pack(side="left", padx=4)
        ttk.Button(buttons, text="Delete", command=self.delete_credential).pack(side="left", padx=4)
        ttk.Button(buttons, text="Refresh", command=self.refresh).pack(side="right", padx=4)
        self.refresh()

    def refresh(self):
        for item in self.tree.get_children():
            self.tree.delete(item)
        with self.connect() as con:
            rows = con.execute("SELECT id, website, username FROM credentials ORDER BY website").fetchall()
        for row in rows:
            self.tree.insert("", "end", iid=str(row[0]), values=(row[1], row[2]))

    def selected_id(self):
        selected = self.tree.selection()
        if not selected:
            messagebox.showinfo("Select", "Please select a credential first.")
            return None
        return int(selected[0])

    def credential_dialog(self, title, data=None):
        win = tk.Toplevel(self.root)
        win.title(title)
        win.geometry("470x360")
        win.transient(self.root)
        win.grab_set()
        frm = ttk.Frame(win, padding=20)
        frm.pack(fill="both", expand=True)

        fields = {}
        for i, (label, show) in enumerate([("Website / Service", None), ("Username / Email", None), ("Password", "*"), ("Notes", None)]):
            ttk.Label(frm, text=label).grid(row=i, column=0, sticky="w", pady=7)
            e = ttk.Entry(frm, width=42, show=show)
            e.grid(row=i, column=1, pady=7)
            fields[label] = e

        if data:
            for label, value in data.items():
                fields[label].insert(0, value)

        result = {}
        def save():
            vals = {k: e.get() for k, e in fields.items()}
            if not vals["Website / Service"] or not vals["Username / Email"] or not vals["Password"]:
                messagebox.showwarning("Missing data", "Website, username and password are required.", parent=win)
                return
            result.update(vals)
            win.destroy()

        ttk.Button(frm, text="Save", command=save).grid(row=5, column=0, columnspan=2, pady=20)
        win.wait_window()
        return result or None

    def add_credential(self):
        data = self.credential_dialog("Add Credential")
        if not data:
            return
        with self.connect() as con:
            con.execute("INSERT INTO credentials(website, username, password, notes) VALUES (?, ?, ?, ?)",
                        (encrypt_text(data["Website / Service"], self.key),
                         encrypt_text(data["Username / Email"], self.key),
                         encrypt_text(data["Password"], self.key),
                         encrypt_text(data["Notes"], self.key)))
        self.refresh()

    def get_credential(self, cid):
        with self.connect() as con:
            row = con.execute("SELECT website, username, password, notes FROM credentials WHERE id=?", (cid,)).fetchone()
        if not row:
            return None
        labels = ["Website / Service", "Username / Email", "Password", "Notes"]
        return dict(zip(labels, [decrypt_text(x, self.key) for x in row]))

    def view_credential(self):
        cid = self.selected_id()
        if cid is None: return
        data = self.get_credential(cid)
        if data:
            self.credential_dialog("View Credential", data)

    def update_credential(self):
        cid = self.selected_id()
        if cid is None: return
        data = self.get_credential(cid)
        new = self.credential_dialog("Update Credential", data)
        if not new: return
        with self.connect() as con:
            con.execute("""UPDATE credentials SET website=?, username=?, password=?, notes=? WHERE id=?""",
                        (encrypt_text(new["Website / Service"], self.key),
                         encrypt_text(new["Username / Email"], self.key),
                         encrypt_text(new["Password"], self.key),
                         encrypt_text(new["Notes"], self.key), cid))
        self.refresh()

    def delete_credential(self):
        cid = self.selected_id()
        if cid is None: return
        if messagebox.askyesno("Confirm", "Delete the selected credential?"):
            with self.connect() as con:
                con.execute("DELETE FROM credentials WHERE id=?", (cid,))
            self.refresh()

    def generate_password(self):
        chars = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
        password = ''.join(secrets.choice(chars) for _ in range(18))
        messagebox.showinfo("Generated Password", password)

    def logout(self):
        self.master_password = None
        self.key = None
        self.show_login()


if __name__ == "__main__":
    root = tk.Tk()
    try:
        root.tk.call("tk", "scaling", 1.1)
    except tk.TclError:
        pass
    PasswordManager(root)
    root.mainloop()
