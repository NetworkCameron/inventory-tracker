import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import db

# Initialize database
db.init_db()

# Add default admin user if it doesn't exist
if not db.user_exists("admin"):
    db.add_user("admin", "admin123", role="admin")  # Default admin credentials

# Global variables
selected_device_id = None
current_username = None
current_role = None

# Root window for login
login_root = tk.Tk()
login_root.title("Login")
login_root.geometry("300x180")
login_root.option_add('*Font', ('Segoe UI', 10))

username_var = tk.StringVar()
password_var = tk.StringVar()

def attempt_login():
    global current_username, current_role
    username = username_var.get()
    password = password_var.get()
    role = db.authenticate_user(username, password)
    if role:
        current_username = username
        current_role = role
        login_root.destroy()
        open_main_window()
    else:
        messagebox.showerror("Login Failed", "Invalid username or password.")

tk.Label(login_root, text="Username:").pack(pady=5)
tk.Entry(login_root, textvariable=username_var).pack(pady=5)
tk.Label(login_root, text="Password:").pack(pady=5)
tk.Entry(login_root, textvariable=password_var, show="*").pack(pady=5)
tk.Button(login_root, text="Login", command=attempt_login).pack(pady=10)

def open_main_window():
    global selected_device_id

    root = tk.Tk()
    root.title("IT Inventory Tracker")
    root.geometry("1000x700")

    # Variables
    search_var = tk.StringVar()
    device_type_filter_var = tk.StringVar()
    device_type_var = tk.StringVar()
    hostname_var = tk.StringVar()
    serial_var = tk.StringVar()
    os_var = tk.StringVar()
    ip_var = tk.StringVar()
    purchase_date_var = tk.StringVar()

    # Search and Filter
    def filter_devices():
        search_text = search_var.get().lower()
        device_type_filter = device_type_filter_var.get()

        for row in tree.get_children():
            tree.delete(row)

        filtered_devices = []
        for row in db.get_all_devices():
            device_id, device_type, hostname, serial, os_, ip, purchase_date = row
            if device_type_filter != "All" and device_type != device_type_filter:
                continue
            if search_text and (search_text not in hostname.lower() and search_text not in serial.lower()):
                continue
            filtered_devices.append((device_id, device_type, hostname, serial, os_, ip, purchase_date))

        for device in filtered_devices:
            tree.insert('', tk.END, iid=device[0], values=device[1:])

        status_label.config(text=f"Devices Displayed: {len(filtered_devices)}")

    def clear_form():
        global selected_device_id
        selected_device_id = None
        device_type_var.set("")
        hostname_var.set("")
        serial_var.set("")
        os_var.set("")
        ip_var.set("")
        purchase_date_var.set("")
        add_update_button.config(text="Add Device")

    def add_device():
        global selected_device_id
        device = {
            'device_type': device_type_var.get(),
            'hostname': hostname_var.get(),
            'serial': serial_var.get(),
            'os': os_var.get(),
            'ip': ip_var.get(),
            'purchase_date': purchase_date_var.get()
        }
        if not device['hostname'] or not device['serial']:
            messagebox.showerror("Error", "Hostname and Serial are required.")
            return

        if selected_device_id is None:
            db.insert_device(device)
            messagebox.showinfo("Success", "Device added.")
        else:
            db.update_device(selected_device_id, device)
            messagebox.showinfo("Success", "Device updated.")
            selected_device_id = None
            add_update_button.config(text="Add Device")

        clear_form()
        filter_devices()

    def load_device_for_edit():
        global selected_device_id
        selected = tree.selection()
        if not selected:
            messagebox.showwarning("Warning", "Select a device to edit.")
            return
        item = tree.item(selected[0])
        selected_device_id = selected[0]

        device_type_var.set(item['values'][0])
        hostname_var.set(item['values'][1])
        serial_var.set(item['values'][2])
        os_var.set(item['values'][3])
        ip_var.set(item['values'][4])
        purchase_date_var.set(item['values'][5])

        add_update_button.config(text="Update Device")

    def delete_selected():
        if current_role != "admin":
            messagebox.showerror("Permission Denied", "Only admins can delete devices.")
            return

        selected = tree.selection()
        if not selected:
            messagebox.showwarning("Warning", "Select a device to delete.")
            return
        confirm = messagebox.askyesno("Confirm", "Are you sure you want to delete this device?")
        if confirm:
            device_id = selected[0]
            db.delete_device(device_id)
            filter_devices()
            clear_form()

    def view_logs():
        selected = tree.selection()
        if not selected:
            messagebox.showwarning("Warning", "Select a device to view logs.")
            return
        device_id = selected[0]

        logs = db.get_update_logs(device_id)

        logs_window = tk.Toplevel(root)
        logs_window.title(f"Update Logs for Device ID {device_id}")
        logs_window.geometry("700x400")

        columns = ("ID", "Update Time", "Changes")
        logs_tree = ttk.Treeview(logs_window, columns=columns, show='headings')
        for col in columns:
            logs_tree.heading(col, text=col)
            logs_tree.column(col, width=200 if col == "Changes" else 100)
        logs_tree.pack(fill="both", expand=True)

        for log in logs:
            logs_tree.insert('', tk.END, values=log)

    def export_logs():
        selected = tree.selection()
        if not selected:
            messagebox.showwarning("Warning", "Select a device to export logs.")
            return
        device_id = selected[0]

        file_path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
            title="Save Update Logs As"
        )
        if not file_path:
            return

        try:
            db.export_logs_to_csv(file_path, device_id)
            messagebox.showinfo("Success", f"Logs exported to {file_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to export logs:\n{e}")

    # User Management GUI (Admins only)
    def open_user_manager():
        if current_role != "admin":
            messagebox.showerror("Permission Denied", "Only admins can manage users.")
            return

        user_win = tk.Toplevel()
        user_win.title("User Manager")
        user_win.geometry("600x400")

        columns = ("Username", "Role", "Created On")
        user_tree = ttk.Treeview(user_win, columns=columns, show="headings")
        for col in columns:
            user_tree.heading(col, text=col)
            user_tree.column(col, width=150 if col != "Created On" else 200)
        user_tree.pack(fill="both", expand=True, padx=10, pady=10)

        def load_users():
            for row in user_tree.get_children():
                user_tree.delete(row)
            users = db.get_all_users()
            for user in users:
                username, role, created_on = user
                user_tree.insert("", tk.END, values=(username, role, created_on))

        # Add new user
        def add_user():
            add_win = tk.Toplevel(user_win)
            add_win.title("Add New User")
            add_win.geometry("300x250")
            add_win.resizable(False, False)

            new_username_var = tk.StringVar()
            new_password_var = tk.StringVar()
            confirm_password_var = tk.StringVar()
            role_var = tk.StringVar(value="user")

            ttk.Label(add_win, text="Username:").pack(pady=5)
            ttk.Entry(add_win, textvariable=new_username_var).pack(pady=5)

            ttk.Label(add_win, text="Password:").pack(pady=5)
            ttk.Entry(add_win, textvariable=new_password_var, show="*").pack(pady=5)

            ttk.Label(add_win, text="Confirm Password:").pack(pady=5)
            ttk.Entry(add_win, textvariable=confirm_password_var, show="*").pack(pady=5)

            ttk.Label(add_win, text="Role:").pack(pady=5)
            ttk.Combobox(add_win, values=["admin", "user"], textvariable=role_var, state="readonly").pack(pady=5)

            def save_new_user():
                username = new_username_var.get().strip()
                password = new_password_var.get()
                confirm_pw = confirm_password_var.get()
                role = role_var.get()

                if not username or not password:
                    messagebox.showerror("Error", "Username and password cannot be empty.")
                    return
                if password != confirm_pw:
                    messagebox.showerror("Error", "Passwords do not match.")
                    return
                if db.user_exists(username):
                    messagebox.showerror("Error", "Username already exists.")
                    return

                db.add_user(username, password, role)
                messagebox.showinfo("Success", f"User '{username}' added.")
                load_users()
                add_win.destroy()

            ttk.Button(add_win, text="Add User", command=save_new_user).pack(pady=10)

        # Edit existing user (username & role)
        def edit_user():
            selected = user_tree.selection()
            if not selected:
                messagebox.showwarning("Warning", "Select a user to edit.")
                return
            user_data = user_tree.item(selected[0])['values']
            old_username = user_data[0]

            edit_win = tk.Toplevel(user_win)
            edit_win.title(f"Edit User: {old_username}")
            edit_win.geometry("300x250")
            edit_win.resizable(False, False)

            new_username_var = tk.StringVar(value=old_username)
            role_var = tk.StringVar(value=user_data[1])

            ttk.Label(edit_win, text="Username:").pack(pady=5)
            ttk.Entry(edit_win, textvariable=new_username_var).pack(pady=5)

            ttk.Label(edit_win, text="Role:").pack(pady=5)
            ttk.Combobox(edit_win, textvariable=role_var, values=["admin", "user"], state="readonly").pack(pady=5)

            def save_changes():
                new_username = new_username_var.get().strip()
                new_role = role_var.get()
                if not new_username:
                    messagebox.showerror("Error", "Username cannot be empty.")
                    return
                if new_username != old_username and db.user_exists(new_username):
                    messagebox.showerror("Error", "Username already exists.")
                    return
                db.update_user(old_username, new_username, new_role)
                messagebox.showinfo("Success", "User updated.")
                load_users()
                edit_win.destroy()

            ttk.Button(edit_win, text="Save", command=save_changes).pack(pady=10)

        # Change user password
        def change_password():
            selected = user_tree.selection()
            if not selected:
                messagebox.showwarning("Warning", "Select a user to change password.")
                return
            user_data = user_tree.item(selected[0])['values']
            username = user_data[0]

            pw_win = tk.Toplevel(user_win)
            pw_win.title(f"Change Password: {username}")
            pw_win.geometry("300x180")
            pw_win.resizable(False, False)

            new_pw_var = tk.StringVar()
            confirm_pw_var = tk.StringVar()

            ttk.Label(pw_win, text="New Password:").pack(pady=5)
            ttk.Entry(pw_win, textvariable=new_pw_var, show="*").pack(pady=5)

            ttk.Label(pw_win, text="Confirm Password:").pack(pady=5)
            ttk.Entry(pw_win, textvariable=confirm_pw_var, show="*").pack(pady=5)

            def save_password():
                new_pw = new_pw_var.get()
                confirm_pw = confirm_pw_var.get()
                if not new_pw:
                    messagebox.showerror("Error", "Password cannot be empty.")
                    return
                if new_pw != confirm_pw:
                    messagebox.showerror("Error", "Passwords do not match.")
                    return
                db.update_password(username, new_pw)
                messagebox.showinfo("Success", f"Password for '{username}' updated.")
                pw_win.destroy()

            ttk.Button(pw_win, text="Change Password", command=save_password).pack(pady=10)

        # Buttons frame
        btn_frame = ttk.Frame(user_win)
        btn_frame.pack(pady=5)

        ttk.Button(btn_frame, text="Add User", command=add_user).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Edit User", command=edit_user).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Change Password", command=change_password).pack(side=tk.LEFT, padx=5)

        load_users()

    # Layout
    filter_frame = ttk.LabelFrame(root, text="Search & Filter")
    filter_frame.pack(fill="x", padx=10, pady=5)

    ttk.Label(filter_frame, text="Search:").pack(side=tk.LEFT, padx=5)
    ttk.Entry(filter_frame, textvariable=search_var, width=30).pack(side=tk.LEFT, padx=5)
    search_var.trace_add('write', lambda *args: filter_devices())

    ttk.Label(filter_frame, text="Device Type:").pack(side=tk.LEFT, padx=5)
    device_type_filter_var.set("All")
    device_types = ["All", "Computer", "Router", "Switch", "Printer", "Other"]
    ttk.Combobox(filter_frame, values=device_types, textvariable=device_type_filter_var, state="readonly", width=15).pack(side=tk.LEFT, padx=5)
    device_type_filter_var.trace_add('write', lambda *args: filter_devices())

    # Device list
    columns = ("Device Type", "Hostname", "Serial", "OS", "IP", "Purchase Date")
    tree = ttk.Treeview(root, columns=columns, show="headings", selectmode="browse")
    for col in columns:
        tree.heading(col, text=col)
        tree.column(col, width=150)
    tree.pack(fill="both", expand=True, padx=10, pady=5)

    # Form frame
    form_frame = ttk.LabelFrame(root, text="Add / Update Device")
    form_frame.pack(fill="x", padx=10, pady=5)

    # Form widgets
    labels = ["Device Type:", "Hostname:", "Serial:", "OS:", "IP:", "Purchase Date:"]
    vars_ = [device_type_var, hostname_var, serial_var, os_var, ip_var, purchase_date_var]
    device_type_var.set(device_types[1])  # Default device type for form

    for i, (label_text, var) in enumerate(zip(labels, vars_)):
        ttk.Label(form_frame, text=label_text).grid(row=i, column=0, sticky=tk.W, padx=5, pady=2)
        if label_text == "Device Type:":
            ttk.Combobox(form_frame, values=device_types[1:], textvariable=var, state="readonly").grid(row=i, column=1, sticky=tk.W, padx=5, pady=2)
        else:
            ttk.Entry(form_frame, textvariable=var).grid(row=i, column=1, sticky=tk.W, padx=5, pady=2)

    add_update_button = ttk.Button(form_frame, text="Add Device", command=add_device)
    add_update_button.grid(row=len(labels), column=1, sticky=tk.W, padx=5, pady=5)

    ttk.Button(form_frame, text="Clear Form", command=clear_form).grid(row=len(labels), column=0, sticky=tk.W, padx=5, pady=5)

    # Action buttons
    action_frame = ttk.Frame(root)
    action_frame.pack(pady=5)

    ttk.Button(action_frame, text="Edit Selected", command=load_device_for_edit).pack(side=tk.LEFT, padx=5)
    ttk.Button(action_frame, text="Delete Selected", command=delete_selected).pack(side=tk.LEFT, padx=5)
    ttk.Button(action_frame, text="View Logs", command=view_logs).pack(side=tk.LEFT, padx=5)
    ttk.Button(action_frame, text="Export Logs", command=export_logs).pack(side=tk.LEFT, padx=5)
    ttk.Button(action_frame, text="Manage Users", command=open_user_manager).pack(side=tk.LEFT, padx=5)

    # Status bar
    status_label = ttk.Label(root, text="Devices Displayed: 0", anchor="w")
    status_label.pack(fill="x", padx=10, pady=5)

    filter_devices()  # Initial population of the treeview


    root.mainloop()

login_root.mainloop()
