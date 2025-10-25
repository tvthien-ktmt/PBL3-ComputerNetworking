import tkinter as tk
from tkinter import ttk, messagebox
import subprocess
import json

class Fail2BanTab:
    def __init__(self, parent):
        self.parent = parent
        self.create_widgets()
        self.refresh_status()
    
    def create_widgets(self):
        # Main frame
        main_frame = ttk.Frame(self.parent)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Status frame
        status_frame = ttk.LabelFrame(main_frame, text="Trạng Thái Fail2Ban")
        status_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.status_var = tk.StringVar(value="Đang kiểm tra...")
        ttk.Label(status_frame, textvariable=self.status_var).pack(side=tk.LEFT, padx=5)
        
        btn_frame = ttk.Frame(status_frame)
        btn_frame.pack(side=tk.RIGHT)
        
        ttk.Button(btn_frame, text="Khởi Động", command=lambda: self.control_service('start')).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_frame, text="Dừng", command=lambda: self.control_service('stop')).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_frame, text="Khởi Động Lại", command=lambda: self.control_service('restart')).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_frame, text="Làm Mới", command=self.refresh_status).pack(side=tk.LEFT, padx=2)
        
        # Jails status
        jails_frame = ttk.LabelFrame(main_frame, text="Trạng Thái Jails")
        jails_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        # Treeview for jails
        columns = ('jail', 'status', 'filter', 'banned')
        self.jails_tree = ttk.Treeview(jails_frame, columns=columns, show='headings')
        
        self.jails_tree.heading('jail', text='Jail')
        self.jails_tree.heading('status', text='Trạng Thái')
        self.jails_tree.heading('filter', text='Filter')
        self.jails_tree.heading('banned', text='Số IP Bị Ban')
        
        self.jails_tree.column('jail', width=150)
        self.jails_tree.column('status', width=100)
        self.jails_tree.column('filter', width=150)
        self.jails_tree.column('banned', width=100)
        
        self.jails_tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Banned IPs frame
        banned_frame = ttk.LabelFrame(main_frame, text="IP Đang Bị Ban")
        banned_frame.pack(fill=tk.BOTH, expand=True)
        
        # Treeview for banned IPs
        banned_columns = ('jail', 'ip', 'time', 'matches')
        self.banned_tree = ttk.Treeview(banned_frame, columns=banned_columns, show='headings')
        
        self.banned_tree.heading('jail', text='Jail')
        self.banned_tree.heading('ip', text='IP')
        self.banned_tree.heading('time', text='Thời Gian')
        self.banned_tree.heading('matches', text='Số Lần Vi Phạm')
        
        self.banned_tree.column('jail', width=100)
        self.banned_tree.column('ip', width=120)
        self.banned_tree.column('time', width=150)
        self.banned_tree.column('matches', width=100)
        
        self.banned_tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Control buttons for banned IPs
        banned_btn_frame = ttk.Frame(banned_frame)
        banned_btn_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Button(banned_btn_frame, text="Làm Mới", command=self.refresh_banned).pack(side=tk.LEFT, padx=2)
        ttk.Button(banned_btn_frame, text="Gỡ Ban IP", command=self.unban_ip).pack(side=tk.LEFT, padx=2)
        ttk.Button(banned_btn_frame, text="Gỡ Ban Tất Cả", command=self.unban_all).pack(side=tk.LEFT, padx=2)
    
    def refresh_status(self):
        """Làm mới trạng thái Fail2ban"""
        try:
            # Kiểm tra trạng thái service
            result = subprocess.run(
                ['systemctl', 'is-active', 'fail2ban'],
                capture_output=True, text=True
            )
            
            if result.stdout.strip() == 'active':
                self.status_var.set("ĐANG CHẠY - Fail2ban hoạt động bình thường")
            else:
                self.status_var.set("DỪNG - Fail2ban không chạy")
            
            # Làm mới danh sách jails
            self.refresh_jails()
            
            # Làm mới danh sách IP bị ban
            self.refresh_banned()
            
        except Exception as e:
            self.status_var.set(f"Lỗi: {str(e)}")
    
    def refresh_jails(self):
        """Làm mới danh sách jails"""
        try:
            # Clear existing data
            for item in self.jails_tree.get_children():
                self.jails_tree.delete(item)
            
            # Lấy thông tin jails
            result = subprocess.run(
                ['fail2ban-client', 'status'],
                capture_output=True, text=True
            )
            
            jails = []
            current_section = None
            
            for line in result.stdout.split('\n'):
                line = line.strip()
                if line.startswith('Jail list:'):
                    current_section = 'jail_list'
                elif line.startswith('|-') and current_section == 'jail_list':
                    jail_name = line.split('|')[-1].strip().strip(',')
                    if jail_name:
                        jails.append(jail_name)
            
            # Lấy chi tiết từng jail
            for jail in jails:
                jail_result = subprocess.run(
                    ['fail2ban-client', 'status', jail],
                    capture_output=True, text=True
                )
                
                status = "Đang chạy"
                filter_name = "N/A"
                banned_count = "0"
                
                for line in jail_result.stdout.split('\n'):
                    if 'Filter' in line:
                        filter_name = line.split(':')[-1].strip()
                    elif 'Currently banned' in line:
                        banned_count = line.split(':')[-1].strip()
                
                self.jails_tree.insert('', tk.END, values=(
                    jail, status, filter_name, banned_count
                ))
                
        except Exception as e:
            print(f"Lỗi làm mới jails: {e}")
    
    def refresh_banned(self):
        """Làm mới danh sách IP bị ban"""
        try:
            # Clear existing data
            for item in self.banned_tree.get_children():
                self.banned_tree.delete(item)
            
            # Lấy danh sách IP bị ban từ tất cả jails
            result = subprocess.run(
                ['fail2ban-client', 'status'],
                capture_output=True, text=True
            )
            
            jails = []
            current_section = None
            
            for line in result.stdout.split('\n'):
                line = line.strip()
                if line.startswith('Jail list:'):
                    current_section = 'jail_list'
                elif line.startswith('|-') and current_section == 'jail_list':
                    jail_name = line.split('|')[-1].strip().strip(',')
                    if jail_name:
                        jails.append(jail_name)
            
            # Lấy IP bị ban từ từng jail
            for jail in jails:
                banned_result = subprocess.run(
                    ['fail2ban-client', 'status', jail],
                    capture_output=True, text=True
                )
                
                for line in banned_result.stdout.split('\n'):
                    if 'IP list:' in line:
                        ips = line.split(':')[-1].strip().split(',')
                        for ip in ips:
                            ip = ip.strip()
                            if ip and ip != '    ':
                            # Thêm vào treeview
                                  self.banned_tree.insert('', tk.END, values=(
                                jail, ip, 'Đang bị ban', 'N/A'
                            ))
                            
        except Exception as e:
            print(f"Lỗi làm mới banned IPs: {e}")
    
    def control_service(self, action):
        """Điều khiển service Fail2ban"""
        try:
            if action == 'start':
                subprocess.run(['sudo', 'systemctl', 'start', 'fail2ban'], check=True)
                messagebox.showinfo("Thành công", "Đã khởi động Fail2ban")
            elif action == 'stop':
                subprocess.run(['sudo', 'systemctl', 'stop', 'fail2ban'], check=True)
                messagebox.showinfo("Thành công", "Đã dừng Fail2ban")
            elif action == 'restart':
                subprocess.run(['sudo', 'systemctl', 'restart', 'fail2ban'], check=True)
                messagebox.showinfo("Thành công", "Đã khởi động lại Fail2ban")
            
            self.refresh_status()
            
        except subprocess.CalledProcessError as e:
            messagebox.showerror("Lỗi", f"Không thể {action} Fail2ban: {e}")
    
    def unban_ip(self):
        """Gỡ ban IP đã chọn"""
        selection = self.banned_tree.selection()
        if not selection:
            messagebox.showwarning("Cảnh báo", "Vui lòng chọn IP để gỡ ban")
            return
        
        for item in selection:
            values = self.banned_tree.item(item)['values']
            jail = values[0]
            ip = values[1]
            
            try:
                subprocess.run(
                    ['sudo', 'fail2ban-client', 'set', jail, 'unbanip', ip],
                    check=True
                )
                messagebox.showinfo("Thành công", f"Đã gỡ ban IP {ip} từ jail {jail}")
            except subprocess.CalledProcessError as e:
                messagebox.showerror("Lỗi", f"Không thể gỡ ban IP {ip}: {e}")
        
        self.refresh_banned()
    
    def unban_all(self):
        """Gỡ ban tất cả IP"""
        if not messagebox.askyesno("Xác nhận", "Bạn có chắc muốn gỡ ban tất cả IP?"):
            return
        
        try:
            # Lấy danh sách tất cả jails
            result = subprocess.run(
                ['fail2ban-client', 'status'],
                capture_output=True, text=True
            )
            
            jails = []
            current_section = None
            
            for line in result.stdout.split('\n'):
                line = line.strip()
                if line.startswith('Jail list:'):
                    current_section = 'jail_list'
                elif line.startswith('|-') and current_section == 'jail_list':
                    jail_name = line.split('|')[-1].strip().strip(',')
                    if jail_name:
                        jails.append(jail_name)
            
            # Gỡ ban tất cả IP từ mỗi jail
            for jail in jails:
                subprocess.run(
                    ['sudo', 'fail2ban-client', 'set', jail, 'unban', '--all'],
                    check=True
                )
            
            messagebox.showinfo("Thành công", "Đã gỡ ban tất cả IP")
            self.refresh_banned()
            
        except subprocess.CalledProcessError as e:
            messagebox.showerror("Lỗi", f"Không thể gỡ ban tất cả IP: {e}")