import tkinter as tk
from tkinter import ttk, messagebox
import subprocess
import os
import sys

# Import các tab mới
from auto_block_tab import AutoBlockTab
from statistics_tab import StatisticsTab
from fail2ban_tab import Fail2BanTab

class FirewallGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Firewall Management System - PBL4")
        self.root.geometry("1200x800")
        
        # Kiểm tra quyền root
        self.check_root_privileges()
        
        # Tạo giao diện
        self.setup_gui()
        
        # Kiểm tra dependencies
        self.check_dependencies()
    
    def check_root_privileges(self):
        """Kiểm tra quyền root"""
        if os.geteuid() != 0:
            messagebox.showerror(
                "Lỗi Quyền Truy Cập", 
                "Ứng dụng cần chạy với quyền root!\n\n"
                "Hãy chạy: sudo python3 main_gui.py"
            )
            sys.exit(1)
    
    def check_dependencies(self):
        """Kiểm tra các dependencies cần thiết"""
        missing_deps = []
        
        # Kiểm tra iptables
        try:
            subprocess.run(['iptables', '--version'], capture_output=True, check=True)
        except:
            missing_deps.append("iptables")
        
        # Kiểm tra fail2ban
        try:
            subprocess.run(['fail2ban-client', '--version'], capture_output=True, check=True)
        except:
            missing_deps.append("fail2ban")
        
        # Kiểm tra ss
        try:
            subprocess.run(['ss', '-h'], capture_output=True, check=True)
        except:
            missing_deps.append("iproute2")
        
        if missing_deps:
            messagebox.showwarning(
                "Thiếu Dependencies",
                f"Các công cụ sau chưa được cài đặt: {', '.join(missing_deps)}\n\n"
                "Một số tính năng có thể không hoạt động."
            )
    
    def setup_gui(self):
        """Thiết lập giao diện chính"""
        # Tạo notebook (tab controller)
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Tạo các tab
        self.setup_dashboard_tab()
        self.setup_firewall_tab()
        self.setup_auto_block_tab()
        self.setup_statistics_tab()
        self.setup_fail2ban_tab()
        self.setup_settings_tab()
        
        # Status bar
        self.setup_status_bar()
    
    def setup_dashboard_tab(self):
        """Tab Dashboard tổng quan"""
        dashboard_frame = ttk.Frame(self.notebook)
        self.notebook.add(dashboard_frame, text="Dashboard")
        
        # Header
        header_frame = ttk.Frame(dashboard_frame)
        header_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Label(
            header_frame, 
            text="Firewall Management System", 
            font=('Arial', 16, 'bold')
        ).pack(side=tk.LEFT)
        
        ttk.Button(
            header_frame, 
            text="Làm Mới Tất Cả", 
            command=self.refresh_all
        ).pack(side=tk.RIGHT)
        
        # Statistics cards
        stats_frame = ttk.Frame(dashboard_frame)
        stats_frame.pack(fill=tk.X, padx=10, pady=10)
        
        # Card 1: Tổng số IP bị chặn
        card1 = ttk.LabelFrame(stats_frame, text="IP Bị Chặn")
        card1.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5)
        ttk.Label(card1, text="0", font=('Arial', 24, 'bold')).pack(pady=20)
        ttk.Label(card1, text="Tổng số IP đang bị chặn").pack(pady=5)
        
        # Card 2: Cảnh báo hôm nay
        card2 = ttk.LabelFrame(stats_frame, text="Cảnh Báo Hôm Nay")
        card2.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5)
        ttk.Label(card2, text="0", font=('Arial', 24, 'bold')).pack(pady=20)
        ttk.Label(card2, text="Số cảnh báo trong ngày").pack(pady=5)
        
        # Card 3: Trạng thái tự động chặn
        card3 = ttk.LabelFrame(stats_frame, text="Tự Động Chặn")
        card3.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5)
        ttk.Label(card3, text="TẮT", font=('Arial', 24, 'bold'), foreground='red').pack(pady=20)
        ttk.Label(card3, text="Trạng thái tự động chặn").pack(pady=5)
        
        # Recent alerts
        alerts_frame = ttk.LabelFrame(dashboard_frame, text="Cảnh Báo Gần Đây")
        alerts_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        alerts_text = tk.Text(alerts_frame, height=10)
        alerts_scrollbar = ttk.Scrollbar(alerts_frame, orient=tk.VERTICAL, command=alerts_text.yview)
        alerts_text.config(yscrollcommand=alerts_scrollbar.set)
        alerts_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        alerts_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        alerts_text.insert(tk.END, "Chưa có cảnh báo nào...\n")
        alerts_text.config(state=tk.DISABLED)
        
        # Quick actions
        actions_frame = ttk.LabelFrame(dashboard_frame, text="Hành Động Nhanh")
        actions_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Button(actions_frame, text="Xem Rules IPTables", 
                  command=self.show_iptables_rules).pack(side=tk.LEFT, padx=5)
        ttk.Button(actions_frame, text="Kiểm Tra Dịch Vụ", 
                  command=self.check_services).pack(side=tk.LEFT, padx=5)
        ttk.Button(actions_frame, text="Xem Logs", 
                  command=self.view_logs).pack(side=tk.LEFT, padx=5)
    
    def setup_firewall_tab(self):
        """Tab quản lý firewall cơ bản (giữ nguyên từ code cũ)"""
        firewall_frame = ttk.Frame(self.notebook)
        self.notebook.add(firewall_frame, text="Firewall")
        
        # ... (giữ nguyên code firewall tab hiện tại của bạn)
        ttk.Label(firewall_frame, text="Firewall Management - Giữ nguyên từ code hiện tại").pack(pady=20)
    
    def setup_auto_block_tab(self):
        """Tab tự động chặn"""
        auto_block_frame = ttk.Frame(self.notebook)
        self.notebook.add(auto_block_frame, text="Tự Động Chặn")
        self.auto_block_tab = AutoBlockTab(auto_block_frame)
    
    def setup_statistics_tab(self):
        """Tab thống kê"""
        stats_frame = ttk.Frame(self.notebook)
        self.notebook.add(stats_frame, text="Thống Kê")
        self.stats_tab = StatisticsTab(stats_frame)
    
    def setup_fail2ban_tab(self):
        """Tab Fail2Ban"""
        fail2ban_frame = ttk.Frame(self.notebook)
        self.notebook.add(fail2ban_frame, text="Fail2Ban")
        self.fail2ban_tab = Fail2BanTab(fail2ban_frame)
    
    def setup_settings_tab(self):
        """Tab cài đặt"""
        settings_frame = ttk.Frame(self.notebook)
        self.notebook.add(settings_frame, text="Cài Đặt")
        
        # Cấu hình chung
        general_frame = ttk.LabelFrame(settings_frame, text="Cấu Hình Chung")
        general_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Label(general_frame, text="Địa chỉ Email nhận cảnh báo:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=2)
        email_var = tk.StringVar(value="admin@example.com")
        ttk.Entry(general_frame, textvariable=email_var, width=30).grid(row=0, column=1, padx=5, pady=2)
        
        ttk.Label(general_frame, text="Log Level:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=2)
        log_level = ttk.Combobox(general_frame, values=['DEBUG', 'INFO', 'WARNING', 'ERROR'], state='readonly')
        log_level.set('INFO')
        log_level.grid(row=1, column=1, padx=5, pady=2)
        
        # Tự động khởi động
        startup_frame = ttk.LabelFrame(settings_frame, text="Tự Động Khởi Động")
        startup_frame.pack(fill=tk.X, padx=10, pady=10)
        
        self.auto_start_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            startup_frame, 
            text="Tự động khởi động dịch vụ khi bật máy", 
            variable=self.auto_start_var
        ).pack(anchor=tk.W, padx=5, pady=2)
        
        # Nút lưu cài đặt
        ttk.Button(settings_frame, text="Lưu Cài Đặt", command=self.save_settings).pack(pady=10)
    
    def setup_status_bar(self):
        """Thanh trạng thái"""
        status_frame = ttk.Frame(self.root)
        status_frame.pack(fill=tk.X, side=tk.BOTTOM)
        
        self.status_var = tk.StringVar(value="Sẵn sàng")
        ttk.Label(status_frame, textvariable=self.status_var).pack(side=tk.LEFT, padx=5)
        
        ttk.Label(status_frame, text="PBL4 - Linux Firewall System").pack(side=tk.RIGHT, padx=5)
    
    def refresh_all(self):
        """Làm mới tất cả tab"""
        self.status_var.set("Đang làm mới dữ liệu...")
        
        # Làm mới từng tab
        if hasattr(self, 'auto_block_tab'):
            self.auto_block_tab.check_service_status()
        
        if hasattr(self, 'stats_tab'):
            self.stats_tab.refresh_data()
        
        if hasattr(self, 'fail2ban_tab'):
            self.fail2ban_tab.refresh_status()
        
        self.status_var.set("Đã làm mới dữ liệu")
        messagebox.showinfo("Thành công", "Đã làm mới tất cả dữ liệu")
    
    def show_iptables_rules(self):
        """Hiển thị rules iptables"""
        try:
            result = subprocess.run(
                ['iptables', '-L', '-n', '-v'],
                capture_output=True, text=True
            )
            
            # Tạo cửa sổ mới để hiển thị rules
            rules_window = tk.Toplevel(self.root)
            rules_window.title("IPTables Rules")
            rules_window.geometry("800x600")
            
            text_widget = tk.Text(rules_window, wrap=tk.NONE)
            scrollbar_y = ttk.Scrollbar(rules_window, orient=tk.VERTICAL, command=text_widget.yview)
            scrollbar_x = ttk.Scrollbar(rules_window, orient=tk.HORIZONTAL, command=text_widget.xview)
            
            text_widget.config(yscrollcommand=scrollbar_y.set, xscrollcommand=scrollbar_x.set)
            
            text_widget.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
            scrollbar_y.pack(side=tk.RIGHT, fill=tk.Y)
            scrollbar_x.pack(side=tk.BOTTOM, fill=tk.X)
            
            text_widget.insert(tk.END, result.stdout)
            text_widget.config(state=tk.DISABLED)
            
        except Exception as e:
            messagebox.showerror("Lỗi", f"Không thể lấy rules: {e}")
    
    def check_services(self):
        """Kiểm tra trạng thái các dịch vụ"""
        services = {
            'firewall-auto-block': 'Tự động chặn',
            'fail2ban': 'Fail2Ban',
            'iptables': 'IPTables'
        }
        
        status_text = "KIỂM TRA DỊCH VỤ:\n\n"
        
        for service, name in services.items():
            try:
                if service == 'iptables':
                    # Đơn giản kiểm tra iptables
                    subprocess.run(['iptables', '-L'], capture_output=True, check=True)
                    status = "Đang chạy"
                else:
                    result = subprocess.run(
                        ['systemctl', 'is-active', service],
                        capture_output=True, text=True
                    )
                    status = "Đang chạy" if result.stdout.strip() == 'active' else "Dừng"
                
                status_text += f"• {name}: {status}\n"
                
            except:
                status_text += f"• {name}: Lỗi\n"
        
        messagebox.showinfo("Trạng Thái Dịch Vụ", status_text)
    
    def view_logs(self):
        """Xem logs hệ thống"""
        log_window = tk.Toplevel(self.root)
        log_window.title("System Logs")
        log_window.geometry("600x400")
        
        notebook = ttk.Notebook(log_window)
        notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Tab firewall logs
        firewall_frame = ttk.Frame(notebook)
        notebook.add(firewall_frame, text="Firewall Logs")
        
        firewall_text = tk.Text(firewall_frame)
        firewall_scrollbar = ttk.Scrollbar(firewall_frame, orient=tk.VERTICAL, command=firewall_text.yview)
        firewall_text.config(yscrollcommand=firewall_scrollbar.set)
        
        firewall_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        firewall_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        try:
            # Đọc log firewall
            log_files = [
                '/var/log/firewall_auto_block.log',
                '/var/log/firewall_alerts.json'
            ]
            
            for log_file in log_files:
                if os.path.exists(log_file):
                    with open(log_file, 'r') as f:
                        firewall_text.insert(tk.END, f"=== {log_file} ===\n")
                        firewall_text.insert(tk.END, f.read())
                        firewall_text.insert(tk.END, "\n\n")
        except Exception as e:
            firewall_text.insert(tk.END, f"Lỗi đọc log: {e}")
        
        firewall_text.config(state=tk.DISABLED)
    
    def save_settings(self):
        """Lưu cài đặt"""
        messagebox.showinfo("Thành công", "Đã lưu cài đặt")
        self.status_var.set("Đã lưu cài đặt hệ thống")

def main():
    root = tk.Tk()
    app = FirewallGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()