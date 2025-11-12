#!/usr/bin/env python3
"""
Laravel Dependency & CVE Scanner
Supports: Composer Audit, Snyk, Online/Offline, HTML Reports
"""

import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk
import subprocess
import os
import json
import re
import webbrowser
from datetime import datetime
import threading
import sys

class LaravelVulnScanner:
    def __init__(self, root):
        self.root = root
        self.root.title("Laravel Dependency & CVE Scanner")
        self.root.geometry("1100x750")
        self.root.minsize(900, 600)
        self.root.configure(bg="#f4f6f9")

        self.vulnerabilities = []
        self.project_dir = ""

        self.setup_styles()
        self.setup_ui()
        self.setup_instructions()

    def setup_styles(self):
        style = ttk.Style()
        style.theme_use('clam')
        style.configure("Treeview", background="white", fieldbackground="white", font=("Consolas", 9))
        style.configure("Treeview.Heading", background="#3498db", foreground="white", font=("Helvetica", 10, "bold"))

    def setup_ui(self):
        # Header
        header = tk.Frame(self.root, bg="#2c3e50", height=60)
        header.pack(fill=tk.X)
        header.pack_propagate(False)
        tk.Label(header, text="Laravel Security Scanner", font=("Helvetica", 18, "bold"), fg="white", bg="#2c3e50").pack(pady=12)

        # Main container
        main = tk.PanedWindow(self.root, orient=tk.VERTICAL, sashrelief=tk.RAISED, sashwidth=6)
        main.pack(fill=tk.BOTH, expand=True, padx=15, pady=15)

        # === Top Panel: Controls ===
        top_panel = tk.Frame(main, bg="#f4f6f9")
        main.add(top_panel, height=220)

        # Project Selection
        proj_frame = tk.LabelFrame(top_panel, text="Project Directory", font=("Helvetica", 11, "bold"), bg="#f4f6f9", padx=10, pady=8)
        proj_frame.pack(fill=tk.X, pady=5)
        dir_inner = tk.Frame(proj_frame, bg="#f4f6f9")
        dir_inner.pack(fill=tk.X)
        self.project_dir_var = tk.StringVar()
        tk.Entry(dir_inner, textvariable=self.project_dir_var, font=("Arial", 10), width=70).pack(side=tk.LEFT, padx=(0,5), expand=True, fill=tk.X)
        tk.Button(dir_inner, text="Browse", command=self.browse_directory, bg="#3498db", fg="white", font=("Arial", 10)).pack(side=tk.RIGHT)

        # Options
        opt_frame = tk.LabelFrame(top_panel, text="Scan Options", font=("Helvetica", 11, "bold"), bg="#f4f6f9", padx=10, pady=8)
        opt_frame.pack(fill=tk.X, pady=5)
        self.composer_var = tk.BooleanVar(value=True)
        self.snyk_var = tk.BooleanVar(value=True)
        tk.Checkbutton(opt_frame, text="Composer Audit (composer.lock)", variable=self.composer_var, bg="#f4f6f9").pack(anchor=tk.W)
        tk.Checkbutton(opt_frame, text="Snyk Scan (requires internet)", variable=self.snyk_var, bg="#f4f6f9").pack(anchor=tk.W)

        # Mode
        mode_frame = tk.LabelFrame(top_panel, text="Scan Mode", font=("Helvetica", 11, "bold"), bg="#f4f6f9", padx=10, pady=8)
        mode_frame.pack(fill=tk.X, pady=5)
        self.online_var = tk.BooleanVar(value=True)
        tk.Radiobutton(mode_frame, text="Online (full CVE database)", variable=self.online_var, value=True, bg="#f4f6f9").pack(anchor=tk.W)
        tk.Radiobutton(mode_frame, text="Offline (local DB only)", variable=self.online_var, value=False, bg="#f4f6f9").pack(anchor=tk.W)

        # Buttons
        btn_frame = tk.Frame(top_panel, bg="#f4f6f9")
        btn_frame.pack(pady=12)
        tk.Button(btn_frame, text="Run Scan", command=self.start_scan_thread, bg="#27ae60", fg="white", font=("Helvetica", 12, "bold"), width=15).pack(side=tk.LEFT, padx=8)
        tk.Button(btn_frame, text="Export HTML Report", command=self.export_html, bg="#e67e22", fg="white", font=("Helvetica", 10), width=20).pack(side=tk.LEFT, padx=8)
        tk.Button(btn_frame, text="Clear", command=self.clear_results, bg="#95a5a6", fg="white", font=("Helvetica", 10), width=10 Sentences).pack(side=tk.LEFT, padx=8)

        # === Bottom Panel: Results ===
        bottom_panel = tk.Frame(main)
        main.add(bottom_panel, stretch="always")

        # Treeview
        tree_frame = tk.LabelFrame(bottom_panel, text="Vulnerabilities", font=("Helvetica", 11, "bold"))
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        columns = ("Package", "CVE", "Severity", "Description", "Suggestion", "Source")
        self.tree = ttk.Treeview(tree_frame, columns=columns, show="headings", selectmode="browse")
        vsb = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview)
        hsb = ttk.Scrollbar(tree_frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        # Column config
        widths = [180, 100, 90, 320, 250, 80]
        for i, (col, w) in enumerate(zip(columns, widths)):
            self.tree.heading(col, text=col)
            self.tree.column(col, width=w, anchor=tk.W if col != "Severity" else "center")

        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        hsb.pack(side=tk.BOTTOM, fill=tk.X)

        # Tags for severity colors
        self.tree.tag_configure("critical", background="#e74c3c", foreground="white")
        self.tree.tag_configure("high", background="#e67e22", foreground="white")
        self.tree.tag_configure("medium", background="#f1c40f", foreground="black")
        self.tree.tag_configure("low", background="#95a5a6", foreground="white")

        # Double-click to open link
        self.tree.bind("<Double-1>", self.open_link)

    def setup_instructions(self):
        inst = tk.LabelFrame(self.root, text="Prerequisites & Setup", font=("Helvetica", 10, "bold"), padx=10, pady=8)
        inst.pack(fill=tk.X, padx=15, pady=(0, 10))
        text = """
• Laravel project with composer.lock
• Composer installed globally
• For offline: Run:
    composer global require enlightn/security-checker
    git clone https://github.com/FriendsOfPHP/security-advisories ~/.composer/security-advisories
• For Snyk: npm install -g snyk && snyk auth
• HTML report auto-opens in browser
        """
        tk.Label(inst, text=text.strip(), justify=tk.LEFT, font=("Courier", 9), bg="white", anchor="w", padx=10, pady=5).pack(fill=tk.X)

    def browse_directory(self):
        dir_path = filedialog.askdirectory(title="Select Laravel Project")
        if dir_path:
            lock_path = os.path.join(dir_path, "composer.lock")
            if os.path.exists(lock_path):
                self.project_dir_var.set(dir_path)
                self.project_dir = dir_path
                messagebox.showinfo("Ready", f"composer.lock found!\n{dir_path}")
            else:
                self.project_dir_var.set(dir_path)
                self.project_dir = dir_path
                messagebox.showwarning("No composer.lock", "Run 'composer install' first.")

    def start_scan_thread(self):
        if not self.project_dir or not os.path.exists(os.path.join(self.project_dir, "composer.lock")):
            messagebox.showerror("Error", "Select a valid Laravel project with composer.lock")
            return
        self.vulnerabilities = []
        self.clear_results()
        threading.Thread(target=self.run_scan, daemon=True).start()

    def run_scan(self):
        self.update_status("Scanning started...")
        os.chdir(self.project_dir)

        if self.composer_var.get():
            if self.online_var.get():
                self.scan_composer_online()
            else:
                self.scan_composer_offline()

        if self.snyk_var.get() and self.online_var.get():
            self.scan_snyk()

        self.update_status(f"Scan complete. {len(self.vulnerabilities)} vulnerabilities found.")
        if self.vulnerabilities:
            self.root.bell()

    def scan_composer_online(self):
        self.update_status("Running: composer audit")
        result = self.run_command("composer audit --format=json")
        if result and result.stdout.strip():
            try:
                data = json.loads(result.stdout)
                for pkg, advisories in data.get("advisories", {}).items():
                    for adv in advisories:
                        self.parse_composer_advisory(adv, pkg)
            except json.JSONDecodeError as e:
                self.update_status(f"JSON parse error: {e}")

    def scan_composer_offline(self):
        self.update_status("Running: security-checker (offline)")
        result = self.run_command("security-checker security:check composer.lock --format=json")
        if result and result.stdout.strip():
            try:
                data = json.loads(result.stdout)
                for pkg, vulns in data.items():
                    for v in vulns:
                        v["package"] = pkg
                        self.parse_composer_advisory(v, pkg)
            except Exception as e:
                self.update_status(f"Offline scan parse error: {e}")
        else:
            self.update_status("No vulnerabilities (offline)")

    def scan_snyk(self):
        self.update_status("Running: snyk test")
        result = self.run_command("snyk test --json")
        if result and result.stdout.strip():
            try:
                data = json.loads(result.stdout)
                vulns = data.get("vulnerabilities") if isinstance(data, dict) else data
                for v in vulns:
                    self.parse_snyk_vuln(v)
            except Exception as e:
                self.update_status(f"Snyk parse error: {e}")

    def parse_composer_advisory(self, adv, pkg_name):
        cve = adv.get("cve") or "N/A"
        title = adv.get("title", "No title")
        severity = self.map_severity(adv.get("severity", "unknown"))
        version = adv.get("affectedVersions", "unknown")
        link = adv.get("link", "")

        suggestion = self.get_suggestion_composer(adv, pkg_name)

        vuln = {
            "package": f"{pkg_name} ({version})",
            "cve": cve,
            "severity": severity,
            "description": title[:150] + "..." if len(title) > 150 else title,
            "full_desc": title,
            "suggestion": suggestion,
            "link": link,
            "source": "Composer"
        }
        self.vulnerabilities.append(vuln)
        self.update_tree(vuln)

    def parse_snyk_vuln(self, vuln):
        cve = vuln.get("id", "N/A")
        title = vuln.get("title", "")
        severity = self.map_severity(vuln.get("severity", "low"))
        package = vuln.get("moduleName", "unknown")
        version = vuln.get("version", "unknown")
        link = next((r["url"] for r in vuln.get("references", []) if r.get("url")), "")

        upgrade = vuln.get("upgradePath", [])
        suggestion = f"Upgrade to {upgrade[1]}" if len(upgrade) > 1 else "Manual review required"

        vuln_data = {
            "package": f"{package} ({version})",
            "cve": cve,
            "severity": severity.capitalize(),
            "description": title[:150] + "..." if len(title) > 150 else title,
            "full_desc": title,
            "suggestion": suggestion,
            "link": link,
            "source": "Snyk"
        }
        self.vulnerabilities.append(vuln_data)
        self.update_tree(vuln_data)

    def map_severity(self, sev):
        s = sev.lower()
        if s in ["critical", "high"]: return "Critical" if s == "critical" else "High"
        if s == "medium": return "Medium"
        return "Low"

    def get_suggestion_composer(self, adv, pkg):
        fixed = adv.get("fixedIn")
        if fixed:
            return f"Upgrade {pkg} to >= {fixed}"
        return "Patch or replace package"

    def run_command(self, cmd):
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=300)
            return result
        except Exception as e:
            self.update_status(f"Command failed: {cmd} → {e}")
            return None

    def update_tree(self, vuln):
        def _insert():
            tag = vuln["severity"].lower()
            self.tree.insert("", tk.END, values=(
                vuln["package"],
                vuln["cve"],
                vuln["severity"],
                vuln["description"],
                vuln["suggestion"],
                vuln["source"]
            ), tags=(tag,))
        self.root.after(0, _insert)

    def update_status(self, msg):
        print(f"[INFO] {msg}")

    def clear_results(self):
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.vulnerabilities = []

    def open_link(self, event):
        item = self.tree.selection()[0]
        col = self.tree.identify_column(event.x)
        if col == "#2":  # CVE column
            cve = self.tree.item(item, "values")[1]
            if cve != "N/A":
                url = f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve}" if cve.startswith("CVE") else cve
                webbrowser.open(url)

    def export_html(self):
        if not self.vulnerabilities:
            messagebox.showwarning("No Data", "Run a scan first.")
            return

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = os.path.join(self.project_dir, f"laravel_security_report_{timestamp}.html")

        counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        for v in self.vulnerabilities:
            counts[v["severity"]] += 1

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Laravel Security Report</title>
    <style>
        body {{ font-family: 'Segoe UI', sans-serif; margin: 40px; background: #f8f9fa; color: #333; }}
        .container {{ max-width: 1200px; margin: auto; }}
        h1 {{ color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; }}
        .summary {{ background: white; padding: 20px; border-radius: 10px; box-shadow: 0 4px 12px rgba(0,0,0,0.1); margin-bottom: 20px; }}
        .summary h3 {{ margin: 0 0 15px 0; color: #2c3e50; }}
        .stats {{ display: flex; gap: 20px; flex-wrap: wrap; }}
        .stat {{ padding: 10px 15px; border-radius: 8px; color: white; font-weight: bold; min-width: 100px; text-align: center; }}
        .critical {{ background: #e74c3c; }}
        .high {{ background: #e67e22; }}
        .medium {{ background: #f1c40f; color: #000; }}
        .low {{ background: #95a5a6; }}
        table {{ width: 100%; border-collapse: collapse; background: white; box-shadow: 0 2px 8px rgba(0,0,0,0.1); border-radius: 8px; overflow: hidden; }}
        th {{ background: #3498db; color: white; padding: 15px; text-align: left; }}
        td {{ padding: 12px 15px; border-bottom: 1px solid #eee; }}
        tr:hover {{ background: #f8f9fa; }}
        .critical td {{ background: #fdf2f2; }}
        .high td {{ background: #fdf4e8; }}
        .medium td {{ background: #fefce8; }}
        .low td {{ background: #f4f4f4; }}
        a {{ color: #3498db; text-decoration: none; }}
        a:hover {{ text-decoration: underline; }}
        .footer {{ margin-top: 50px; text-align: center; color: #7f8c8d; font-size: 0.9em; }}
    </style>
</head>
<body>
<div class="container">
    <h1>Laravel Dependency Security Report</h1>
    <div class="summary">
        <h3>Project: <strong>{os.path.basename(self.project_dir)}</strong></h3>
        <p><strong>Generated:</strong> {datetime.now().strftime("%B %d, %Y at %I:%M %p")}</p>
        <div class="stats">
            <div class="stat critical">Critical: {counts['Critical']}</div>
            <div class="stat high">High: {counts['High']}</div>
            <div class="stat medium">Medium: {counts['Medium']}</div>
            <div class="stat low">Low: {counts['Low']}</div>
        </div>
    </div>

    <table>
        <tr>
            <th>Package</th>
            <th>CVE</th>
            <th>Severity</th>
            <th>Description</th>
            <th>Suggestion</th>
            <th>Source</th>
        </tr>"""

        for v in self.vulnerabilities:
            row_class = v["severity"].lower()
            cve_link = f'<a href="{v["link"]}" target="_blank">{v["cve"]}</a>' if v["link"] and v["link"] != "N/A" else v["cve"]
            html += f"""
        <tr class="{row_class}">
            <td><strong>{v["package"]}</strong></td>
            <td>{cve_link}</td>
            <td><strong>{v["severity"]}</strong></td>
            <td>{v["full_desc"]}</td>
            <td>{v["suggestion"]}</td>
            <td>{v["source"]}</td>
        </tr>"""

        html += """
    </table>
    <div class="footer">
        Generated by <strong>Laravel Security Scanner</strong> • Supports Composer & Snyk
    </div>
</div>
</body>
</html>"""

        try:
            with open(report_file, "w", encoding="utf-8") as f:
                f.write(html)
            webbrowser.open(f"file://{os.path.abspath(report_file)}")
            messagebox.showinfo("Success", f"Report exported and opened:\n{report_file}")
        except Exception as e:
            messagebox.showerror("Export Failed", str(e))


if __name__ == "__main__":
    # Ensure Tkinter works
    try:
        root = tk.Tk()
        app = LaravelVulnScanner(root)
        root.mainloop()
    except Exception as e:
        print(f"Failed to start GUI: {e}")
        sys.exit(1)