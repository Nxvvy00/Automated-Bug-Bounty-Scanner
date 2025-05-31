## ⚡ Automated Bug Bounty Scanner ⚡

🚀 Overview
Welcome to Automated Bug Bounty Scanner, your all-in-one 🔍 reconnaissance and vulnerability scanning tool designed for bug bounty hunters, penetration testers, and security researchers. This Python-powered scanner automates the tedious parts of web app security testing by crawling, enumerating, and analyzing target websites with blazing speed — all wrapped in a sleek, futuristic GUI.

It helps you uncover hidden admin panels, WordPress weak points, cPanel portals, and sensitive hidden files. Plus, it packs built-in brute force modules to test common authentication mechanisms, speeding up your workflow and maximizing your chances to discover valuable vulnerabilities.

💡 Key Features
🌐 Intelligent Recursive Crawling:
Efficiently explores target websites to map accessible URLs, respecting max depth and concurrency.

🔎 Multi-Vector Vulnerability Checks:
Detects common attack surfaces such as admin panels, WordPress endpoints, cPanel, and sensitive hidden files (e.g., .env, .git/config, robots.txt).

🎯 Prioritized Results:
Assigns dynamic risk scores to vulnerabilities to help triage and focus on the most critical findings first.

💥 Built-in Brute Force Modules:
Test WordPress logins, cPanel portals, and HTTP Basic Authentication using customizable or popular password lists like rockyou.txt.

🛑 Scan Control:
Easy to start, stop, and monitor scans without freezing the UI — built with thread-safe concurrency.

🖥️ Futuristic, User-Friendly GUI:
Intuitive Tkinter interface with real-time logging and customizable scan options.

🔧 Extensible & Customizable:
Modify paths, user agents, and brute force parameters easily to suit your testing needs.

🎯 Why Use Automated Bug Bounty Scanner?
Bug bounty hunting can be overwhelming with endless recon tasks. This tool simplifies and automates:

Finding hidden pages attackers often miss

Checking common CMS and control panel login points

Hunting down publicly exposed sensitive files

Running brute force attacks intelligently without manual setup

Prioritizing results to optimize your reporting time

All while giving you full control from an easy-to-use desktop interface.

# ⚙️ Installation
Clone the repo:

git clone https://github.com/Threadlinee/Automated-Bug-Bounty-Scanner.git
cd Automated-Bug-Bounty-Scanner
Install dependencies:

pip install -r requirements.txt
Run the scanner:

python bugbounty_scanner.py

# 🧭 How To Use
Launch the app and enter your target URL (include http:// or https://).

Click START SCAN to begin crawling and vulnerability enumeration.

Monitor live logs streaming in the GUI.

Use STOP SCAN to abort anytime.

Explore brute force attack options on WordPress, cPanel, or HTTP Auth via dedicated buttons.

After scans complete, review the prioritized vulnerabilities and take action!

# 📸 Screenshots
Add your screenshots below to showcase the app’s interface and functionality.

Main Scan Window	Brute Force Module

# 🤝 Contributing
Contributions are what make the open source community awesome! Feel free to:

Submit bug reports 🐞

Request features ✨

Open pull requests to enhance functionality 💻

Please follow the standard GitHub flow for contributions.

# ⚠️ Disclaimer
This tool is strictly for authorized security testing and educational use only. Unauthorized scanning, brute forcing, or exploitation of systems without explicit permission is illegal and unethical. The author is not responsible for misuse.

Always obtain proper authorization before testing targets.

# 📜 License
This project is licensed under the MIT License — see the LICENSE file for details.

# 🙏 Acknowledgments
Big shoutout to the security community for continuous inspiration. Keep hunting and stay safe!
