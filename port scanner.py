#!/usr/bin/env python3
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import ipaddress
import socket
import ssl
import concurrent.futures
import threading
import csv
import json
import urllib.request
import urllib.parse
import urllib.error
from datetime import datetime

DEFAULT_PORTS = "21,22,23,25,53,80,110,143,443,445,587,993,995,3306,3389,5432,5900,8080,8443"
MAX_TARGET_IPS = 100_000
MAX_SCAN_JOBS = 300_000

PROVIDER_PRESETS = {
    "Cloud / CDN": [
        "Cloudflare", "Amazon Web Services", "AWS", "Amazon CloudFront", "Google Cloud",
        "Google", "Microsoft Azure", "Microsoft", "Akamai", "Fastly", "DigitalOcean",
        "Oracle Cloud", "Alibaba Cloud", "Tencent Cloud", "IBM Cloud", "OVHcloud", "OVH",
        "Hetzner", "Linode", "Akamai Connected Cloud", "Vultr", "G-Core Labs",
        "Bunny.net", "CloudFront", "Cloudflare Magic Transit", "StackPath", "CDNetworks",
        "Edgecast", "Edgio", "CloudSigma", "UpCloud", "Exoscale", "Kamatera"
    ],
    "Hosting / VPS / Datacenter": [
        "Leaseweb", "Contabo", "Scaleway", "IONOS", "1&1", "GoDaddy", "Namecheap",
        "Hostinger", "Bluehost", "DreamHost", "SiteGround", "Rackspace", "HostHatch",
        "Serverius", "Clouvider", "Psychz Networks", "Hivelocity", "ColoCrossing",
        "WebNX", "NForce", "FranTech", "BuyVM", "QuadraNet", "DataCamp", "M247",
        "Servers.com", "Eonix", "Choopa", "Zenlayer", "Equinix Metal", "Packet",
        "WorldStream", "Netcup", "Strato", "Aruba", "Seeweb", "Register.it"
    ],
    "Backbone / Transit": [
        "Hurricane Electric", "Cogent", "Lumen", "Level 3", "NTT", "Arelion", "Telia",
        "Zayo", "GTT", "PCCW Global", "Tata Communications", "Liberty Global", "RETN",
        "Colt", "Sparkle", "Telecom Italia Sparkle", "Cogent Communications"
    ],
    "Networks / Telecom": [
        "Comcast", "Verizon", "AT&T", "T-Mobile", "Vodafone", "Orange", "Telecom Italia",
        "TIM", "BT", "Telefonica", "Movistar", "Deutsche Telekom", "Swisscom", "Proximus",
        "KPN", "Bouygues Telecom", "Free", "Iliad", "SFR", "WindTre", "Fastweb",
        "Tiscali", "Virgin Media", "O2", "EE", "Rogers", "Bell Canada", "Telus",
        "Telstra", "Optus", "NTT Docomo", "KDDI", "SoftBank", "SK Telecom", "KT",
        "China Telecom", "China Unicom", "China Mobile", "Reliance Jio", "Airtel"
    ],
    "Security / VPN / Proxy": [
        "NordVPN", "ExpressVPN", "Mullvad", "Proton", "ProtonVPN", "Surfshark", "Tor",
        "Private Internet Access", "CyberGhost", "Windscribe", "TunnelBear", "VyprVPN",
        "HideMyAss", "IPVanish", "PureVPN", "M247", "DataCamp", "PacketHub",
        "Datapacket", "TorGuard", "VPN Unlimited", "StrongVPN", "Hola VPN"
    ],
    "Search / Social / Platforms": [
        "Meta", "Facebook", "Instagram", "WhatsApp", "Apple", "Netflix", "Spotify", "GitHub",
        "GitLab", "Discord", "Telegram", "Reddit", "Dropbox", "Zoom", "Salesforce", "Shopify",
        "OpenAI", "Twitter", "X Corp", "LinkedIn", "TikTok", "ByteDance", "Pinterest"
    ],
}

# Offline fallback list. Prefix lookup still needs internet, but this prevents provider search from just failing.
LOCAL_PROVIDER_ASNS = {
    "Cloudflare": {"asns": ["13335"], "aliases": ["cloudflare"]},
    "Amazon Web Services": {"asns": ["16509", "14618"], "aliases": ["amazon", "aws", "cloudfront"]},
    "Google": {"asns": ["15169"], "aliases": ["google", "google cloud", "gcp"]},
    "Microsoft": {"asns": ["8075"], "aliases": ["microsoft", "azure"]},
    "Akamai": {"asns": ["20940", "16625"], "aliases": ["akamai", "linode", "akamai connected cloud"]},
    "Fastly": {"asns": ["54113"], "aliases": ["fastly"]},
    "DigitalOcean": {"asns": ["14061"], "aliases": ["digitalocean", "digital ocean"]},
    "OVHcloud": {"asns": ["16276"], "aliases": ["ovh", "ovhcloud"]},
    "Hetzner": {"asns": ["24940"], "aliases": ["hetzner"]},
    "Vultr": {"asns": ["20473"], "aliases": ["vultr", "choopa"]},
    "Oracle Cloud": {"asns": ["31898"], "aliases": ["oracle", "oracle cloud", "oci"]},
    "Alibaba Cloud": {"asns": ["45102"], "aliases": ["alibaba", "aliyun"]},
    "Tencent Cloud": {"asns": ["132203"], "aliases": ["tencent"]},
    "IBM Cloud": {"asns": ["36351"], "aliases": ["ibm", "softlayer"]},
    "Leaseweb": {"asns": ["60781", "16265"], "aliases": ["leaseweb"]},
    "Scaleway": {"asns": ["12876"], "aliases": ["scaleway", "online sas"]},
    "Contabo": {"asns": ["51167"], "aliases": ["contabo"]},
    "IONOS": {"asns": ["8560"], "aliases": ["ionos", "1&1", "oneandone"]},
    "GoDaddy": {"asns": ["26496"], "aliases": ["godaddy"]},
    "Hostinger": {"asns": ["47583"], "aliases": ["hostinger"]},
    "Rackspace": {"asns": ["19994"], "aliases": ["rackspace"]},
    "M247": {"asns": ["9009"], "aliases": ["m247"]},
    "DataCamp": {"asns": ["60068"], "aliases": ["datacamp", "datapacket"]},
    "Hurricane Electric": {"asns": ["6939"], "aliases": ["hurricane", "he.net"]},
    "Cogent": {"asns": ["174"], "aliases": ["cogent"]},
    "Lumen / Level 3": {"asns": ["3356"], "aliases": ["lumen", "level 3", "level3"]},
    "NTT": {"asns": ["2914"], "aliases": ["ntt"]},
    "Arelion / Telia": {"asns": ["1299"], "aliases": ["arelion", "telia"]},
    "Zayo": {"asns": ["6461"], "aliases": ["zayo"]},
    "GTT": {"asns": ["3257"], "aliases": ["gtt"]},
    "Comcast": {"asns": ["7922"], "aliases": ["comcast", "xfinity"]},
    "Verizon": {"asns": ["701", "6167"], "aliases": ["verizon"]},
    "AT&T": {"asns": ["7018"], "aliases": ["at&t", "att"]},
    "T-Mobile US": {"asns": ["21928"], "aliases": ["t-mobile", "tmobile"]},
    "Vodafone": {"asns": ["1273"], "aliases": ["vodafone"]},
    "Orange": {"asns": ["5511", "3215"], "aliases": ["orange"]},
    "Telecom Italia / TIM": {"asns": ["3269"], "aliases": ["telecom italia", "tim"]},
    "BT": {"asns": ["2856"], "aliases": ["bt", "british telecom"]},
    "Telefonica": {"asns": ["12956"], "aliases": ["telefonica", "movistar"]},
    "Deutsche Telekom": {"asns": ["3320"], "aliases": ["deutsche telekom", "telekom"]},
    "Swisscom": {"asns": ["3303"], "aliases": ["swisscom"]},
    "KPN": {"asns": ["1136"], "aliases": ["kpn"]},
    "Proximus": {"asns": ["5432"], "aliases": ["proximus"]},
    "Meta / Facebook": {"asns": ["32934"], "aliases": ["meta", "facebook", "instagram", "whatsapp"]},
    "Apple": {"asns": ["714"], "aliases": ["apple"]},
    "Netflix": {"asns": ["2906"], "aliases": ["netflix"]},
    "GitHub": {"asns": ["36459"], "aliases": ["github"]},
    "GitLab": {"asns": ["54825"], "aliases": ["gitlab"]},
    "Discord": {"asns": ["49544"], "aliases": ["discord"]},
    "Telegram": {"asns": ["62041"], "aliases": ["telegram"]},
    "Dropbox": {"asns": ["19679"], "aliases": ["dropbox"]},
    "Zoom": {"asns": ["30103"], "aliases": ["zoom"]},
    "Shopify": {"asns": ["62679"], "aliases": ["shopify"]},
}

class IPScannerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Authorized IP Range Scanner + Provider/ASN Search")
        self.root.geometry("1380x840")
        self.stop_flag = threading.Event()
        self.lock = threading.Lock()
        self.profiles = {}
        self.provider_cache = {}
        self.geo_cache = {}
        self.asn_results = []
        self.prefix_items = []
        self.build_ui()

    def build_ui(self):
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill="both", expand=True)
        self.scanner_tab = ttk.Frame(self.notebook)
        self.provider_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.scanner_tab, text="Scanner")
        self.notebook.add(self.provider_tab, text="Provider Search")
        self.build_scanner_tab()
        self.build_provider_tab()

    def build_scanner_tab(self):
        top = ttk.Frame(self.scanner_tab, padding=10)
        top.pack(fill="x")
        ttk.Label(top, text="IP range(s):").grid(row=0, column=0, sticky="w")
        self.range_entry = ttk.Entry(top, width=75)
        self.range_entry.grid(row=0, column=1, padx=5, sticky="we")
        self.range_entry.insert(0, "192.168.1.0/24")
        ttk.Label(top, text="Ports:").grid(row=1, column=0, sticky="w")
        self.ports_entry = ttk.Entry(top, width=75)
        self.ports_entry.grid(row=1, column=1, padx=5, sticky="we")
        self.ports_entry.insert(0, DEFAULT_PORTS)
        ttk.Label(top, text="Timeout:").grid(row=0, column=2, sticky="w")
        self.timeout_var = tk.DoubleVar(value=0.7)
        ttk.Entry(top, textvariable=self.timeout_var, width=8).grid(row=0, column=3, padx=5)
        ttk.Label(top, text="Threads:").grid(row=1, column=2, sticky="w")
        self.threads_var = tk.IntVar(value=250)
        ttk.Entry(top, textvariable=self.threads_var, width=8).grid(row=1, column=3, padx=5)
        opts = ttk.Frame(top)
        opts.grid(row=2, column=1, columnspan=3, sticky="w", pady=5)
        self.scan_ports_var = tk.BooleanVar(value=True)
        self.resolve_var = tk.BooleanVar(value=True)
        self.rdap_var = tk.BooleanVar(value=True)
        self.geo_var = tk.BooleanVar(value=False)
        self.banner_var = tk.BooleanVar(value=True)
        self.tls_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(opts, text="Scan ports", variable=self.scan_ports_var).pack(side="left", padx=4)
        ttk.Checkbutton(opts, text="Reverse DNS", variable=self.resolve_var).pack(side="left", padx=4)
        ttk.Checkbutton(opts, text="RDAP/provider", variable=self.rdap_var).pack(side="left", padx=4)
        ttk.Checkbutton(opts, text="Geo/ASN lookup", variable=self.geo_var).pack(side="left", padx=4)
        ttk.Checkbutton(opts, text="Grab banners", variable=self.banner_var).pack(side="left", padx=4)
        ttk.Checkbutton(opts, text="TLS certs", variable=self.tls_var).pack(side="left", padx=4)
        self.auth_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(top, text="I confirm I am authorized to scan these IPs", variable=self.auth_var).grid(row=3, column=1, columnspan=3, sticky="w")
        top.columnconfigure(1, weight=1)
        buttons = ttk.Frame(self.scanner_tab, padding=(10, 0))
        buttons.pack(fill="x")
        ttk.Button(buttons, text="Start", command=self.start_scan).pack(side="left", padx=4)
        ttk.Button(buttons, text="Stop", command=self.stop_scan).pack(side="left", padx=4)
        ttk.Button(buttons, text="Export CSV", command=self.export_csv).pack(side="left", padx=4)
        ttk.Button(buttons, text="Export JSON", command=self.export_json).pack(side="left", padx=4)
        ttk.Button(buttons, text="Clear", command=self.clear_results).pack(side="left", padx=4)
        ttk.Label(buttons, text="Sort by:").pack(side="left", padx=(25, 5))
        self.sort_var = tk.StringVar(value="IP")
        sort_box = ttk.Combobox(buttons, textvariable=self.sort_var, values=["IP", "Provider", "ASN", "Country", "Hostname", "Open Ports", "Version"], state="readonly", width=15)
        sort_box.pack(side="left")
        sort_box.bind("<<ComboboxSelected>>", lambda e: self.refresh_table())
        ttk.Label(buttons, text="All-fields filter:").pack(side="left", padx=(25, 5))
        self.filter_var = tk.StringVar()
        filter_entry = ttk.Entry(buttons, textvariable=self.filter_var, width=22)
        filter_entry.pack(side="left")
        filter_entry.bind("<KeyRelease>", lambda e: self.refresh_table())
        ttk.Label(buttons, text="Provider filter:").pack(side="left", padx=(15, 5))
        self.provider_filter_var = tk.StringVar()
        provider_filter = ttk.Entry(buttons, textvariable=self.provider_filter_var, width=22)
        provider_filter.pack(side="left")
        provider_filter.bind("<KeyRelease>", lambda e: self.refresh_table())
        paned = ttk.PanedWindow(self.scanner_tab, orient="vertical")
        paned.pack(fill="both", expand=True, padx=10, pady=10)
        table_frame = ttk.Frame(paned)
        detail_frame = ttk.Frame(paned)
        paned.add(table_frame, weight=3)
        paned.add(detail_frame, weight=2)
        columns = ("ip", "version", "flags", "hostname", "provider", "asn", "country", "open_ports", "services")
        self.tree = ttk.Treeview(table_frame, columns=columns, show="headings")
        self.tree.pack(fill="both", expand=True, side="left")
        yscroll = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        yscroll.pack(side="right", fill="y")
        self.tree.configure(yscrollcommand=yscroll.set)
        headings = {"ip": "IP", "version": "Ver", "flags": "Flags", "hostname": "Hostname", "provider": "Provider / Owner", "asn": "ASN", "country": "Country", "open_ports": "Open Ports", "services": "Services"}
        widths = {"ip": 155, "version": 50, "flags": 185, "hostname": 215, "provider": 310, "asn": 120, "country": 90, "open_ports": 160, "services": 240}
        for col in columns:
            self.tree.heading(col, text=headings[col])
            self.tree.column(col, width=widths[col])
        self.tree.bind("<<TreeviewSelect>>", self.show_selected_details)
        ttk.Label(detail_frame, text="Selected IP full details:").pack(anchor="w")
        self.details = tk.Text(detail_frame, height=12, wrap="none")
        self.details.pack(fill="both", expand=True)
        self.progress = ttk.Progressbar(self.scanner_tab, mode="determinate")
        self.progress.pack(fill="x", padx=10, pady=(0, 5))
        self.status_var = tk.StringVar(value="Ready.")
        ttk.Label(self.scanner_tab, textvariable=self.status_var).pack(fill="x", padx=10, pady=(0, 10))

    def build_provider_tab(self):
        top = ttk.Frame(self.provider_tab, padding=10)
        top.pack(fill="x")
        ttk.Label(top, text="Provider name or ASN:").grid(row=0, column=0, sticky="w")
        self.provider_search_var = tk.StringVar()
        search_entry = ttk.Entry(top, textvariable=self.provider_search_var, width=55)
        search_entry.grid(row=0, column=1, padx=5, sticky="we")
        search_entry.insert(0, "Cloudflare")
        search_entry.bind("<Return>", lambda e: self.search_provider())
        ttk.Button(top, text="Search provider/ASN", command=self.search_provider).grid(row=0, column=2, padx=5)
        ttk.Button(top, text="Provider list", command=self.open_provider_picker).grid(row=0, column=3, padx=5)
        ttk.Button(top, text="Load selected ASN prefixes", command=self.load_selected_asn_prefixes).grid(row=0, column=4, padx=5)
        ttk.Label(top, text="Prefix family:").grid(row=1, column=0, sticky="w", pady=(5, 0))
        self.prefix_family_var = tk.StringVar(value="IPv4")
        family_box = ttk.Combobox(top, textvariable=self.prefix_family_var, values=["IPv4", "IPv6", "Both"], state="readonly", width=10)
        family_box.grid(row=1, column=1, sticky="w", padx=5, pady=(5, 0))
        family_box.bind("<<ComboboxSelected>>", lambda e: self.refresh_prefix_tree(self.prefix_items))
        ttk.Button(top, text="Add selected prefixes to scanner", command=self.add_selected_prefixes_to_scanner).grid(row=1, column=2, padx=5, pady=(5, 0))
        ttk.Button(top, text="Scan selected prefixes", command=self.scan_selected_prefixes).grid(row=1, column=3, padx=5, pady=(5, 0))
        top.columnconfigure(1, weight=1)
        ttk.Label(self.provider_tab, text="Provider search uses online BGP/RIR APIs when available and a built-in offline ASN fallback. Prefix loading needs internet.").pack(anchor="w", padx=10)
        paned = ttk.PanedWindow(self.provider_tab, orient="vertical")
        paned.pack(fill="both", expand=True, padx=10, pady=10)
        asn_frame = ttk.Frame(paned)
        prefix_frame = ttk.Frame(paned)
        paned.add(asn_frame, weight=1)
        paned.add(prefix_frame, weight=2)
        ttk.Label(asn_frame, text="Matching ASNs:").pack(anchor="w")
        self.asn_tree = ttk.Treeview(asn_frame, columns=("asn", "name", "description", "country"), show="headings", selectmode="browse")
        self.asn_tree.pack(fill="both", expand=True, side="left")
        asn_scroll = ttk.Scrollbar(asn_frame, orient="vertical", command=self.asn_tree.yview)
        asn_scroll.pack(side="right", fill="y")
        self.asn_tree.configure(yscrollcommand=asn_scroll.set)
        for col, text, width in [("asn", "ASN", 100), ("name", "Name", 220), ("description", "Description", 650), ("country", "Country", 80)]:
            self.asn_tree.heading(col, text=text)
            self.asn_tree.column(col, width=width)
        self.asn_tree.bind("<Double-1>", lambda e: self.load_selected_asn_prefixes())
        ttk.Label(prefix_frame, text="Prefixes for selected ASN / provider search:").pack(anchor="w")
        self.prefix_tree = ttk.Treeview(prefix_frame, columns=("prefix", "family", "name", "description", "country"), show="headings", selectmode="extended")
        self.prefix_tree.pack(fill="both", expand=True, side="left")
        prefix_scroll = ttk.Scrollbar(prefix_frame, orient="vertical", command=self.prefix_tree.yview)
        prefix_scroll.pack(side="right", fill="y")
        self.prefix_tree.configure(yscrollcommand=prefix_scroll.set)
        for col, text, width in [("prefix", "Prefix", 190), ("family", "Family", 70), ("name", "Name", 220), ("description", "Description", 650), ("country", "Country", 80)]:
            self.prefix_tree.heading(col, text=text)
            self.prefix_tree.column(col, width=width)
        self.provider_status_var = tk.StringVar(value="Ready.")
        ttk.Label(self.provider_tab, textvariable=self.provider_status_var).pack(fill="x", padx=10, pady=(0, 10))

    def friendly_error(self, err):
        text = str(err)
        if isinstance(err, urllib.error.URLError):
            text = str(err.reason)
        lowered = text.lower()
        if "getaddrinfo failed" in lowered or "name or service not known" in lowered or "temporary failure in name resolution" in lowered:
            return "DNS/network lookup unavailable. Check internet/DNS, proxy, firewall, or VPN."
        if "timed out" in lowered or "timeout" in lowered:
            return "Lookup timed out. The API may be slow or blocked."
        return text

    def open_provider_picker(self):
        win = tk.Toplevel(self.root)
        win.title("Select Provider")
        win.geometry("580x600")
        win.transient(self.root)
        ttk.Label(win, text="Search provider:").pack(anchor="w", padx=10, pady=(10, 2))
        search_var = tk.StringVar()
        search_entry = ttk.Entry(win, textvariable=search_var)
        search_entry.pack(fill="x", padx=10)
        frame = ttk.Frame(win)
        frame.pack(fill="both", expand=True, padx=10, pady=10)
        tree = ttk.Treeview(frame, columns=("provider",), show="tree headings", selectmode="browse")
        tree.heading("#0", text="Category")
        tree.heading("provider", text="Provider")
        tree.column("#0", width=220)
        tree.column("provider", width=310)
        tree.pack(side="left", fill="both", expand=True)
        scroll = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
        scroll.pack(side="right", fill="y")
        tree.configure(yscrollcommand=scroll.set)
        def load_items(filter_text=""):
            for row in tree.get_children():
                tree.delete(row)
            filter_text = filter_text.lower().strip()
            for category, providers in PROVIDER_PRESETS.items():
                matching = [p for p in providers if filter_text in p.lower()]
                if filter_text and not matching:
                    continue
                parent = tree.insert("", "end", text=category, values=("",), open=True)
                for provider in matching if filter_text else providers:
                    tree.insert(parent, "end", text="", values=(provider,))
        def choose_provider(search_now=False):
            selected = tree.selection()
            if not selected:
                return
            values = tree.item(selected[0], "values")
            if not values or not values[0]:
                return
            provider = values[0]
            self.provider_search_var.set(provider)
            win.destroy()
            if search_now:
                self.search_provider()
        search_var.trace_add("write", lambda *_: load_items(search_var.get()))
        buttons = ttk.Frame(win)
        buttons.pack(fill="x", padx=10, pady=(0, 10))
        ttk.Button(buttons, text="Use selected", command=lambda: choose_provider(False)).pack(side="left", padx=4)
        ttk.Button(buttons, text="Use and search", command=lambda: choose_provider(True)).pack(side="left", padx=4)
        ttk.Button(buttons, text="Cancel", command=win.destroy).pack(side="right", padx=4)
        tree.bind("<Double-1>", lambda e: choose_provider(True))
        load_items()
        search_entry.focus_set()

    def host_count(self, network):
        if network.version == 4 and network.prefixlen < 31:
            return max(0, network.num_addresses - 2)
        return network.num_addresses

    def parse_ranges(self, text, max_targets=MAX_TARGET_IPS):
        targets, seen = [], set()
        for part in text.replace("\n", ",").split(","):
            part = part.strip()
            if not part:
                continue
            if "-" in part and "/" not in part:
                start, end = [x.strip() for x in part.split("-", 1)]
                start_ip = ipaddress.ip_address(start)
                end_ip = ipaddress.ip_address(end)
                if start_ip.version != end_ip.version:
                    raise ValueError("Mixed IPv4/IPv6 ranges are not supported.")
                if int(end_ip) < int(start_ip):
                    raise ValueError(f"Invalid IP range: {part}")
                count = int(end_ip) - int(start_ip) + 1
                if len(targets) + count > max_targets:
                    raise ValueError(f"Too many target IPs. Limit is {max_targets:,}.")
                current = start_ip
                while current <= end_ip:
                    s = str(current)
                    if s not in seen:
                        seen.add(s)
                        targets.append(s)
                    current += 1
            else:
                net = ipaddress.ip_network(part, strict=False)
                count = self.host_count(net)
                if len(targets) + count > max_targets:
                    raise ValueError(f"Too many target IPs. Limit is {max_targets:,}. Narrow this range: {part}")
                iterable = net.hosts() if net.version == 4 and net.prefixlen < 31 else net
                for ip in iterable:
                    s = str(ip)
                    if s not in seen:
                        seen.add(s)
                        targets.append(s)
        return sorted(targets, key=lambda x: ipaddress.ip_address(x))

    def parse_ports(self, text):
        ports = set()
        for part in text.replace(" ", "").split(","):
            if not part:
                continue
            if "-" in part:
                start, end = part.split("-", 1)
                start, end = int(start), int(end)
                if start < 1 or end > 65535 or start > end:
                    raise ValueError(f"Invalid port range: {part}")
                ports.update(range(start, end + 1))
            else:
                port = int(part)
                if port < 1 or port > 65535:
                    raise ValueError(f"Invalid port: {port}")
                ports.add(port)
        return sorted(ports)

    def base_ip_properties(self, ip):
        obj = ipaddress.ip_address(ip)
        flags = {"is_private": obj.is_private, "is_global": obj.is_global, "is_loopback": obj.is_loopback, "is_link_local": obj.is_link_local, "is_multicast": obj.is_multicast, "is_reserved": obj.is_reserved, "is_unspecified": obj.is_unspecified}
        true_flags = [k.replace("is_", "") for k, v in flags.items() if v]
        return {"ip": ip, "version": obj.version, "compressed": obj.compressed, "exploded": obj.exploded, "reverse_pointer": obj.reverse_pointer, "flags": flags, "flags_text": ", ".join(true_flags), "hostname": "", "forward_dns": [], "provider": "", "asn": "", "country": "", "city": "", "region": "", "timezone": "", "latitude": "", "longitude": "", "isp": "", "organization": "", "rdap": {}, "geo": {}, "open_ports": [], "last_checked": datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

    def reverse_dns(self, ip):
        if not self.resolve_var.get():
            return "", []
        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except Exception:
            return "", []
        try:
            forward = list(socket.gethostbyname_ex(hostname)[2])
        except Exception:
            forward = []
        return hostname, forward

    def fetch_json(self, url, timeout=8):
        req = urllib.request.Request(url, headers={"User-Agent": "AuthorizedIPScanner/2.0"})
        with urllib.request.urlopen(req, timeout=timeout) as response:
            return json.loads(response.read().decode("utf-8", errors="replace"))

    def rdap_lookup(self, ip):
        if not self.rdap_var.get():
            return {}
        if ip in self.provider_cache:
            return self.provider_cache[ip]
        obj = ipaddress.ip_address(ip)
        if obj.is_private or obj.is_loopback or obj.is_link_local or obj.is_multicast:
            data = {"name": "Private / local network"}
        else:
            try:
                data = self.fetch_json(f"https://rdap.org/ip/{urllib.parse.quote(ip)}", timeout=5)
            except Exception as e:
                data = {"error": self.friendly_error(e)}
        self.provider_cache[ip] = data
        return data

    def geo_lookup(self, ip):
        if not self.geo_var.get():
            return {}
        if ip in self.geo_cache:
            return self.geo_cache[ip]
        obj = ipaddress.ip_address(ip)
        if obj.is_private or obj.is_loopback or obj.is_link_local or obj.is_multicast:
            data = {"success": False, "message": "Private / local network"}
        else:
            try:
                data = self.fetch_json(f"https://ipwho.is/{urllib.parse.quote(ip)}", timeout=5)
            except Exception as e:
                data = {"success": False, "error": self.friendly_error(e)}
        self.geo_cache[ip] = data
        return data

    def extract_rdap_summary(self, rdap):
        if not rdap:
            return "", "", ""
        provider = rdap.get("name") or rdap.get("handle") or ""
        country = rdap.get("country") or ""
        asn = ""
        for entity in rdap.get("entities", []) or []:
            name = self.extract_vcard_name(entity)
            if name and not provider:
                provider = name
        for notice in rdap.get("notices", []) or []:
            title = notice.get("title", "")
            if "ASN" in title.upper():
                asn = title
        if not provider and rdap.get("error"):
            provider = "Lookup unavailable"
        return provider, asn, country

    def extract_vcard_name(self, entity):
        try:
            vcard = entity.get("vcardArray", [])
            if len(vcard) < 2:
                return ""
            for item in vcard[1]:
                if item and item[0] == "fn":
                    return str(item[3])
        except Exception:
            pass
        return ""

    def extract_geo_summary(self, geo):
        if not geo or geo.get("success") is False:
            return {}
        connection = geo.get("connection", {}) or {}
        timezone = geo.get("timezone", {}) or {}
        return {"asn": str(connection.get("asn", "")), "isp": connection.get("isp", ""), "organization": connection.get("org", ""), "country": geo.get("country", ""), "region": geo.get("region", ""), "city": geo.get("city", ""), "timezone": timezone.get("id", ""), "latitude": geo.get("latitude", ""), "longitude": geo.get("longitude", "")}

    def enrich_ip(self, ip):
        profile = self.base_ip_properties(ip)
        hostname, forward = self.reverse_dns(ip)
        profile["hostname"] = hostname
        profile["forward_dns"] = forward
        rdap = self.rdap_lookup(ip)
        provider, rdap_asn, rdap_country = self.extract_rdap_summary(rdap)
        profile["rdap"] = rdap
        profile["provider"] = provider
        profile["asn"] = rdap_asn
        profile["country"] = rdap_country
        geo = self.geo_lookup(ip)
        profile["geo"] = geo
        for key, value in self.extract_geo_summary(geo).items():
            if value:
                profile[key] = value
        return profile

    def get_service_name(self, port):
        try:
            return socket.getservbyport(port, "tcp")
        except Exception:
            return "unknown"

    def socket_family(self, ip):
        return socket.AF_INET6 if ipaddress.ip_address(ip).version == 6 else socket.AF_INET

    def grab_banner(self, ip, port, timeout):
        if not self.banner_var.get():
            return ""
        try:
            with socket.create_connection((ip, port), timeout=timeout) as sock:
                sock.settimeout(timeout)
                if port in (80, 8080, 8000, 8888):
                    sock.sendall(b"HEAD / HTTP/1.0\r\nHost: scan.local\r\n\r\n")
                try:
                    return sock.recv(512).decode("utf-8", errors="replace").strip()
                except Exception:
                    return ""
        except Exception:
            return ""

    def grab_tls_cert(self, ip, port, timeout, hostname=""):
        if not self.tls_var.get() or port not in (443, 8443, 9443, 993, 995, 465):
            return {}
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            with socket.create_connection((ip, port), timeout=timeout) as raw:
                with context.wrap_socket(raw, server_hostname=hostname or ip) as tls:
                    cert = tls.getpeercert()
            return {"subject": cert.get("subject", []), "issuer": cert.get("issuer", []), "notBefore": cert.get("notBefore", ""), "notAfter": cert.get("notAfter", ""), "serialNumber": cert.get("serialNumber", ""), "subjectAltName": cert.get("subjectAltName", [])}
        except Exception as e:
            return {"error": str(e)}

    def scan_port(self, ip, port, timeout):
        if self.stop_flag.is_set():
            return None
        try:
            with socket.socket(self.socket_family(ip), socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                result = sock.connect_ex((ip, port))
            if result != 0:
                return None
            service = self.get_service_name(port)
            hostname = self.profiles.get(ip, {}).get("hostname", "")
            return {"port": port, "service": service, "banner": self.grab_banner(ip, port, timeout), "tls_cert": self.grab_tls_cert(ip, port, timeout, hostname), "checked_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
        except Exception:
            return None

    def start_scan(self):
        if not self.auth_var.get():
            messagebox.showwarning("Authorization required", "Confirm that you are authorized to scan these IPs.")
            return
        try:
            targets = self.parse_ranges(self.range_entry.get())
            ports = self.parse_ports(self.ports_entry.get()) if self.scan_ports_var.get() else []
            timeout = float(self.timeout_var.get())
            threads = int(self.threads_var.get())
        except Exception as e:
            messagebox.showerror("Invalid input", str(e))
            return
        total_jobs = len(targets) + (len(targets) * len(ports))
        if not targets:
            messagebox.showerror("No targets", "No valid IPs were provided.")
            return
        if total_jobs > MAX_SCAN_JOBS:
            messagebox.showerror("Scan too large", f"This GUI limits scans to {MAX_SCAN_JOBS:,} jobs. Use a smaller range or fewer ports.")
            return
        self.stop_flag.clear()
        self.profiles.clear()
        for ip in targets:
            self.profiles[ip] = self.base_ip_properties(ip)
        self.refresh_table()
        self.progress["value"] = 0
        self.progress["maximum"] = total_jobs
        self.status_var.set(f"Scanning {len(targets)} IPs...")
        threading.Thread(target=self.run_scan, args=(targets, ports, timeout, threads), daemon=True).start()

    def run_scan(self, targets, ports, timeout, threads):
        completed = 0
        max_workers = max(1, min(threads, 1000))
        futures = {}
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            for ip in targets:
                futures[executor.submit(self.enrich_ip, ip)] = ("ip", ip)
            for ip in targets:
                for port in ports:
                    futures[executor.submit(self.scan_port, ip, port, timeout)] = ("port", ip)
            for future in concurrent.futures.as_completed(futures):
                if self.stop_flag.is_set():
                    break
                kind, ip = futures[future]
                try:
                    result = future.result()
                except Exception:
                    result = None
                with self.lock:
                    if kind == "ip" and result:
                        existing_ports = self.profiles.get(ip, {}).get("open_ports", [])
                        self.profiles[ip].update(result)
                        self.profiles[ip]["open_ports"] = existing_ports
                    elif kind == "port" and result:
                        self.profiles[ip]["open_ports"].append(result)
                completed += 1
                if completed % 25 == 0:
                    self.root.after(0, self.update_progress, completed)
                    self.root.after(0, self.update_row, ip)
        self.root.after(0, self.update_progress, completed)
        self.root.after(0, self.refresh_table)
        self.root.after(0, lambda: self.status_var.set("Done." if not self.stop_flag.is_set() else "Stopped."))

    def update_progress(self, completed):
        self.progress["value"] = completed
        self.status_var.set(f"Completed {completed}/{int(self.progress['maximum'])} jobs...")

    def stop_scan(self):
        self.stop_flag.set()
        self.status_var.set("Stopping...")

    def clear_results(self):
        self.stop_flag.set()
        self.profiles.clear()
        for row in self.tree.get_children():
            self.tree.delete(row)
        self.details.delete("1.0", "end")
        self.progress["value"] = 0
        self.status_var.set("Ready.")

    def profile_to_row(self, profile):
        ports = sorted(profile.get("open_ports", []), key=lambda x: x["port"])
        return (profile.get("ip", ""), profile.get("version", ""), profile.get("flags_text", ""), profile.get("hostname", ""), profile.get("provider", ""), profile.get("asn", ""), profile.get("country", ""), ", ".join(str(p["port"]) for p in ports), ", ".join(f'{p["port"]}/{p["service"]}' for p in ports))

    def provider_text(self, profile):
        return " ".join(str(x) for x in [profile.get("provider", ""), profile.get("isp", ""), profile.get("organization", ""), profile.get("asn", ""), json.dumps(profile.get("rdap", {}), default=str)]).lower()

    def update_row(self, ip):
        if ip not in self.profiles:
            return
        profile = self.profiles[ip]
        query = self.filter_var.get().lower().strip()
        provider_query = self.provider_filter_var.get().lower().strip()
        all_text = json.dumps(profile, default=str).lower()
        iid = "ip:" + ip
        if query and query not in all_text:
            if self.tree.exists(iid):
                self.tree.delete(iid)
            return
        if provider_query and provider_query not in self.provider_text(profile):
            if self.tree.exists(iid):
                self.tree.delete(iid)
            return
        if self.tree.exists(iid):
            self.tree.item(iid, values=self.profile_to_row(profile))
        else:
            self.tree.insert("", "end", iid=iid, values=self.profile_to_row(profile))

    def sort_profiles(self):
        mode = self.sort_var.get()
        def key(profile):
            if mode == "IP":
                return ipaddress.ip_address(profile.get("ip", "0.0.0.0"))
            if mode == "Provider":
                return profile.get("provider", "")
            if mode == "ASN":
                return str(profile.get("asn", ""))
            if mode == "Country":
                return profile.get("country", "")
            if mode == "Hostname":
                return profile.get("hostname", "")
            if mode == "Open Ports":
                return len(profile.get("open_ports", []))
            if mode == "Version":
                return int(profile.get("version", 0))
            return profile.get("ip", "")
        return sorted(self.profiles.values(), key=key)

    def refresh_table(self):
        for row in self.tree.get_children():
            self.tree.delete(row)
        query = self.filter_var.get().lower().strip()
        provider_query = self.provider_filter_var.get().lower().strip()
        for profile in self.sort_profiles():
            all_text = json.dumps(profile, default=str).lower()
            if query and query not in all_text:
                continue
            if provider_query and provider_query not in self.provider_text(profile):
                continue
            self.tree.insert("", "end", iid="ip:" + profile["ip"], values=self.profile_to_row(profile))

    def show_selected_details(self, event=None):
        selected = self.tree.selection()
        if not selected:
            return
        iid = selected[0]
        ip = iid[3:] if iid.startswith("ip:") else iid
        self.details.delete("1.0", "end")
        self.details.insert("1.0", json.dumps(self.profiles.get(ip, {}), indent=2, ensure_ascii=False, default=str))

    def normalize_asn(self, value):
        value = value.strip().upper()
        if value.startswith("AS"):
            value = value[2:]
        return value if value.isdigit() else ""

    def local_provider_search(self, query):
        q = query.lower().strip()
        results = []
        exact_asn = self.normalize_asn(query)
        for name, meta in LOCAL_PROVIDER_ASNS.items():
            aliases = [name.lower()] + [a.lower() for a in meta.get("aliases", [])]
            if exact_asn and exact_asn in meta.get("asns", []):
                matched = True
            else:
                matched = any(q in a or a in q for a in aliases)
            if matched:
                for asn in meta.get("asns", []):
                    results.append({"asn": asn, "name": name, "description": "Built-in fallback ASN entry; online lookup may provide fresher data.", "country_code": ""})
        return results

    def search_provider(self):
        query = self.provider_search_var.get().strip()
        if not query:
            messagebox.showerror("Missing query", "Enter a provider name or ASN, for example Cloudflare or AS13335.")
            return
        self.provider_status_var.set("Searching provider/ASN...")
        self.asn_results.clear()
        self.prefix_items.clear()
        for row in self.asn_tree.get_children():
            self.asn_tree.delete(row)
        for row in self.prefix_tree.get_children():
            self.prefix_tree.delete(row)
        threading.Thread(target=self._search_provider_worker, args=(query,), daemon=True).start()

    def _search_provider_worker(self, query):
        asn = self.normalize_asn(query)
        results, prefixes, error = [], [], ""
        used_fallback = False
        try:
            if asn:
                try:
                    info = self.fetch_json(f"https://api.bgpview.io/asn/{asn}", timeout=8)
                    data = info.get("data", {}) or {}
                    results.append({"asn": str(data.get("asn", asn)), "name": data.get("name", ""), "description": data.get("description_short") or data.get("description_full") or "", "country_code": data.get("country_code", "")})
                except Exception as e:
                    error = self.friendly_error(e)
                    results = self.local_provider_search(asn) or [{"asn": asn, "name": f"AS{asn}", "description": "Online ASN lookup unavailable; loaded bare ASN entry.", "country_code": ""}]
                    used_fallback = True
                try:
                    prefixes = self.fetch_asn_prefixes(asn)
                except Exception as e:
                    if not error:
                        error = self.friendly_error(e)
            else:
                try:
                    url = "https://api.bgpview.io/search?query=" + urllib.parse.quote(query)
                    data = self.fetch_json(url, timeout=10).get("data", {}) or {}
                    results = data.get("asns", []) or []
                    raw_prefixes = []
                    raw_prefixes.extend(data.get("ipv4_prefixes", []) or [])
                    raw_prefixes.extend(data.get("ipv6_prefixes", []) or [])
                    prefixes = [self.normalize_prefix_item(p) for p in raw_prefixes if p.get("prefix")]
                except Exception as e:
                    error = self.friendly_error(e)
                    results = self.local_provider_search(query)
                    used_fallback = True
        except Exception as e:
            error = self.friendly_error(e)
            results = self.local_provider_search(query)
            used_fallback = True
        self.root.after(0, self.display_provider_results, results, prefixes, error, used_fallback)

    def fetch_asn_prefixes(self, asn):
        errors = []
        try:
            data = self.fetch_json(f"https://api.bgpview.io/asn/{asn}/prefixes", timeout=12).get("data", {}) or {}
            items = []
            for p in data.get("ipv4_prefixes", []) or []:
                items.append(self.normalize_prefix_item(p, "IPv4"))
            for p in data.get("ipv6_prefixes", []) or []:
                items.append(self.normalize_prefix_item(p, "IPv6"))
            if items:
                return items
        except Exception as e:
            errors.append("BGPView: " + self.friendly_error(e))
        try:
            ripe_url = f"https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{asn}"
            data = self.fetch_json(ripe_url, timeout=12).get("data", {}) or {}
            items = []
            for p in data.get("prefixes", []) or []:
                prefix = p.get("prefix")
                if prefix:
                    items.append(self.normalize_prefix_item({"prefix": prefix, "name": f"AS{asn}", "description": "RIPEstat announced prefix"}))
            if items:
                return items
        except Exception as e:
            errors.append("RIPEstat: " + self.friendly_error(e))
        raise RuntimeError("No online prefix source reachable. " + " | ".join(errors[:3]))

    def normalize_prefix_item(self, item, family=""):
        prefix = item.get("prefix", "")
        if not family:
            try:
                family = "IPv6" if ipaddress.ip_network(prefix, strict=False).version == 6 else "IPv4"
            except Exception:
                family = ""
        return {"prefix": prefix, "family": family, "name": item.get("name", "") or "", "description": item.get("description", "") or item.get("description_short", "") or "", "country_code": item.get("country_code", "") or ""}

    def display_provider_results(self, results, prefixes, error="", used_fallback=False):
        self.asn_results = results
        self.prefix_items = prefixes
        for row in self.asn_tree.get_children():
            self.asn_tree.delete(row)
        for i, item in enumerate(results):
            asn = str(item.get("asn", ""))
            self.asn_tree.insert("", "end", iid=f"asn:{asn or i}", values=(asn, item.get("name", ""), item.get("description", ""), item.get("country_code", "")))
        self.refresh_prefix_tree(prefixes)
        if error and used_fallback:
            self.provider_status_var.set(f"Online lookup unavailable; showing built-in ASN fallback. {error}")
        elif error:
            self.provider_status_var.set(f"Lookup warning: {error}")
        else:
            self.provider_status_var.set(f"Found {len(results)} ASN result(s) and {len(prefixes)} prefix result(s).")

    def load_selected_asn_prefixes(self):
        selected = self.asn_tree.selection()
        if not selected:
            messagebox.showinfo("No ASN selected", "Select an ASN first.")
            return
        values = self.asn_tree.item(selected[0], "values")
        asn = str(values[0]) if values else ""
        if not asn:
            messagebox.showerror("Invalid ASN", "Could not read the selected ASN.")
            return
        self.provider_status_var.set(f"Loading prefixes for AS{asn}...")
        threading.Thread(target=self._load_asn_prefixes_worker, args=(asn,), daemon=True).start()

    def _load_asn_prefixes_worker(self, asn):
        try:
            prefixes = self.fetch_asn_prefixes(asn)
            error = ""
        except Exception as e:
            prefixes = []
            error = self.friendly_error(e)
        self.root.after(0, self.display_prefixes_only, prefixes, error)

    def display_prefixes_only(self, prefixes, error=""):
        self.prefix_items = prefixes
        self.refresh_prefix_tree(prefixes)
        if error:
            self.provider_status_var.set(f"Prefix lookup unavailable: {error}")
        else:
            self.provider_status_var.set(f"Loaded {len(prefixes)} prefix(es).")

    def refresh_prefix_tree(self, prefixes):
        family_filter = self.prefix_family_var.get()
        for row in self.prefix_tree.get_children():
            self.prefix_tree.delete(row)
        visible_count = 0
        for i, item in enumerate(prefixes):
            if family_filter != "Both" and item.get("family") != family_filter:
                continue
            visible_count += 1
            self.prefix_tree.insert("", "end", iid=f"prefix:{i}", values=(item.get("prefix", ""), item.get("family", ""), item.get("name", ""), item.get("description", ""), item.get("country_code", "")))
        if prefixes:
            self.provider_status_var.set(f"Showing {visible_count} prefix(es).")

    def selected_prefixes(self):
        prefixes = []
        for iid in self.prefix_tree.selection():
            values = self.prefix_tree.item(iid, "values")
            if values:
                prefixes.append(values[0])
        return prefixes

    def add_selected_prefixes_to_scanner(self):
        prefixes = self.selected_prefixes()
        if not prefixes:
            messagebox.showinfo("No prefixes selected", "Select one or more prefixes first.")
            return
        current = self.range_entry.get().strip()
        self.range_entry.delete(0, "end")
        self.range_entry.insert(0, (current + ", " if current else "") + ", ".join(prefixes))
        self.notebook.select(self.scanner_tab)
        self.status_var.set(f"Added {len(prefixes)} prefix(es) to scanner input.")

    def scan_selected_prefixes(self):
        prefixes = self.selected_prefixes()
        if not prefixes:
            messagebox.showinfo("No prefixes selected", "Select one or more prefixes first.")
            return
        self.range_entry.delete(0, "end")
        self.range_entry.insert(0, ", ".join(prefixes))
        self.notebook.select(self.scanner_tab)
        self.start_scan()

    def export_csv(self):
        if not self.profiles:
            messagebox.showinfo("No results", "There are no results to export.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv")])
        if not path:
            return
        with open(path, "w", newline="", encoding="utf-8") as f:
            fields = ["ip", "version", "flags", "hostname", "forward_dns", "provider", "asn", "country", "region", "city", "timezone", "latitude", "longitude", "isp", "organization", "open_ports", "services", "last_checked"]
            writer = csv.DictWriter(f, fieldnames=fields)
            writer.writeheader()
            for profile in self.sort_profiles():
                ports = sorted(profile.get("open_ports", []), key=lambda x: x["port"])
                writer.writerow({"ip": profile.get("ip", ""), "version": profile.get("version", ""), "flags": profile.get("flags_text", ""), "hostname": profile.get("hostname", ""), "forward_dns": "; ".join(profile.get("forward_dns", [])), "provider": profile.get("provider", ""), "asn": profile.get("asn", ""), "country": profile.get("country", ""), "region": profile.get("region", ""), "city": profile.get("city", ""), "timezone": profile.get("timezone", ""), "latitude": profile.get("latitude", ""), "longitude": profile.get("longitude", ""), "isp": profile.get("isp", ""), "organization": profile.get("organization", ""), "open_ports": ", ".join(str(p["port"]) for p in ports), "services": ", ".join(f'{p["port"]}/{p["service"]}' for p in ports), "last_checked": profile.get("last_checked", "")})
        messagebox.showinfo("Exported", f"Saved CSV to:\n{path}")

    def export_json(self):
        if not self.profiles:
            messagebox.showinfo("No results", "There are no results to export.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON files", "*.json")])
        if not path:
            return
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.profiles, f, indent=2, ensure_ascii=False, default=str)
        messagebox.showinfo("Exported", f"Saved JSON to:\n{path}")

if __name__ == "__main__":
    root = tk.Tk()
    app = IPScannerGUI(root)
    root.mainloop()
