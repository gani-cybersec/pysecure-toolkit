
import tkinter as tk
from tkinter import ttk, messagebox
import threading

from modules.port_scanner import scan_ports
from modules.url_analyzer import analyze_domain
from modules.http_analyzer import analyze_http


class NetSentryApp:

    def __init__(self, root):

        self.root = root
        self.root.title("NetSentry | Cybersecurity Assessment Toolkit")
        self.root.geometry("1000x700")
        self.root.minsize(820, 580)
        self.root.configure(bg="#101820")

        # ================= STYLE =================

        style = ttk.Style()
        style.theme_use("clam")

        style.configure(
            "TNotebook",
            background="#101820",
            borderwidth=0
        )

        style.configure(
            "TNotebook.Tab",
            background="#263746",
            foreground="white",
            padding=(18, 10),
            font=("Segoe UI", 10, "bold")
        )

        style.map(
            "TNotebook.Tab",
            background=[("selected", "#087E8B")]
        )

        style.configure(
            "TLabel",
            background="#101820",
            foreground="#EAF2F8",
            font=("Segoe UI", 10)
        )

        style.configure(
            "Header.TLabel",
            font=("Segoe UI", 21, "bold"),
            foreground="#35C6CD"
        )

        style.configure(
            "TButton",
            font=("Segoe UI", 10, "bold"),
            padding=8
        )

        style.configure("TEntry", padding=6)

        # ================= HEADER =================

        header = ttk.Frame(root, padding=(20, 16))
        header.pack(fill="x")

        ttk.Label(
            header,
            text="NETSENTRY",
            style="Header.TLabel"
        ).pack(anchor="w")

        ttk.Label(
            header,
            text="Cybersecurity Assessment Toolkit | Use only on systems you own or are authorized to test.",
            wraplength=900
        ).pack(anchor="w", pady=(4, 0))

        # ================= NOTEBOOK =================

        self.notebook = ttk.Notebook(root)

        self.notebook.pack(
            fill="both",
            expand=True,
            padx=18,
            pady=(0, 18)
        )

        self.port_tab = ttk.Frame(
            self.notebook,
            padding=16
        )

        self.url_tab = ttk.Frame(
            self.notebook,
            padding=16
        )

        self.http_tab = ttk.Frame(
            self.notebook,
            padding=16
        )

        self.notebook.add(
            self.port_tab,
            text="Port Scanner"
        )

        self.notebook.add(
            self.url_tab,
            text="URL / DNS Analyzer"
        )

        self.notebook.add(
            self.http_tab,
            text="HTTP Analyzer"
        )

        # Build all tabs

        self._build_port_tab()
        self._build_url_tab()
        self._build_http_tab()

    # ================= OUTPUT AREA =================

    def _make_output(self, parent):

        frame = ttk.Frame(parent)

        # Pack is used only inside this separate frame
        frame.pack(
            fill="both",
            expand=True
        )

        output = tk.Text(
            frame,
            wrap="word",
            bg="#0B1118",
            fg="#D7E3EA",
            insertbackground="white",
            font=("Consolas", 10),
            relief="flat",
            padx=12,
            pady=12
        )

        scrollbar = ttk.Scrollbar(
            frame,
            command=output.yview
        )

        output.configure(
            yscrollcommand=scrollbar.set
        )

        output.pack(
            side="left",
            fill="both",
            expand=True
        )

        scrollbar.pack(
            side="right",
            fill="y"
        )

        return output

    # ================= PORT SCANNER TAB =================

    def _build_port_tab(self):

        f = self.port_tab

        ttk.Label(
            f,
            text="Target host (IP address or hostname)"
        ).grid(row=0, column=0, sticky="w")

        self.port_host = ttk.Entry(f, width=38)

        self.port_host.grid(
            row=1,
            column=0,
            sticky="ew",
            padx=(0, 12),
            pady=5
        )

        self.port_host.insert(0, "127.0.0.1")

        ttk.Label(
            f,
            text="Ports (e.g. 1-1024 or 22,80,443)"
        ).grid(row=0, column=1, sticky="w")

        self.port_range = ttk.Entry(f, width=30)

        self.port_range.grid(
            row=1,
            column=1,
            sticky="ew",
            pady=5
        )

        self.port_range.insert(0, "1-1024")

        ttk.Label(
            f,
            text="Timeout per port (seconds)"
        ).grid(
            row=2,
            column=0,
            sticky="w",
            pady=(8, 0)
        )

        self.port_timeout = ttk.Entry(f, width=12)

        self.port_timeout.grid(
            row=3,
            column=0,
            sticky="w",
            pady=5
        )

        self.port_timeout.insert(0, "0.5")

        self.port_button = ttk.Button(
            f,
            text="Start Port Scan",
            command=self._start_port_scan
        )

        self.port_button.grid(
            row=3,
            column=1,
            sticky="w",
            pady=5
        )

        f.columnconfigure(0, weight=1)
        f.columnconfigure(1, weight=1)
        f.rowconfigure(4, weight=1)

        # FIX: Separate output frame managed using grid

        output_frame = ttk.Frame(f)

        output_frame.grid(
            row=4,
            column=0,
            columnspan=2,
            sticky="nsew",
            pady=(14, 0)
        )

        self.port_output = self._make_output(
            output_frame
        )

    # ================= URL ANALYZER TAB =================

    def _build_url_tab(self):

        f = self.url_tab

        ttk.Label(
            f,
            text="Domain name (e.g. example.com)"
        ).pack(anchor="w")

        self.url_domain = ttk.Entry(f)

        self.url_domain.pack(
            fill="x",
            pady=5
        )

        self.url_domain.insert(
            0,
            "example.com"
        )

        self.url_button = ttk.Button(
            f,
            text="Analyze Domain",
            command=self._start_url_analysis
        )

        self.url_button.pack(
            anchor="w",
            pady=5
        )

        self.url_output = self._make_output(f)

    # ================= HTTP ANALYZER TAB =================

    def _build_http_tab(self):

        f = self.http_tab

        ttk.Label(
            f,
            text="Website URL (include https:// or http://)"
        ).pack(anchor="w")

        self.http_url = ttk.Entry(f)

        self.http_url.pack(
            fill="x",
            pady=5
        )

        self.http_url.insert(
            0,
            "https://example.com"
        )

        self.http_button = ttk.Button(
            f,
            text="Analyze HTTP Security",
            command=self._start_http_analysis
        )

        self.http_button.pack(
            anchor="w",
            pady=5
        )

        self.http_output = self._make_output(f)

    # ================= BACKGROUND THREAD =================

    def _run_in_thread(self, button, output, task):

        button.configure(state="disabled")

        output.delete("1.0", "end")

        output.insert(
            "end",
            "Working... Please wait.\n"
        )

        def worker():

            try:

                result = task()

            except Exception as exc:

                result = f"Error: {exc}"

            self.root.after(
                0,
                lambda result=result: self._show_result(
                    button,
                    output,
                    result
                )
            )

        threading.Thread(
            target=worker,
            daemon=True
        ).start()

    # ================= DISPLAY RESULTS =================

    def _show_result(self, button, output, result):

        output.delete("1.0", "end")

        output.insert(
            "end",
            str(result)
        )

        button.configure(state="normal")

    # ================= START PORT SCAN =================

    def _start_port_scan(self):

        host = self.port_host.get().strip()

        ports = self.port_range.get().strip()

        try:

            timeout = float(
                self.port_timeout.get().strip()
            )

            if not 0.05 <= timeout <= 10:
                raise ValueError

        except ValueError:

            messagebox.showerror(
                "Invalid timeout",
                "Enter a timeout between 0.05 and 10 seconds."
            )

            return

        if not host or not ports:

            messagebox.showerror(
                "Missing input",
                "Enter a host and port range."
            )

            return

        authorized = messagebox.askyesno(
            "Authorization",
            "Only scan systems you own or have explicit permission to test. Continue?"
        )

        if not authorized:
            return

        self._run_in_thread(
            self.port_button,
            self.port_output,
            lambda: scan_ports(
                host,
                ports,
                timeout
            )
        )

    # ================= START URL ANALYSIS =================

    def _start_url_analysis(self):

        domain = self.url_domain.get().strip()

        if not domain:

            messagebox.showerror(
                "Missing input",
                "Enter a domain."
            )

            return

        self._run_in_thread(
            self.url_button,
            self.url_output,
            lambda: analyze_domain(domain)
        )

    # ================= START HTTP ANALYSIS =================

    def _start_http_analysis(self):

        url = self.http_url.get().strip()

        if not url:

            messagebox.showerror(
                "Missing input",
                "Enter a URL."
            )

            return

        self._run_in_thread(
            self.http_button,
            self.http_output,
            lambda: analyze_http(url)
        )


# ================= MAIN =================

if __name__ == "__main__":

    root = tk.Tk()

    app = NetSentryApp(root)

    root.mainloop()
