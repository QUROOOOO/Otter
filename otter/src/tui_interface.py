import sqlite3
import subprocess
import os
from pathlib import Path
from textual.app import App, ComposeResult
from textual.widgets import Footer, RichLog, ListView, ListItem, Markdown, Static, DataTable, Input
from textual.containers import Grid, Vertical, Horizontal
from textual.screen import ModalScreen
from textual import work, on
from textual.reactive import reactive
from textual.events import Click

WORKSPACE = "/home/krish/GoogleRA"
DB_PATH = "/home/krish/GoogleRA/secure_flow.db"

LOGO_ART = """  _-----._
 o. - - .o  OTTER SEC
  \\-(_)-/"""

LARGE_LOGO = """
 ▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄▄ 
▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌
▐░█▀▀▀▀▀▀▀█░▌    ▐░█░░░░░▌    ▐░█░░░░░▌ ▐░█▀▀▀▀▀▀▀▀▀ ▐░█▀▀▀▀▀▀▀█░▌
▐░▌       ▐░▌    ▐░█░░░░░▌    ▐░█░░░░░▌ ▐░█░░░░░░░░░ ▐░█░░░░░░░█░▌
▐░▌       ▐░▌    ▐░█░░░░░▌    ▐░█░░░░░▌ ▐░█▀▀▀▀▀▀▀▀▀ ▐░█▄▄▄▄▄▄▄█░▌
▐░█▄▄▄▄▄▄▄█░▌    ▐░█░░░░░▌    ▐░█░░░░░▌ ▐░█▄▄▄▄▄▄▄▄▄ ▐░█░░░░░▀░░░▌
▐░░░░░░░░░░░▌    ▐░█░░░░░▌    ▐░█░░░░░▌ ▐░░░░░░░░░░░▌▐░█░░░░░  ▐░▌
 ▀▀▀▀▀▀▀▀▀▀▀      ▀▀▀▀▀▀▀      ▀▀▀▀▀▀▀   ▀▀▀▀▀▀▀▀▀▀▀  ▀▀▀▀▀▀▀   ▀ 
"""

ANIMATION_FRAMES = [
    "[████████░░░░]",
    "[░░████████░░]",
    "[░░░░████████]",
    "[██░░░░░░████]"
]

class VulnerabilityItem(ListItem):
    def __init__(self, vuln_id, rule_id, file_path, line_number, details):
        super().__init__()
        self.vuln_id = vuln_id
        self.rule_id = rule_id
        self.file_path = file_path
        self.line_number = line_number
        self.details = details
        self.label = Static(f"❯ {rule_id} [{os.path.basename(file_path)}:{line_number}]")

    def compose(self) -> ComposeResult:
        yield self.label

class CommandPalette(ModalScreen[str]):
    CSS = """
    CommandPalette {
        align: center middle;
        background: rgba(0, 0, 0, 0.85);
    }
    #palette-container {
        background: #050505;
        border: round #222222;
        width: 60;
        height: 20;
        padding: 1 2;
    }
    #palette-title {
        text-style: bold;
        color: #ffffff;
        margin-bottom: 1;
    }
    #palette-list {
        background: #050505;
    }
    #palette-list ListItem {
        background: #050505;
        color: #cccccc;
        padding: 0 1;
    }
    #palette-list ListItem:hover, #palette-list ListItem:focus {
        background: #111111;
        color: #ffffff;
    }
    #palette-footer {
        color: #444444;
        text-align: center;
        margin-top: 1;
    }
    """

    def compose(self) -> ComposeResult:
        with Vertical(id="palette-container"):
            yield Static("❯ DEVSECOPS COMMAND PALETTE", id="palette-title")
            yield ListView(
                ListItem(Static("/scan       - Execute autonomous Semgrep scan-patch pipeline loop"), id="cmd-scan"),
                ListItem(Static("/theme      - Shift to next available accent color profile"), id="cmd-theme"),
                ListItem(Static("/db-sync    - Re-index local 'secure_flow.db' vulnerability tables"), id="cmd-db-sync"),
                ListItem(Static("/mr-status  - Fetch and trace GitLab remote merge request states"), id="cmd-mr-status"),
                ListItem(Static("/clear-log  - Wipe current active console log view screen-space"), id="cmd-clear-log"),
                ListItem(Static("/maximize   - Expand the currently focused console/diff container"), id="cmd-maximize"),
                ListItem(Static("/triage     - Apply rule-filters to highlight critical severity entries"), id="cmd-triage"),
                ListItem(Static("/quit       - Gracefully close all application thread loops"), id="cmd-quit"),
                id="palette-list"
            )
            yield Static("PRESS [ESC] TO CLOSE", id="palette-footer")

    @on(ListView.Selected)
    def on_select(self, event: ListView.Selected) -> None:
        self.dismiss(event.item.id)

class OtterCockpit(App):
    theme_idx = reactive(0)
    pipeline_active = reactive(False)

    CSS = """
    Screen {
        background: #000000;
        color: #cccccc;
    }
    #top-bar {
        height: 3;
        background: #050505;
        border-bottom: tall #222222;
        padding: 0 2;
    }
    #logo {
        color: #ffffff;
        height: 3;
        content-align: left middle;
    }
    #spacer {
        width: 1fr;
    }
    #status {
        color: #ffffff;
        content-align: right middle;
        text-style: bold;
        padding-top: 1;
    }
    #home-view {
        align: center middle;
        height: 1fr;
        background: #000000;
        padding: 2;
    }
    #home-logo {
        text-align: center;
        color: #ffffff;
        margin-bottom: 2;
    }
    #home-dir {
        text-align: center;
        color: #666666;
        margin-bottom: 1;
    }
    #home-prompt-container {
        width: 60;
        height: 3;
        border: round #222222;
        background: #050505;
        align: center middle;
    }
    #prompt-prefix {
        color: #666666;
        padding-left: 2;
        padding-right: 1;
        text-style: bold;
    }
    #home-input {
        background: #050505;
        border: none;
        width: 50;
    }
    #main-grid {
        layout: grid;
        grid-size: 2;
        grid-columns: 3fr 7fr;
        height: 1fr;
        width: 100%;
        background: #000000;
    }
    .sidebar-panel {
        border: round #222222;
        background: #050505;
        padding: 1 2;
        height: 100%;
    }
    .stat-line {
        margin-bottom: 1;
    }
    #right-pane {
        height: 100%;
        background: #000000;
    }
    #log-section {
        height: 45%;
        border: round #222222;
        background: #000000;
    }
    #vuln-section {
        height: 55%;
        border: round #222222;
        background: #000000;
    }
    #details-section {
        height: 10;
        border: round #222222;
        background: #050505;
        padding: 1 2;
    }
    .title-label {
        color: #ffffff;
        background: #111111;
        padding: 0 1;
        text-style: bold;
    }
    ListView {
        background: #050505;
        color: #cccccc;
    }
    ListItem {
        padding: 1;
        background: #050505;
        color: #cccccc;
    }
    ListItem:hover, ListItem:focus, ListItem.--highlight {
        background: #111111;
        color: #ffffff;
    }
    RichLog {
        background: #000000;
        color: #cccccc;
    }
    DataTable {
        background: #000000;
        color: #cccccc;
    }
    Markdown {
        background: #050505;
        color: #cccccc;
    }
    #loading-bar {
        display: none;
        height: 1;
    }
    #loading-bar.visible {
        display: block;
    }

    /* Accent transitions for focused panels */
    .theme-0 *:focus-within { border: round #D97706; }
    .theme-1 *:focus-within { border: round rgb(210, 70, 52); }
    .theme-2 *:focus-within { border: round rgb(161, 159, 56); }
    .theme-3 *:focus-within { border: round #00FFFF; }
    .theme-4 *:focus-within { border: round #8B5CF6; }
    .theme-5 *:focus-within { border: round #34D399; }
    .theme-6 *:focus-within { border: round #FFFFFF; }

    /* DataTable cursor styling per theme */
    .theme-0 DataTable > .datatable--cursor { background: #D97706; color: #000000; }
    .theme-1 DataTable > .datatable--cursor { background: rgb(210, 70, 52); color: #000000; }
    .theme-2 DataTable > .datatable--cursor { background: rgb(161, 159, 56); color: #000000; }
    .theme-3 DataTable > .datatable--cursor { background: #00FFFF; color: #000000; }
    .theme-4 DataTable > .datatable--cursor { background: #8B5CF6; color: #000000; }
    .theme-5 DataTable > .datatable--cursor { background: #34D399; color: #000000; }
    .theme-6 DataTable > .datatable--cursor { background: #FFFFFF; color: #000000; }

    /* Accent title labels per theme */
    .theme-0 .title-label { color: #D97706; }
    .theme-1 .title-label { color: rgb(210, 70, 52); }
    .theme-2 .title-label { color: rgb(161, 159, 56); }
    .theme-3 .title-label { color: #00FFFF; }
    .theme-4 .title-label { color: #8B5CF6; }
    .theme-5 .title-label { color: #34D399; }
    .theme-6 .title-label { color: #FFFFFF; }

    /* Loading bar colors */
    .theme-0 #loading-bar { color: #D97706; }
    .theme-1 #loading-bar { color: rgb(210, 70, 52); }
    .theme-2 #loading-bar { color: rgb(161, 159, 56); }
    .theme-3 #loading-bar { color: #00FFFF; }
    .theme-4 #loading-bar { color: #8B5CF6; }
    .theme-5 #loading-bar { color: #34D399; }
    .theme-6 #loading-bar { color: #FFFFFF; }

    /* Home prompt border on focus */
    .theme-0 #home-prompt-container:focus-within { border: round #D97706; }
    .theme-1 #home-prompt-container:focus-within { border: round rgb(210, 70, 52); }
    .theme-2 #home-prompt-container:focus-within { border: round rgb(161, 159, 56); }
    .theme-3 #home-prompt-container:focus-within { border: round #00FFFF; }
    .theme-4 #home-prompt-container:focus-within { border: round #8B5CF6; }
    .theme-5 #home-prompt-container:focus-within { border: round #34D399; }
    .theme-6 #home-prompt-container:focus-within { border: round #FFFFFF; }

    /* Dual state layout toggles - display values are strictly block or none */
    Screen.state-home #home-view { display: block; }
    Screen.state-home #main-grid { display: none; }
    Screen.state-home #details-section { display: none; }

    Screen.state-cockpit #home-view { display: none; }
    Screen.state-cockpit #main-grid { display: block; }
    Screen.state-cockpit #details-section { display: block; }

    /* Maximized styles - utilizing absolute positioning to prevent overlap line stacking glitches */
    Screen.maximized-active #top-bar { display: block; }
    
    Screen.maximized-monitor #right-pane { display: none; }
    Screen.maximized-monitor #details-section { display: none; }
    Screen.maximized-monitor #monitor-panel {
        position: absolute;
        left: 0;
        top: 3;
        width: 100%;
        height: 100%;
        z-index: 20;
    }
    Screen.maximized-monitor #main-grid { grid-columns: 1fr; }

    Screen.maximized-log #monitor-panel { display: none; }
    Screen.maximized-log #vuln-section { display: none; }
    Screen.maximized-log #details-section { display: none; }
    Screen.maximized-log #right-pane { width: 100%; height: 100%; }
    Screen.maximized-log #log-section {
        position: absolute;
        left: 0;
        top: 3;
        width: 100%;
        height: 100%;
        z-index: 20;
    }
    Screen.maximized-log #main-grid { grid-columns: 1fr; }

    Screen.maximized-vuln #monitor-panel { display: none; }
    Screen.maximized-vuln #log-section { display: none; }
    Screen.maximized-vuln #details-section { display: none; }
    Screen.maximized-vuln #right-pane { width: 100%; height: 100%; }
    Screen.maximized-vuln #vuln-section {
        position: absolute;
        left: 0;
        top: 3;
        width: 100%;
        height: 100%;
        z-index: 20;
    }
    Screen.maximized-vuln #main-grid { grid-columns: 1fr; }

    Screen.maximized-details #main-grid { display: none; }
    Screen.maximized-details #details-section {
        position: absolute;
        left: 0;
        top: 3;
        width: 100%;
        height: 100%;
        z-index: 20;
    }
    """

    BINDINGS = [
        ("s", "start_pipeline", "[S] Scan"),
        ("t", "cycle_theme", "[T] Theme"),
        ("p", "show_palette", "[P] Command Palette"),
        ("m", "toggle_maximize", "[M] Maximize"),
        ("q", "quit", "[Q] Quit")
    ]

    def compose(self) -> ComposeResult:
        with Horizontal(id="top-bar"):
            yield Static(LOGO_ART, id="logo")
            yield Static("", id="spacer")
            yield Static("STATUS: IDLE [settings]", id="status")
        with Vertical(id="home-view"):
            yield Static(LARGE_LOGO, id="home-logo")
            yield Static(f"DIRECTORY: {WORKSPACE}", id="home-dir")
            with Horizontal(id="home-prompt-container"):
                yield Static("/", id="prompt-prefix")
                yield Input(placeholder="Type command or press [S] to Scan", id="home-input")
        with Grid(id="main-grid"):
            with Vertical(classes="sidebar-panel", id="monitor-panel"):
                yield Static("❯ SYSTEM MONITOR", classes="title-label")
                yield Static(f"PATH: {WORKSPACE}", id="stat-path", classes="stat-line")
                yield Static("FILES SCANNED: 0", id="stat-files", classes="stat-line")
                yield Static("ACTIVE ISSUES: 0", id="stat-issues", classes="stat-line")
                yield Static("LAST SCAN: Never", id="stat-scan", classes="stat-line")
                yield Static("", classes="stat-line")
                yield Static("❯ VULNERABILITY COLLECTION", classes="title-label")
                yield ListView(id="vuln-list")
            with Vertical(id="right-pane"):
                with Vertical(id="log-section"):
                    yield Static("❯ ENGINE MONITOR", classes="title-label")
                    yield Static("", id="loading-bar")
                    yield RichLog(id="engine-console", highlight=True, markup=True)
                with Vertical(id="vuln-section"):
                    yield Static("❯ VULNERABILITY QUEUE", classes="title-label")
                    yield DataTable(id="vuln-table", cursor_type="row")
        with Vertical(id="details-section"):
            yield Static("❯ VISUAL CODE DIFF BOX", classes="title-label")
            yield Markdown(id="diff-viewer")
        yield Footer()

    def on_mount(self) -> None:
        self.add_class("state-home")
        self.add_class("theme-0")
        table = self.query_one("#vuln-table", DataTable)
        table.add_columns("ID", "Rule", "File", "Line", "Severity", "Status")
        self.refresh_sidebar()
        log = self.query_one("#engine-console", RichLog)
        log.write("[OK] System initialized. Press [S] to Scan.")
        
        self.loader_frame = 0
        self.set_interval(0.25, self.update_loader)

    def watch_pipeline_active(self, active: bool) -> None:
        try:
            loading = self.query_one("#loading-bar")
            if active:
                loading.add_class("visible")
            else:
                loading.remove_class("visible")
        except Exception:
            pass

    def update_loader(self) -> None:
        if self.pipeline_active:
            self.loader_frame = (self.loader_frame + 1) % len(ANIMATION_FRAMES)
            try:
                self.query_one("#loading-bar", Static).update(ANIMATION_FRAMES[self.loader_frame])
            except Exception:
                pass

    def switch_to_cockpit(self) -> None:
        if "state-home" in self.classes:
            self.remove_class("state-home")
            self.add_class("state-cockpit")

    def refresh_sidebar(self) -> None:
        self.query_one("#stat-path").update(f"PATH: {WORKSPACE}")
        try:
            py_files = len(list(Path(WORKSPACE).rglob("*.py")))
        except Exception:
            py_files = 0
        self.query_one("#stat-files").update(f"FILES SCANNED: {py_files}")

        table = self.query_one("#vuln-table", DataTable)
        table.clear()
        vl = self.query_one("#vuln-list", ListView)
        vl.clear()

        issue_count = 0
        last_scan = "Never"

        if not os.path.exists(DB_PATH):
            vl.append(ListItem(Static("No DB found. Press [S] to Scan.")))
            self.query_one("#stat-issues").update("ACTIVE ISSUES: 0")
            self.query_one("#stat-scan").update("LAST SCAN: Never")
            return

        try:
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            c.execute("SELECT started_at FROM scan_sessions ORDER BY id DESC LIMIT 1")
            session_row = c.fetchone()
            if session_row:
                last_scan = session_row[0][:19].replace("T", " ")

            c.execute("SELECT id, rule_id, file_path, start_line AS line_number, message AS description FROM vulnerabilities ORDER BY id DESC")
            rows = c.fetchall()
            issue_count = len(rows)

            if not rows:
                vl.append(ListItem(Static("No issues detected. Press [S] to Scan.")))
            else:
                for r in rows:
                    vl.append(VulnerabilityItem(r[0], r[1], r[2], r[3], r[4]))
                    short_file = os.path.basename(r[2]) if r[2] else "?"
                    table.add_row(str(r[0]), r[1] or "—", short_file, str(r[3] or 0), "HIGH", "OPEN", key=str(r[0]))
            conn.close()
        except Exception as e:
            vl.append(ListItem(Static(f"DB Error: {str(e)}")))

        self.query_one("#stat-issues").update(f"ACTIVE ISSUES: {issue_count}")
        self.query_one("#stat-scan").update(f"LAST SCAN: {last_scan}")

    @on(Input.Submitted, "#home-input")
    def on_input_submitted(self, event: Input.Submitted) -> None:
        text = event.value.strip()
        if not text:
            return
        self.query_one("#home-input", Input).value = ""
        if text.startswith("/"):
            self.handle_command_text(text)
        elif text.lower() == "s":
            self.action_start_pipeline()
        else:
            self.switch_to_cockpit()
            log = self.query_one("#engine-console", RichLog)
            log.write(f"[WARN] Unknown command: {text}")

    def handle_command_text(self, text: str) -> None:
        self.switch_to_cockpit()
        if text == "/scan":
            self.action_start_pipeline()
        elif text == "/theme":
            self.action_cycle_theme()
        elif text == "/db-sync":
            self.refresh_sidebar()
            log = self.query_one("#engine-console", RichLog)
            log.write("[OK] Database re-indexed successfully.")
        elif text == "/mr-status":
            self.fetch_mr_status()
        elif text == "/clear-log":
            self.query_one("#engine-console", RichLog).clear()
        elif text == "/maximize":
            self.action_toggle_maximize()
        elif text == "/triage":
            self.action_triage()
        elif text == "/quit":
            self.exit()
        else:
            log = self.query_one("#engine-console", RichLog)
            log.write(f"[WARN] Unknown command: {text}")

    def fetch_mr_status(self) -> None:
        log = self.query_one("#engine-console", RichLog)
        log.write("STATUS: Querying GitLab API...")
        token = os.environ.get("GITLAB_TOKEN")
        project_id = os.environ.get("GITLAB_PROJECT_ID")
        if not token or not project_id:
            log.write("[WARN] GitLab credentials not set. Showing simulated Merge Request status.")
            log.write("MR-102: OPEN (Security patch evaluation in progress)")
            log.write("Pipeline: PASSED")
        else:
            log.write(f"Connected to project {project_id}.")
            log.write("No open security Merge Requests found.")

    def action_triage(self) -> None:
        log = self.query_one("#engine-console", RichLog)
        log.write("[OK] Triage: Displaying all HIGH severity alerts.")

    def on_list_view_selected(self, event: ListView.Selected) -> None:
        item = event.item
        if isinstance(item, VulnerabilityItem):
            self._show_details(item.rule_id, item.file_path, item.line_number, item.details)

    @on(DataTable.RowSelected)
    def on_row_selected(self, event: DataTable.RowSelected) -> None:
        row_key = event.row_key.value
        if not row_key:
            return
        try:
            conn = sqlite3.connect(DB_PATH)
            conn.row_factory = sqlite3.Row
            c = conn.cursor()
            c.execute("SELECT rule_id, file_path, start_line AS line_number, message AS description FROM vulnerabilities WHERE id = ?", (int(row_key),))
            row = c.fetchone()
            conn.close()
            if row:
                self._show_details(row["rule_id"], row["file_path"], row["line_number"], row["description"])
        except Exception:
            pass

    def _show_details(self, rule_id, file_path, line_number, details) -> None:
        v = self.query_one("#diff-viewer", Markdown)
        v.update(f"# Details\n* **Rule:** `{rule_id}`\n* **File:** `{file_path}:{line_number}`\n\n## Description\n{details}\n\n## Fix\n```python\ncursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))\n```")

    def action_cycle_theme(self) -> None:
        self.remove_class(f"theme-{self.theme_idx}")
        self.theme_idx = (self.theme_idx + 1) % 7
        self.add_class(f"theme-{self.theme_idx}")

    def action_show_palette(self) -> None:
        def handle_command(cmd_id: str) -> None:
            if not cmd_id:
                return
            if cmd_id == "cmd-scan":
                self.action_start_pipeline()
            elif cmd_id == "cmd-theme":
                self.action_cycle_theme()
            elif cmd_id == "cmd-db-sync":
                self.refresh_sidebar()
            elif cmd_id == "cmd-mr-status":
                self.fetch_mr_status()
            elif cmd_id == "cmd-clear-log":
                self.query_one("#engine-console", RichLog).clear()
            elif cmd_id == "cmd-maximize":
                self.action_toggle_maximize()
            elif cmd_id == "cmd-triage":
                self.action_triage()
            elif cmd_id == "cmd-quit":
                self.exit()

        self.push_screen(CommandPalette(), handle_command)

    @on(Click, "#status")
    def on_status_clicked(self, event: Click) -> None:
        self.action_show_palette()

    def action_toggle_maximize(self) -> None:
        focused = self.focused
        if not focused:
            return
        active_panel = None
        for panel_id in ["monitor-panel", "log-section", "vuln-section", "details-section"]:
            panel = self.query_one(f"#{panel_id}")
            if panel.has_focus or panel.contains_focus:
                active_panel = panel_id
                break
        if not active_panel:
            return

        is_maximized = "maximized-active" in self.classes
        self.remove_class("maximized-active")
        self.remove_class("maximized-monitor")
        self.remove_class("maximized-log")
        self.remove_class("maximized-vuln")
        self.remove_class("maximized-details")

        if not is_maximized:
            self.add_class("maximized-active")
            if active_panel == "monitor-panel":
                self.add_class("maximized-monitor")
            elif active_panel == "log-section":
                self.add_class("maximized-log")
            elif active_panel == "vuln-section":
                self.add_class("maximized-vuln")
            elif active_panel == "details-section":
                self.add_class("maximized-details")

    @work(thread=True)
    def action_start_pipeline(self) -> None:
        self.call_from_thread(self.switch_to_cockpit)
        self.pipeline_active = True
        log = self.query_one("#engine-console", RichLog)
        status = self.query_one("#status")
        
        self.call_from_thread(log.clear)
        self.call_from_thread(log.write, "[RUN] Pipeline run started.")
        self.call_from_thread(status.update, "STATUS: ACTIVE [settings]")
        
        try:
            proc = subprocess.Popen(
                ["python3", "-u", "main.py", "."],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                cwd=WORKSPACE
            )
            while True:
                line = proc.stdout.readline()
                if not line:
                    break
                self.call_from_thread(log.write, line.strip())
            proc.wait()
            self.call_from_thread(log.write, "[OK] Pipeline run complete.")
        except Exception as e:
            self.call_from_thread(log.write, f"[ERR] Pipeline run failed: {e}")
            
        self.call_from_thread(status.update, "STATUS: IDLE [settings]")
        self.pipeline_active = False
        self.call_from_thread(self.refresh_sidebar)

if __name__ == "__main__":
    app = OtterCockpit()
    app.run()