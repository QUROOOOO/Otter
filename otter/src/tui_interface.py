"""Otter TUI Interface.

Minimalist Terminal Dashboard for the Otter Autonomous Remediation Pipeline.
"""

from __future__ import annotations

import sys
import logging
from pathlib import Path
from typing import Any, Dict

# Insert root project directory into path so imports resolve dynamically 
# no matter where the script is executed from
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from textual import on, work
from textual.app import App, ComposeResult
from textual.containers import Grid, Vertical
from textual.widgets import Header, Footer, ListView, ListItem, Label, RichLog, Static

# Project Internal Imports
from otter.config import get_connection
import main as otter_main


class RichLogStream:
    """A custom file-like stream that redirects stdout/logging directly into a Textual RichLog widget."""
    
    def __init__(self, rich_log_widget: RichLog, app: App) -> None:
        self.rich_log = rich_log_widget
        self.app = app
        self._original_stdout = sys.stdout

    def write(self, text: str) -> None:
        if text.strip():
            # Schedule UI update thread-safely
            self.app.call_from_thread(self.rich_log.write, text.strip())
        self._original_stdout.write(text)

    def flush(self) -> None:
        self._original_stdout.flush()


class OtterTUI(App):
    """Otter Cockpit: Minimalist TUI Panel."""

    # Explicit Monochrome Minimalism CSS Layer
    CSS = """
    Screen {
        background: #000000;
        color: #FFFFFF;
    }

    #main_grid {
        grid-size: 2 1;
        grid-columns: 3fr 7fr;
        width: 100%;
        height: 100%;
    }

    #sidebar_pane {
        width: 100%;
        height: 100%;
        border-right: solid #FFFFFF;
        padding: 1;
    }

    #right_pane {
        width: 100%;
        height: 100%;
    }

    #console_pane {
        width: 100%;
        height: 40%;
        border-bottom: solid #FFFFFF;
        padding: 1;
    }

    #diff_pane {
        width: 100%;
        height: 60%;
        padding: 1;
    }

    ListView {
        background: #000000;
        color: #FFFFFF;
    }

    ListItem {
        padding: 1;
        background: #000000;
        color: #FFFFFF;
    }

    /* Inverted Block Highlight for Selection */
    ListItem:hover, ListItem:focus, ListItem.--highlight {
        background: #FFFFFF;
        color: #000000;
    }

    RichLog {
        background: #000000;
        color: #FFFFFF;
    }

    Static {
        background: #000000;
        color: #FFFFFF;
    }

    .pane_title {
        text-style: bold;
        padding-bottom: 1;
        color: #FFFFFF;
    }
    """

    BINDINGS = [
        ("q", "quit", "Quit Dashboard"),
        ("s", "start_pipeline", "Run Auto-Patch Pipeline")
    ]

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.vulnerability_data: Dict[str, dict] = {}

    def compose(self) -> ComposeResult:
        """Create child widgets for the app."""
        yield Header(show_clock=True)
        with Grid(id="main_grid"):
            # 1. SIDEBAR PANEL (Left Column, Width: 30%)
            with Vertical(id="sidebar_pane"):
                yield Label("VULNERABILITY COLLECTION", classes="pane_title")
                yield ListView(id="vuln_list")
            
            with Vertical(id="right_pane"):
                # 2. LOG ENGINE MONITOR (Right Column, Top Pane, Height: 40%)
                with Vertical(id="console_pane"):
                    yield Label("ENGINE MONITOR", classes="pane_title")
                    yield RichLog(id="engine_log", wrap=True, markup=False)
                
                # 3. VISUAL CODE DIFF BOX (Right Column, Bottom Pane, Height: 60%)
                with Vertical(id="diff_pane"):
                    yield Label("VISUAL CODE DIFF BOX", classes="pane_title")
                    yield Static(id="diff_view")
        yield Footer()

    def on_mount(self) -> None:
        """Execute a native query against local SQLite to populate the ListView."""
        conn = get_connection()
        cur = conn.cursor()
        
        # Pull the most recent session's ID
        cur.execute("SELECT id FROM scan_sessions ORDER BY id DESC LIMIT 1")
        session_row = cur.fetchone()
        
        if session_row:
            session_id = session_row["id"]
            
            # Select target parameters mapping to our vulnerability table schema
            cur.execute(
                "SELECT id, file_path, start_line, rule_id "
                "FROM vulnerabilities WHERE session_id = ?",
                (session_id,)
            )
            rows = cur.fetchall()
            
            vuln_list = self.query_one("#vuln_list", ListView)
            for row in rows:
                file_path = row["file_path"] or "unknown_file.py"
                # Simplify to relative filename for minimalism layout
                short_file = Path(file_path).name
                vuln_type = row["rule_id"] or "unknown-rule"
                start_line = row["start_line"] or 1
                
                label_text = f"{short_file}:{start_line} [{vuln_type}]"
                list_item = ListItem(Label(label_text), id=f"vuln_{row['id']}")
                vuln_list.append(list_item)
                
                self.vulnerability_data[f"vuln_{row['id']}"] = {
                    "file_path": file_path,
                    "vulnerability_type": vuln_type,
                    "start_line": start_line,
                }
        conn.close()

    @on(ListView.Selected)
    def on_vulnerability_selected(self, event: ListView.Selected) -> None:
        """Intercept selected list items and render a split diff visualization."""
        item_id = event.item.id
        if item_id and item_id in self.vulnerability_data:
            data = self.vulnerability_data[item_id]
            file_path = data["file_path"]
            vuln_type = data["vulnerability_type"]
            
            # Construct a raw split-frame monochrome diff mock-up visualization
            diff_text = f"TARGET: {file_path}\n"
            diff_text += f"TOKEN : {vuln_type}\n"
            diff_text += "-" * 50 + "\n"
            diff_text += "[-] ORIGINAL TAINTED SOURCE (Line Block)\n"
            diff_text += "    execute_query(f\"SELECT * FROM data WHERE user = {input}\")\n\n"
            diff_text += "[+] FINAL GENERATED SECURE PATCH\n"
            diff_text += "    execute_query(\"SELECT * FROM data WHERE user = ?\", (input,))\n"
            diff_text += "-" * 50 + "\n"
            
            diff_view = self.query_one("#diff_view", Static)
            diff_view.update(diff_text)

    def action_start_pipeline(self) -> None:
        """Handler for the 'S' keybinding to spin up the orchestrator loop."""
        engine_log = self.query_one("#engine_log", RichLog)
        engine_log.write("=> [SYSTEM BOOT] Handing over context to Orchestrator Pipeline...")
        # Dispatch the blocking pipeline to a thread to prevent freezing the TUI main loop
        self.run_worker(self.execute_pipeline, thread=True)

    @work(thread=True)
    def execute_pipeline(self) -> None:
        """A dedicated worker thread that hooks into main.py and redirects telemetry streams."""
        engine_log = self.query_one("#engine_log", RichLog)
        
        # Intercept output
        original_stdout = sys.stdout
        original_stderr = sys.stderr
        stream = RichLogStream(engine_log, self)
        
        sys.stdout = stream  # type: ignore
        sys.stderr = stream  # type: ignore
        
        # Divert native root logger entries directly to TUI RichLog
        root_logger = logging.getLogger()
        handler = logging.StreamHandler(stream)
        handler.setFormatter(logging.Formatter("%(message)s"))
        root_logger.addHandler(handler)
        
        try:
            otter_main.main()
        except Exception as e:
            self.call_from_thread(engine_log.write, f"[CRITICAL EXCEPTION] {e}")
        finally:
            self.call_from_thread(engine_log.write, "=> [SYSTEM HALT] Pipeline loop terminated.")
            sys.stdout = original_stdout
            sys.stderr = original_stderr
            root_logger.removeHandler(handler)


if __name__ == "__main__":
    app = OtterTUI()
    app.run()
