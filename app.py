#!/usr/bin/env python3
"""TITAN IOC Converter — generic edition (choose CS / S1 / R7 outputs)."""

from __future__ import annotations

import sys
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox

from converter import S1_SCOPE_PATH, SUPPORTED_SUFFIXES, convert_files, write_outputs

# Neutral slate / indigo palette
BG = "#0f1115"
BG_2 = "#15181e"
CARD = "#1b1f27"
CARD_LINE = "#2a303b"
ACCENT = "#7c8cff"
ACCENT_HOVER = "#9aa6ff"
ACCENT_SOFT = "#262c45"
WHITE = "#eef0f4"
MUTED = "#8b93a3"
DIM = "#4a5160"
CS_RED = "#ef4b5f"
S1_GREEN = "#3ad07a"
R7_ORANGE = "#f7b13d"

APP_TITLE = "TITAN IOC Converter"

VENDORS = [
    # key, short, full name, color
    ("cs", "CS", "CrowdStrike", CS_RED),
    ("s1", "S1", "SentinelOne", S1_GREEN),
    ("r7", "R7", "Rapid7 InsightIDR", R7_ORANGE),
]


def app_dir() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent


class VendorToggle(tk.Frame):
    """Clickable card that turns a vendor output on/off."""

    def __init__(self, master, short: str, name: str, color: str, var: tk.BooleanVar, on_change) -> None:
        super().__init__(master, bg=CARD_LINE, padx=1, pady=1, cursor="hand2")
        self.color = color
        self.var = var
        self.on_change = on_change
        self.inner = tk.Frame(self, bg=CARD, padx=14, pady=10)
        self.inner.pack(fill="both", expand=True)
        self.box = tk.Label(self.inner, text="", width=2, font=("Segoe UI", 10, "bold"))
        self.box.pack(side="left", padx=(0, 10))
        text = tk.Frame(self.inner, bg=CARD)
        text.pack(side="left", fill="x")
        self.short = tk.Label(text, text=short, font=("Segoe UI", 13, "bold"), bg=CARD, anchor="w")
        self.short.pack(anchor="w")
        self.name = tk.Label(text, text=name, font=("Segoe UI", 9), bg=CARD, anchor="w")
        self.name.pack(anchor="w")
        self._text = text
        for w in (self, self.inner, self.box, text, self.short, self.name):
            w.bind("<Button-1>", self._toggle)
        var.trace_add("write", lambda *_: self.render())
        self.render()

    def _toggle(self, _event=None) -> None:
        self.var.set(not self.var.get())
        self.on_change()

    def render(self) -> None:
        on = self.var.get()
        self.configure(bg=self.color if on else CARD_LINE)
        self.box.configure(
            text="✓" if on else "",
            bg=self.color if on else BG_2,
            fg=BG,
        )
        self.short.configure(fg=self.color if on else DIM)
        self.name.configure(fg=WHITE if on else DIM)


class App(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title(APP_TITLE)
        self.geometry("900x720")
        self.minsize(800, 640)
        self.configure(bg=BG)
        self.files: list[Path] = []
        self._busy = False
        self.selected = {key: tk.BooleanVar(value=True) for key, *_ in VENDORS}
        self.scope_var = tk.StringVar(value=S1_SCOPE_PATH)
        self._build()
        self._on_selection_change()

    # ---------- layout ----------
    def _build(self) -> None:
        header = tk.Frame(self, bg=BG)
        header.pack(fill="x", padx=22, pady=(18, 4))
        tk.Label(header, text="TITAN IOC Converter", bg=BG, fg=WHITE, font=("Segoe UI", 17, "bold")).pack(anchor="w")
        tk.Label(
            header, text="Turn TITAN exports into EDR / SIEM import files",
            bg=BG, fg=MUTED, font=("Segoe UI", 10),
        ).pack(anchor="w")
        tk.Frame(self, bg=CARD_LINE, height=1).pack(fill="x", padx=22, pady=(10, 0))

        body = tk.Frame(self, bg=BG)
        body.pack(fill="both", expand=True, padx=22, pady=14)

        # Step 1 — output formats
        self._section(body, "1", "Output formats")
        vendors = tk.Frame(body, bg=BG)
        vendors.pack(fill="x", pady=(0, 6))
        for i, (key, short, name, color) in enumerate(VENDORS):
            vendors.columnconfigure(i, weight=1, uniform="v")
            VendorToggle(vendors, short, name, color, self.selected[key], self._on_selection_change).grid(
                row=0, column=i, sticky="nsew", padx=(0 if i == 0 else 8, 0)
            )

        self.scope_row = tk.Frame(body, bg=BG)
        tk.Label(self.scope_row, text="S1 Scope Path", bg=BG, fg=MUTED, font=("Segoe UI", 9)).pack(side="left", padx=(0, 10))
        scope_wrap = tk.Frame(self.scope_row, bg=CARD_LINE, padx=1, pady=1)
        scope_wrap.pack(side="left", fill="x", expand=True)
        tk.Entry(
            scope_wrap, textvariable=self.scope_var, bg=CARD, fg=WHITE, insertbackground=ACCENT,
            relief="flat", font=("Segoe UI", 10), highlightthickness=0,
        ).pack(fill="x", ipady=5, padx=6)
        self._scope_anchor = tk.Frame(body, bg=BG, height=0)
        self._scope_anchor.pack(fill="x")

        # Step 2 — input files
        self._section(body, "2", "TITAN files", top=12)
        actions = tk.Frame(body, bg=BG)
        actions.pack(fill="x", pady=(0, 8))
        self._btn(actions, "Add files", self.add_files).pack(side="left", padx=(0, 8))
        self._btn(actions, "Add folder", self.add_folder).pack(side="left", padx=(0, 8))
        self._btn(actions, "Remove", self.remove_selected).pack(side="left", padx=(0, 8))
        self._btn(actions, "Clear", self.clear_list).pack(side="left")
        self.status = tk.Label(actions, text="", bg=BG, fg=MUTED, font=("Segoe UI", 9))
        self.status.pack(side="right")

        list_wrap = tk.Frame(body, bg=CARD_LINE, padx=1, pady=1)
        list_wrap.pack(fill="both", expand=True)
        inner = tk.Frame(list_wrap, bg=CARD)
        inner.pack(fill="both", expand=True)
        self.listbox = tk.Listbox(
            inner, bg=CARD, fg=WHITE, selectbackground=ACCENT_SOFT, selectforeground=WHITE,
            activestyle="none", highlightthickness=0, bd=0, font=("Segoe UI", 10), relief="flat",
            selectmode="extended",
        )
        sb = tk.Scrollbar(inner, command=self.listbox.yview)
        self.listbox.configure(yscrollcommand=sb.set)
        self.listbox.pack(side="left", fill="both", expand=True, padx=8, pady=8)
        sb.pack(side="right", fill="y")

        # Step 3 — generate
        self.gen_btn = tk.Button(
            body, text="Generate", command=self.generate,
            bg=ACCENT, fg=BG, activebackground=ACCENT_HOVER, activeforeground=BG,
            disabledforeground=DIM, font=("Segoe UI", 12, "bold"), relief="flat", cursor="hand2", pady=10,
        )
        self.gen_btn.pack(fill="x", pady=(12, 0))

        log_wrap = tk.Frame(body, bg=CARD_LINE, padx=1, pady=1)
        log_wrap.pack(fill="x", pady=(12, 0))
        self.log = tk.Text(
            log_wrap, height=8, bg=BG_2, fg="#c3c9d4", insertbackground=ACCENT,
            relief="flat", font=("Consolas", 9), wrap="word", highlightthickness=0, padx=10, pady=8,
        )
        self.log.pack(fill="x")
        self._log(f"Output folder: {app_dir()}")
        self._log("Pick the output formats, add TITAN CSV / XLSX / XLSB files, then Generate.")
        self._refresh()

    def _section(self, parent, num: str, title: str, top: int = 0) -> None:
        row = tk.Frame(parent, bg=BG)
        row.pack(fill="x", pady=(top, 8))
        tk.Label(row, text=num, bg=ACCENT_SOFT, fg=ACCENT, font=("Segoe UI", 9, "bold"), width=2).pack(side="left")
        tk.Label(row, text=title, bg=BG, fg=WHITE, font=("Segoe UI", 11, "bold")).pack(side="left", padx=(8, 0))

    def _btn(self, parent, text, cmd) -> tk.Button:
        return tk.Button(
            parent, text=text, command=cmd, bg=CARD, fg=WHITE,
            activebackground=ACCENT_SOFT, activeforeground=WHITE,
            font=("Segoe UI", 9), relief="flat", cursor="hand2", padx=14, pady=6,
        )

    # ---------- state ----------
    def _targets(self) -> list[str]:
        return [key for key, *_ in VENDORS if self.selected[key].get()]

    def _gen_label(self) -> str:
        shorts = [short for key, short, *_ in VENDORS if self.selected[key].get()]
        return "Generate  " + "  +  ".join(shorts) if shorts else "Select at least one format"

    def _on_selection_change(self) -> None:
        if self.selected["s1"].get():
            self.scope_row.pack(fill="x", pady=(4, 0), before=self._scope_anchor)
        else:
            self.scope_row.pack_forget()
        if not self._busy:
            self.gen_btn.configure(
                text=self._gen_label(),
                state="normal" if self._targets() else "disabled",
                bg=ACCENT if self._targets() else CARD,
            )

    def _log(self, msg: str) -> None:
        self.log.insert("end", msg + "\n")
        self.log.see("end")

    def _refresh(self) -> None:
        self.listbox.delete(0, "end")
        for p in self.files:
            self.listbox.insert("end", f"  {p.name}")
        n = len(self.files)
        self.status.configure(text=f"{n} file{'s' if n != 1 else ''} selected" if n else "No files yet")

    # ---------- file list ----------
    def add_files(self) -> None:
        paths = filedialog.askopenfilenames(
            title="Select TITAN files",
            filetypes=[
                ("TITAN exports", "*.csv *.xlsx *.xlsb"),
                ("CSV", "*.csv"),
                ("Excel", "*.xlsx *.xlsb"),
                ("All files", "*.*"),
            ],
        )
        self._add([Path(p) for p in paths])

    def add_folder(self) -> None:
        folder = filedialog.askdirectory(title="Select folder with TITAN files")
        if not folder:
            return
        found = [p for p in Path(folder).iterdir() if p.is_file() and p.suffix.lower() in SUPPORTED_SUFFIXES]
        if not found:
            messagebox.showinfo(APP_TITLE, "No CSV / XLSX / XLSB files in that folder.")
            return
        self._add(found)

    def _add(self, paths: list[Path]) -> None:
        existing = {p.resolve() for p in self.files}
        added = 0
        for p in paths:
            rp = p.resolve()
            if rp.suffix.lower() not in SUPPORTED_SUFFIXES or rp in existing:
                continue
            self.files.append(rp)
            existing.add(rp)
            added += 1
        self._refresh()
        if added:
            self._log(f"Added {added} file(s).")

    def remove_selected(self) -> None:
        for i in reversed(list(self.listbox.curselection())):
            del self.files[i]
        self._refresh()

    def clear_list(self) -> None:
        self.files.clear()
        self._refresh()

    # ---------- conversion ----------
    def generate(self) -> None:
        if self._busy:
            return
        targets = self._targets()
        if not targets:
            messagebox.showwarning(APP_TITLE, "Select at least one output format.")
            return
        if not self.files:
            messagebox.showwarning(APP_TITLE, "Add at least one TITAN file.")
            return
        self._busy = True
        self.gen_btn.configure(state="disabled", text="Generating…")
        self._log("Converting...")
        scope = self.scope_var.get()
        threading.Thread(target=self._run_convert, args=(targets, scope), daemon=True).start()

    def _run_convert(self, targets: list[str], scope: str) -> None:
        try:
            result = convert_files(list(self.files))
            out = write_outputs(result, app_dir(), targets=targets, s1_scope_path=scope)
            lines = ["Done.", f"  Files read: {result.files_ok}"]
            if "cs" in out:
                lines.append(f"  CS rows: {len(result.cs)}")
            if "s1" in out:
                n = len(result.s1_sha256) + len(result.s1_sha1)
                lines.append(
                    f"  S1 hashes: {len(result.s1_sha256)} SHA256 + {len(result.s1_sha1)} SHA1 ({n * 3} rows)"
                )
            if "r7" in out:
                lines.append(f"  R7 indicators: {len(result.r7)}")
            lines.append(f"  Skipped rows: {result.skipped}")
            for key, path in out.items():
                lines.append(f"  {key.upper()} : {path.name}")
            summary = "\n".join(lines)
            if result.files_fail:
                summary += "\n  Failed:\n    " + "\n    ".join(result.files_fail)

            def done() -> None:
                self._log(summary)
                self._busy = False
                self._on_selection_change()
                messagebox.showinfo(APP_TITLE, summary)

            self.after(0, done)
        except Exception as exc:
            def fail() -> None:
                self._busy = False
                self._on_selection_change()
                self._log(f"ERROR: {exc}")
                messagebox.showerror(APP_TITLE, str(exc))
            self.after(0, fail)


def main() -> None:
    app = App()
    app.mainloop()


if __name__ == "__main__":
    main()
