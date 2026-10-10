#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Project Code Converter GUI

AI-assisted project-level converter:
- Recursively scans a project folder
- Converts supported source-code files to one target language
- Copies assets/config files safely
- Supports dry-run, resume/skip existing, retries, cancellation, filters
- Writes reports: CONVERSION_REPORT.md, PROJECT_PATH_MAP.json, MIGRATION_PLAN.md
"""

from __future__ import annotations

import concurrent.futures
import dataclasses
import datetime as _dt
import fnmatch
import hashlib
import json
import os
import pathlib
import queue
import re
import shutil
import sys
import threading
import time
import traceback
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

try:
    from openai import OpenAI
except Exception:
    OpenAI = None


APP_VERSION = "2.0.0"


CODE_EXT_TO_LANG = {
    ".py": "Python",
    ".pyw": "Python",
    ".js": "JavaScript",
    ".mjs": "JavaScript",
    ".cjs": "JavaScript",
    ".jsx": "JavaScript React",
    ".ts": "TypeScript",
    ".tsx": "TypeScript React",
    ".java": "Java",
    ".c": "C",
    ".h": "C/C++ Header",
    ".cpp": "C++",
    ".cc": "C++",
    ".cxx": "C++",
    ".hpp": "C++ Header",
    ".hh": "C++ Header",
    ".cs": "C#",
    ".go": "Go",
    ".rs": "Rust",
    ".php": "PHP",
    ".rb": "Ruby",
    ".swift": "Swift",
    ".kt": "Kotlin",
    ".kts": "Kotlin Script",
    ".lua": "Lua",
    ".sh": "Bash",
    ".bash": "Bash",
    ".zsh": "Zsh",
    ".ps1": "PowerShell",
    ".r": "R",
    ".jl": "Julia",
    ".scala": "Scala",
    ".dart": "Dart",
    ".vb": "Visual Basic",
    ".pl": "Perl",
    ".pm": "Perl Module",
    ".sql": "SQL",
}

TEXT_TEMPLATE_EXT_TO_LANG = {
    ".html": "HTML",
    ".htm": "HTML",
    ".css": "CSS",
    ".scss": "SCSS",
    ".sass": "Sass",
    ".less": "Less",
    ".vue": "Vue Single File Component",
    ".svelte": "Svelte Component",
    ".xml": "XML",
    ".xaml": "XAML",
    ".json": "JSON",
    ".yaml": "YAML",
    ".yml": "YAML",
    ".toml": "TOML",
    ".ini": "INI",
    ".cfg": "Config",
    ".md": "Markdown",
}

TARGET_EXT = {
    "Python": ".py",
    "JavaScript": ".js",
    "TypeScript": ".ts",
    "Java": ".java",
    "C": ".c",
    "C++": ".cpp",
    "C#": ".cs",
    "Go": ".go",
    "Rust": ".rs",
    "PHP": ".php",
    "Ruby": ".rb",
    "Swift": ".swift",
    "Kotlin": ".kt",
    "Lua": ".lua",
    "Bash": ".sh",
    "PowerShell": ".ps1",
    "R": ".r",
    "Julia": ".jl",
    "Scala": ".scala",
    "Dart": ".dart",
    "Perl": ".pl",
}

TARGET_LANGUAGES = list(TARGET_EXT.keys())

DEFAULT_IGNORE_DIRS = {
    ".git", ".hg", ".svn",
    "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache",
    "node_modules",
    "venv", ".venv", "env", ".env",
    "dist", "build", "target", "bin", "obj", "out",
    ".gradle", ".idea", ".vscode",
    ".next", ".nuxt", ".svelte-kit",
    "coverage", ".nyc_output",
    ".tox", ".cache",
}

DEFAULT_IGNORE_GLOBS = {
    "*.min.js",
    "*.min.css",
    "*.map",
    "*.lock",
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "Cargo.lock",
    "poetry.lock",
    "Pipfile.lock",
    "*.png", "*.jpg", "*.jpeg", "*.gif", "*.webp", "*.ico", "*.bmp",
    "*.mp3", "*.mp4", "*.avi", "*.mov", "*.wav", "*.ogg",
    "*.zip", "*.tar", "*.gz", "*.7z", "*.rar",
    "*.exe", "*.dll", "*.so", "*.dylib", "*.class", "*.jar",
    "*.pdf",
}

IMPORTANT_CONFIG_NAMES = {
    "package.json",
    "tsconfig.json",
    "jsconfig.json",
    "requirements.txt",
    "pyproject.toml",
    "setup.py",
    "setup.cfg",
    "Pipfile",
    "pom.xml",
    "build.gradle",
    "settings.gradle",
    "gradle.properties",
    "Cargo.toml",
    "go.mod",
    "composer.json",
    "Gemfile",
    "Makefile",
    "CMakeLists.txt",
    "Dockerfile",
    "docker-compose.yml",
    "docker-compose.yaml",
    ".env.example",
}


@dataclasses.dataclass
class FileRecord:
    src: pathlib.Path
    rel: str
    kind: str
    lang: str
    dest: pathlib.Path
    size: int
    sha256: str | None = None


@dataclasses.dataclass
class ConvertResult:
    status: str
    rel: str
    dest_rel: str | None = None
    message: str = ""
    seconds: float = 0.0
    source_hash: str | None = None


def parse_set(text: str) -> set[str]:
    out = set()
    for item in re.split(r"[,\n;]+", text):
        item = item.strip()
        if item:
            out.add(item)
    return out


def normalize_ext_set(text: str) -> set[str]:
    out = set()
    for item in parse_set(text):
        item = item.strip().lower()
        if not item:
            continue
        if not item.startswith("."):
            item = "." + item
        out.add(item)
    return out


def sha256_file(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def is_binary_file(path: pathlib.Path) -> bool:
    try:
        data = path.read_bytes()[:4096]
    except Exception:
        return True

    if b"\x00" in data:
        return True

    try:
        data.decode("utf-8")
        return False
    except UnicodeDecodeError:
        return True


def read_text(path: pathlib.Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def atomic_write_text(path: pathlib.Path, text: str):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    tmp.replace(path)


def atomic_copy(src: pathlib.Path, dest: pathlib.Path):
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_name(dest.name + ".tmpcopy")
    shutil.copy2(src, tmp)
    tmp.replace(dest)


def detect_language(path: pathlib.Path, convert_templates: bool = False) -> str:
    ext = path.suffix.lower()
    if ext in CODE_EXT_TO_LANG:
        return CODE_EXT_TO_LANG[ext]
    if convert_templates and ext in TEXT_TEMPLATE_EXT_TO_LANG:
        return TEXT_TEMPLATE_EXT_TO_LANG[ext]
    return "Unknown"


def is_convertible_file(path: pathlib.Path, include_exts: set[str], convert_templates: bool) -> bool:
    ext = path.suffix.lower()

    if include_exts and ext not in include_exts:
        return False

    if ext in CODE_EXT_TO_LANG:
        return True

    if convert_templates and ext in TEXT_TEMPLATE_EXT_TO_LANG:
        return True

    return False


def strip_code_fence(text: str) -> str:
    text = text.strip()
    match = re.match(r"^```[a-zA-Z0-9_+.#-]*\n(.*?)\n```$", text, re.DOTALL)
    if match:
        return match.group(1).strip()
    return text


def should_ignore_path(
    path: pathlib.Path,
    source_dir: pathlib.Path,
    output_dir: pathlib.Path,
    ignore_dirs: set[str],
    ignore_globs: set[str],
) -> bool:
    try:
        rel = path.relative_to(source_dir)
    except ValueError:
        return True

    try:
        path.resolve().relative_to(output_dir.resolve())
        return True
    except ValueError:
        pass

    parts = set(rel.parts)
    if parts & ignore_dirs:
        return True

    rel_posix = rel.as_posix()
    for pattern in ignore_globs:
        if fnmatch.fnmatch(path.name, pattern) or fnmatch.fnmatch(rel_posix, pattern):
            return True

    return False


def build_project_tree(records: list[FileRecord], max_entries: int = 1200) -> str:
    lines = []
    for rec in records[:max_entries]:
        arrow = f" -> {rec.dest.as_posix()}" if rec.kind == "code" else ""
        lines.append(f"{rec.kind:6} | {rec.lang:20} | {rec.rel}{arrow}")
    if len(records) > max_entries:
        lines.append(f"... plus {len(records) - max_entries} more files")
    return "\n".join(lines)


def collect_config_context(source_dir: pathlib.Path, records: list[FileRecord], max_total_chars: int = 45000) -> str:
    chunks = []
    used = 0

    for rec in records:
        path = rec.src
        if path.name not in IMPORTANT_CONFIG_NAMES:
            continue
        if is_binary_file(path):
            continue

        try:
            text = read_text(path)
        except Exception:
            continue

        remaining = max_total_chars - used
        if remaining <= 0:
            break

        text = text[:remaining]
        chunks.append(f"\n--- {rec.rel} ---\n{text}")
        used += len(text)

    return "\n".join(chunks).strip()


def make_path_map(records: list[FileRecord], output_dir: pathlib.Path) -> dict[str, str]:
    mapping = {}
    for rec in records:
        if rec.kind == "code":
            try:
                mapping[rec.rel] = rec.dest.relative_to(output_dir).as_posix()
            except Exception:
                mapping[rec.rel] = rec.dest.as_posix()
    return mapping


def target_path_for(
    src: pathlib.Path,
    source_dir: pathlib.Path,
    output_dir: pathlib.Path,
    target_lang: str,
    convert: bool,
) -> pathlib.Path:
    rel = src.relative_to(source_dir)

    if convert:
        target_suffix = TARGET_EXT.get(target_lang, ".txt")
        rel = rel.with_suffix(target_suffix)

    return output_dir / rel


def collect_records(
    source_dir: pathlib.Path,
    output_dir: pathlib.Path,
    target_lang: str,
    ignore_dirs: set[str],
    ignore_globs: set[str],
    include_exts: set[str],
    convert_templates: bool,
) -> list[FileRecord]:
    records = []

    for path in sorted(source_dir.rglob("*")):
        if not path.is_file():
            continue

        if should_ignore_path(path, source_dir, output_dir, ignore_dirs, ignore_globs):
            continue

        try:
            size = path.stat().st_size
        except OSError:
            size = 0

        convert = is_convertible_file(path, include_exts, convert_templates) and not is_binary_file(path)
        kind = "code" if convert else "asset"
        lang = detect_language(path, convert_templates) if convert else "Asset"

        dest = target_path_for(path, source_dir, output_dir, target_lang, convert)
        records.append(FileRecord(src=path, rel=path.relative_to(source_dir).as_posix(), kind=kind, lang=lang, dest=dest, size=size))

    return records


def load_state(output_dir: pathlib.Path) -> dict:
    path = output_dir / ".conversion_state.json"
    if not path.exists():
        return {"converted": {}}

    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {"converted": {}}


def save_state(output_dir: pathlib.Path, state: dict):
    path = output_dir / ".conversion_state.json"
    atomic_write_text(path, json.dumps(state, indent=2, ensure_ascii=False))


def call_openai_convert(
    *,
    api_key: str,
    model: str,
    source_code: str,
    source_lang: str,
    target_lang: str,
    rel_path: str,
    dest_rel_path: str,
    project_tree: str,
    config_context: str,
    path_map: dict[str, str],
    custom_instructions: str,
    retries: int,
    timeout_seconds: int,
    cancel_event: threading.Event,
) -> str:
    if OpenAI is None:
        raise RuntimeError("The 'openai' package is not installed. Run: pip install openai")

    if cancel_event.is_set():
        raise RuntimeError("Cancelled")

    client = OpenAI(api_key=api_key, timeout=timeout_seconds)

    path_map_text = json.dumps(path_map, indent=2, ensure_ascii=False)[:50000]

    developer_instructions = f"""
You are an expert software migration assistant.

Your job is to convert exactly one file from {source_lang} to {target_lang} while keeping it compatible with the rest of the converted project.

Rules:
- Output only the converted file contents.
- Do not wrap output in markdown.
- Preserve behavior as much as possible.
- Use idiomatic {target_lang}.
- Update imports/module references using the provided path map.
- Keep public APIs, names, comments, and behavior where useful.
- Replace unavailable libraries with common equivalents in {target_lang}.
- Add TODO comments where manual project-level work is needed.
- Do not invent unrelated features.
- Do not remove important logic.
"""

    user_prompt = f"""
Current source file:
{rel_path}

Expected converted output path:
{dest_rel_path}

Project path map:
{path_map_text}

Project tree:
{project_tree}

Important config/dependency files:
{config_context if config_context else "(none found)"}

Extra user instructions:
{custom_instructions if custom_instructions.strip() else "(none)"}

SOURCE FILE CONTENT:
{source_code}
"""

    last_error = None

    for attempt in range(1, retries + 2):
        if cancel_event.is_set():
            raise RuntimeError("Cancelled")

        try:
            response = client.responses.create(
                model=model,
                instructions=developer_instructions,
                input=user_prompt,
            )

            output = getattr(response, "output_text", None)
            if output is None:
                output = str(response)

            return strip_code_fence(output)

        except Exception as e:
            last_error = e
            if attempt >= retries + 1:
                break
            time.sleep(min(2 ** attempt, 10))

    raise RuntimeError(str(last_error))


def generate_migration_plan(
    *,
    api_key: str,
    model: str,
    target_lang: str,
    project_tree: str,
    config_context: str,
    path_map: dict[str, str],
    custom_instructions: str,
    retries: int,
    timeout_seconds: int,
    cancel_event: threading.Event,
) -> str:
    if OpenAI is None:
        raise RuntimeError("The 'openai' package is not installed. Run: pip install openai")

    client = OpenAI(api_key=api_key, timeout=timeout_seconds)

    instructions = f"""
You are a software migration planner.
Create a concise but useful migration plan for converting this project to {target_lang}.
Return Markdown.
Include:
- likely source stack
- dependency replacements
- build/run instructions likely needed
- files that need manual review
- risks/TODOs
"""

    prompt = f"""
Target language:
{target_lang}

Project tree:
{project_tree}

Important configs:
{config_context if config_context else "(none found)"}

Path map:
{json.dumps(path_map, indent=2, ensure_ascii=False)[:50000]}

Extra user instructions:
{custom_instructions if custom_instructions.strip() else "(none)"}
"""

    last_error = None

    for attempt in range(1, retries + 2):
        if cancel_event.is_set():
            raise RuntimeError("Cancelled")

        try:
            response = client.responses.create(
                model=model,
                instructions=instructions,
                input=prompt,
            )
            output = getattr(response, "output_text", None)
            return output or str(response)
        except Exception as e:
            last_error = e
            if attempt >= retries + 1:
                break
            time.sleep(min(2 ** attempt, 10))

    raise RuntimeError(str(last_error))


def write_report(
    *,
    output_dir: pathlib.Path,
    source_dir: pathlib.Path,
    target_lang: str,
    model: str,
    records: list[FileRecord],
    results: list[ConvertResult],
    dry_run: bool,
    started: str,
    finished: str,
):
    report = output_dir / "CONVERSION_REPORT.md"

    converted = [r for r in results if r.status == "converted"]
    copied = [r for r in results if r.status == "copied"]
    skipped = [r for r in results if r.status == "skipped"]
    failed = [r for r in results if r.status == "failed"]
    planned = [r for r in results if r.status == "planned"]

    lines = [
        "# Project Conversion Report",
        "",
        f"App version: `{APP_VERSION}`",
        f"Started: `{started}`",
        f"Finished: `{finished}`",
        f"Source project: `{source_dir}`",
        f"Target language: `{target_lang}`",
        f"Model: `{model}`",
        f"Dry run: `{dry_run}`",
        "",
        "## Summary",
        "",
        f"- Total scanned files: {len(records)}",
        f"- Planned conversions: {len(planned)}",
        f"- Converted files: {len(converted)}",
        f"- Copied assets: {len(copied)}",
        f"- Skipped files: {len(skipped)}",
        f"- Failed files: {len(failed)}",
        "",
    ]

    def section(title: str, items: list[ConvertResult]):
        lines.extend([f"## {title}", ""])
        if not items:
            lines.append("(none)")
            lines.append("")
            return
        for item in items:
            if item.dest_rel:
                lines.append(f"- `{item.rel}` -> `{item.dest_rel}` — {item.message}")
            else:
                lines.append(f"- `{item.rel}` — {item.message}")
        lines.append("")

    section("Planned", planned)
    section("Converted", converted)
    section("Copied", copied)
    section("Skipped", skipped)
    section("Failed", failed)

    lines.extend([
        "## Note",
        "",
        "This is an AI-assisted conversion. You still need to run tests, install target-language dependencies, and manually review TODO comments.",
        "",
    ])

    atomic_write_text(report, "\n".join(lines))
    return report


class ProjectConverterGUI:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title(f"Project Code Converter v{APP_VERSION}")
        self.root.geometry("1120x780")

        self.events: queue.Queue = queue.Queue()
        self.cancel_event = threading.Event()
        self.running = False

        self.source_dir = tk.StringVar()
        self.output_dir = tk.StringVar()
        self.target_lang = tk.StringVar(value="JavaScript")
        self.model = tk.StringVar(value=os.environ.get("OPENAI_MODEL", "gpt-5.5"))
        self.api_key = tk.StringVar(value=os.environ.get("OPENAI_API_KEY", ""))

        self.max_chars = tk.IntVar(value=90000)
        self.workers = tk.IntVar(value=2)
        self.retries = tk.IntVar(value=2)
        self.timeout_seconds = tk.IntVar(value=120)

        self.copy_assets = tk.BooleanVar(value=True)
        self.skip_existing = tk.BooleanVar(value=True)
        self.dry_run = tk.BooleanVar(value=False)
        self.convert_templates = tk.BooleanVar(value=False)
        self.generate_plan = tk.BooleanVar(value=True)

        self.ignore_dirs_text = tk.StringVar(value=", ".join(sorted(DEFAULT_IGNORE_DIRS)))
        self.ignore_globs_text = tk.StringVar(value=", ".join(sorted(DEFAULT_IGNORE_GLOBS)))
        self.include_exts_text = tk.StringVar(value="")

        self._build_ui()

    def _build_ui(self):
        main = ttk.Frame(self.root, padding=10)
        main.pack(fill="both", expand=True)

        row = 0

        ttk.Label(main, text="Source project folder:").grid(row=row, column=0, sticky="w")
        ttk.Entry(main, textvariable=self.source_dir).grid(row=row, column=1, sticky="ew", padx=5)
        ttk.Button(main, text="Browse", command=self.choose_source).grid(row=row, column=2)
        row += 1

        ttk.Label(main, text="Output folder:").grid(row=row, column=0, sticky="w", pady=5)
        ttk.Entry(main, textvariable=self.output_dir).grid(row=row, column=1, sticky="ew", padx=5)
        ttk.Button(main, text="Browse", command=self.choose_output).grid(row=row, column=2)
        row += 1

        ttk.Label(main, text="Target language:").grid(row=row, column=0, sticky="w")
        ttk.Combobox(main, textvariable=self.target_lang, values=TARGET_LANGUAGES, state="readonly").grid(row=row, column=1, sticky="ew", padx=5)
        row += 1

        ttk.Label(main, text="Model:").grid(row=row, column=0, sticky="w", pady=5)
        ttk.Entry(main, textvariable=self.model).grid(row=row, column=1, sticky="ew", padx=5)
        row += 1

        ttk.Label(main, text="OpenAI API key:").grid(row=row, column=0, sticky="w")
        ttk.Entry(main, textvariable=self.api_key, show="*").grid(row=row, column=1, sticky="ew", padx=5)
        row += 1

        options = ttk.LabelFrame(main, text="Options", padding=8)
        options.grid(row=row, column=0, columnspan=3, sticky="ew", pady=8)
        row += 1

        ttk.Checkbutton(options, text="Copy assets", variable=self.copy_assets).grid(row=0, column=0, sticky="w")
        ttk.Checkbutton(options, text="Skip existing / resume", variable=self.skip_existing).grid(row=0, column=1, sticky="w", padx=10)
        ttk.Checkbutton(options, text="Dry run only", variable=self.dry_run).grid(row=0, column=2, sticky="w", padx=10)
        ttk.Checkbutton(options, text="Convert HTML/CSS/config/templates", variable=self.convert_templates).grid(row=0, column=3, sticky="w", padx=10)
        ttk.Checkbutton(options, text="Generate migration plan", variable=self.generate_plan).grid(row=0, column=4, sticky="w", padx=10)

        ttk.Label(options, text="Max chars/file:").grid(row=1, column=0, sticky="w", pady=6)
        ttk.Spinbox(options, from_=10000, to=500000, increment=10000, textvariable=self.max_chars, width=10).grid(row=1, column=1, sticky="w")

        ttk.Label(options, text="Workers:").grid(row=1, column=2, sticky="w")
        ttk.Spinbox(options, from_=1, to=8, increment=1, textvariable=self.workers, width=6).grid(row=1, column=3, sticky="w")

        ttk.Label(options, text="Retries:").grid(row=2, column=0, sticky="w")
        ttk.Spinbox(options, from_=0, to=6, increment=1, textvariable=self.retries, width=6).grid(row=2, column=1, sticky="w")

        ttk.Label(options, text="Timeout seconds:").grid(row=2, column=2, sticky="w")
        ttk.Spinbox(options, from_=30, to=600, increment=30, textvariable=self.timeout_seconds, width=6).grid(row=2, column=3, sticky="w")

        filters = ttk.LabelFrame(main, text="Filters", padding=8)
        filters.grid(row=row, column=0, columnspan=3, sticky="ew", pady=6)
        row += 1

        ttk.Label(filters, text="Only convert extensions, blank = all supported:").grid(row=0, column=0, sticky="w")
        ttk.Entry(filters, textvariable=self.include_exts_text).grid(row=0, column=1, sticky="ew", padx=5)

        ttk.Label(filters, text="Ignored folders:").grid(row=1, column=0, sticky="w", pady=5)
        ttk.Entry(filters, textvariable=self.ignore_dirs_text).grid(row=1, column=1, sticky="ew", padx=5)

        ttk.Label(filters, text="Ignored globs:").grid(row=2, column=0, sticky="w")
        ttk.Entry(filters, textvariable=self.ignore_globs_text).grid(row=2, column=1, sticky="ew", padx=5)

        filters.columnconfigure(1, weight=1)

        ttk.Label(main, text="Extra conversion instructions:").grid(row=row, column=0, columnspan=3, sticky="w")
        row += 1

        self.instructions = tk.Text(main, height=4, wrap="word")
        self.instructions.grid(row=row, column=0, columnspan=3, sticky="ew", pady=5)
        self.instructions.insert("1.0", "Keep the same features. Replace unavailable libraries with common equivalents. Add TODO comments where manual work is needed.")
        row += 1

        buttons = ttk.Frame(main)
        buttons.grid(row=row, column=0, columnspan=3, sticky="ew", pady=8)
        row += 1

        self.scan_button = ttk.Button(buttons, text="Scan Project", command=self.scan_project)
        self.scan_button.pack(side="left")

        self.start_button = ttk.Button(buttons, text="Convert Project", command=self.start_conversion)
        self.start_button.pack(side="left", padx=8)

        self.cancel_button = ttk.Button(buttons, text="Cancel", command=self.cancel, state="disabled")
        self.cancel_button.pack(side="left")

        self.open_output_button = ttk.Button(buttons, text="Open Output Folder", command=self.open_output_folder)
        self.open_output_button.pack(side="right")

        self.progress = ttk.Progressbar(main, mode="determinate")
        self.progress.grid(row=row, column=0, columnspan=3, sticky="ew", pady=5)
        row += 1

        self.status = tk.StringVar(value="Ready")
        ttk.Label(main, textvariable=self.status).grid(row=row, column=0, columnspan=3, sticky="w")
        row += 1

        ttk.Label(main, text="Log:").grid(row=row, column=0, columnspan=3, sticky="w", pady=(8, 0))
        row += 1

        self.log_box = tk.Text(main, height=20, wrap="word")
        self.log_box.grid(row=row, column=0, columnspan=3, sticky="nsew")
        row += 1

        main.columnconfigure(1, weight=1)
        main.rowconfigure(row - 1, weight=1)

    def choose_source(self):
        path = filedialog.askdirectory(title="Choose source project folder")
        if path:
            self.source_dir.set(path)
            src = pathlib.Path(path)
            self.output_dir.set(str(src.parent / f"{src.name}_converted"))

    def choose_output(self):
        path = filedialog.askdirectory(title="Choose output folder")
        if path:
            self.output_dir.set(path)

    def log(self, msg: str):
        stamp = _dt.datetime.now().strftime("%H:%M:%S")
        self.log_box.insert("end", f"[{stamp}] {msg}\n")
        self.log_box.see("end")

    def validate_paths(self) -> tuple[pathlib.Path, pathlib.Path] | None:
        if not self.source_dir.get().strip():
            messagebox.showerror("Missing source", "Choose a source project folder.")
            return None

        if not self.output_dir.get().strip():
            messagebox.showerror("Missing output", "Choose an output folder.")
            return None

        source = pathlib.Path(self.source_dir.get()).resolve()
        output = pathlib.Path(self.output_dir.get()).resolve()

        if not source.exists() or not source.is_dir():
            messagebox.showerror("Invalid source", "The source folder does not exist.")
            return None

        if source == output:
            messagebox.showerror("Invalid output", "Output folder must be different from source folder.")
            return None

        return source, output

    def current_options(self):
        return {
            "target_lang": self.target_lang.get(),
            "ignore_dirs": parse_set(self.ignore_dirs_text.get()),
            "ignore_globs": parse_set(self.ignore_globs_text.get()),
            "include_exts": normalize_ext_set(self.include_exts_text.get()),
            "convert_templates": bool(self.convert_templates.get()),
        }

    def scan_project(self):
        paths = self.validate_paths()
        if not paths:
            return

        source, output = paths
        opts = self.current_options()

        try:
            records = collect_records(source, output, **opts)
            code = [r for r in records if r.kind == "code"]
            assets = [r for r in records if r.kind == "asset"]

            self.log_box.delete("1.0", "end")
            self.log(f"Scanned: {source}")
            self.log(f"Total files: {len(records)}")
            self.log(f"Convertible code files: {len(code)}")
            self.log(f"Assets/support files: {len(assets)}")
            self.log("")
            self.log("First convertible files:")

            for rec in code[:80]:
                self.log(f"  {rec.rel} [{rec.lang}] -> {rec.dest.relative_to(output).as_posix()}")

            if len(code) > 80:
                self.log(f"  ... plus {len(code) - 80} more")

            self.status.set(f"Scan complete: {len(code)} code files, {len(assets)} assets.")

        except Exception as e:
            messagebox.showerror("Scan failed", str(e))

    def start_conversion(self):
        if self.running:
            return

        paths = self.validate_paths()
        if not paths:
            return

        if not self.dry_run.get() and not self.api_key.get().strip():
            messagebox.showerror("Missing API key", "Enter your OpenAI API key or set OPENAI_API_KEY.")
            return

        if OpenAI is None and not self.dry_run.get():
            messagebox.showerror("Missing dependency", "Install the OpenAI library first:\n\npip install openai")
            return

        source, output = paths

        self.running = True
        self.cancel_event.clear()
        self.log_box.delete("1.0", "end")
        self.progress["value"] = 0
        self.scan_button.config(state="disabled")
        self.start_button.config(state="disabled")
        self.cancel_button.config(state="normal")
        self.status.set("Starting...")

        kwargs = {
            "source_dir": source,
            "output_dir": output,
            "target_lang": self.target_lang.get(),
            "model": self.model.get().strip(),
            "api_key": self.api_key.get().strip(),
            "max_chars": int(self.max_chars.get()),
            "workers": max(1, int(self.workers.get())),
            "retries": max(0, int(self.retries.get())),
            "timeout_seconds": max(30, int(self.timeout_seconds.get())),
            "copy_assets": bool(self.copy_assets.get()),
            "skip_existing": bool(self.skip_existing.get()),
            "dry_run": bool(self.dry_run.get()),
            "generate_plan_enabled": bool(self.generate_plan.get()),
            "convert_templates": bool(self.convert_templates.get()),
            "ignore_dirs": parse_set(self.ignore_dirs_text.get()),
            "ignore_globs": parse_set(self.ignore_globs_text.get()),
            "include_exts": normalize_ext_set(self.include_exts_text.get()),
            "custom_instructions": self.instructions.get("1.0", "end").strip(),
        }

        t = threading.Thread(target=self.worker, kwargs=kwargs, daemon=True)
        t.start()
        self.root.after(100, self.poll_events)

    def cancel(self):
        self.cancel_event.set()
        self.status.set("Cancelling after current running request finishes...")
        self.log("Cancel requested.")

    def poll_events(self):
        while True:
            try:
                event = self.events.get_nowait()
            except queue.Empty:
                break

            kind = event[0]

            if kind == "log":
                self.log(event[1])

            elif kind == "progress":
                done, total = event[1], event[2]
                self.progress["maximum"] = max(total, 1)
                self.progress["value"] = done
                self.status.set(f"Processed {done}/{total} files")

            elif kind == "done":
                self.running = False
                self.scan_button.config(state="normal")
                self.start_button.config(state="normal")
                self.cancel_button.config(state="disabled")
                self.status.set(f"Done. Report: {event[1]}")
                messagebox.showinfo("Done", f"Project conversion finished.\n\nReport:\n{event[1]}")

            elif kind == "error":
                self.running = False
                self.scan_button.config(state="normal")
                self.start_button.config(state="normal")
                self.cancel_button.config(state="disabled")
                self.status.set("Error")
                messagebox.showerror("Conversion failed", event[1])

        if self.running:
            self.root.after(100, self.poll_events)

    def open_output_folder(self):
        path = self.output_dir.get().strip()
        if not path:
            return

        p = pathlib.Path(path)
        p.mkdir(parents=True, exist_ok=True)

        try:
            if os.name == "nt":
                os.startfile(str(p))
            elif sys.platform == "darwin":
                os.system(f'open "{p}"')
            else:
                os.system(f'xdg-open "{p}"')
        except Exception as e:
            messagebox.showerror("Open failed", str(e))

    def worker(
        self,
        *,
        source_dir: pathlib.Path,
        output_dir: pathlib.Path,
        target_lang: str,
        model: str,
        api_key: str,
        max_chars: int,
        workers: int,
        retries: int,
        timeout_seconds: int,
        copy_assets: bool,
        skip_existing: bool,
        dry_run: bool,
        generate_plan_enabled: bool,
        convert_templates: bool,
        ignore_dirs: set[str],
        ignore_globs: set[str],
        include_exts: set[str],
        custom_instructions: str,
    ):
        started = _dt.datetime.now().isoformat(timespec="seconds")
        results: list[ConvertResult] = []

        try:
            output_dir.mkdir(parents=True, exist_ok=True)

            records = collect_records(
                source_dir=source_dir,
                output_dir=output_dir,
                target_lang=target_lang,
                ignore_dirs=ignore_dirs,
                ignore_globs=ignore_globs,
                include_exts=include_exts,
                convert_templates=convert_templates,
            )

            code_records = [r for r in records if r.kind == "code"]
            asset_records = [r for r in records if r.kind == "asset"]

            self.events.put(("log", f"Found {len(records)} files."))
            self.events.put(("log", f"Convertible files: {len(code_records)}."))
            self.events.put(("log", f"Asset/support files: {len(asset_records)}."))

            path_map = make_path_map(records, output_dir)
            atomic_write_text(output_dir / "PROJECT_PATH_MAP.json", json.dumps(path_map, indent=2, ensure_ascii=False))

            project_tree = build_project_tree(records)
            config_context = collect_config_context(source_dir, records)

            if dry_run:
                self.events.put(("log", "Dry run enabled: no files will be converted by AI."))
                for rec in code_records:
                    results.append(ConvertResult(status="planned", rel=rec.rel, dest_rel=rec.dest.relative_to(output_dir).as_posix(), message="Would convert"))
                for rec in asset_records:
                    if copy_assets:
                        results.append(ConvertResult(status="planned", rel=rec.rel, dest_rel=rec.dest.relative_to(output_dir).as_posix(), message="Would copy asset"))
                report = write_report(
                    output_dir=output_dir,
                    source_dir=source_dir,
                    target_lang=target_lang,
                    model=model,
                    records=records,
                    results=results,
                    dry_run=True,
                    started=started,
                    finished=_dt.datetime.now().isoformat(timespec="seconds"),
                )
                self.events.put(("done", str(report)))
                return

            if copy_assets:
                for rec in asset_records:
                    if self.cancel_event.is_set():
                        results.append(ConvertResult(status="skipped", rel=rec.rel, message="Cancelled before copy"))
                        continue
                    try:
                        if skip_existing and rec.dest.exists():
                            results.append(ConvertResult(status="skipped", rel=rec.rel, dest_rel=rec.dest.relative_to(output_dir).as_posix(), message="Existing asset skipped"))
                        else:
                            atomic_copy(rec.src, rec.dest)
                            results.append(ConvertResult(status="copied", rel=rec.rel, dest_rel=rec.dest.relative_to(output_dir).as_posix(), message="Asset copied"))
                    except Exception as e:
                        results.append(ConvertResult(status="failed", rel=rec.rel, message=f"Asset copy failed: {e}"))

                self.events.put(("log", "Asset copying finished."))

            if generate_plan_enabled and not self.cancel_event.is_set():
                try:
                    self.events.put(("log", "Generating MIGRATION_PLAN.md..."))
                    plan = generate_migration_plan(
                        api_key=api_key,
                        model=model,
                        target_lang=target_lang,
                        project_tree=project_tree,
                        config_context=config_context,
                        path_map=path_map,
                        custom_instructions=custom_instructions,
                        retries=retries,
                        timeout_seconds=timeout_seconds,
                        cancel_event=self.cancel_event,
                    )
                    atomic_write_text(output_dir / "MIGRATION_PLAN.md", plan)
                    self.events.put(("log", "Migration plan saved."))
                except Exception as e:
                    self.events.put(("log", f"Migration plan failed: {e}"))

            state = load_state(output_dir)
            total = len(code_records)
            done = 0
            self.events.put(("progress", done, total))

            state_lock = threading.Lock()

            def convert_one(rec: FileRecord) -> ConvertResult:
                start = time.time()

                if self.cancel_event.is_set():
                    return ConvertResult(status="skipped", rel=rec.rel, message="Cancelled before conversion")

                try:
                    dest_rel = rec.dest.relative_to(output_dir).as_posix()
                    source_hash = sha256_file(rec.src)
                    rec.sha256 = source_hash

                    if skip_existing and rec.dest.exists():
                        previous = state.get("converted", {}).get(rec.rel)
                        if previous and previous.get("source_hash") == source_hash:
                            return ConvertResult(status="skipped", rel=rec.rel, dest_rel=dest_rel, message="Already converted, unchanged", source_hash=source_hash)

                    source_code = read_text(rec.src)

                    if len(source_code) > max_chars:
                        if not rec.dest.exists():
                            atomic_copy(rec.src, output_dir / rec.rel)
                        return ConvertResult(
                            status="skipped",
                            rel=rec.rel,
                            dest_rel=rec.rel,
                            message=f"Too large ({len(source_code)} chars), copied original instead",
                            source_hash=source_hash,
                        )

                    converted_code = call_openai_convert(
                        api_key=api_key,
                        model=model,
                        source_code=source_code,
                        source_lang=rec.lang,
                        target_lang=target_lang,
                        rel_path=rec.rel,
                        dest_rel_path=dest_rel,
                        project_tree=project_tree,
                        config_context=config_context,
                        path_map=path_map,
                        custom_instructions=custom_instructions,
                        retries=retries,
                        timeout_seconds=timeout_seconds,
                        cancel_event=self.cancel_event,
                    )

                    atomic_write_text(rec.dest, converted_code)

                    with state_lock:
                        state.setdefault("converted", {})[rec.rel] = {
                            "source_hash": source_hash,
                            "dest": dest_rel,
                            "converted_at": _dt.datetime.now().isoformat(timespec="seconds"),
                        }
                        save_state(output_dir, state)

                    return ConvertResult(
                        status="converted",
                        rel=rec.rel,
                        dest_rel=dest_rel,
                        message="Converted",
                        seconds=time.time() - start,
                        source_hash=source_hash,
                    )

                except Exception as e:
                    return ConvertResult(
                        status="failed",
                        rel=rec.rel,
                        message=str(e),
                        seconds=time.time() - start,
                    )

            with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
                future_map = {executor.submit(convert_one, rec): rec for rec in code_records}

                for future in concurrent.futures.as_completed(future_map):
                    result = future.result()
                    results.append(result)
                    done += 1

                    if result.status == "converted":
                        self.events.put(("log", f"Converted: {result.rel} -> {result.dest_rel} ({result.seconds:.1f}s)"))
                    elif result.status == "skipped":
                        self.events.put(("log", f"Skipped: {result.rel} — {result.message}"))
                    elif result.status == "failed":
                        self.events.put(("log", f"FAILED: {result.rel} — {result.message}"))
                    else:
                        self.events.put(("log", f"{result.status}: {result.rel}"))

                    self.events.put(("progress", done, total))

                    if self.cancel_event.is_set():
                        for f in future_map:
                            if not f.done():
                                f.cancel()

            report = write_report(
                output_dir=output_dir,
                source_dir=source_dir,
                target_lang=target_lang,
                model=model,
                records=records,
                results=results,
                dry_run=False,
                started=started,
                finished=_dt.datetime.now().isoformat(timespec="seconds"),
            )

            self.events.put(("done", str(report)))

        except Exception as e:
            details = f"{e}\n\n{traceback.format_exc()}"
            self.events.put(("error", details))


def main():
    root = tk.Tk()
    ProjectConverterGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()

