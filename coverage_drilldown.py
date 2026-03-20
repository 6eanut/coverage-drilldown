#!/usr/bin/env python3
"""
coverage_drilldown.py — Generate a drill-down HTML coverage report.

For a given vmlinux + rawcover file, shows:
  subsystem → source file → function → individual addresses (with file:line)
with addr-based and function-based coverage rates at every level.

Usage:
  python3 coverage_drilldown.py \\
      --vmlinux  prefix/addr2function/input/fuzz-old-vmlinux \\
      --rawcover prefix/addr2function/input/fuzz-old-rawcover.txt \\
      --output   prefix/drilldown/fuzz-old-drilldown.html \\
      --tag      fuzz-old
"""

import os, re, sys, shutil, subprocess, argparse
from pathlib import Path
from collections import defaultdict


# ── Fake-function filter ──────────────────────────────────────────────────────
# Compiler/linker-generated stubs that appear in every file but are not real
# kernel functions worth tracking.
_FAKE_FN_RE = re.compile(
    r"^(_sub_[DI]_\d+_\d+"      # _sub_D_65535_0, _sub_I_65535_1, ...
    r"|__GLOBAL__sub_[DI]_.*"   # __GLOBAL__sub_D_...
    r"|__cxx_global_var_init.*" # C++ global constructors
    r"|_GLOBAL__sub_.*"         # another variant
    r"|__static_initialization.*"
    r")$"
)

def is_fake_func(name: str) -> bool:
    return bool(_FAKE_FN_RE.match(name))


# ── Tool detection ────────────────────────────────────────────────────────────

def find_tool(*candidates):
    for c in candidates:
        if shutil.which(c):
            return c
    raise FileNotFoundError(
        f"None of {candidates} found. "
        "Install binutils-riscv64-linux-gnu."
    )


# ── Address extraction ────────────────────────────────────────────────────────

def get_init_exit_ranges(vmlinux: str, objdump: str) -> list[tuple[int, int]]:
    """
    Parse 'objdump -h vmlinux' to find address ranges of .init.text and
    .exit.text sections. Functions there are __init/__exit and cannot be
    triggered at runtime via system calls.
    Returns list of (start, end) integer pairs (end exclusive).
    """
    ranges: list[tuple[int, int]] = []
    try:
        out = subprocess.check_output(
            [objdump, "-h", vmlinux],
            stderr=subprocess.DEVNULL, text=True,
        )
    except subprocess.CalledProcessError:
        return ranges
    # objdump -h line:  Idx Name   Size      VMA               ...
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        name = parts[1]
        if name not in (".init.text", ".exit.text"):
            continue
        try:
            size  = int(parts[2], 16)
            start = int(parts[3], 16)
            ranges.append((start, start + size))
            print(f"  [init/exit filter] {name}: "
                  f"0x{start:016x} - 0x{start+size:016x}")
        except (ValueError, IndexError):
            continue
    if not ranges:
        print("  [init/exit filter] No .init.text/.exit.text found")
    return ranges


def in_init_exit(addr_int: int, ranges: list[tuple[int, int]]) -> bool:
    return any(s <= addr_int < e for s, e in ranges)


def extract_kcov_addrs(vmlinux: str, objdump: str) -> list[str]:
    init_exit_ranges = get_init_exit_ranges(vmlinux, objdump)

    print(f"  [objdump] Disassembling {os.path.basename(vmlinux)} ...")
    cmd = [objdump, "-d", "--no-show-raw-insn", vmlinux]
    addrs: list[str] = []
    seen:  set[str]  = set()
    skipped = 0
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, text=True, bufsize=1 << 20)
        for line in proc.stdout:
            if "__sanitizer_cov_trace_pc>" not in line:
                continue
            m = re.match(r"^\s*([0-9a-f]+):", line)
            if not m:
                continue
            a_hex = m.group(1)
            a_int = int(a_hex, 16)
            if init_exit_ranges and in_init_exit(a_int, init_exit_ranges):
                skipped += 1
                continue
            a = "0x" + a_hex
            if a not in seen:
                seen.add(a)
                addrs.append(a)
        proc.wait()
    except FileNotFoundError:
        print(f"  ERROR: {objdump} not found"); sys.exit(1)
    if skipped:
        print(f"  [objdump] Skipped {skipped} __init/__exit kcov points")
    print(f"  [objdump] Found {len(addrs)} unique kcov points (runtime-reachable)")
    return addrs


# ── addr2line via stdin ───────────────────────────────────────────────────────

def addr2line_batch(vmlinux: str, addrs: list[str], a2l: str) -> list[tuple[str, str]]:
    """Returns list of (function, file:line) in same order as addrs."""
    print(f"  [addr2line] Mapping {len(addrs)} addresses ...")
    cmd = [a2l, "-e", vmlinux, "-f"]
    out = subprocess.check_output(cmd, input="\n".join(addrs) + "\n",
                                  stderr=subprocess.DEVNULL, text=True)
    lines = out.splitlines()
    result = []
    for i in range(len(addrs)):
        func = lines[i * 2].strip()     if i * 2     < len(lines) else "??"
        fl   = lines[i * 2 + 1].strip() if i * 2 + 1 < len(lines) else "??:0"
        result.append((func, fl))
    print("  [addr2line] Done.")
    return result


# ── Path helpers ──────────────────────────────────────────────────────────────

def classify(fileline: str) -> tuple[str | None, str, str]:
    """
    Returns (subsystem_key, srcfile, rel_fileline).
      subsystem_key : 'arch/riscv/kvm' | 'virt' | None
      srcfile       : relative path without line number, e.g. arch/riscv/kvm/vcpu.c
      rel_fileline  : relative path WITH line number, e.g. arch/riscv/kvm/vcpu.c:42
                      discriminator suffixes are kept as-is for display.
    """
    # Separate discriminator suffix for later re-attachment
    disc = ""
    m = re.search(r"( \(discriminator \d+\))$", fileline)
    if m:
        disc = m.group(1)
        fileline = fileline[:m.start()].strip()

    filepath, _, lineno = fileline.rpartition(":")
    if not filepath:
        return None, "", ""

    norm = os.path.normpath(filepath)

    for anchor, key in (("arch/riscv/kvm", "arch/riscv/kvm"), ("virt/", "virt")):
        idx = norm.find(anchor)
        if idx == -1:
            continue
        rel_path = norm[idx:]
        if key == "arch/riscv/kvm" and "arch/riscv/kvm" not in rel_path:
            continue
        if key == "virt" and not rel_path.startswith("virt/"):
            continue
        srcfile      = rel_path                           # e.g. arch/riscv/kvm/vcpu.c
        rel_fileline = f"{rel_path}:{lineno}{disc}"       # e.g. arch/riscv/kvm/vcpu.c:42
        return key, srcfile, rel_fileline

    return None, "", ""


# ── Data model ────────────────────────────────────────────────────────────────
#
# tree[subsystem][srcfile][func] = {
#     "entries": [(addr, rel_fileline), ...],  # all instrumented points
#     "hit_set": {addr, ...},                  # subset present in rawcover
# }

def build_tree(addrs: list[str],
               mapping: list[tuple[str, str]],
               covered: set[str]) -> dict:
    tree: dict = {}
    for addr, (func, fileline) in zip(addrs, mapping):
        if func in ("??", "") or is_fake_func(func):
            continue
        sub, srcfile, rel_fl = classify(fileline)
        if sub is None:
            continue

        tree.setdefault(sub, {})
        tree[sub].setdefault(srcfile, {})
        tree[sub][srcfile].setdefault(func, {"entries": [], "hit_set": set()})

        entry = tree[sub][srcfile][func]
        entry["entries"].append((addr, rel_fl))
        if addr in covered:
            entry["hit_set"].add(addr)

    return tree


# ── HTML ──────────────────────────────────────────────────────────────────────

CSS = r"""
:root{
  --bg:#f4f6f9;--card:#fff;--border:#dee2e6;--text:#212529;
  --muted:#6c757d;--blue:#0d6efd;--green:#198754;--orange:#fd7e14;
  --red:#dc3545;--row-hover:#f0f4ff;
}
*{box-sizing:border-box;margin:0;padding:0;}
body{font-family:'Segoe UI',system-ui,sans-serif;background:var(--bg);
     color:var(--text);padding:1.5rem 2rem;}
h1{font-size:1.5rem;margin-bottom:.25rem;}
.subtitle{color:var(--muted);font-size:.85rem;margin-bottom:1.5rem;}

/* summary */
.summary-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));
  gap:.8rem;margin-bottom:1.5rem;}
.scard{background:var(--card);border:1px solid var(--border);border-radius:8px;
  padding:1rem 1.2rem;}
.scard-label{font-size:.72rem;text-transform:uppercase;letter-spacing:.05em;
  color:var(--muted);margin-bottom:.4rem;}
.scard-nums{display:flex;gap:1.5rem;align-items:baseline;}
.scard-big{font-size:1.6rem;font-weight:700;}
.scard-sub{font-size:.8rem;color:var(--muted);}

/* search */
.search-wrap{margin-bottom:1rem;}
.search-box{width:100%;max-width:440px;padding:.38rem .7rem;
  border:1px solid var(--border);border-radius:6px;font-size:.875rem;}

/* subsystem */
.subsystem{background:var(--card);border:1px solid var(--border);
  border-radius:10px;margin-bottom:1.2rem;overflow:hidden;}
.subsystem-hdr{display:flex;align-items:center;gap:.8rem;padding:.75rem 1rem;
  cursor:pointer;user-select:none;background:#f8f9fb;
  border-bottom:1px solid var(--border);}
.subsystem-hdr:hover{background:#eef1f7;}
.chevron{font-size:.8rem;transition:transform .18s;flex-shrink:0;}
.open>.chevron,.open .chevron{transform:rotate(90deg);}
.subsystem-name{font-weight:700;font-size:.95rem;flex:1;}
.subsystem-body{padding:.5rem;}

/* file */
.file-block{margin:.3rem 0;}
.file-hdr{display:flex;align-items:center;gap:.6rem;padding:.4rem .6rem;
  border-radius:6px;cursor:pointer;user-select:none;}
.file-hdr:hover{background:var(--row-hover);}
.file-name{font-family:monospace;font-size:.83rem;flex:1;word-break:break-all;}
.file-body{margin:.2rem 0 .5rem 1.4rem;}

/* function table */
.fn-table{width:100%;border-collapse:collapse;font-size:.82rem;margin-top:.3rem;}
.fn-table thead th{background:#f8f9fb;padding:.35rem .6rem;text-align:left;
  border-bottom:2px solid var(--border);font-weight:600;white-space:nowrap;}
.fn-table tbody td{padding:.3rem .6rem;border-bottom:1px solid #f0f0f0;
  vertical-align:top;}
.fn-table tbody tr:last-child td{border-bottom:none;}
.fn-table tbody tr:hover td{background:var(--row-hover);}
.fn-name{font-family:monospace;}

/* addr list */
.addr-toggle{font-size:.75rem;color:var(--blue);cursor:pointer;
  text-decoration:underline dotted;white-space:nowrap;}
.addr-list{display:none;margin-top:.4rem;}
.addr-list.open{display:table;width:100%;border-collapse:collapse;}
.addr-row{display:table-row;}
.addr-row td{display:table-cell;padding:.15rem .4rem;font-family:monospace;
  font-size:.74rem;border-bottom:1px solid #f5f5f5;vertical-align:middle;}
.addr-row:last-child td{border-bottom:none;}
.addr-val{white-space:nowrap;}
.addr-fl {color:var(--muted);word-break:break-all;}
.addr-hit .addr-val{color:var(--green);}
.addr-hit .addr-fl {color:#5a9a6a;}
.addr-miss .addr-val{color:#bbb;}
.addr-miss .addr-fl {color:#ddd;}

/* bar + badge */
.bar-wrap{display:inline-block;width:80px;height:8px;background:var(--border);
  border-radius:4px;vertical-align:middle;overflow:hidden;margin-right:.3rem;}
.bar-fill{height:100%;border-radius:4px;}
.pct-text{font-size:.78rem;font-weight:600;}
.badge{display:inline-block;padding:1px 6px;border-radius:4px;
  font-size:.72rem;font-weight:600;white-space:nowrap;}
.badge-green{background:#d1e7dd;color:#0f5132;}
.badge-orange{background:#fff3cd;color:#664d03;}
.badge-red{background:#f8d7da;color:#842029;}
.badge-gray{background:#e9ecef;color:#495057;}
.search-hidden{display:none!important;}
"""

JS = r"""
function pctBar(hit,tot){
  const p=tot>0?hit/tot*100:0;
  const c=p>=70?'#198754':p>=40?'#fd7e14':tot>0?'#dc3545':'#adb5bd';
  return `<span class="bar-wrap"><span class="bar-fill" style="width:${p.toFixed(1)}%;background:${c}"></span></span>`
        +`<span class="pct-text" style="color:${c}">${p.toFixed(1)}%</span>`;
}
function toggleSection(hdr,bodyId){
  const open=hdr.classList.toggle('open');
  document.getElementById(bodyId).style.display=open?'':'none';
}
function toggleAddrList(btn){
  const list=btn.nextElementSibling;
  const open=list.classList.toggle('open');
  btn.textContent=open?'hide ▲':`show (${btn.dataset.n}) ▼`;
}
function doSearch(q){
  q=q.toLowerCase().trim();
  document.querySelectorAll('.file-block').forEach(fb=>{
    const fname=fb.querySelector('.file-name').textContent.toLowerCase();
    const fns=[...fb.querySelectorAll('.fn-name')].map(e=>e.textContent.toLowerCase());
    const ok=!q||fname.includes(q)||fns.some(f=>f.includes(q));
    fb.classList.toggle('search-hidden',!ok);
  });
  document.querySelectorAll('.subsystem').forEach(s=>{
    const any=[...s.querySelectorAll('.file-block')].some(f=>!f.classList.contains('search-hidden'));
    s.classList.toggle('search-hidden',!any);
  });
}
"""


def _bar(hit: int, tot: int) -> str:
    p = hit / tot * 100 if tot > 0 else 0
    c = "#198754" if p >= 70 else "#fd7e14" if p >= 40 else "#dc3545" if tot > 0 else "#adb5bd"
    return (f'<span class="bar-wrap"><span class="bar-fill" '
            f'style="width:{p:.1f}%;background:{c}"></span></span>'
            f'<span class="pct-text" style="color:{c}">{p:.1f}%</span>')


def _badge(hit: int, tot: int) -> str:
    p = hit / tot * 100 if tot > 0 else 0
    cls = ("badge-green" if p >= 70 else "badge-orange" if p >= 40
           else "badge-red" if tot > 0 else "badge-gray")
    return f'<span class="badge {cls}">{p:.1f}%</span>'


def render_summary(tree: dict, tag: str) -> str:
    html = f'<h1>🔬 Coverage Drill-Down — <code>{tag}</code></h1>\n'
    html += '<p class="subtitle">Subsystem → File → Function → Address &amp; file:line &nbsp;|&nbsp; arch/riscv/kvm &amp; virt/</p>\n'
    html += '<div class="summary-grid">\n'
    for sub in ("arch/riscv/kvm", "virt"):
        files = tree.get(sub, {})
        ta = sum(len(d["entries"]) for f in files.values() for d in f.values())
        ha = sum(len(d["hit_set"]) for f in files.values() for d in f.values())
        tf = sum(1 for f in files.values() for d in f.values())
        hf = sum(1 for f in files.values() for d in f.values() if d["hit_set"])
        nf = len(files)
        hfile = sum(1 for f in files.values() if any(d["hit_set"] for d in f.values()))
        pa = ha / ta * 100 if ta else 0
        pf = hf / tf * 100 if tf else 0
        ca = "#198754" if pa >= 70 else "#fd7e14" if pa >= 40 else "#dc3545"
        cf = "#198754" if pf >= 70 else "#fd7e14" if pf >= 40 else "#dc3545"
        html += f'''<div class="scard">
  <div class="scard-label">{sub}</div>
  <div class="scard-nums">
    <div><div class="scard-big" style="color:{ca}">{pa:.1f}%</div>
         <div class="scard-sub">addr &nbsp;{ha}/{ta}</div></div>
    <div><div class="scard-big" style="color:{cf}">{pf:.1f}%</div>
         <div class="scard-sub">func &nbsp;{hf}/{tf}</div></div>
    <div><div class="scard-big">{hfile}/{nf}</div>
         <div class="scard-sub">files covered</div></div>
  </div>
</div>\n'''
    html += '</div>\n'
    return html


def render_addr_col(fname: str, entries: list, hit_set: set) -> str:
    """
    Render the address + file:line column for one function.
    Each row: [addr]  [file:line]
    ≤10 entries: always expanded; >10: collapsed behind a toggle.
    """
    n = len(entries)
    uid = re.sub(r"[^a-z0-9]", "_", fname.lower()) + f"_{n}"

    rows_html = ""
    for addr, rel_fl in sorted(entries, key=lambda x: x[0]):
        hit = addr in hit_set
        row_cls = "addr-row addr-hit" if hit else "addr-row addr-miss"
        rows_html += (f'<tr class="{row_cls}">'
                      f'<td class="addr-val">{addr}</td>'
                      f'<td class="addr-fl">{rel_fl}</td>'
                      f'</tr>')

    table = f'<table class="addr-list" id="al_{uid}">{rows_html}</table>'

    if n <= 10:
        # pre-open
        table = table.replace('class="addr-list"', 'class="addr-list open"')
        return table
    else:
        toggle = (f'<span class="addr-toggle" data-n="{n}" '
                  f'onclick="toggleAddrList(this)">show ({n}) ▼</span>')
        return toggle + table


def render_tree(tree: dict) -> str:
    html = '<div class="search-wrap">'
    html += '<input class="search-box" type="text" placeholder="🔍  Search file or function…" oninput="doSearch(this.value)">'
    html += '</div>\n'

    sub_idx = 0
    for sub in ("arch/riscv/kvm", "virt"):
        files = tree.get(sub, {})
        if not files:
            continue
        ta = sum(len(d["entries"]) for f in files.values() for d in f.values())
        ha = sum(len(d["hit_set"]) for f in files.values() for d in f.values())
        tf = sum(1 for f in files.values() for d in f.values())
        hf = sum(1 for f in files.values() for d in f.values() if d["hit_set"])
        body_id = f"sub_body_{sub_idx}"; sub_idx += 1

        html += f'''<div class="subsystem">
  <div class="subsystem-hdr open" onclick="toggleSection(this,'{body_id}')">
    <span class="chevron">▶</span>
    <span class="subsystem-name">📁 {sub}/</span>
    <span style="font-size:.8rem;color:var(--muted)">
      {len(files)} files &nbsp;|&nbsp;
      addr: {_bar(ha,ta)} ({ha}/{ta}) &nbsp;|&nbsp;
      func: {_bar(hf,tf)} ({hf}/{tf})
    </span>
  </div>
  <div class="subsystem-body" id="{body_id}">\n'''

        def file_sort(fn):
            fdata = files[fn]
            hit = sum(len(d["hit_set"]) for d in fdata.values())
            return (0 if hit > 0 else 1, fn)

        file_idx = 0
        for srcfile in sorted(files, key=file_sort):
            funcs = files[srcfile]
            fa = sum(len(d["entries"]) for d in funcs.values())
            ha2 = sum(len(d["hit_set"]) for d in funcs.values())
            ff  = len(funcs)
            hf2 = sum(1 for d in funcs.values() if d["hit_set"])

            display = srcfile
            for pfx in ("arch/riscv/kvm/", "virt/kvm/", "virt/"):
                if display.startswith(pfx):
                    display = display[len(pfx):]; break

            fbody_id = f"fb_{sub_idx}_{file_idx}"; file_idx += 1
            html += f'''    <div class="file-block">
      <div class="file-hdr open" onclick="toggleSection(this,'{fbody_id}')">
        <span class="chevron">▶</span>
        <span class="file-name" title="{srcfile}">📄 {display}</span>
        <span style="font-size:.78rem;color:var(--muted);white-space:nowrap;margin-left:.5rem">
          addr {_bar(ha2,fa)} ({ha2}/{fa})
          &nbsp; func {_badge(hf2,ff)} {hf2}/{ff}
        </span>
      </div>
      <div class="file-body" id="{fbody_id}">
        <table class="fn-table">
          <thead><tr>
            <th>Function</th><th>Addr Coverage</th><th>Hit&nbsp;/&nbsp;Total</th>
            <th>Address &amp; file:line</th>
          </tr></thead>
          <tbody>\n'''

            def fn_sort(fn):
                return (0 if funcs[fn]["hit_set"] else 1, fn)

            for fname in sorted(funcs, key=fn_sort):
                d = funcs[fname]
                nt = len(d["entries"])
                nh = len(d["hit_set"])
                addr_col = render_addr_col(fname, d["entries"], d["hit_set"])
                html += (f'            <tr>'
                         f'<td class="fn-name">{fname}</td>'
                         f'<td>{_bar(nh,nt)}</td>'
                         f'<td style="white-space:nowrap">{nh}&nbsp;/&nbsp;{nt}</td>'
                         f'<td>{addr_col}</td>'
                         f'</tr>\n')

            html += "          </tbody></table>\n      </div>\n    </div>\n"

        html += "  </div>\n</div>\n"
    return html


INIT_JS = """
document.querySelectorAll('.subsystem-hdr,.file-hdr').forEach(h=>{
  h.classList.add('open');
});
"""

def build_html(tag: str, tree: dict) -> str:
    parts = [
        '<!DOCTYPE html><html lang="en"><head>',
        '<meta charset="UTF-8">',
        '<meta name="viewport" content="width=device-width,initial-scale=1.0">',
        f'<title>Coverage Drill-Down — {tag}</title>',
        f'<style>{CSS}</style>',
        '</head><body>',
        render_summary(tree, tag),
        render_tree(tree),
        f'<script>{JS}</script>',
        f'<script>{INIT_JS}</script>',
        '</body></html>',
    ]
    return ''.join(parts)


# ── Main ──────────────────────────────────────────────────────────────────────

def run(vmlinux: str, rawcover: str, output: str, tag: str) -> None:
    try:
        objdump   = find_tool("riscv64-linux-gnu-objdump",
                              "riscv64-unknown-linux-gnu-objdump", "objdump")
        addr2line = find_tool("riscv64-linux-gnu-addr2line",
                              "riscv64-unknown-linux-gnu-addr2line", "addr2line")
    except FileNotFoundError as e:
        print(f"ERROR: {e}"); sys.exit(1)
    print(f"  objdump   : {objdump}")
    print(f"  addr2line : {addr2line}")

    all_addrs = extract_kcov_addrs(vmlinux, objdump)
    if not all_addrs:
        print("ERROR: no kcov points found"); sys.exit(1)

    mapping = addr2line_batch(vmlinux, all_addrs, addr2line)

    print(f"  Loading rawcover: {rawcover} ...")
    covered = {ln.strip() for ln in open(rawcover) if ln.strip()}
    print(f"  Rawcover addresses: {len(covered)}")

    print("  Building coverage tree ...")
    tree = build_tree(all_addrs, mapping, covered)

    for sub, files in tree.items():
        ta = sum(len(d["entries"]) for f in files.values() for d in f.values())
        ha = sum(len(d["hit_set"]) for f in files.values() for d in f.values())
        print(f"  [{sub}] {len(files)} files, {ta} addrs, {ha} hit "
              + (f"({ha/ta*100:.1f}%)" if ta else "(n/a)"))

    print("  Generating HTML ...")
    html = build_html(tag, tree)
    Path(output).parent.mkdir(parents=True, exist_ok=True)
    open(output, "w", encoding="utf-8").write(html)
    print(f"  Written -> {output}  ({os.path.getsize(output):,} bytes)")


if __name__ == "__main__":
    p = argparse.ArgumentParser(
        description="Drill-down coverage HTML: vmlinux + rawcover → HTML"
    )
    p.add_argument("--vmlinux",  required=True)
    p.add_argument("--rawcover", required=True)
    p.add_argument("--output",   required=True)
    p.add_argument("--tag",      default="coverage")
    a = p.parse_args()
    run(a.vmlinux, a.rawcover, a.output, a.tag)
