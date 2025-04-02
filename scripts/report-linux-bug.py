#!/usr/bin/env python3
import subprocess
import re
import os
import argparse
import contextlib
import sys

try:
    from llama_cpp import Llama
except ImportError:
    print("llama_cpp not installed. Please install with: pip install llama-cpp-python")
    raise

ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")

def generate_bug_report_locally(analysis_data, llm_path):
    prompt_text = f"""You are Linux Kernel expert. You are analyzing a Linux kernel crash and here are some inputs about crash:

Details:
Blame Module: {analysis_data['module']}
Instruction Pointer (RIP): {analysis_data['rip']}
Function: {analysis_data['function']}

Register Dump:
{analysis_data['registers']}

Additional Info:
{analysis_data['info']}

Source Snippet (kv_reset_tainted):
{analysis_data['source_code']}

===

Provide a short and concise bug report describing:
- The likely cause of the crash.
- Which module and function are implicated.
- Check function arguments and registers (e.g. arg one is RDI, second is RDI, etc.).
- Potential next steps or debugging strategies.
- Be short.
- Should be in up to 2 sentences.
- Print summary only.
- Do not print <think> process!
===
"""
    print("== Prompt used:")
    print(prompt_text)

    # Hide llama-cpp logs by redirecting stdout/stderr
    with open(os.devnull, 'w') as devnull:
        with contextlib.redirect_stdout(devnull), contextlib.redirect_stderr(devnull):
            llm = Llama(
                model_path=llm_path,
                n_ctx=2048,
                n_gpu_layers=0,
                n_threads=4,
                f16_kv=False,
                use_mlock=False
            )
            output = llm(
                prompt=prompt_text,
                max_tokens=512,
                temperature=0.2,
                stop=["</s>"]
            )

    if "choices" in output and output["choices"]:
        return output["choices"][0]["text"].strip()
    return output.get("data", "").strip()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--llm-path", required=True)
    parser.add_argument("--lldb-path", default="/usr/bin/lldb")
    parser.add_argument("--kdump-plugin-path", default="/path/to/libkLLDBLinux.so")
    parser.add_argument("--vmlinux-path", default="/path/to/vmlinux")
    parser.add_argument("--crash-file-path", default="./crash.file")
    parser.add_argument("--lkm-path", default="kovid.ko")
    parser.add_argument("--source-dir-old", default="/kovid/",
                        help="Old source dir path inside the kernel debug info.")
    parser.add_argument("--source-dir-new", default="/path/to/KoviD/kovid",
                        help="New source dir path on your filesystem.")
    parser.add_argument("--report-file", default=None,
                        help="Path to save the generated bug report (if provided). Otherwise prints to stdout.")

    args = parser.parse_args()

    lldb_cmd = [
        args.lldb_path,
        "-o", f"target create {args.vmlinux_path}",
        "-o", f"plugin load {args.kdump_plugin_path}",
        "-o", f"kdump open {args.crash_file_path}",
        "-o", "kdump info",
        "-o", f"kdump load-lkm {args.lkm_path}",
        "-o", "kdump bugpoint",
        "-o", f"kdump source-dir-map {args.source_dir_old} {args.source_dir_new}",
        "-o", "list kv_reset_tainted",
        "-o", "kdump registers",
        "-o", "q"
    ]

    print("Running LLDB with one-shot commands...")
    print(" ".join(lldb_cmd))

    # Run the command, capture output
    result = subprocess.run(lldb_cmd, capture_output=True, text=True)
    full_output = result.stdout

    if result.returncode != 0:
        print("WARNING: LLDB returned a non-zero status!", result.returncode)

    # Strip ANSI color codes
    clean_output = ANSI_RE.sub("", full_output)

    # --- PARSE BUGPOINT ---
    blame_module = re.search(r"Blame module:\s*(.*)", clean_output)
    rip_address  = re.search(r"Instructon pointer at rip=(0x[0-9A-Fa-f]+)", clean_output)
    blame_func   = re.search(r"Blame function:\s*(.*)", clean_output)

    # --- PARSE REGISTERS ---
    registers = {}
    for line in clean_output.splitlines():
        line_strip = line.strip()
        # Example: "  RAX=0x0000..."
        if "=" in line_strip and re.match(r"^[A-Z]+=", line_strip, re.IGNORECASE):
            parts = line_strip.split()
            for part in parts:
                if "=" in part:
                    reg, val = part.split("=")
                    registers[reg] = val

    # --- PARSE "kdump info" ---
    info_regex = re.compile(r"kdump info\s+(.*?)\s+kLLDB>", re.DOTALL)
    info_match = info_regex.search(clean_output)
    info_text = info_match.group(1).strip() if info_match else ""

    # --- PARSE "list kv_reset_tainted" ---
    snippet_regex = re.compile(r"list kv_reset_tainted\s+(.*?)\s+kLLDB>", re.DOTALL)
    snippet_match = snippet_regex.search(clean_output)
    source_snippet = snippet_match.group(1).strip() if snippet_match else ""

    # Debug prints
    print("\n=== PARSED RESULTS ===")
    mod_parsed = blame_module.group(1).strip() if blame_module else ""
    rip_parsed = rip_address.group(1).strip() if rip_address else ""
    func_parsed = blame_func.group(1).strip() if blame_func else ""
    print("Blame module:", mod_parsed)
    print("RIP address:", rip_parsed)
    print("Blame function:", func_parsed)
    print("Registers found:", registers)
    print("Info text:\n", info_text)
    print("Source snippet:\n", source_snippet)
    print("=====================")

    # Build analysis data
    analysis_data = {
        "module":     mod_parsed,
        "rip":        rip_parsed,
        "function":   func_parsed,
        "registers":  registers,
        "info":       info_text,
        "source_code": source_snippet,
    }

    print("\nGenerating bug report with local LLM...")
    bug_report = generate_bug_report_locally(analysis_data, args.llm_path)

    final_report = "kLLDB sesion:\n"
    final_report += full_output
    final_report += "\n=====\n\n"
    final_report += "LLM report:\n"
    final_report += bug_report
    final_report += "\n=====\n\n"

    # Print or write to file, depending on --report-file
    if args.report_file:
        print(f"\nWriting bug report to {args.report_file} ...")
        with open(args.report_file, "w", encoding="utf-8") as rf:
            rf.write(final_report + "\n")
        print("Done.")
    else:
        print("\n=== Bug Report ===")
        print(final_report)
        print("==================")

if __name__ == "__main__":
    main()
