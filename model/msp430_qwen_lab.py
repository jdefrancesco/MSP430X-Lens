#!/usr/bin/env python3
"""
msp430_qwen_lab.py

A small end-to-end experiment for domain-adapting a Qwen coder model to
MSP430/MSP430X reverse engineering.

What it does:
  1) fetch-docs   - download official TI MSP430X/GCC documentation
  2) make-data    - generate deterministic MSP430 C functions, compile them at
                    several optimization levels, disassemble them, and build
                    ChatML-style SFT JSONL examples
  3) train        - LoRA/QLoRA SFT with Hugging Face Transformers/PEFT/TRL
  4) eval         - compare base vs adapter on a held-out deterministic set
  5) export       - merge the adapter into a normal Hugging Face model

The synthetic examples have deterministic labels rather than labels invented by
another LLM. Official TI documentation is used to seed architecture/ABI prompt
context and to keep the corpus MSP430X-specific.

Expected toolchain executable names:
  msp430-elf-gcc
  msp430-elf-objdump
  pdftotext

Example:
  python3 msp430_qwen_lab.py all --samples 3000
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import random
import re
import shutil
import subprocess
import sys
import textwrap
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

ROOT = Path(os.environ.get("MSP430_QWEN_LAB", "./msp430-qwen-lab")).resolve()
DOCS = ROOT / "docs"
SRC = ROOT / "generated-src"
OBJ = ROOT / "obj"
DATA = ROOT / "data"
OUT = ROOT / "out"

DEFAULT_MODEL = os.environ.get(
    "MODEL_ID", "Qwen/Qwen2.5-Coder-3B-Instruct"
)

TI_DOCS = {
    "msp430x_users_guide.pdf":
        "https://www.ti.com/lit/ug/slau208q/slau208q.pdf",
    "msp430_gcc_users_guide.pdf":
        "https://www.ti.com/lit/ug/slau646f/slau646f.pdf",
}

ARCH_CONTEXT = """\
Target: TI MSP430/MSP430X firmware.
MSP430X extends the classic MSP430 architecture with a 20-bit address space.
R0 is PC, R1 is SP, R2 is SR/constant-generator related, and R3 is a constant
generator. Byte, word, and address-width operations must not be conflated.
For reverse engineering, distinguish machine-level facts from guesses about
peripheral identity. Do not invent a peripheral name unless a target-specific
memory map is supplied.
"""

SYSTEM_PROMPT = """\
You are a firmware reverse engineer specializing in TI MSP430 and MSP430X.
Analyze only the evidence provided. Prefer precise data width, signedness,
pointer, loop, calling-convention, and MMIO observations over generic prose.
When a hardware register map is not provided, describe an access as MMIO rather
than guessing a peripheral name.
"""

OPT_LEVELS = ["-O0", "-O1", "-O2", "-Os"]

# We intentionally avoid libc/header dependencies so each function can be
# compiled as a freestanding translation unit by the MSP430 cross compiler.
PREAMBLE = """\
typedef unsigned char  u8;
typedef signed char    s8;
typedef unsigned short u16;
typedef signed short   s16;
typedef unsigned long  u32;
typedef signed long    s32;
typedef unsigned long  uptr;
#define NOINLINE __attribute__((noinline))
"""

@dataclass
class Case:
    name: str
    source: str
    summary: str
    prototype: str
    tags: list[str]
    key_terms: list[str]


def run(cmd: list[str], *, cwd: Path | None = None, capture=True, check=True) -> subprocess.CompletedProcess:
    return subprocess.run(
        cmd,
        cwd=str(cwd) if cwd else None,
        text=True,
        capture_output=capture,
        check=check,
    )


def need(tool: str) -> str:
    p = shutil.which(tool)
    if not p:
        raise SystemExit(
            f"Missing required tool: {tool}\n"
            f"Install the MSP430 GCC toolchain and make sure its bin directory is in PATH."
        )
    return p


def mkdirs():
    for p in (ROOT, DOCS, SRC, OBJ, DATA, OUT):
        p.mkdir(parents=True, exist_ok=True)


def download(url: str, dst: Path):
    if dst.exists() and dst.stat().st_size > 1024:
        return
    print(f"[+] download {url}")
    req = urllib.request.Request(url, headers={"User-Agent": "msp430-qwen-lab/1.0"})
    with urllib.request.urlopen(req, timeout=60) as r, dst.open("wb") as f:
        shutil.copyfileobj(r, f)


def fetch_docs():
    mkdirs()
    for name, url in TI_DOCS.items():
        try:
            download(url, DOCS / name)
        except Exception as e:
            print(f"[!] could not download {url}: {e}")
    pdftotext = shutil.which("pdftotext")
    if not pdftotext:
        print("[!] pdftotext missing; PDFs were downloaded but text extraction is skipped")
        return
    for pdf in DOCS.glob("*.pdf"):
        txt = pdf.with_suffix(".txt")
        if not txt.exists():
            print(f"[+] extracting {pdf.name}")
            run([pdftotext, "-layout", str(pdf), str(txt)], capture=True)


def doc_snippets() -> list[str]:
    """
    Pull only small architecture-relevant snippets. These are used as contextual
    grounding in prompts, not copied wholesale into assistant targets.
    """
    terms = [
        "MSP430X CPU",
        "20-bit address",
        "constant generator",
        "calling convention",
        "register arguments",
        "CALLA",
        "RETA",
        "PUSHM",
        "POPM",
    ]
    snippets: list[str] = []
    for txt in DOCS.glob("*.txt"):
        try:
            data = txt.read_text(errors="ignore")
        except OSError:
            continue
        lines = data.splitlines()
        for term in terms:
            for i, line in enumerate(lines):
                if term.lower() in line.lower():
                    chunk = " ".join(x.strip() for x in lines[max(0, i-1):i+3])
                    chunk = re.sub(r"\s+", " ", chunk).strip()
                    if 40 <= len(chunk) <= 700:
                        snippets.append(chunk)
                    break
    return snippets[:16]


def make_cases(n: int, seed: int) -> list[Case]:
    rng = random.Random(seed)
    cases: list[Case] = []

    def add(kind: str, body: str, summary: str, prototype: str, tags, keys):
        idx = len(cases)
        name = f"{kind}_{idx:05d}"
        src = PREAMBLE + "\n" + body.replace("__NAME__", name) + "\n"
        cases.append(Case(name, src, summary, prototype, list(tags), list(keys)))

    while len(cases) < n:
        choice = rng.randrange(14)

        if choice == 0:
            k = rng.randrange(1, 16)
            add("add_const",
                f"NOINLINE u16 __NAME__(u16 x) {{ return (u16)(x + {k}u); }}",
                f"Adds the unsigned 16-bit constant {k} to a 16-bit argument and returns the result modulo 2^16.",
                "u16 func(u16 x)", ["arithmetic", "u16"], ["16-bit", "add"])

        elif choice == 1:
            mask = 1 << rng.randrange(0, 8)
            add("mask_test",
                f"NOINLINE u8 __NAME__(u8 x) {{ return (u8)((x & 0x{mask:02x}u) != 0); }}",
                f"Tests whether mask 0x{mask:02x} is set in an 8-bit value and returns a boolean-like byte.",
                "u8 func(u8 x)", ["bit-test", "u8"], ["8-bit", "mask", "test"])

        elif choice == 2:
            add("sum_u8",
                """NOINLINE u16 __NAME__(const u8 *p, u16 n) {
                    u16 s = 0;
                    while (n--) s = (u16)(s + *p++);
                    return s;
                }""",
                "Computes an unsigned 16-bit additive checksum/sum over n bytes from a buffer.",
                "u16 func(const u8 *p, u16 n)",
                ["loop", "buffer", "checksum"], ["buffer", "byte", "sum", "loop"])

        elif choice == 3:
            add("xor_u8",
                """NOINLINE u8 __NAME__(const u8 *p, u16 n) {
                    u8 x = 0;
                    while (n--) x ^= *p++;
                    return x;
                }""",
                "XOR-reduces n bytes from a buffer into an 8-bit result.",
                "u8 func(const u8 *p, u16 n)",
                ["loop", "buffer", "xor"], ["buffer", "xor", "byte"])

        elif choice == 4:
            needle = rng.randrange(0, 256)
            add("find_u8",
                f"""NOINLINE s16 __NAME__(const u8 *p, u16 n) {{
                    u16 i;
                    for (i = 0; i < n; i++) if (p[i] == 0x{needle:02x}u) return (s16)i;
                    return (s16)-1;
                }}""",
                f"Searches a byte buffer for constant 0x{needle:02x}; returns its index or -1 when absent.",
                "s16 func(const u8 *p, u16 n)",
                ["search", "buffer", "signed-return"], ["search", "buffer", "-1"])

        elif choice == 5:
            limit = rng.randrange(5, 240)
            add("clamp_u8",
                f"""NOINLINE u8 __NAME__(u16 x) {{
                    if (x > {limit}u) return (u8){limit}u;
                    return (u8)x;
                }}""",
                f"Clamps an unsigned value to an upper bound of {limit} and returns an 8-bit result.",
                "u8 func(u16 x)", ["branch", "clamp"], ["clamp", "upper", "bound"])

        elif choice == 6:
            bit = rng.randrange(0, 16)
            addr = rng.randrange(0x0100, 0x0400, 2)
            add("mmio_set",
                f"""NOINLINE void __NAME__(void) {{
                    volatile u16 *r = (volatile u16 *)(uptr)0x{addr:04x}u;
                    *r = (u16)(*r | (u16)(1u << {bit}));
                }}""",
                f"Performs a volatile 16-bit MMIO read-modify-write at address 0x{addr:04x}, setting bit {bit}. The peripheral identity is unknown without a device memory map.",
                "void func(void)", ["mmio", "rmw", "volatile"], ["MMIO", "volatile", "bit"])

        elif choice == 7:
            bit = rng.randrange(0, 8)
            addr = rng.randrange(0x0020, 0x0100)
            add("mmio_clear8",
                f"""NOINLINE void __NAME__(void) {{
                    volatile u8 *r = (volatile u8 *)(uptr)0x{addr:04x}u;
                    *r = (u8)(*r & (u8)~(1u << {bit}));
                }}""",
                f"Performs a volatile 8-bit MMIO read-modify-write at address 0x{addr:04x}, clearing bit {bit}. The peripheral identity is not inferable from this code alone.",
                "void func(void)", ["mmio", "rmw", "u8"], ["MMIO", "8-bit", "clear"])

        elif choice == 8:
            add("read_be16",
                """NOINLINE u16 __NAME__(const u8 *p) {
                    return (u16)(((u16)p[0] << 8) | (u16)p[1]);
                }""",
                "Reads two bytes from memory and assembles them as a big-endian 16-bit integer.",
                "u16 func(const u8 *p)", ["endian", "buffer"], ["big-endian", "16-bit", "two bytes"])

        elif choice == 9:
            add("copy_u8",
                """NOINLINE void __NAME__(u8 *d, const u8 *s, u16 n) {
                    while (n--) *d++ = *s++;
                }""",
                "Copies n bytes from a source buffer to a destination buffer using a simple forward loop.",
                "void func(u8 *dst, const u8 *src, u16 n)",
                ["copy", "loop", "buffer"], ["copy", "source", "destination"])

        elif choice == 10:
            val = rng.randrange(0, 256)
            add("fill_u8",
                f"""NOINLINE void __NAME__(u8 *d, u16 n) {{
                    while (n--) *d++ = (u8)0x{val:02x}u;
                }}""",
                f"Fills n bytes of a destination buffer with constant byte 0x{val:02x}.",
                "void func(u8 *dst, u16 n)",
                ["fill", "loop", "buffer"], ["fill", "buffer", "constant"])

        elif choice == 11:
            add("max_s16",
                """NOINLINE s16 __NAME__(s16 a, s16 b) {
                    return a > b ? a : b;
                }""",
                "Returns the greater of two signed 16-bit values.",
                "s16 func(s16 a, s16 b)",
                ["signed", "compare"], ["signed", "16-bit", "greater"])

        elif choice == 12:
            add("state3",
                """NOINLINE u8 __NAME__(u8 s, u8 x) {
                    switch (s) {
                    case 0: return x == 0x55u ? 1u : 0u;
                    case 1: return x == 0xaau ? 2u : 0u;
                    case 2: return x == 0x0du ? 3u : 0u;
                    default: return 0u;
                    }
                }""",
                "Implements a small byte-oriented state transition function with states 0, 1, and 2 and specific input-byte transitions.",
                "u8 func(u8 state, u8 input)",
                ["state-machine", "switch"], ["state", "switch", "byte"])

        else:
            add("sat_add_u8",
                """NOINLINE u8 __NAME__(u8 a, u8 b) {
                    u16 s = (u16)a + (u16)b;
                    return s > 255u ? 255u : (u8)s;
                }""",
                "Adds two unsigned bytes with saturation at 255 rather than wraparound.",
                "u8 func(u8 a, u8 b)",
                ["saturating", "arithmetic"], ["saturat", "255", "unsigned"])

    return cases


def compiler_flags(opt: str) -> list[str]:
    # -mmcu selects an MSP430X-class F5xx device. Compile-only avoids requiring
    # startup objects/linker configuration.
    return [
        "-mmcu=msp430f5529",
        opt,
        "-ffreestanding",
        "-fno-builtin",
        "-fno-inline",
        "-fno-inline-functions",
        "-fno-ipa-cp",
        "-fno-ipa-sra",
        "-c",
    ]


def compile_case(case: Case, opt: str) -> tuple[str, str]:
    gcc = need("msp430-elf-gcc")
    objdump = need("msp430-elf-objdump")

    optname = opt.replace("-", "")
    cpath = SRC / f"{case.name}_{optname}.c"
    opath = OBJ / f"{case.name}_{optname}.o"
    cpath.write_text(case.source)

    cmd = [gcc, *compiler_flags(opt), str(cpath), "-o", str(opath)]
    cp = run(cmd, check=False)
    if cp.returncode != 0:
        # Some toolchains don't recognize one of the anti-IPA switches.
        fallback = [
            gcc, "-mmcu=msp430f5529", opt, "-ffreestanding",
            "-fno-builtin", "-fno-inline", "-c",
            str(cpath), "-o", str(opath)
        ]
        cp = run(fallback, check=False)
        if cp.returncode != 0:
            raise RuntimeError(f"compile failed:\n{cp.stderr}")

    dis = run([objdump, "-drwC", str(opath)]).stdout

    # One generated function per TU. Strip noisy headers but retain relocation
    # information because it can be useful to a reverser.
    m = re.search(
        rf"(?ms)^[0-9a-fA-F]+\s+<{re.escape(case.name)}>:\n(.*?)(?=^\s*$|\Z)",
        dis,
    )
    asm = m.group(1).strip() if m else dis.strip()

    # Normalize generated file paths/addresses that aren't semantically useful.
    asm = re.sub(r"\b[0-9a-fA-F]{8,16}\b", "<ADDR>", asm)
    return asm, cp.stderr


def assistant_target(case: Case) -> str:
    return (
        f"Prototype: {case.prototype}\n"
        f"Purpose: {case.summary}\n"
        f"Evidence: infer widths, memory accesses, branches, and data flow from the disassembly.\n"
        f"Confidence: high for the software semantics; hardware-peripheral identity requires a device-specific memory map."
    )


def make_record(case: Case, opt: str, asm: str, snippets: list[str]) -> dict:
    grounded = ""
    if snippets:
        # Add a tiny amount of official-doc context to some examples, but not
        # enough to swamp the assembly task.
        h = int(hashlib.sha256((case.name + opt).encode()).hexdigest(), 16)
        if h % 5 == 0:
            grounded = "\nArchitecture note from TI documentation:\n" + snippets[h % len(snippets)]

    user = f"""{ARCH_CONTEXT}{grounded}

Compiler optimization: {opt}
Function symbol: {case.name}

MSP430/MSP430X disassembly:
```asm
{asm}
```

Determine:
1. probable C prototype
2. function purpose
3. important width/signedness/pointer/MMIO observations
4. confidence and any uncertainty
"""
    return {
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user},
            {"role": "assistant", "content": assistant_target(case)},
        ],
        "meta": {
            "name": case.name,
            "optimization": opt,
            "tags": case.tags,
            "key_terms": case.key_terms,
        },
    }


def make_data(samples: int, seed: int):
    mkdirs()
    need("msp430-elf-gcc")
    need("msp430-elf-objdump")

    snippets = doc_snippets()
    cases = make_cases(samples, seed)
    rng = random.Random(seed)

    # Split by source case BEFORE multiplying by optimization level. That keeps
    # variants of the same source function out of both train and eval.
    rng.shuffle(cases)
    n_eval = max(30, int(len(cases) * 0.10))
    eval_cases = cases[:n_eval]
    train_cases = cases[n_eval:]

    train_records = []
    eval_records = []

    print(f"[+] compiling {len(cases)} source cases x {len(OPT_LEVELS)} optimization levels")

    for split, group, sink in [
        ("train", train_cases, train_records),
        ("eval", eval_cases, eval_records),
    ]:
        for i, case in enumerate(group, 1):
            for opt in OPT_LEVELS:
                try:
                    asm, _ = compile_case(case, opt)
                except Exception as e:
                    print(f"[!] {case.name} {opt}: {e}")
                    continue
                sink.append(make_record(case, opt, asm, snippets))
            if i % 100 == 0:
                print(f"    {split}: {i}/{len(group)}")

    random.Random(seed + 1).shuffle(train_records)
    random.Random(seed + 2).shuffle(eval_records)

    for name, recs in [("train.jsonl", train_records), ("eval.jsonl", eval_records)]:
        p = DATA / name
        with p.open("w") as f:
            for r in recs:
                f.write(json.dumps(r) + "\n")
        print(f"[+] wrote {len(recs):,} examples -> {p}")


def pip_hint():
    print(textwrap.dedent("""
    Training dependencies:
      pip install -U torch transformers datasets peft trl accelerate bitsandbytes

    For an NVIDIA GPU, bitsandbytes enables 4-bit QLoRA.
    On Apple Silicon, omit --load-in-4bit; the 3B model needs substantially
    more unified memory in bf16/fp16.
    """).strip())


def train(model_id: str, epochs: float, lr: float, batch: int, grad_accum: int,
          load_in_4bit: bool, max_seq: int):
    try:
        import torch
        from datasets import load_dataset
        from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig
        from peft import LoraConfig
        from trl import SFTConfig, SFTTrainer
    except Exception as e:
        pip_hint()
        raise SystemExit(f"\nImport error: {e}")

    train_file = DATA / "train.jsonl"
    if not train_file.exists():
        raise SystemExit("Run make-data first.")

    tokenizer = AutoTokenizer.from_pretrained(model_id, trust_remote_code=True)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token

    quant = None
    dtype = torch.bfloat16 if torch.cuda.is_available() and torch.cuda.is_bf16_supported() else torch.float16

    if load_in_4bit:
        if not torch.cuda.is_available():
            raise SystemExit("--load-in-4bit currently requires an NVIDIA/CUDA setup in this script.")
        quant = BitsAndBytesConfig(
            load_in_4bit=True,
            bnb_4bit_quant_type="nf4",
            bnb_4bit_use_double_quant=True,
            bnb_4bit_compute_dtype=dtype,
        )

    model = AutoModelForCausalLM.from_pretrained(
        model_id,
        quantization_config=quant,
        torch_dtype=None if quant else dtype,
        device_map="auto",
        trust_remote_code=True,
    )
    model.config.use_cache = False

    ds = load_dataset("json", data_files=str(train_file), split="train")

    def format_example(ex):
        return tokenizer.apply_chat_template(
            ex["messages"], tokenize=False, add_generation_prompt=False
        )

    peft_cfg = LoraConfig(
        r=32,
        lora_alpha=64,
        lora_dropout=0.05,
        bias="none",
        task_type="CAUSAL_LM",
        target_modules=[
            "q_proj", "k_proj", "v_proj", "o_proj",
            "gate_proj", "up_proj", "down_proj",
        ],
    )

    adapter_dir = OUT / "msp430-qwen-lora"
    cfg = SFTConfig(
        output_dir=str(adapter_dir),
        num_train_epochs=epochs,
        learning_rate=lr,
        per_device_train_batch_size=batch,
        gradient_accumulation_steps=grad_accum,
        logging_steps=10,
        save_steps=200,
        save_total_limit=2,
        warmup_ratio=0.05,
        lr_scheduler_type="cosine",
        max_length=max_seq,
        packing=True,
        report_to="none",
        gradient_checkpointing=True,
        bf16=bool(torch.cuda.is_available() and torch.cuda.is_bf16_supported()),
        fp16=bool(torch.cuda.is_available() and not torch.cuda.is_bf16_supported()),
    )

    trainer = SFTTrainer(
        model=model,
        args=cfg,
        train_dataset=ds,
        peft_config=peft_cfg,
        formatting_func=format_example,
        processing_class=tokenizer,
    )

    trainer.train()
    trainer.save_model(str(adapter_dir))
    tokenizer.save_pretrained(str(adapter_dir))
    print(f"[+] adapter saved to {adapter_dir}")


def load_jsonl(path: Path) -> list[dict]:
    out = []
    with path.open() as f:
        for line in f:
            line = line.strip()
            if line:
                out.append(json.loads(line))
    return out


def keyword_score(text: str, keys: Iterable[str]) -> float:
    low = text.lower()
    keys = list(keys)
    if not keys:
        return 0.0
    return sum(1 for k in keys if k.lower() in low) / len(keys)


def generate(model, tok, prompt_messages, max_new_tokens=180) -> str:
    import torch
    prompt = tok.apply_chat_template(
        prompt_messages, tokenize=False, add_generation_prompt=True
    )
    inp = tok(prompt, return_tensors="pt").to(model.device)
    with torch.no_grad():
        out = model.generate(
            **inp,
            max_new_tokens=max_new_tokens,
            do_sample=False,
            temperature=None,
            top_p=None,
            pad_token_id=tok.eos_token_id,
        )
    new_tokens = out[0, inp["input_ids"].shape[1]:]
    return tok.decode(new_tokens, skip_special_tokens=True)


def eval_models(model_id: str, limit: int, load_in_4bit: bool):
    try:
        import torch
        from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig
        from peft import PeftModel
    except Exception as e:
        pip_hint()
        raise SystemExit(f"\nImport error: {e}")

    records = load_jsonl(DATA / "eval.jsonl")
    # One optimization variant per source symbol to avoid inflating the score.
    seen = set()
    chosen = []
    for r in records:
        n = r["meta"]["name"]
        if n not in seen:
            seen.add(n)
            chosen.append(r)
        if len(chosen) >= limit:
            break

    tok = AutoTokenizer.from_pretrained(model_id, trust_remote_code=True)
    if tok.pad_token is None:
        tok.pad_token = tok.eos_token

    quant = None
    dtype = torch.bfloat16 if torch.cuda.is_available() and torch.cuda.is_bf16_supported() else torch.float16
    if load_in_4bit:
        quant = BitsAndBytesConfig(
            load_in_4bit=True,
            bnb_4bit_quant_type="nf4",
            bnb_4bit_use_double_quant=True,
            bnb_4bit_compute_dtype=dtype,
        )

    def fresh_base():
        return AutoModelForCausalLM.from_pretrained(
            model_id,
            quantization_config=quant,
            torch_dtype=None if quant else dtype,
            device_map="auto",
            trust_remote_code=True,
        )

    print(f"[+] evaluating base model on {len(chosen)} held-out source functions")
    base = fresh_base()
    base_scores = []
    base_outputs = []
    for r in chosen:
        out = generate(base, tok, r["messages"][:2])
        base_outputs.append(out)
        base_scores.append(keyword_score(out, r["meta"]["key_terms"]))
    del base
    if torch.cuda.is_available():
        torch.cuda.empty_cache()

    adapter = OUT / "msp430-qwen-lora"
    if not adapter.exists():
        raise SystemExit(f"Adapter not found: {adapter}")

    print("[+] evaluating LoRA-adapted model")
    tuned = fresh_base()
    tuned = PeftModel.from_pretrained(tuned, str(adapter))
    tuned_scores = []
    tuned_outputs = []
    for r in chosen:
        out = generate(tuned, tok, r["messages"][:2])
        tuned_outputs.append(out)
        tuned_scores.append(keyword_score(out, r["meta"]["key_terms"]))

    avg_base = sum(base_scores) / max(1, len(base_scores))
    avg_tuned = sum(tuned_scores) / max(1, len(tuned_scores))

    result = {
        "n": len(chosen),
        "base_keyword_recall": avg_base,
        "tuned_keyword_recall": avg_tuned,
        "delta": avg_tuned - avg_base,
    }
    (OUT / "eval_summary.json").write_text(json.dumps(result, indent=2))

    with (OUT / "eval_examples.jsonl").open("w") as f:
        for r, b, t, bs, ts in zip(chosen, base_outputs, tuned_outputs, base_scores, tuned_scores):
            f.write(json.dumps({
                "name": r["meta"]["name"],
                "keys": r["meta"]["key_terms"],
                "base_score": bs,
                "tuned_score": ts,
                "base": b,
                "tuned": t,
                "reference": r["messages"][2]["content"],
            }) + "\n")

    print(json.dumps(result, indent=2))
    print(f"[+] detailed outputs: {OUT / 'eval_examples.jsonl'}")


def export_merged(model_id: str):
    try:
        import torch
        from transformers import AutoModelForCausalLM, AutoTokenizer
        from peft import PeftModel
    except Exception as e:
        pip_hint()
        raise SystemExit(f"\nImport error: {e}")

    adapter = OUT / "msp430-qwen-lora"
    merged = OUT / "msp430-qwen-merged"
    base = AutoModelForCausalLM.from_pretrained(
        model_id,
        torch_dtype=torch.float16,
        device_map="cpu",
        trust_remote_code=True,
    )
    model = PeftModel.from_pretrained(base, str(adapter))
    model = model.merge_and_unload()
    model.save_pretrained(str(merged), safe_serialization=True)
    tok = AutoTokenizer.from_pretrained(model_id, trust_remote_code=True)
    tok.save_pretrained(str(merged))
    print(f"[+] merged Hugging Face model -> {merged}")
    print("[i] Convert this directory to GGUF with llama.cpp, quantize it, then create an Ollama model.")


def cmd_all(args):
    fetch_docs()
    make_data(args.samples, args.seed)
    train(
        args.model, args.epochs, args.lr, args.batch, args.grad_accum,
        args.load_in_4bit, args.max_seq
    )
    eval_models(args.model, args.eval_limit, args.load_in_4bit)


def main():
    mkdirs()
    p = argparse.ArgumentParser(
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("fetch-docs")
    s.set_defaults(fn=lambda a: fetch_docs())

    s = sub.add_parser("make-data")
    s.add_argument("--samples", type=int, default=2500,
                   help="number of unique source functions; each is compiled at 4 optimization levels")
    s.add_argument("--seed", type=int, default=430)
    s.set_defaults(fn=lambda a: make_data(a.samples, a.seed))

    def train_args(s):
        s.add_argument("--model", default=DEFAULT_MODEL)
        s.add_argument("--epochs", type=float, default=2.0)
        s.add_argument("--lr", type=float, default=1e-4)
        s.add_argument("--batch", type=int, default=1)
        s.add_argument("--grad-accum", type=int, default=16)
        s.add_argument("--max-seq", type=int, default=4096)
        s.add_argument("--load-in-4bit", action="store_true",
                       help="use NF4 QLoRA; NVIDIA/CUDA only in this script")

    s = sub.add_parser("train")
    train_args(s)
    s.set_defaults(fn=lambda a: train(
        a.model, a.epochs, a.lr, a.batch, a.grad_accum,
        a.load_in_4bit, a.max_seq
    ))

    s = sub.add_parser("eval")
    s.add_argument("--model", default=DEFAULT_MODEL)
    s.add_argument("--eval-limit", type=int, default=60)
    s.add_argument("--load-in-4bit", action="store_true")
    s.set_defaults(fn=lambda a: eval_models(a.model, a.eval_limit, a.load_in_4bit))

    s = sub.add_parser("export")
    s.add_argument("--model", default=DEFAULT_MODEL)
    s.set_defaults(fn=lambda a: export_merged(a.model))

    s = sub.add_parser("all")
    s.add_argument("--samples", type=int, default=2500)
    s.add_argument("--seed", type=int, default=430)
    s.add_argument("--eval-limit", type=int, default=60)
    train_args(s)
    s.set_defaults(fn=cmd_all)

    args = p.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()
