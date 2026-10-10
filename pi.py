#!/usr/bin/env python3
"""
pi_resume.py

Compute digits of pi using the Chudnovsky algorithm with binary splitting.

Main features
- Real resume support using cached segment results
- Optional multiprocessing
- decimal backend or gmpy2 backend
- Validation against known digits
- SHA256 output hash
- Benchmark and self-test

Examples
--------
python pi_resume.py 1000
python pi_resume.py 100000 --show-time
python pi_resume.py 500000 --backend gmpy2 --workers 4 --output pi.txt --wrap 100
python pi_resume.py 500000 --resume --cache-dir pi_cache
python pi_resume.py --self-test
python pi_resume.py --benchmark
"""

from __future__ import annotations

import argparse
import hashlib
import math
import os
import pickle
import sys
import time
from dataclasses import dataclass
from decimal import Decimal, localcontext
from multiprocessing import Pool
from pathlib import Path
from typing import Iterable

try:
    import gmpy2
    HAS_GMPY2 = True
except Exception:
    HAS_GMPY2 = False


KNOWN_PI_PREFIX = (
    "3.14159265358979323846264338327950288419716939937510"
    "58209749445923078164062862089986280348253421170679"
    "82148086513282306647093844609550582231725359408128"
    "48111745028410270193852110555964462294895493038196"
    "44288109756659334461284756482337867831652712019091"
    "45648566923460348610454326648213393607260249141273"
)


@dataclass(frozen=True)
class BSResult:
    p: int
    q: int
    t: int


class PiCalculator:
    CHUD_C = 640320
    CHUD_C3 = CHUD_C**3
    CHUD_A = 13591409
    CHUD_B = 545140134

    def __init__(
        self,
        digits: int,
        backend: str = "auto",
        workers: int = 1,
        cache_dir: str | Path = "pi_cache",
        use_resume: bool = False,
        segment_terms: int = 2000,
        verbose: bool = True,
    ) -> None:
        if digits < 1:
            raise ValueError("digits must be >= 1")
        if workers < 1:
            raise ValueError("workers must be >= 1")
        if segment_terms < 1:
            raise ValueError("segment_terms must be >= 1")

        self.digits = digits
        self.backend = self._resolve_backend(backend)
        self.workers = workers
        self.cache_dir = Path(cache_dir)
        self.use_resume = use_resume
        self.segment_terms = segment_terms
        self.verbose = verbose

    @staticmethod
    def _resolve_backend(backend: str) -> str:
        backend = backend.lower()
        if backend not in {"auto", "decimal", "gmpy2"}:
            raise ValueError("backend must be one of: auto, decimal, gmpy2")
        if backend == "auto":
            return "gmpy2" if HAS_GMPY2 else "decimal"
        if backend == "gmpy2" and not HAS_GMPY2:
            raise RuntimeError("gmpy2 requested but not installed")
        return backend

    @property
    def terms(self) -> int:
        return self.digits // 14 + 1

    def log(self, msg: str) -> None:
        if self.verbose:
            print(msg)

    @classmethod
    def _binary_split(cls, a: int, b: int) -> BSResult:
        if b - a == 1:
            if a == 0:
                return BSResult(1, 1, cls.CHUD_A)

            p = (6 * a - 5) * (2 * a - 1) * (6 * a - 1)
            q = a * a * a * cls.CHUD_C3
            t = p * (cls.CHUD_A + cls.CHUD_B * a)
            if a & 1:
                t = -t
            return BSResult(p, q, t)

        m = (a + b) // 2
        left = cls._binary_split(a, m)
        right = cls._binary_split(m, b)
        return BSResult(
            p=left.p * right.p,
            q=left.q * right.q,
            t=left.t * right.q + left.p * right.t,
        )

    @staticmethod
    def _merge(parts: Iterable[BSResult]) -> BSResult:
        parts = list(parts)
        if not parts:
            raise ValueError("No parts to merge")

        cur = parts[0]
        for nxt in parts[1:]:
            cur = BSResult(
                p=cur.p * nxt.p,
                q=cur.q * nxt.q,
                t=cur.t * nxt.q + cur.p * nxt.t,
            )
        return cur

    @staticmethod
    def _split_ranges(start: int, stop: int, chunk_size: int) -> list[tuple[int, int]]:
        ranges = []
        a = start
        while a < stop:
            b = min(a + chunk_size, stop)
            ranges.append((a, b))
            a = b
        return ranges

    def _segment_file(self, a: int, b: int) -> Path:
        return self.cache_dir / f"seg_{a}_{b}.pkl"

    def _cache_meta_file(self) -> Path:
        return self.cache_dir / "meta.pkl"

    def _write_segment(self, a: int, b: int, result: BSResult) -> None:
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        with self._segment_file(a, b).open("wb") as f:
            pickle.dump(result, f, protocol=pickle.HIGHEST_PROTOCOL)

    def _read_segment(self, a: int, b: int) -> BSResult:
        with self._segment_file(a, b).open("rb") as f:
            return pickle.load(f)

    def _segment_exists(self, a: int, b: int) -> bool:
        return self._segment_file(a, b).exists()

    def _write_meta(self) -> None:
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        meta = {
            "digits": self.digits,
            "terms": self.terms,
            "backend": self.backend,
            "segment_terms": self.segment_terms,
        }
        with self._cache_meta_file().open("wb") as f:
            pickle.dump(meta, f, protocol=pickle.HIGHEST_PROTOCOL)

    def _validate_meta(self) -> None:
        if not self.use_resume:
            return
        meta_file = self._cache_meta_file()
        if not meta_file.exists():
            self._write_meta()
            return

        with meta_file.open("rb") as f:
            meta = pickle.load(f)

        expected = {
            "digits": self.digits,
            "terms": self.terms,
            "segment_terms": self.segment_terms,
        }
        for key, value in expected.items():
            if meta.get(key) != value:
                raise RuntimeError(
                    f"Cache mismatch for {key}: expected {value}, found {meta.get(key)}"
                )

    @staticmethod
    def _worker_range(args: tuple[int, int]) -> tuple[int, int, BSResult]:
        a, b = args
        result = PiCalculator._binary_split(a, b)
        return a, b, result

    def _compute_bs_segmented(self) -> BSResult:
        self._validate_meta()
        ranges = self._split_ranges(0, self.terms, self.segment_terms)

        completed: list[BSResult] = []
        todo: list[tuple[int, int]] = []

        for a, b in ranges:
            if self.use_resume and self._segment_exists(a, b):
                completed.append(self._read_segment(a, b))
            else:
                todo.append((a, b))

        self.log(f"Terms: {self.terms}")
        self.log(f"Segments: {len(ranges)}")
        self.log(f"Cached: {len(completed)}")
        self.log(f"To compute: {len(todo)}")

        if todo:
            if self.workers == 1:
                for idx, (a, b) in enumerate(todo, 1):
                    result = self._binary_split(a, b)
                    if self.use_resume:
                        self._write_segment(a, b, result)
                    completed.append(result)
                    self.log(f"[{idx}/{len(todo)}] computed segment {a}:{b}")
            else:
                with Pool(processes=self.workers) as pool:
                    for idx, (a, b, result) in enumerate(pool.imap_unordered(self._worker_range, todo), 1):
                        if self.use_resume:
                            self._write_segment(a, b, result)
                        completed.append(result)
                        self.log(f"[{idx}/{len(todo)}] computed segment {a}:{b}")

        # merge in canonical order
        ordered = []
        for a, b in ranges:
            if self.use_resume:
                ordered.append(self._read_segment(a, b))
            else:
                # fallback: locate in completed by order
                # when resume disabled, completed was appended in todo order,
                # and ranges == todo if nothing cached
                pass

        if not self.use_resume:
            # compute again in proper order from completed list
            # simplest and safe because when resume is off there are no cached segments
            ordered = [self._binary_split(a, b) for a, b in ranges]

        self.log("Merging segment results")
        return self._merge(ordered)

    def compute(self) -> str:
        bs = self._compute_bs_segmented()
        if self.backend == "gmpy2":
            return self._compute_gmpy2(bs)
        return self._compute_decimal(bs)

    def _compute_decimal(self, bs: BSResult) -> str:
        with localcontext() as ctx:
            ctx.prec = self.digits + 25
            c = Decimal(426880) * Decimal(10005).sqrt()
            pi_val = (c * Decimal(bs.q)) / Decimal(bs.t)
            return f"{pi_val:.{self.digits}f}"

    def _compute_gmpy2(self, bs: BSResult) -> str:
        bits = math.ceil((self.digits + 25) * math.log2(10)) + 16
        gmpy2.get_context().precision = bits
        c = gmpy2.mpfr(426880) * gmpy2.sqrt(gmpy2.mpfr(10005))
        pi_val = c * gmpy2.mpz(bs.q) / gmpy2.mpz(bs.t)
        return self._format_gmpy2_fixed(pi_val, self.digits)

    @staticmethod
    def _format_gmpy2_fixed(value, digits: int) -> str:
        mantissa, exp, _ = value.digits(10)

        if exp <= 0:
            whole = "0"
            frac = "0" * (-exp) + mantissa
        else:
            if exp >= len(mantissa):
                whole = mantissa + "0" * (exp - len(mantissa))
                frac = ""
            else:
                whole = mantissa[:exp]
                frac = mantissa[exp:]

        frac = frac + "0" * (digits + 1)
        frac_main = list(frac[:digits])
        round_digit = frac[digits]

        if round_digit >= "5":
            carry = 1
            for i in range(len(frac_main) - 1, -1, -1):
                d = ord(frac_main[i]) - 48 + carry
                if d == 10:
                    frac_main[i] = "0"
                    carry = 1
                else:
                    frac_main[i] = chr(48 + d)
                    carry = 0
                    break

            if carry:
                whole_digits = list(whole)
                for i in range(len(whole_digits) - 1, -1, -1):
                    d = ord(whole_digits[i]) - 48 + carry
                    if d == 10:
                        whole_digits[i] = "0"
                        carry = 1
                    else:
                        whole_digits[i] = chr(48 + d)
                        carry = 0
                        break
                if carry:
                    whole_digits.insert(0, "1")
                whole = "".join(whole_digits)

        return f"{whole}.{''.join(frac_main)}"

    @staticmethod
    def validate_prefix(pi_str: str, prefix_len: int | None = None) -> bool:
        if prefix_len is None:
            prefix_len = min(len(KNOWN_PI_PREFIX), len(pi_str))
        return pi_str[:prefix_len] == KNOWN_PI_PREFIX[:prefix_len]

    @staticmethod
    def write_to_file(
        pi_str: str,
        output_path: Path,
        wrap: int = 0,
        chunk_size: int = 1 << 20,
    ) -> None:
        output_path.parent.mkdir(parents=True, exist_ok=True)

        with output_path.open("w", encoding="utf-8", newline="\n") as f:
            if wrap <= 0:
                for i in range(0, len(pi_str), chunk_size):
                    f.write(pi_str[i:i + chunk_size])
                return

            f.write("3.\n")
            body = pi_str[2:]
            for i in range(0, len(body), wrap):
                f.write(body[i:i + wrap] + "\n")

    @staticmethod
    def sha256_file(path: Path) -> str:
        h = hashlib.sha256()
        with path.open("rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        return h.hexdigest()


def run_self_test() -> int:
    cases = [1, 2, 5, 10, 50, 100]
    backends = ["decimal"]
    if HAS_GMPY2:
        backends.append("gmpy2")

    for backend in backends:
        for digits in cases:
            calc = PiCalculator(digits=digits, backend=backend, verbose=False)
            s = calc.compute()
            expected = KNOWN_PI_PREFIX[:digits + 2]
            if s != expected:
                print(f"Self-test failed: backend={backend}, digits={digits}")
                print(f"Expected: {expected}")
                print(f"Got:      {s}")
                return 1

    if HAS_GMPY2:
        s1 = PiCalculator(250, backend="decimal", verbose=False).compute()
        s2 = PiCalculator(250, backend="gmpy2", verbose=False).compute()
        if s1 != s2:
            print("Self-test failed: decimal and gmpy2 mismatch at 250 digits")
            return 1

    print("Self-test: OK")
    return 0


def run_benchmark() -> int:
    tests = [1000, 10000, 100000]
    backends = ["decimal"]
    if HAS_GMPY2:
        backends.insert(0, "gmpy2")

    print("Benchmark")
    print("=" * 60)
    for backend in backends:
        print(f"\nBackend: {backend}")
        for digits in tests:
            t0 = time.perf_counter()
            calc = PiCalculator(digits, backend=backend, verbose=False)
            s = calc.compute()
            elapsed = time.perf_counter() - t0
            ok = calc.validate_prefix(s)
            print(f"{digits:>9} digits | {elapsed:>9.4f} s | validate={'OK' if ok else 'FAIL'}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Compute digits of pi using Chudnovsky + segmented binary splitting."
    )
    parser.add_argument("digits", nargs="?", type=int, help="Digits after the decimal point.")
    parser.add_argument("--backend", choices=["auto", "decimal", "gmpy2"], default="auto")
    parser.add_argument("--workers", type=int, default=1)
    parser.add_argument("--resume", action="store_true", help="Use on-disk segment cache.")
    parser.add_argument("--cache-dir", type=Path, default=Path("pi_cache"))
    parser.add_argument("--segment-terms", type=int, default=2000)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--wrap", type=int, default=0)
    parser.add_argument("--validate", action="store_true")
    parser.add_argument("--hash", action="store_true", dest="want_hash")
    parser.add_argument("--show-time", action="store_true")
    parser.add_argument("--preview", type=int, default=120)
    parser.add_argument("--quiet", action="store_true")
    parser.add_argument("--benchmark", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    return parser


def main(argv: list[str]) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.self_test:
        return run_self_test()

    if args.benchmark:
        return run_benchmark()

    if args.digits is None:
        parser.error("digits is required unless --benchmark or --self-test is used")

    try:
        workers = max(1, min(args.workers, os.cpu_count() or 1))

        t0 = time.perf_counter()
        calc = PiCalculator(
            digits=args.digits,
            backend=args.backend,
            workers=workers,
            cache_dir=args.cache_dir,
            use_resume=args.resume,
            segment_terms=args.segment_terms,
            verbose=not args.quiet,
        )
        pi_str = calc.compute()
        elapsed = time.perf_counter() - t0

        if args.validate:
            ok = calc.validate_prefix(pi_str)
            if not args.quiet:
                print("Validation:", "OK" if ok else "FAILED")
            if not ok:
                return 1

        if args.output:
            calc.write_to_file(pi_str, args.output, wrap=args.wrap)
            if not args.quiet:
                print(f"Saved to: {args.output}")
            if args.want_hash:
                print("SHA256:", calc.sha256_file(args.output))
        else:
            if not args.quiet:
                preview = pi_str[:args.preview]
                if len(preview) < len(pi_str):
                    preview += "..."
                print(preview)

        if not args.quiet:
            print(f"Backend: {calc.backend}")
            print(f"Terms:   {calc.terms}")
            print(f"Workers: {workers}")
            print(f"Resume:  {'on' if args.resume else 'off'}")

        if args.show_time and not args.quiet:
            print(f"Time: {elapsed:.4f} seconds")

        return 0

    except KeyboardInterrupt:
        print("\nInterrupted.")
        return 130
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
