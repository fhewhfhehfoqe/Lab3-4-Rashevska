import os
import time
import psutil
import csv
from pathlib import Path

from crypto_module import encrypt_file, decrypt_file

TEST_DIR = Path("test_files/benchmark")
RESULTS_DIR = Path("benchmark_results")

TEST_DIR.mkdir(parents=True, exist_ok=True)
RESULTS_DIR.mkdir(parents=True, exist_ok=True)

password = "Benchmark_Test_Password_2026"

files = [
    TEST_DIR / "file_1mb.bin",
    TEST_DIR / "file_5mb.bin",
    TEST_DIR / "file_10mb.bin",
]

results = []

process = psutil.Process(os.getpid())

for source in files:
    if not source.exists():
        print(f"File not found: {source}")
        continue

    size_mb = source.stat().st_size / (1024 * 1024)

    for algorithm in ["AES-GCM", "AES-CBC"]:
        encrypted = RESULTS_DIR / f"{source.stem}_{algorithm}.json"
        decrypted = RESULTS_DIR / f"{source.stem}_{algorithm}_decrypted.bin"

        memory_before = process.memory_info().rss / (1024 * 1024)

        start = time.perf_counter()
        encrypt_file(str(source), str(encrypted), password, algorithm)
        encryption_time = time.perf_counter() - start

        start = time.perf_counter()
        decrypt_file(str(encrypted), str(decrypted), password)
        decryption_time = time.perf_counter() - start

        memory_after = process.memory_info().rss / (1024 * 1024)
        memory_used = max(0, memory_after - memory_before)

        results.append({
            "File size (MB)": size_mb,
            "Algorithm": algorithm,
            "Encryption time (s)": round(encryption_time, 4),
            "Decryption time (s)": round(decryption_time, 4),
            "Memory change (MB)": round(memory_used, 2),
        })

        print(
            f"{source.name} | {algorithm} | "
            f"Encrypt: {encryption_time:.4f}s | "
            f"Decrypt: {decryption_time:.4f}s | "
            f"Memory change: {memory_used:.2f} MB"
        )

with open(RESULTS_DIR / "benchmark.csv", "w", newline="") as csvfile:
    writer = csv.DictWriter(csvfile, fieldnames=results[0].keys())
    writer.writeheader()
    writer.writerows(results)

print("\nBenchmark completed.")
print(f"Results saved to: {RESULTS_DIR / 'benchmark.csv'}")
