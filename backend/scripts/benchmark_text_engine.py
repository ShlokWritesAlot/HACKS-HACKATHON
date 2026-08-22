"""
Benchmark script for the BhashaRakshak text normalization engine.
Measures execution time on normal, obfuscated, and pathological inputs.
"""

import time
import sys
import os

# Ensure backend root is in PYTHONPATH
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app.core.text.pipeline import analyze_and_normalize

PAYLOADS = {
    "Normal English": "Dear customer, your account balance is $500. Please log in to check.",
    "Normal Hindi": "प्रिय ग्राहक, आपका खाता शेष 500 रुपये है।",
    "Hinglish Obfuscated": "apna acnt upd8 kro v3rify kyyc jaldi plz",
    "Extremely Long (5000 chars)": "A" * 5000,
    "ReDoS Trigger (Repeated chars)": "ple" + ("a" * 2500) + "se " + ("b" * 2500),
    "Leetspeak Heavy": "y0ur 4cc0unt h4s b33n l0ck3d. p13453 r3p1y.",
    "Whitespace Hell": "   space    " * 500,
}


def run_benchmark():
    print("========================================")
    print(" BhashaRakshak Text Engine Benchmarks")
    print("========================================")
    
    for name, payload in PAYLOADS.items():
        print(f"\nBenchmarking: {name}")
        print(f"Payload length: {len(payload)} chars")
        
        # Warmup
        analyze_and_normalize(payload)
        
        iterations = 100
        start_time = time.perf_counter()
        
        for _ in range(iterations):
            analyze_and_normalize(payload)
            
        end_time = time.perf_counter()
        total_time_ms = (end_time - start_time) * 1000
        avg_time_ms = total_time_ms / iterations
        
        print(f"Total time ({iterations} runs): {total_time_ms:.2f} ms")
        print(f"Average time per run: {avg_time_ms:.4f} ms")


if __name__ == "__main__":
    run_benchmark()
