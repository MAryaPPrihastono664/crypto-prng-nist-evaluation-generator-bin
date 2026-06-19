import hashlib
import time
from generators import LinearCongruentialGenerator, ChaCha20PRNG

def run_experiment():
    # Target scale definitions
    TOTAL_BYTES = 128 * 1024 * 1024  # 128 Megabytes = 1,024,000,000 bits
    CHUNK_SIZE = 64 * 1024          # 64 KB memory chunk buffer for disk streams
    
    print("="*60)
    print("  COMMENCING STREAM GENERATION & SERIALIZATION METRICS")
    print("="*60)
    
    # ----------------------------------------------------------------
    # PIPELINE 1: Linear Congruential Generator (LCG)
    # ----------------------------------------------------------------
    print(f"\n[*] Instantiating Numerical Recipes LCG...")
    lcg = LinearCongruentialGenerator(seed=1234567890)
    lcg_filename = "lcg_output.bin"
    bytes_written_lcg = 0
    
    start_time = time.time()
    with open(lcg_filename, "wb") as f_lcg:
        buffer = bytearray()
        while bytes_written_lcg < TOTAL_BYTES:
            buffer.extend(lcg.next_bits())
            if len(buffer) >= CHUNK_SIZE:
                f_lcg.write(buffer)
                bytes_written_lcg += len(buffer)
                buffer.clear()
        if buffer: # Clear remainder
            f_lcg.write(buffer)
            bytes_written_lcg += len(buffer)
            
    lcg_duration = time.time() - start_time
    print(f"[+] Complete. Target file output: '{lcg_filename}'")
    print(f"    Total Size   : {bytes_written_lcg:,} bytes ({bytes_written_lcg * 8:,} bits)")
    print(f"    Time Elapsed : {lcg_duration:.4f} seconds")
    print(f"    Throughput   : {(bytes_written_lcg / (1024*1024)) / lcg_duration:.2f} MB/s")

    # ----------------------------------------------------------------
    # PIPELINE 2: ChaCha20 CSPRNG
    # ----------------------------------------------------------------
    print(f"\n[*] Instantiating RFC 8439 ChaCha20 PRNG...")
    # Derive uniform key via SHA-256 hash of baseline seed string
    seed_string = "ITB-STEI-18223068-SEED"
    crypto_seed = hashlib.sha256(seed_string.encode('utf-8')).digest()
    
    chacha = ChaCha20PRNG(key_bytes=crypto_seed)
    chacha_filename = "chacha20_output.bin"
    bytes_written_chacha = 0
    
    start_time = time.time()
    with open(chacha_filename, "wb") as f_chacha:
        buffer = bytearray()
        while bytes_written_chacha < TOTAL_BYTES:
            buffer.extend(chacha.generate_block()) # Fetches 64 bytes per block
            if len(buffer) >= CHUNK_SIZE:
                f_chacha.write(buffer)
                bytes_written_chacha += len(buffer)
                buffer.clear()
        if buffer: # Clear remainder
            f_chacha.write(buffer)
            bytes_written_chacha += len(buffer)
            
    chacha_duration = time.time() - start_time
    print(f"[+] Complete. Target file output: '{chacha_filename}'")
    print(f"    Total Size   : {bytes_written_chacha:,} bytes ({bytes_written_chacha * 8:,} bits)")
    print(f"    Time Elapsed : {chacha_duration:.4f} seconds")
    print(f"    Throughput   : {(bytes_written_chacha / (1024*1024)) / chacha_duration:.2f} MB/s")
    
    print("\n" + "="*60)
    print("  PIPELINE COMPLETION: Data ready for NIST SP 800-22 processing.")
    print("="*60)

if __name__ == "__main__":
    run_experiment()