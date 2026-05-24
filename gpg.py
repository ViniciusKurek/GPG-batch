import subprocess, time, argparse, os, json
from pprint import pprint
from collections import defaultdict


def cleanup_gpg(fingerprint):
    try:
        subprocess.run(
            ["gpg", "--batch", "--yes", "--delete-secret-keys", fingerprint],
            check=True, capture_output=True
        )
        subprocess.run(
            ["gpg", "--batch", "--yes", "--delete-keys", fingerprint],
            check=True, capture_output=True
        )

        if args.debug:
            print(f"Success deleting key: {fingerprint}")
    except subprocess.CalledProcessError as e:
        if args.debug:
            print(f"Error deleting key: {e.stderr.decode()}")

def generate_gpg_key_batch(algorithm, key_length, iterator):

    user_id = f"Test_{iterator}_{algorithm}_{key_length}"

    if algorithm.upper() == "RSA":
        batch_config = f"""
        Key-Type: {algorithm}
        Key-Length: {key_length}
        Subkey-Type: {algorithm}
        Subkey-Length: {key_length}
        Name-Real: {user_id}
        Expire-Date: 0
        %no-protection
        %commit
        """
    elif algorithm.upper() == "ELGAMAL":
        batch_config = f"""
        Key-Type: RSA
        Key-Length: 2048
        Subkey-Type: ELG-E
        Subkey-Length: {key_length}
        Name-Real: {user_id}
        Expire-Date: 0
        %no-protection
        %commit
        """
    elif algorithm.upper() == "ECC":
        #subkey_curve = "cv25519" if str(key_length) == "ed25519" else key_length
        batch_config = f"""
        Key-Type: RSA
        Key-Length: 2048
        Subkey-Type: ECC
        Subkey-Curve: {key_length}
        Name-Real: {user_id}
        Expire-Date: 0
        %no-protection
        %commit
        """
    else:
        print(f"Unsupported algorithm: {algorithm}")
        return None

    start = time.perf_counter()
    
    process = subprocess.run(
        ["gpg", "--batch","--status-fd", "1", "--gen-key"],
        input=batch_config,
        text=True,
        capture_output=True
    )
    
    end = time.perf_counter()

    fingerprint = None

    for line in process.stdout.splitlines():
        if "KEY_CREATED" in line:
            fingerprint = line.split()[3]
            break

    if process.returncode == 0:
        if args.debug:
            print(f"Success on creating the key {iterator}")
        return (end - start), fingerprint
    else:
        print(f"Error on creating the key {iterator}: {process.stderr}")
        return None

def encrypt_file(fingerprint, file, prefix):
    '''
        Encrypt the file and return the time it took to encrypt it and the size of 
        the encrypted file. The encrypted file will be saved in a new "encrypted" folder with the 
        name "{prefix}_{original_file_name}.gpg".
    '''

    try:
        dirname = os.path.dirname(file) 
        output_dir = os.path.join(dirname, "encrypted")
        os.makedirs(output_dir, exist_ok=True)
        
        filename = os.path.basename(file)

        output_file = os.path.join(output_dir, f"{prefix}_{filename}.gpg")

        start = time.perf_counter()
        subprocess.run(
            ["gpg", "--batch", "--yes", "--trust-model", "always",
             "--encrypt", "--output", output_file,
             "--recipient", fingerprint, file],
            check=True, capture_output=True
        )
        end = time.perf_counter()
        
        if args.debug:
            print(f"Success encrypting file {file} with key {fingerprint}")

        return (end - start), output_file
    except subprocess.CalledProcessError as e:
        print(f"Error encrypting file {file} with key {fingerprint}: {e.stderr.decode()}")
        return 0

def decrypt_file(fingerprint, encrypted_file, original_file):
    '''
        Decrypt the file and return the time it took to decrypt it. The decrypted file will be saved in
        a new "decrypted" folder with the name "decrypted_{original_file_name}".
    '''

    try:
        dirname = os.path.dirname(original_file) 
        output_dir = os.path.join(dirname, "decrypted")
        os.makedirs(output_dir, exist_ok=True)
        
        filename = os.path.basename(original_file).replace(".gpg", "")

        output_file = os.path.join(output_dir, f"decrypted_{filename}")

        start = time.perf_counter()
        subprocess.run(
            ["gpg", "--batch", "--yes", "--trust-model", "always",
             "--decrypt", "--output", output_file,
             "--recipient", fingerprint, encrypted_file],
            check=True, capture_output=True
        )
        end = time.perf_counter()

        if args.debug:
            print(f"Success decrypting file {encrypted_file} with key {fingerprint}")

        return (end - start)
    except subprocess.CalledProcessError as e:
        print(f"Error decrypting file {encrypted_file} with key {fingerprint}: {e.stderr.decode()}")
        return 0

def run_test_suite(algorithm, key_lengths: list, qtd: int = 30):
    '''
        Run the test suite for the given algorithm and key lengths 
        and return a dictionary with the time it took for each step and the size
        for the encrypted file
    '''

    tree = lambda: defaultdict(tree)

    dict = tree()

    for key_length in key_lengths:
        for i in range(qtd):
            data = dict[algorithm][key_length][i]

            data["generate_key"], fingerprint = generate_gpg_key_batch(algorithm, key_length, i)
            data["encryption"], output_file = encrypt_file(fingerprint, args.file, f"{algorithm}_{key_length}_{i}")
            data["encrypted_file_size"] = os.path.getsize(output_file)
            data["decryption"] = decrypt_file(fingerprint, output_file, args.file)
            cleanup_gpg(fingerprint)
    return dict

def show_averages(results):
    # Larguras definidas para cada coluna para fácil ajuste
    w_algo = 12
    w_size = 7
    w_gen  = 13
    w_enc  = 13
    w_dec  = 13
    w_ratio = 10
    w_tam   = 15

    header = (f"{'ALGORITMO':<{w_algo}} | {'CHAVE':<{w_size}} | {'GEN AVG (s)':<{w_gen}} | "
              f"{'ENC AVG (s)':<{w_enc}} | {'DEC AVG (s)':<{w_dec}} | {'DEC/ENC':<{w_ratio}} | {'TAM OUTPUT (B)'}")
    
    total_width = len(header)
    print("\n" + "=" * total_width)
    print(header)
    print("-" * total_width)

    for algo, sizes in results.items():
        for size, iterations in sizes.items():
            total_iters = len(iterations)
            if total_iters == 0: continue

            # Somatórios
            sum_gen = sum(data['generate_key'] for data in iterations.values())
            sum_enc = sum(data['encryption'] for data in iterations.values())
            sum_dec = sum(data['decryption'] for data in iterations.values())
            sum_size = sum(data['encrypted_file_size'] for data in iterations.values())

            # Médias
            avg_gen = sum_gen / total_iters
            avg_enc = sum_enc / total_iters
            avg_dec = sum_dec / total_iters
            avg_size = sum_size / total_iters

            ratio = avg_dec / avg_enc if avg_enc > 0 else 0
            ratio_str = f"{ratio:.2f}x"

            # Print formatado com as mesmas larguras do cabeçalho
            print(f"{algo:<{w_algo}} | {size:<{w_size}} | {avg_gen:<{w_gen}.4f} | "
                  f"{avg_enc:<{w_enc}.4f} | {avg_dec:<{w_dec}.4f} | {ratio_str:<{w_ratio}} | {avg_size:.0f}")

    print("=" * total_width)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="GPG Benchmark")

    parser.add_argument("-a","--algorithm", type=str, required=True, help="Encryption algorithm", choices=["RSA", "ElGamal", "ECC"])
    parser.add_argument("-k","--key-lengths", type=str, nargs="+", required=True, help="Key lengths to test")
    parser.add_argument("-f","--file", type=str, default="test/test.txt", help="File to encrypt")
    parser.add_argument("-q","--qtd", type=int, default=30, help="Number of keys to generate")
    parser.add_argument("-d","--debug", action="store_true", help="Enable debug mode")

    args = parser.parse_args()

    output = run_test_suite(args.algorithm, args.key_lengths, args.qtd)
    show_averages(output)