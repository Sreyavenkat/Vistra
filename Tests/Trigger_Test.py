import os
import time
import random
import string

TEST_DIR = "./ransom_test"
NUM_FILES = 30
FILE_SIZE = 500_000  # 500 KB per file → 30 * 500KB = 15MB

def random_data(size):
    return ''.join(random.choices(string.ascii_letters, k=size))

def setup():
    os.makedirs(TEST_DIR, exist_ok=True)

    for i in range(NUM_FILES):
        with open(f"{TEST_DIR}/file_{i}.txt", "w") as f:
            f.write(random_data(FILE_SIZE))

def simulate():
    for i in range(NUM_FILES):
        path = f"{TEST_DIR}/file_{i}.txt"

        # Overwrite file (large write)
        with open(path, "w") as f:
            f.write(random_data(FILE_SIZE))

        # Rename file
        new_path = path + ".encrypted"
        os.rename(path, new_path)

        # Optional delete
        # os.remove(new_path)

        # NO SLEEP → create burst

if __name__ == "__main__":
    setup()
    simulate()