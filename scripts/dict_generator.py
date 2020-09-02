# DICT GENERATOR.py
#   by HACKER_HANDLE
#
# Created:
#   02/09/2020, 20:50:33
# Last edited:
#   02/09/2020, 21:17:03
# Auto updated?
#   Yes
#
# Description:
#   The dictionary generator takes a list of files as input, and then
#   outputs a single file with a constant format that contains all the
#   (unique) passwords in the given databases.
#

import argparse
import os
import re


pattern = re.compile("[\W_]+")
def clean(word):
    """
        Cleans given word.
    """

    # Some standard stuff
    word = word.strip().lower()
    return pattern.sub('', word)


def main(dicts, output):
    print("\n*** DICTIONARY GENERATOR ***\n")
    print("Dictionaries to collect:")
    for d in dicts:
        print(f" - '{d}'")
    print(f"Output directory: {output}\n")

    print("Reading dictionaries...")
    words = set()
    i = 0
    for d in dicts:
        print(f"   {i + 1:02}/{len(dicts):02} '{d}'...")

        # Open the file
        with open(d, "r") as f:
            for line in f.readlines():
                if '\t' in line:
                    # We assume it to be top250, so split on tabs and only use the last
                    words.add(line.split("\t")[-1].strip())
                else:
                    # We assume it's an e-book, so simply add the words splitted
                    for word in [clean(w) for w in line.split(" ")]:
                        if len(word) == 0: continue
                        words.add(word)

        i += 1
    print(f"Read {len(words)} passwords\n")

    print("Applying mutations...")
    print("Done\n")

    print("Writing to file...")
    with open(output, "w") as f:
        for w in words:
            f.write(w + "\n")
    print("Done\n")

    print("Done.\n")

    return 0


if __name__ == "__main__":
    # Parse the input
    parser = argparse.ArgumentParser()

    parser.add_argument("-d", "--dict", nargs='+', help="Used to specify a single directory. Can be specified multiple times to add more than one dictionary file.")
    parser.add_argument("-o", "--output", help="The path to the output file.")

    args = parser.parse_args()

    # Check if the given dictionary files exist
    for f in args.dict:
        if not os.path.isfile(f):
            raise ValueError(f"Given dictionary '{f}' is not a file.")
        if len([d for d in args.dict if d == f]) > 1:
            raise ValueError(f"Given dictionary '{f}' occurs more than once.")

    exit(main(args.dict, args.output))
