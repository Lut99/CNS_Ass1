# DICT GENERATOR.py
#   by HACKER_HANDLE
#
# Created:
#   02/09/2020, 20:50:33
# Last edited:
#   02/09/2020, 22:02:43
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


letter_map = {
    "a" : ["/-\\", "/\\"],
    #"b" : "a",
    "c" : "<",
    "d" : "|)",
    "e" : "3",
    #"f" : "a",
    "g" : "&",
    #"h" : "a",
    "i" : "!",
    "j" : "]",
    "k" : "|(",
    #"l" : "a",
    "m" : "/V\\",
    "n" : "[\\]",
    "o" : ["0", "()", "°"],
    "p" : "|>",
    #"q" : "a",
    #"r" : "a",
    #"s" : "a",
    "t" : "7",
    "u" : "|_|",
    #"v" : "a",
    "w" : "\\|/",
    #"x" : "a",
    "y" : "`/"#,
    #"z" : "a",
}
month_map = {
    1: 31,
    2: 28,
    3: 31,
    4: 30,
    5: 31,
    6: 30,
    7: 31,
    8: 31,
    9: 30,
    10: 31,
    11: 30,
    12: 31
}


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
    print(f"Done, read {len(words)} passwords\n")

    print("Applying mutations...")
    complete_words = set()
    j = 1
    for word in words:
        complete_words.add(word)

        # Mutation 1: Replace each letter by a capital (and once all caps)
        for i in range(len(word)):
            complete_words.add(word[:i] + word[i].upper() + word[i + 1:])
        complete_words.add(word.upper())
        
        # Mutation 2: Replace certain letters with words
        for i in range(len(word)):
            letter = word[i]
            if letter in letter_map:
                letter = letter_map[letter]
            if type(letter) == list:
                for l in letter:
                    complete_words.add(word[:i] + l + word[i + 1:])
            else:
                complete_words.add(word[:i] + letter + word[i + 1:])
        
        # Mutation 3: Add all years between 1970-2000 as years and their '97 form
        complete_words.add(word + "2000")
        complete_words.add(word + "00")
        for year in range(70, 100):
            complete_words.add(word + f"19{year}")
            complete_words.add(word + f"{year}")

        print(f"   (Word {j}/{len(words)})", end="\r")
        j += 1
    
    # Mutation 5: Finally, generate a set of all birthdays between 1970 and 2000
    for year in range(1970, 2001):
        for month in range(1, 13):
            for day in range(1, (29 if (month == 2 and year % 4 and year != 2000) else month_map[month]) + 1):
                if (month == 2 and year % 4 and year != 2000):
                    day += 1
                complete_words.add(f"{day:02}{month:02}{year}")
                complete_words.add(f"{day:02}{month:02}{str(year)[-2:]}")
                complete_words.add(f"{month:02}{day:02}{year}")
                complete_words.add(f"{month:02}{day:02}{str(year)[-2:]}")
                complete_words.add(f"{day}{month}{year}")
                complete_words.add(f"{day}{month}{str(year)[-2:]}")
                complete_words.add(f"{month}{day}{year}")
                complete_words.add(f"{month}{day}{str(year)[-2:]}")

    print(f"\nDone, mutated to {len(complete_words)} passwords\n")

    print("Writing to file...")
    with open(output, "w") as f:
        for w in complete_words:
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
