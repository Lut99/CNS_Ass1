# CORRECTNESS CHECK.py
#   by Lut99
#
# Created:
#   05/09/2020, 21:17:59
# Last edited:
#   05/09/2020, 23:00:03
# Auto updated?
#   Yes
#
# Description:
#   Checks if the output of the given guessword binary is correct, based on
#   the golden standard in the given *-plain.txt file.
#

import argparse
import os
import sys
import subprocess


DEFAULT_EXEC_PATH = "bin/guessword.out data/training-passwd.txt data/training-shadow.txt"
DEFAULT_GOLD_PATH = "data/training-plain.txt"
GRADE_MACHINE_HPS = 11120
GRADE_MACHINE_TIMEOUT = 480 #s
GRADE_MACHINE_CORES = 8


def main(exec_cmd, gold_path, benchmark_cmd):
    print("\n*** GUESSWORD CORRECTNESS TEST ***\n")

    print("Using:")
    print(f" - Command to run guessword  : '{exec_cmd}'")
    print(f" - Path to golden standard   : '{gold_path}'")
    print(f" - Using benchmark for grade ? {'no' if benchmark_cmd == None else 'yes'}")
    if benchmark_cmd is not None:
        print(f"    - Command to run benchmark : '{benchmark_cmd}'")
    print("")

    # First, if given, run the benchmark
    if benchmark_cmd is not None:
        print("Performing benchmark...", end=""); sys.stdout.flush()
        res = subprocess.run([benchmark_cmd], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if (res.returncode != 0):
            print(f"\nERROR: Failed to run '{benchmark_cmd}' (return status {res.returncode}):\n{res.stderr.decode('utf-8')}", file=sys.stderr)
            exit(-1)
        hashes_per_second = None
        for line in res.stdout.decode("utf-8").split("\n"):
            if line[:15] == "> Total score: ":
                hashes_per_second = float(line[15:line.find(" hashes/s")])
        if hashes_per_second == None:
            print(f"\nERROR: Failed to extract time from benchmark result.", file=sys.stderr)
            exit(-1)
        print(f" Done ({hashes_per_second} hash/s)")
    
    # Find guessword's command with timeout, possibly
    command = exec_cmd.split(" ")
    if benchmark_cmd is not None:
        # Set a timeout to it, that is proportional to 8 minutes
        command = ["timeout", f"{GRADE_MACHINE_TIMEOUT * ((GRADE_MACHINE_HPS * GRADE_MACHINE_CORES) / hashes_per_second)}s"] + command
    # Then, run the guessword exec
    print(f"Running '{' '.join(command)}'...", end=""); sys.stdout.flush()
    res = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if (res.returncode != 0):
        print(f"\nERROR: Failed to run '{' '.join(command)}' (return status {res.returncode}):\n{res.stderr.decode('utf-8')}", file=sys.stderr)
        exit(-1)
    results = res.stdout.decode("utf-8").split("\n")
    print(f" Done ({len(results)} guesses)")

    # Then, read the plaintext file
    print("Reading golden standard...", end=""); sys.stdout.flush()
    with open(gold_path, "r") as f:
        gold = f.read().split("\n")
    print(f" Done ({len(gold)} results)")
    print("")

    # Compare them by searching for each line in results if it exists in gold
    correct = 0
    for result in results:
        if result in gold:
            correct += 1
    print("Results:")
    print(f" - Correct: {correct} ({correct / len(results) * 100:.2f}%)")
    print(f" - Guessed: {len(results)}/{len(gold)}")
    print(f" - Overall: {correct / len(gold) * 100:.2f}%")
    # If given, compute the expected grade as well
    if benchmark_cmd is not None:
        # Compute the grade
        print(f">> Expected grade: {1 + 9 * ((correct - (len(results) - correct)) / len(gold)):.2f} <<")
    print("")

    print("Done.\n")

    return 0



if __name__ == "__main__":
    # Get those arguments from the command line
    parser = argparse.ArgumentParser()
    parser.add_argument("-g", "--gold", default=DEFAULT_GOLD_PATH, help=f"Path to the file containing the gold standards. Will assume that each line is stored in exactly the same way as a line from guessword. DEFAULT: '{DEFAULT_GOLD_PATH}'")
    parser.add_argument("-e", "--exec", default=DEFAULT_EXEC_PATH, help=f"Command to run the executable file. DEFAULT: '{DEFAULT_EXEC_PATH}'")
    parser.add_argument("-b", "--benchmark", help="If given, runs the benchmark with the given command beforehand to be able to compute a grade based on the number of arguments parsed and the time it took.")

    args = parser.parse_args()
    if not os.path.isfile(args.gold):
        print(f"[ERROR] Given path to gold standard '{args.gold}' does not point to a file.", file=sys.stderr)
        exit(-1)
    path = args.exec if args.exec.find(" ") == -1 else args.exec[:args.exec.find(" ")]
    if not os.path.isfile(path) or not os.access(path, os.X_OK):
        print(f"[ERROR] Given path to guessword '{path}' does not point to an executable file.", file=sys.stderr)
        exit(-1)
    path = args.benchmark if args.benchmark.find(" ") == -1 else args.benchmark[:args.benchmark.find(" ")]
    if args.benchmark is not None and (not os.path.isfile(path) or not os.access(path, os.X_OK)):
        print(f"[ERROR] Given path to benchmark '{path}' does not point to an executable file.", file=sys.stderr)
        exit(-1)
    
    # Run main
    exit(main(args.exec, args.gold, args.benchmark))
