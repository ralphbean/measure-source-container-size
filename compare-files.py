#!/usr/bin/env python3

import argparse
import sys
import os

def count_file_stats(filename):
    """Count lines, words, characters, and bytes in a file."""
    try:
        with open(filename, 'rb') as f:
            content_bytes = f.read()

        with open(filename, 'r', encoding='utf-8', errors='replace') as f:
            content_text = f.read()

        lines = content_text.count('\n')
        words = len(content_text.split())
        chars = len(content_text)
        bytes_count = len(content_bytes)

        return lines, words, chars, bytes_count

    except FileNotFoundError:
        print(f"Error: File '{filename}' not found", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error reading file '{filename}': {e}", file=sys.stderr)
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(
        description="Compare two files and return what percentage the first file is of the second file"
    )
    parser.add_argument('file1', help='First file (numerator)')
    parser.add_argument('file2', help='Second file (denominator)')
    parser.add_argument('-l', '--lines', action='store_true', help='Count lines')
    parser.add_argument('-w', '--words', action='store_true', help='Count words')
    parser.add_argument('-c', '--bytes', action='store_true', help='Count bytes')
    parser.add_argument('-m', '--chars', action='store_true', help='Count characters')

    args = parser.parse_args()

    # If no options specified, default to lines (like wc)
    if not any([args.lines, args.words, args.bytes, args.chars]):
        args.lines = True

    # Get stats for both files
    lines1, words1, chars1, bytes1 = count_file_stats(args.file1)
    lines2, words2, chars2, bytes2 = count_file_stats(args.file2)

    # Determine which count to use based on options
    if args.lines:
        count1, count2 = lines1, lines2
        unit = "lines"
    elif args.words:
        count1, count2 = words1, words2
        unit = "words"
    elif args.bytes:
        count1, count2 = bytes1, bytes2
        unit = "bytes"
    elif args.chars:
        count1, count2 = chars1, chars2
        unit = "characters"

    # Calculate percentage
    if count2 == 0:
        if count1 == 0:
            percentage = 100.0
        else:
            print(f"Error: Cannot divide by zero - second file has 0 {unit}", file=sys.stderr)
            sys.exit(1)
    else:
        percentage = (count1 / count2) * 100

    print(f"{percentage:.2f}%")

if __name__ == '__main__':
    main()