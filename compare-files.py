#!/usr/bin/env python3

import argparse
import sys
import os
import select
import signal
import time
from datetime import datetime
from collections import deque

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
        return 0, 0, 0, 0
    except Exception as e:
        print(f"Error reading file '{filename}': {e}", file=sys.stderr)
        return 0, 0, 0, 0

class RateTracker:
    """Track rate of change over a rolling window."""
    def __init__(self, window_size=10):
        self.window_size = window_size
        self.measurements = deque(maxlen=window_size)

    def add_measurement(self, timestamp, percentage):
        """Add a new measurement."""
        self.measurements.append((timestamp, percentage))

    def get_rate(self):
        """Calculate rate of change per second over the window."""
        if len(self.measurements) < 2:
            return None

        # Get oldest and newest measurements
        oldest_time, oldest_pct = self.measurements[0]
        newest_time, newest_pct = self.measurements[-1]

        # Handle inf values
        if oldest_pct == float('inf') or newest_pct == float('inf'):
            return None

        # Calculate time difference in seconds
        time_diff = (newest_time - oldest_time).total_seconds()
        if time_diff <= 0:
            return None

        # Calculate percentage change per second
        pct_diff = newest_pct - oldest_pct
        rate = pct_diff / time_diff

        return rate

def format_time_duration(seconds):
    """Format seconds into human-readable duration."""
    if seconds < 0:
        return "completed"
    elif seconds < 60:
        return f"{seconds:.0f}s"
    elif seconds < 3600:
        minutes = seconds / 60
        return f"{minutes:.1f}m"
    elif seconds < 86400:
        hours = seconds / 3600
        return f"{hours:.1f}h"
    elif seconds < 604800:
        days = seconds / 86400
        return f"{days:.1f}d"
    else:
        weeks = seconds / 604800
        return f"{weeks:.1f}w"

def calculate_time_to_completion(percentage, rate):
    """Calculate time until 100% completion based on current rate."""
    if rate is None or rate <= 0:
        return None

    if percentage >= 100.0:
        return 0

    remaining_percentage = 100.0 - percentage
    seconds_to_completion = remaining_percentage / rate

    return seconds_to_completion

def calculate_and_print_percentage(file1, file2, count_mode, unit, rate_tracker, first_run=False):
    """Calculate and print the percentage."""
    lines1, words1, chars1, bytes1 = count_file_stats(file1)
    lines2, words2, chars2, bytes2 = count_file_stats(file2)

    # Determine which count to use based on mode
    if count_mode == 'lines':
        count1, count2 = lines1, lines2
    elif count_mode == 'words':
        count1, count2 = words1, words2
    elif count_mode == 'bytes':
        count1, count2 = bytes1, bytes2
    elif count_mode == 'chars':
        count1, count2 = chars1, chars2

    # Calculate percentage
    if count2 == 0:
        if count1 == 0:
            percentage = 100.0
        else:
            percentage = float('inf')
    else:
        percentage = (count1 / count2) * 100

    timestamp = datetime.now()
    timestamp_str = timestamp.strftime("%Y-%m-%d %H:%M:%S")

    # Track rate of change
    rate_tracker.add_measurement(timestamp, percentage)
    rate = rate_tracker.get_rate()

    # Calculate time to completion
    time_to_completion = None
    if percentage != float('inf'):
        time_to_completion = calculate_time_to_completion(percentage, rate)

    # Format rate display
    if rate is None:
        rate_str = ""
    elif abs(rate) < 0.01:
        rate_str = f" (±{abs(rate):.3f}%/s)"
    else:
        rate_str = f" ({'+' if rate > 0 else ''}{rate:.2f}%/s)"

    # Format time to completion display
    eta_str = ""
    if time_to_completion is not None:
        if time_to_completion == 0:
            eta_str = " [DONE]"
        elif time_to_completion > 0:
            eta_str = f" [ETA: {format_time_duration(time_to_completion)}]"

    if percentage == float('inf'):
        output = f"[{timestamp_str}] inf% ({count1} {unit} / 0 {unit}){rate_str}{eta_str}"
    else:
        output = f"[{timestamp_str}] {percentage:.2f}% ({count1} {unit} / {count2} {unit}){rate_str}{eta_str}"

    if first_run:
        print(output)
    else:
        # Clear the line and rewrite it
        print(f"\r{output}", end="", flush=True)

def setup_inotify(files):
    """Setup inotify to watch files for changes."""
    try:
        import ctypes
        import ctypes.util

        # Load libc
        libc = ctypes.CDLL(ctypes.util.find_library('c'))

        # inotify constants
        IN_MODIFY = 0x00000002
        IN_CLOSE_WRITE = 0x00000008
        IN_MOVED_TO = 0x00000080

        # Create inotify instance
        fd = libc.inotify_init()
        if fd < 0:
            raise OSError("Failed to initialize inotify")

        # Add watches for both files
        watch_mask = IN_MODIFY | IN_CLOSE_WRITE | IN_MOVED_TO
        watches = {}

        for file_path in files:
            if os.path.exists(file_path):
                # Watch the file directly
                wd = libc.inotify_add_watch(fd, file_path.encode(), watch_mask)
                if wd >= 0:
                    watches[wd] = file_path

                # Also watch the directory in case file gets recreated
                dir_path = os.path.dirname(os.path.abspath(file_path))
                dir_wd = libc.inotify_add_watch(fd, dir_path.encode(), watch_mask)
                if dir_wd >= 0:
                    watches[dir_wd] = dir_path

        return fd, watches

    except ImportError:
        print("Error: ctypes not available", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error setting up inotify: {e}", file=sys.stderr)
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(
        description="Watch two files and continuously report what percentage the first file is of the second file"
    )
    parser.add_argument('file1', help='First file (numerator)')
    parser.add_argument('file2', help='Second file (denominator)')
    parser.add_argument('-l', '--lines', action='store_true', help='Count lines')
    parser.add_argument('-w', '--words', action='store_true', help='Count words')
    parser.add_argument('-c', '--bytes', action='store_true', help='Count bytes')
    parser.add_argument('-m', '--chars', action='store_true', help='Count characters')
    parser.add_argument('--once', action='store_true', help='Calculate once and exit (no watching)')

    args = parser.parse_args()

    # If no options specified, default to lines (like wc)
    if not any([args.lines, args.words, args.bytes, args.chars]):
        args.lines = True

    # Determine count mode and unit
    if args.lines:
        count_mode, unit = 'lines', 'lines'
    elif args.words:
        count_mode, unit = 'words', 'words'
    elif args.bytes:
        count_mode, unit = 'bytes', 'bytes'
    elif args.chars:
        count_mode, unit = 'chars', 'characters'

    # Create rate tracker
    rate_tracker = RateTracker(window_size=100)

    # Calculate initial percentage
    calculate_and_print_percentage(args.file1, args.file2, count_mode, unit, rate_tracker, first_run=True)

    # If --once flag is set, exit after initial calculation
    if args.once:
        return

    # Setup inotify watching
    print(f"Watching {args.file1} and {args.file2} for changes... (Ctrl+C to exit)", file=sys.stderr)

    fd, watches = setup_inotify([args.file1, args.file2])

    def signal_handler(signum, frame):
        print()  # Print newline to clean up the in-place update
        os.close(fd)
        print("Exiting...", file=sys.stderr)
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Watch for changes
    try:
        while True:
            ready, _, _ = select.select([fd], [], [], 1.0)
            if ready:
                # Read inotify events
                data = os.read(fd, 1024)
                if data:
                    # Small delay to allow file operations to complete
                    time.sleep(0.1)
                    calculate_and_print_percentage(args.file1, args.file2, count_mode, unit, rate_tracker, first_run=False)
    except KeyboardInterrupt:
        print()  # Print newline on exit
        pass
    finally:
        os.close(fd)

if __name__ == '__main__':
    main()