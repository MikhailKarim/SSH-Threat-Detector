import argparse
import json
import os
import re
from datetime import datetime, timezone
from collections import defaultdict
from colorama import Fore, Style, init as colorinit

colorinit(autoreset=True)

SUCCESS_TAG = f"{Style.BRIGHT}{Fore.WHITE}[{Fore.GREEN}INFO{Fore.WHITE}]{Style.RESET_ALL}"
ALERT_TAG = f"{Style.BRIGHT}{Fore.WHITE}[{Fore.RED}ALERT{Fore.WHITE}]{Style.RESET_ALL}"
WARN_TAG = f"{Style.BRIGHT}{Fore.WHITE}[{Fore.YELLOW}WARNING{Fore.WHITE}]{Style.RESET_ALL}"

THRESHOLD = 5


class Detector:

    def __init__(self, basepath, clear, dryrun, threshold):
        self.clear = clear
        self.dryrun = dryrun
        self.threshold = threshold

        self.inputdir = os.path.join(basepath, "Input")
        self.outputdir = os.path.join(basepath, "Output")

        self.logpath = os.path.join(self.inputdir, "auth.log")
        self.textpath = os.path.join(self.outputdir, "Results.txt")
        self.jsonpath = os.path.join(self.outputdir, "Results.json")

    def readlogs(self):
        if not os.path.exists(self.logpath):
            print(f"{WARN_TAG} Log file not found: {self.logpath}")
            return []

        with open(self.logpath, "r", encoding="utf-8", errors="ignore") as f:
            return f.readlines()

    def detect(self, lines):

        pattern = re.compile(r"Failed password.*from (\d+\.\d+\.\d+\.\d+)")

        attempts = defaultdict(int)
        events = []

        for line in lines:
            match = pattern.search(line)
            if not match:
                continue

            ip = match.group(1)
            attempts[ip] += 1

        for ip, count in attempts.items():

            if count >= self.threshold:

                events.append({
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "ip": ip,
                    "attempts": count,
                    "type": "BRUTE_FORCE"
                })

        return events

    def print_event(self, event):

        print(
            f"{ALERT_TAG} Possible SSH brute force detected "
            f"IP={event['ip']} Attempts={event['attempts']}"
        )

    def writetext(self, events):

        mode = "w" if self.clear else "a"

        with open(self.textpath, mode, encoding="utf-8") as f:

            for event in events:

                line = (
                    f"[{event['timestamp']}] "
                    f"SSH BRUTE FORCE "
                    f"IP={event['ip']} "
                    f"Attempts={event['attempts']}\n"
                )

                f.write(line)

    def writejson(self, events):

        existing = []

        if not self.clear and os.path.exists(self.jsonpath):

            try:
                with open(self.jsonpath, "r", encoding="utf-8") as f:
                    existing = json.load(f)

            except json.JSONDecodeError:
                existing = []

        existing.extend(events)

        with open(self.jsonpath, "w", encoding="utf-8") as f:
            json.dump(existing, f, indent=2)

    def summary(self, events):

        total = len(events)

        print("-" * 40)
        print(f"{Style.BRIGHT}Summary{Style.RESET_ALL}")

        if total == 0:
            print(f"{SUCCESS_TAG} No brute force activity detected")
        else:
            print(f"{ALERT_TAG} Detected {total} suspicious IP(s)")

    def run(self):

        lines = self.readlogs()

        events = self.detect(lines)

        if self.dryrun:

            print("Dry run: no files will be written")

            for event in events:
                self.print_event(event)

            self.summary(events)
            return

        for event in events:
            self.print_event(event)

        self.summary(events)

        os.makedirs(self.outputdir, exist_ok=True)

        self.writetext(events)
        self.writejson(events)


def main():

    parser = argparse.ArgumentParser(description="SSH Threat Detector")

    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="show what would execute"
    )

    parser.add_argument(
        "--clear",
        action="store_true",
        help="overwrite previous results"
    )

    parser.add_argument(
        "--threshold",
        type=int,
        default=THRESHOLD,
        help="failed attempts before flagging attack"
    )

    args = parser.parse_args()

    base_dir = os.path.dirname(os.path.abspath(__file__))

    Detector(base_dir, args.clear, args.dry_run, args.threshold).run()


if __name__ == "__main__":
    main()
