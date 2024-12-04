import re
import csv
from collections import defaultdict
FAILED_LOGIN_THRESHOLD = 10
LOG_FILE = "C:/Users/chand/OneDrive/Desktop/vrv security python code/sample.log"
OUTPUT_CSV = "log_analysis_results.csv"
def parse_log_file(log_file):
    ip_requests = defaultdict(int)
    endpoint_requests = defaultdict(int)
    failed_logins = defaultdict(int)
    with open(log_file, "r") as file:
        for line in file:
            ip_match = re.search(r"^(\d+\.\d+\.\d+\.\d+)", line)
            ip = ip_match.group(1) if ip_match else None
            endpoint_match = re.search(r'"[A-Z]+\s(/[^ ]*)\sHTTP', line)
            endpoint = endpoint_match.group(1) if endpoint_match else None
            if "401" in line or "Invalid credentials" in line:
                if ip:
                    failed_logins[ip] += 1
            if ip:
                ip_requests[ip] += 1
            if endpoint:
                endpoint_requests[endpoint] += 1
    return ip_requests, endpoint_requests, failed_logins

def save_to_csv(ip_requests, most_accessed_endpoint, failed_logins):
    with open(OUTPUT_CSV, "w", newline="") as csvfile:
        csvwriter = csv.writer(csvfile)
        csvwriter.writerow(["IP Address", "Request Count"])
        for ip, count in sorted(ip_requests.items(), key=lambda x: x[1], reverse=True):
            csvwriter.writerow([ip, count])
        csvwriter.writerow([])
        csvwriter.writerow(["Endpoint", "Access Count"])
        csvwriter.writerow(most_accessed_endpoint)
        csvwriter.writerow([])
        csvwriter.writerow(["IP Address", "Failed Login Count"])
        for ip, count in failed_logins.items():
            if count > FAILED_LOGIN_THRESHOLD:
                csvwriter.writerow([ip, count])

def main():
    ip_requests, endpoint_requests, failed_logins = parse_log_file(LOG_FILE)
    most_accessed_endpoint = max(endpoint_requests.items(), key=lambda x: x[1], default=("None", 0))
    print("IP Address           Request Count")
    for ip, count in sorted(ip_requests.items(), key=lambda x: x[1], reverse=True):
        print(f"{ip:<20} {count}")
    print("\nMost Frequently Accessed Endpoint:")
    print(f"{most_accessed_endpoint[0]} (Accessed {most_accessed_endpoint[1]} times)")
    print("\nSuspicious Activity Detected:")
    print("IP Address           Failed Login Attempts")
    for ip, count in failed_logins.items():
        if count > FAILED_LOGIN_THRESHOLD:
            print(f"{ip:<20} {count}")
    save_to_csv(ip_requests, most_accessed_endpoint, failed_logins)

if __name__ == "__main__":
    main()
