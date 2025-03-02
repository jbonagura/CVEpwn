import datetime
import requests
import time
import urllib.parse
from bs4 import BeautifulSoup
from pathlib import Path
import re

# Function to print CVE IDs with color based on severity
def print_cve_with_color(cve_id, severity, base_score):
    try:
        base_score = float(base_score)  # Ensure base_score is a float
    except (ValueError, TypeError):
        base_score = 0.0  # Default to 0 if base_score is not valid

    # Check if severity is "CRITICAL" or base_score >= 9.0
    if severity == "CRITICAL" or base_score >= 9.0:
        color = "\033[91m"  # Red for CRITICAL or base score >= 9.0
    elif severity == "HIGH" or base_score >= 7.0 :
        color = "\033[93m"  # Yellow for HIGH severity
    else:
        color = "\033[0m"  # Default color for others

    # Return the CVE ID with the appropriate color
    return f"{color}{cve_id}\033[0m"  # Reset color after the CVE ID

def save_to_txt(cve_list, keyword, folder):
    filename = f"{folder}/CVEs_{keyword}.txt"  # Default filename

    try:
        # Open the file for writing inside the context manager (with block)
        with open(filename, "w", encoding="utf-8") as file:
            # Write the user responsibility message at the top of the file
            file.write("===============================================================\n")
            file.write("                 CVEpwn - CVE Exploit Finder\n")
            file.write("---------------------------------------------------------------\n")
            file.write("Author: jbonagura\n")
            file.write("Version: 1.0\n")
            file.write("Date: 3/2/2025\n\n")

            file.write("Description:\n")
            file.write("CVEpwn is a tool designed to search for exploits related to CVE\n")
            file.write("vulnerabilities across multiple platforms like GitHub, ExploitDB,\n")
            file.write("and CXSecurity. It helps security professionals and researchers\n")
            file.write("find potential exploits for discovered vulnerabilities.\n\n")

            file.write("Disclaimer:\n")
            file.write("This tool is intended for ethical research and penetration testing\n")
            file.write("purposes only. The author is not responsible for any misuse or\n")
            file.write("illegal activities involving this tool.\n\n")

            file.write("===============================================================\n")
            file.write("CVE NIST Data Results:\n\n")

            # Check if there are any CVEs in the list and write accordingly
            if not cve_list:
                file.write("No CVE found on NIST.\n")
            else:
                # Write CVE details to the file
                for cve in cve_list:
                    file.write(f"CVE ID: {cve['cve_id']}\n")
                    file.write(f"Published: {cve['published']}\n")
                    file.write(f"VulnStatus: {cve['vulnStatus']}\n")
                    file.write(f"Description: {cve['description']}\n")
                    file.write(f"Base Score: {cve['base_score']}\n")
                    file.write(f"Severity: {cve['severity']}\n")
                    file.write(f"Attack Vector: {cve['attack_vector']}\n")
                    file.write('-' * 50 + '\n')

            print(f"\nCVE data has been saved to '{filename}'")

    except Exception as e:
        print(f"Error while saving to file: {e}")

def save_to_html(cve_list, keyword, folder):
    filename = f"{folder}/CVEs_{keyword}.html"  # Default filename

    try:
        with open(filename, "w", encoding="utf-8") as file:
            # Write the HTML header with some basic styles
            file.write("<html>\n")
            file.write("<head><title>CVEpwn - CVE Exploit Finder</title><style>\n")
            file.write("body { font-family: Arial, sans-serif; margin: 20px; }\n")
            file.write("h1 { color: #333; }\n")
            file.write(".critical { color: red; font-weight: bold; }\n")
            file.write(".high { color: orange; font-weight: bold; }\n")
            file.write(".normal { color: black; }\n")
            file.write(".description { font-size: 14px; margin-bottom: 10px; }\n")
            file.write(".separator { border-top: 1px solid #ccc; margin: 20px 0; }\n")
            file.write("</style></head>\n")
            file.write("<body>\n")
            file.write("<h1>CVEpwn - CVE Exploit Finder</h1>\n")
            file.write("<p><strong>Author:</strong> jbonagura</p>\n")
            file.write("<p><strong>Version:</strong> 1.0</p>\n")
            file.write("<p><strong>Date:</strong> 3/2/2025</p>\n")
            file.write("<h2>Description</h2>\n")
            file.write("<p>CVEpwn is a tool designed to search for exploits related to CVE\n")
            file.write("vulnerabilities across multiple platforms like GitHub, ExploitDB,\n")
            file.write("and CXSecurity. It helps security professionals and researchers\n")
            file.write("find potential exploits for discovered vulnerabilities.</p>\n")
            file.write("<div class='separator'></div>\n")
            file.write("<h2>Disclaimer</h2>\n")
            file.write("<p>This tool is intended for ethical research and penetration testing\n")
            file.write("purposes only. The author is not responsible for any misuse or\n")
            file.write("illegal activities involving this tool.</p>\n")
            file.write("<div class='separator'></div>\n")
            file.write("<h2>CVE NIST Data Results:</h2>\n")

            # Check if there are any CVEs in the list and write accordingly
            if not cve_list:
                file.write("<p>No CVE found on NIST.</p>\n")
            else:
                # Add CVE information with color-coding for Critical and High severities
                for cve in cve_list:
                    # Assign class based on severity
                    if cve['severity'] == 'CRITICAL' or cve['base_score'] >= 9.0:
                        severity_class = "critical"
                    elif cve['severity'] == 'HIGH' or (7.0 <= cve['base_score'] < 9.0):
                        severity_class = "high"
                    else:
                        severity_class = "normal"

                    # Write CVE information with color class
                    file.write(f"<h2 class='{severity_class}'>{cve['cve_id']}</h2>\n")
                    file.write(f"<p><strong>Published:</strong> {cve['published']}</p>\n")
                    file.write(f"<p><strong>VulnStatus:</strong> {cve['vulnStatus']}</p>\n")
                    file.write(f"<p class='description'><strong>Description:</strong> {cve['description']}</p>\n")
                    file.write(f"<p><strong>Base Score:</strong> {cve['base_score']}</p>\n")
                    file.write(f"<p><strong>Severity:</strong> {cve['severity']}</p>\n")
                    file.write(f"<p><strong>Attack Vector:</strong> {cve['attack_vector']}</p>\n")
                    file.write("<div class='separator'></div>\n")

            # Write the HTML footer
            file.write("</body>\n")
            file.write("</html>\n")

        print(f"\nCVE data has been saved to '{filename}'")

    except Exception as e:
        print(f"Error while saving to HTML file: {e}")

def extract_cvss_data(cvss_metric_v2, cvss_metric_v3):
    """ Extract CVSS data from v2 or v3 metrics. """
    # Default values
    base_score = None
    severity = "Not Available"
    attack_vector = "Not Available"

    # Use CVSS v3 if available, otherwise fallback to CVSS v2
    if cvss_metric_v3:
        cvss_data = cvss_metric_v3[0].get("cvssData", {})
        base_score = cvss_data.get("baseScore")
        severity = cvss_data.get("baseSeverity", "Not Available")
        attack_vector = cvss_data.get("attackVector", "Not Available")
    elif cvss_metric_v2:
        cvss_data = cvss_metric_v2[0].get("cvssData", {})
        base_score = cvss_data.get("baseScore")
        severity = cvss_data.get("baseSeverity", "Not Available")
        attack_vector = cvss_data.get("attackVector", "Not Available")

    return base_score, severity, attack_vector

def process_vulnerabilities(vulnerabilities):
    """ Process and extract CVE details from vulnerabilities list. """
    cve_list = []
    severity_count = {
        "Critical": 0,
        "High": 0,
        "Medium": 0,
        "Low": 0,
        "Not Available": 0,
        "Total": 0
    }

    for vulnerability in vulnerabilities:
        cve = vulnerability.get("cve", {})
        cve_id = cve.get("id")
        published = cve.get("published")
        vuln_status = cve.get("vulnStatus")
        descriptions = cve.get("descriptions", [])
        description_values = [desc.get("value") for desc in descriptions if
                              "value" in desc and desc.get("lang") == "en"]
        metrics = cve.get("metrics", {})
        cvss_metric_v2 = metrics.get("cvssMetricV2", [])
        cvss_metric_v3 = metrics.get("cvssMetricV31", [])

        # Get CVSS details
        base_score, severity, attack_vector = extract_cvss_data(cvss_metric_v2, cvss_metric_v3)

        if base_score is not None:
            # Append CVE data
            cve_list.append({
                'cve_id': cve_id,
                'published': published,
                'vulnStatus': vuln_status,
                'description': " | ".join(description_values),
                'base_score': base_score,
                'severity': severity,
                'attack_vector': attack_vector
            })

            # Update severity counts
            severity_count["Total"] += 1
            if severity == "CRITICAL" or (base_score >= 9.0):
                severity_count["Critical"] += 1
            elif severity == "HIGH" or (7.0 <= base_score < 9.0):
                severity_count["High"] += 1
            elif severity == "MEDIUM" or (4.0 <= base_score < 7.0):
                severity_count["Medium"] += 1
            elif severity == "LOW" or (base_score < 4.0):
                severity_count["Low"] += 1
            else:
                severity_count["Not Available"] += 1

    return cve_list, severity_count

def display_cve_info(cve_list, severity_count):
    """ Display CVE information and severity counts. """
    print("\n**********************************************")
    print("This is totally an USER responsibility tool.")
    print("**********************************************\n")

    for cve in cve_list:
        # Print the CVE ID with color based on severity
        print(print_cve_with_color(cve['cve_id'], cve['severity'], cve['base_score']))
        print(f"Published: {cve['published']}")
        print(f"VulnStatus: {cve['vulnStatus']}")
        print(f"Description: {cve['description']}")
        print(f"Base Score: {cve['base_score']}")
        print(f"Severity: {cve['severity']}")
        print(f"Attack Vector: {cve['attack_vector']}")
        print('-' * 50)  # Separator for readability

    # Display severity classification
    print("\n************************************")
    print("CVE Severity Classification:")
    print(f"{'Total:':<15} {severity_count['Total']}")
    print(f"\033[91m{'Critical:':<15} {severity_count['Critical']}\033[0m")  # Red for label and value
    print(f"\033[93m{'High:':<15} {severity_count['High']}\033[0m")  # Yellow for label and value
    print(f"{'Medium:':<15} {severity_count['Medium']}")
    print(f"{'Low:':<15} {severity_count['Low']}")
    print(f"{'Not Available:':<15} {severity_count['Not Available']}")
    print("************************************")

def get_cve_data(keyword, foldername):
    print("Working on it...")
    # URL encode the keyword to handle spaces and special characters
    encoded_keyword = urllib.parse.quote_plus(keyword)

    # Build the URL with the user-provided keyword
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={encoded_keyword}"

    try:
        # Send GET request to the API
        response = requests.get(url)

        # Check if the response is successful
        if response.status_code == 200:
            data = response.json()

            # Extract the vulnerabilities list
            vulnerabilities = data.get("vulnerabilities", [])

            # Process vulnerabilities and severity counts
            cve_list, severity_count = process_vulnerabilities(vulnerabilities)

            # Sort the CVE list by base score in descending order
            cve_list.sort(key=lambda x: x['base_score'], reverse=True)

            # Display the CVE information and severity counts
            display_cve_info(cve_list, severity_count)

            # Ask the user whether they want to save as txt or html
            user_choice = input(
                "\nDo you want to save the results?: \033[1mYes(y)\033[0m or No(n) ").strip().lower()

            if user_choice in ('y', 'yeap', ''):
                save_to_html(cve_list,keyword,foldername)  # Save as HTML
                save_to_txt(cve_list,keyword,foldername)  # Save as TXT
            elif user_choice in ('n','none','nope'):
                print("Ok, continuing without save...")
            else:
                print("Invalid choice, no file will be saved.")

            # Ask user if they want to search for exploits on GitHub
            handle_github_search(severity_count, cve_list, foldername)
            handle_exploitdb_search(severity_count,cve_list, foldername)
        elif response.status_code == 503:
            print(f"Error: NIST is unavailable, try again: {response.status_code}")
        else:
            print(f"Error: Unable to fetch CVE data. Status code: {response.status_code}")

    except requests.exceptions.RequestException as e:
        print(f"An error occurred during the API request: {e}")

def write_to_file(file, content):
    """Helper function to write content to a file.""" #Github
    file.write(content)

def fetch_github_repositories(query_list, folder):
    """Fetches repositories from GitHub using a query and saves the results to a file."""

    # Ensure the folder path exists
    folder_path = Path(folder)
    folder_path.mkdir(parents=True, exist_ok=True)

    # Filename logic
    filename_git_html = f"{folder}/Github_critical_exploits.html"
    filename_git_txt = f"{folder}/Github_critical_exploits.txt"

    # Prepare the HTML Top
    top_html = f"""
<html>
<head><title>CVEpwn - CVE Exploit Finder</title>
</head>
<body>
<h1>CVEpwn - CVE Exploit Finder</h1>
<p><strong>Author:</strong> jbonagura</p>
<p><strong>Version:</strong> 1.0</p>
<p><strong>Date:</strong> 3/2/2025</p>
<h2>Description</h2>
<p> 
    CVEpwn is a tool designed to search for exploits related to CVE
    vulnerabilities across multiple platforms like GitHub, ExploitDB,
    and CXSecurity. It helps security professionals and researchers
    find potential exploits for discovered vulnerabilities.
</p>
<h2>Disclaimer</h2 >
<p>
    This tool is intended for ethical research and penetration testing
    purposes only.The author is not responsible for any misuse or
    illegal activities involving this tool.
</p>
<div class="top">
    <h3>********************************************************</h3>
    <b><i><p style="color:red;">This tool doesn't test the exploits!!!</p></i></b>
    <h3>********************************************************</h3>
    <hr>
</div>
<div class="content">
    <h2>Github Exploits Results:</h2>
</div>
"""
    # Prepare the TXT Top
    top_txt = f""" 
===============================================================
CVEpwn - CVE Exploit Finder
---------------------------------------------------------------
Author: jbonagura
Version: 1.0
Date: 3/2/2025

Description:
CVEpwn is a tool designed to search for exploits related to CVE
vulnerabilities across multiple platforms like GitHub, ExploitDB,
and CXSecurity. It helps security professionals and researchers
find potential exploits for discovered vulnerabilities.

Disclaimer:
This tool is intended for ethical research and penetration testing
purposes only. The author is not responsible for any misuse or
illegal activities involving this tool.

===============================================================
Github Exploits Results:

"""

    # Open files for writing (one time only)
    with open(filename_git_html, "w", encoding="utf-8") as filehtml, open(filename_git_txt, "w",
                                                                          encoding="utf-8") as filetxt:
        # Write top HTML and TXT content at the start
        write_to_file(filehtml, top_html)
        write_to_file(filetxt, top_txt)

        # Process each query in the cve_queries
        total_queries = len(query_list)  # Get the total number of queries

        for i, query in enumerate(query_list, 1):
            # URL encode the query
            encoded_query = urllib.parse.quote_plus(query)
            github_url = f"https://api.github.com/search/repositories?q={encoded_query}"
            print(f"Working on: {i} of {total_queries} - {query}")  # Print the GitHub URL to the console
            response = requests.get(github_url)

            if response.status_code == 200:
                data = response.json()

                if data["total_count"] > 0:
                    # Write the query search information to the files
                    html_message = f"<h3>Searching for repositories related to: <strong>{query}</strong></h3>"
                    write_to_file(filehtml, html_message)

                    message = f"Searching for repositories with query: {query}\n"
                    write_to_file(filetxt, message)
                    print(message)  # Print message to console (only once)

                    # Process each repository in the results
                    for repo in data["items"][:10]:  # Show only the top 10 repositories
                        repo_details = {
                            "repo_name": repo['name'],
                            "description": repo.get('description', 'No description available.'),
                            "url": repo['html_url']
                        }

                        # HTML content for the repository
                        repo_html = f"""
<div class="repo">
   <h3>{repo_details["repo_name"]}</h3>
   <p><strong>Description:</strong> {repo_details["description"]}</p>
   <p><strong>URL:</strong> <a href="{repo_details["url"]}" target="_blank">{repo_details["url"]}</a></p>
   <hr>
</div>
"""
                        write_to_file(filehtml, repo_html)

                        # TXT content for the repository
                        repo_text = f"""
Repository Name: {repo_details['repo_name']}
Description: {repo_details['description']}
URL: {repo_details['url']}
{'-' * 50}\n
"""
                        write_to_file(filetxt, repo_text)
                        print(repo_text)  # Print plain text content to the console
                else:
                    # If no repositories were found
                    norepo_html = f"""
<div class="norepo">
   <p>No repositories found for {query}.\n</p>
   <hr>
</div>
"""
                    html_message = f"<h3>Searching for repositories related to: <strong>{query}</strong></h3>"
                    write_to_file(filehtml, html_message)
                    write_to_file(filehtml, norepo_html)
                    message = f"Searching for repositories with query: {query}\n"
                    write_to_file(filetxt, message)
                    message = f"No repositories found for {query}.\n" + '-' * 50 + '\n\n'
                    write_to_file(filetxt, message)
                    print(message)  # Print message to console

                # If there are more than 10 queries, add a delay after each request
                if len(query_list) > 10:
                    print("Delaying between requests to avoid rate limits or CAPTCHA...")
                    time.sleep(10)  # Introduce a 10-second delay after each request when there are more than 15 queries

            else:
                # Handle GitHub API errors
                message = f"Error searching GitHub for {query}. Status code: {response.status_code}\n"
                print(message)  # Print error message to console


    # Final message indicating that data has been saved
    print(f"\nGithub exploit data has been saved to files: {filename_git_txt} and {filename_git_html}")


def handle_github_search(severity_count, cve_list, folder):
    repos_data = []  # To store results from the fetch

    """ Handle the logic for asking the user about GitHub search. """
    if severity_count['Critical'] == 0:
        github_search_novuln = input(
            f"\nSince no Critical vulnerabilities were found. Do you want to search for a keyword on GitHub? \033[1mYes(y)\033[0m - No(n)").strip().lower()
        if github_search_novuln in ['yes', 'y', '']:
            github_key = input("What's the keyword to search for? ").strip().lower()
            fetch_github_repositories([github_key], folder)
        elif github_search_novuln in ['no', 'n']:
            print("Skipping Github!")
        else:
            print("No valid input. Exiting search.")
    else:
        github_search = input(
            f"\nDo you want to search for \033[91m{severity_count['Critical']}\033[0m CRITICAL CVEs exploits on GitHub? \033[1mYes(y)\033[0m - No(n) - Keyword(k): ").strip().lower()
        if github_search in ['yes', 'y', '']:
            filtered_cve_list = [cve for cve in cve_list if cve['severity'] == 'CRITICAL' or cve['base_score'] >= 9.0]
            cve_queries = [cve['cve_id'] for cve in filtered_cve_list]  # Get the list of CVE IDs
            fetch_github_repositories(cve_queries, folder)

        elif github_search in ['key', 'k']:
            github_key = input("What's the keyword to look for? ").strip().lower()
            fetch_github_repositories([github_key], folder)

        elif github_search in ['no', 'n']:
            print("Skipping Github!")

        else:
            print("No valid input. Exiting search.")

    return repos_data

def handle_exploitdb_search(severity_count, cve_list, folder):
    repos_data = []  # To store results from the fetch

    """ Handle the logic for asking the user about ExploitDB search. """
    if severity_count['Critical'] == 0:
        exploitdb_search_novuln = input(
            f"\nSince no Critical vulnerabilities were found. Do you want to search for a keyword on ExploitDB? \033[1mYes(y)\033[0m - No(n)").strip().lower()
        if exploitdb_search_novuln in ['yes', 'y', '']:
            exploitdb_key = input("What's the keyword to search for? ").strip().lower()
            fetch_exploitdb_repositories([exploitdb_key], folder)
        elif exploitdb_search_novuln in ['no', 'n']:
            print("Skipping ExploitDB!")
        else:
            print("No valid input. Exiting search.")
    else:
        exploitdb_search = input(
            f"\nDo you want to search for \033[91m{severity_count['Critical']}\033[0m CRITICAL CVEs exploits on ExploitDB? \033[1mYes(y)\033[0m - No(n) - Keyword(k): ").strip().lower()
        if exploitdb_search in ['yes', 'y', '']:
            filtered_cve_list = [cve for cve in cve_list if cve['severity'] == 'CRITICAL' or cve['base_score'] >= 9.0]
            cve_queries = [cve['cve_id'] for cve in filtered_cve_list]  # Get the list of CVE IDs
            fetch_exploitdb_repositories(cve_queries, folder)

        elif exploitdb_search in ['key', 'k']:
            exploitdb_key = input("What's the keyword to look for? ").strip().lower()
            fetch_exploitdb_repositories([exploitdb_key], folder)

        elif exploitdb_search in ['no', 'n']:
            print("Skipping ExploitDB!")

        else:
            print("No valid input. Exiting search.")

    return repos_data

def fetch_exploitdb_repositories(query_list, folder):
    """Fetches repositories from ExploitDB using a query and saves the results to a file."""

    # Ensure the folder path exists
    folder_path = Path(folder)
    folder_path.mkdir(parents=True, exist_ok=True)

    # Filename logic
    filename_edb_html = f"{folder}/ExploitDB_critical_exploits.html"
    filename_edb_txt = f"{folder}/ExploitDB_critical_exploits.txt"

    # Start the HTML structure
    html_content = """
<html>
<head><title>CVEpwn - CVE Exploit Finder</title>
</head>
<body>
<h1>CVEpwn - CVE Exploit Finder</h1>
<p><strong>Author:</strong> jbonagura</p>
<p><strong>Version:</strong> 1.0</p>
<p><strong>Date:</strong> 3/2/2025</p>
<h2>Description</h2>
<p> 
    CVEpwn is a tool designed to search for exploits related to CVE
    vulnerabilities across multiple platforms like GitHub, ExploitDB,
    and CXSecurity. It helps security professionals and researchers
    find potential exploits for discovered vulnerabilities.
</p>
<h2>Disclaimer</h2>
<p>
    This tool is intended for ethical research and penetration testing
    purposes only.The author is not responsible for any misuse or
    illegal activities involving this tool.
</p>
<div class="top">
    <h3>********************************************************</h3>
    <b><i><p style="color:red;">This tool doesn't test the exploits!!!</p></i></b>
    <h3>********************************************************</h3>
    <hr>
</div>
<div class="content">
    <h2>ExploitDB Exploits Results:</h2>
    <br>
</div>
<div style="margin-bottom: 20px;">
"""
    # Prepare the TXT Top
    top_txt = f""" 
===============================================================
CVEpwn - CVE Exploit Finder
---------------------------------------------------------------
Author: jbonagura
Version: 1.0
Date: 3/2/2025

Description:
CVEpwn is a tool designed to search for exploits related to CVE
vulnerabilities across multiple platforms like GitHub, ExploitDB,
and CXSecurity. It helps security professionals and researchers
find potential exploits for discovered vulnerabilities.

Disclaimer:
This tool is intended for ethical research and penetration testing
purposes only. The author is not responsible for any misuse or
illegal activities involving this tool.

===============================================================
ExploitDB Exploits Results:

"""
    # Open files for writing (one time only)
    with open(filename_edb_html, "w", encoding="utf-8") as filehtml, open(filename_edb_txt, "w",
                                                                          encoding="utf-8") as filetxt:
        # Write top HTML and TXT content at the start
        write_to_file(filehtml, html_content)
        write_to_file(filetxt, top_txt)

        # Process each query in the cve_queries
        total_queries = len(query_list)  # Get the total number of queries

        for i, query in enumerate(query_list, 1):
            # URL encode the query
            encoded_query = urllib.parse.quote_plus(query)
            pattern_CVE =  r'^(CVE-\d{4}|\d{4})-\d+$'
            if re.match(pattern_CVE,encoded_query):
                exploitdb_url = f"https://www.exploit-db.com/search?cve={encoded_query}"
            else:
                exploitdb_url = f"https://www.exploit-db.com/search?q={encoded_query}"

            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36',
                'X-Requested-With': 'XMLHttpRequest',
                'Accept': 'application/json, text/javascript, */*; q=0.01'
            }
            print(f"Working on: {i} of {total_queries} - {query}")  # Print the URL to the console
            response = requests.get(exploitdb_url, headers=headers)

            if response.status_code == 200:
                data = response.json()

                # Check if there are any results
                if "data" in data and len(data["data"]) > 0:
                    exploit = data["data"][0]  # Get the first exploit in the list

                    # Extract relevant information
                    description = " - ".join(exploit.get("description", ["No description"]))
                    download_link = f"https://www.exploit-db.com{exploit.get('download', '').split('href="')[1].split('"')[0]}" if 'download' in exploit else "No download link"

                    #HTML
                    html_message = f"<h3>Searching for repositories related to: <strong>{query}</strong></h3>"
                    write_to_file(filehtml, html_message)

                    #TXT
                    message = f"Searching for repositories with query: {query}\n"
                    write_to_file(filetxt, message)
                    print(message)  # Print message to console (only once)

                    # Print the extracted details
                    print(f"Description: {description}")
                    print(f"Download Link: {download_link}")

                    # HTML content for the repository
                    repo_html = f"""
<div class="repo">
   <h3>{query}</h3>
   <p><strong>Description:</strong> {description}</p>
   <p><strong>URL:</strong> <a href="{download_link}" target="_blank">{download_link}</a></p>
   <hr>
</div>
"""
                    write_to_file(filehtml, repo_html)

                    # TXT content for the repository
                    repo_text = f"""
Repository Name: {query}
Description: {description}
URL: {download_link}
{'-' * 50}\n
"""
                    write_to_file(filetxt, repo_text)
                    print(repo_text)  # Print plain text content to the console

                else:
                    print("No exploits found.")
                    # If no repositories were found
                    norepo_html = f"""
<div class="norepo">
   <p>No repositories found for {query}.\n</p>
   <hr>
</div>
"""
                    write_to_file(filehtml, norepo_html)
                    message = f"No repositories found for {query}.\n" + '-' * 50 + '\n\n'
                    write_to_file(filetxt, message)
                    print(message)  # Print message to console

            else:
                print(f"Failed to retrieve the data. Status code: {response.status_code}")

            # If there are more than 10 queries, add a delay after each request
            if len(query_list) > 10:
                print("Delaying between requests to avoid rate limits or CAPTCHA...")
                time.sleep(10)  # Introduce a 10-second delay after each request when there are more than 15 queries

        # Final message indicating that data has been saved
        print(f"\nExploitDB data has been saved to files: {filename_edb_txt} and {filename_edb_html}")


def scrape_cxsecurity(folder):
    base_url = 'https://cxsecurity.com/exploit/'
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    }
    while True:
        # Ask the user to provide the keyword to search for CVEs on NIST
        keyword = input("Please enter the keyword to search for: ").strip()
        # Validate the keyword input
        if not keyword:
            print("Error: You must enter a valid keyword. Try again")
        else:
            break

    while True:
        user_input = input("Enter how many pages do you want to scrape on CXSecurity? ")

        # Check if the input is empty or not a valid integer
        if not user_input.isdigit() or user_input == "":
            print("Invalid input. Please enter a valid number of pages.")
        else:
            varpagecx = int(user_input)  # Assign the valid input to varpagecx

            # Check if the number of pages is within the valid range (1 to 98)
            if varpagecx <= 0 or varpagecx >= 99:
                print("Next time enter a number of pages bigger than 0 and smaller than 100. Try again.")
            else:
                # Now we have a valid varpagecx value, so break out of the loop
                print(f"Proceeding to scrape {varpagecx} pages.")
                break  # Exit the loop once a valid value is assigned

    # Use the varpagecx variable after it's been properly assigned and loop has exited
    print(f"Scraping {varpagecx} pages now...")  # This will now print after varpagecx has been assigned

    # Start the HTML structure
    html_content = """
<html>
<head><title>CVEpwn - CVE Exploit Finder</title>
</head>
<body>
<h1>CVEpwn - CVE Exploit Finder</h1>
<p><strong>Author:</strong> jbonagura</p>
<p><strong>Version:</strong> 1.0</p>
<p><strong>Date:</strong> 3/2/2025</p>
<h2>Description</h2>
<p> 
    CVEpwn is a tool designed to search for exploits related to CVE
    vulnerabilities across multiple platforms like GitHub, ExploitDB,
    and CXSecurity. It helps security professionals and researchers
    find potential exploits for discovered vulnerabilities.
</p>
<h2>Disclaimer</h2>
<p>
    This tool is intended for ethical research and penetration testing
    purposes only.The author is not responsible for any misuse or
    illegal activities involving this tool.
</p>
<div class="top">
    <h3>********************************************************</h3>
    <b><i><p style="color:red;">This tool doesn't test the exploits!!!</p></i></b>
    <h3>********************************************************</h3>
    <hr>
</div>
<div class="content">
    <h2>CXSecurity Exploits Results:</h2>
    <br>
</div>
<div style="margin-bottom: 20px;">
"""
    # Prepare the TXT Top
    top_txt = f""" 
===============================================================
CVEpwn - CVE Exploit Finder
---------------------------------------------------------------
Author: jbonagura
Version: 1.0
Date: 3/2/2025

Description:
CVEpwn is a tool designed to search for exploits related to CVE
vulnerabilities across multiple platforms like GitHub, ExploitDB,
and CXSecurity. It helps security professionals and researchers
find potential exploits for discovered vulnerabilities.

Disclaimer:
This tool is intended for ethical research and penetration testing
purposes only. The author is not responsible for any misuse or
illegal activities involving this tool.

===============================================================
CXSecurity Exploits Results:

"""

    #lowercase - to adapt to search correctly
    keyword = keyword.lower()

    # Initialize a list for plain text results
    plain_text_results = []

    # Loop through pages 1 to 5 (you can modify this loop as needed)
    for page in range(1, varpagecx +1):
        url = f"{base_url}{page}"
        print(f"Scraping page {page} - URL: {url}")  # Debug print to check URL being accessed

    # Send the HTTP request to the page
        response = requests.get(url, headers=headers)
        if response.status_code != 200:
            print(f"Failed to retrieve page {page}")
            continue

        soup = BeautifulSoup(response.content, 'html.parser')

        # Find all rows where the span contains class 'label label-danger' (indicating High severity)
        rows = soup.find_all('tr')

        for row in rows:
            label = row.find('span', class_='label label-danger')
            if label:
                # Extract the necessary data
                link = row.find('div', class_='col-md-7').find('a', href=True)
                if link:
                    title = link['title']
                    # Only save if the title contains the keyword
                    if keyword in title.lower():
                        issue_link = link['href']

                        # Add formatted result to HTML content
                        html_entry = f"""
<div style="margin-bottom: 15px; padding: 10px; border: 1px solid #ddd; border-radius: 5px;">
    <strong>Title:</strong> {title}<br>
    <strong>Link:</strong> <a href="{issue_link}" target="_blank">{issue_link}</a>
</div>
"""
                        html_content += html_entry

                        # Also store result in plain text for .txt file
                        plain_text_results.append(f"Title: {title} - Link: {issue_link}\n{'-' * 50}\n")

        if varpagecx >30:
            print(f"Since it's more than 30 page, we need 5 seconds between request to avoid rate limit/captcha...")
            time.sleep(5)  # Sleep for 5 seconds (you can adjust the time)

    # Closing the HTML structure
    html_content += """
</div>
</body>
</html>
"""

    csxec_found = len(plain_text_results)
    if csxec_found > 0:

        # Write results to a .txt file (plain text)
        filename = f"{folder}/CXSecurity_{keyword}.txt"  # Default filename
        with open(filename, 'w', encoding='utf-8') as txt_file:
            txt_file.writelines(top_txt)
            txt_file.writelines(plain_text_results)

        # Write results to a .html file (formatted HTML)
        filenamehtml = f"{folder}/CXSecurity_{keyword}.html"  # Default filename
        with open(filenamehtml, 'w', encoding='utf-8') as html_file:
            html_file.write(html_content)

        print(f"Results saved in {filenamehtml} and {filename}")
        print(f"Scraping complete. Found {len(plain_text_results)} results for the keyword: {keyword}.")
    else:
        print(f"Scraping complete. No results were found for the keyword: '{keyword}'.")

def main():

    while True:
        # Ask the user to provide the keyword to search for CVEs on NIST
        keyword = input("Please enter the keyword to search for CVEs on NIST: ").strip()
        # Validate the keyword input
        if not keyword:
            print("Error: You must enter a valid keyword. Try again")
        else:
            break

    # Get the current date in the format YYYY-MM-DD
    current_date = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

    # Construct the folder name with the keyword and date
    folder_name = Path(f"{keyword}_{current_date}")

    # Create the folder if it doesn't exist
    if not folder_name.exists():
        folder_name.mkdir(parents=True)
        print(f"Folder '{folder_name}' created successfully.")
    else:
        print(f"Folder '{folder_name}' already exists.")

    try:
        #CVE + Github
        get_cve_data(keyword, folder_name)
        #CXSec
        cxsec_search = input(
            f"\nDo you want to search for \033[91mHigh\033[0m exploits on CXSecurity? \033[1mYes(y)\033[0m - No(n)").strip().lower()
        if cxsec_search in ['yes', 'y', '']:
            scrape_cxsecurity(folder_name)
        elif cxsec_search in ['no', 'n']:
            print("See you!")
        else:
            print("No valid input. Exiting search.")

    except Exception as e:
        # Handle any errors that occur during the function call
        print(f"An error occurred while retrieving CVE data: {e}")
        return

# Call the main function when the script is executed
if __name__ == "__main__":
    main()
