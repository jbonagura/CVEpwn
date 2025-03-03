---
# CVEpwn - CVE Exploit Finder

**CVEpwn** is a security tool designed to search for exploits related to CVE vulnerabilities across multiple platforms like ExploitDB, CXSecurity, and GitHub. 
It assists security professionals and researchers by identifying and gathering potential exploits for discovered vulnerabilities based on specific keywords or CVE identifiers.

## Features

- **CVE Search**: Search and fetch data related to NIST CVEs.
- **GitHub Repositories**: Look for exploits on GitHub repositories that could potentially be associated with vulnerabilities.
- **ExploitDB Search**: Query ExploitDB for exploits based on CVE IDs or keywords, specifically for critical vulnerabilities.
- **CXSecurity Scraping**: Scrape CXSecurity for high-severity vulnerabilities using a specific keyword.

- **Output**: Store the results in `.txt` and `.html` files, with detailed exploit descriptions, links, and more.
- **Interactive Interface**: The tool interacts with the user, asking for keywords, CVE IDs, and preferences on how to search and retrieve exploit data.

## Requirements (you can also use the requirements.txt)

- Python 3.x
- Required libraries:
  - `requests`
  - `beautifulsoup4`
  - `urllib`
  - `datetime`
  
Install required libraries using `pip`:

```bash
pip install requests beautifulsoup4
```

## Setup and Usage

1. **Clone or Download the Repository:**
   Clone or download the `CVEpwn` repository to your local machine.

2. **Run the Script:**
   Navigate to the directory where the script is located and execute:

   ```bash
   python3 cvepwn.py
   ```

3. **Input Prompts:**
   The script will prompt you to input:
   - A **keyword** to search for CVEs on NIST.
   - Whether you want to **search for GitHub repositories** related to the exploits.   
   - Whether you want to search for **Critical CVEs** or **Custom Exploits** in ExploitDB.
   - If you want to **scrape CXSecurity** for high-severity exploits related to the keyword.
   
4. **Directory Structure:**
   - The script will create a folder named after the keyword and timestamp (e.g., `apache_2025-03-02_10-30-15`) to store the results.
   - It will create `.html` and `.txt` files for ExploitDB and CXSecurity, containing detailed data for each found exploit.

5. **Results Format:**
   
   - **CVE** results will include:****
      - CVE ID: The CVE identifier (e.g., CVE-2023-XXXX).
      - Title: A short title or description of the CVE.
      - Description: A detailed description of what the CVE addresses.
      - Published: The date when the CVE was published.
      - Last Modified: The date when the CVE entry was last updated.
      - CVSS Score: The severity score given to the vulnerability, such as "Critical" or "High."
      - References: A URL to further details or official resources related to the CVE.

   - **Github** results will include:
     - Repository Name
     - Description
     - URL

   - **ExploitDB** results will include:
     - CVE ID
     - Description of the exploit
     - Download links (if available)
   
   - **CXSecurity** results will include:
     - Title and link to the exploit
     - Severity level
     - Description of the vulnerability

## Example Workflow

1. **Initial Keyword Input:**
   The script will ask you for a keyword (e.g., `apache`, `nginx`, etc.) to search for CVEs.

   ```
   Please enter the keyword to search for CVEs on NIST: apache
   ```

2. **GitHub Repositories (Optional):**
   After getting the CVE data, the script will ask if you want to search for **Critical CVEs** on Github

   ```
   Do you want to search for CRITICAL CVEs exploits on Github? Yes(y) - No(n) - Keyword(k):
   ```

3. **ExploitDB (Optional):**
   The script will ask if you want to search for **Critical CVEs**:

   ```
   Do you want to search for CRITICAL CVEs exploits on ExploitDB? Yes(y) - No(n) - Keyword(k):
   ```

4. **CXSecurity Scraping (Optional):**
   After handling ExploitDB, it will ask if you want to scrape **CXSecurity** for high-severity exploits:
   On this case a keywork and a number of pages to scrap will be asked, since the CXSecurity don't necessarilly works with CVE
   number or products version. Also the classification is only until High.

   ```
   Do you want to search for High exploits on CXSecurity? Yes(y) - No(n)
   ```

5. **Output Files:**
   - **CVE Data**: `CVE_exploits_apache_2025-03-02_10-30-15.txt` and `CVE_exploits_apache_2025-03-02_10-30-15.html`
   - **Github Results**: `GitHub_exploits_apache_2025-03-02_10-30-15.txt` and `GitHub_exploits_apache_2025-03-02_10-30-15.html`
   - **ExploitDB Results**: `ExploitDB_critical_exploits_apache_2025-03-02_10-30-15.txt` and `ExploitDB_critical_exploits_apache_2025-03-02_10-30-15.html`
   - **CXSecurity Results**: `CXSecurity_apache_2025-03-02_10-30-15.txt` and `CXSecurity_apache_2025-03-02_10-30-15.html`
   

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

This tool is intended for ethical research and penetration testing purposes only. The author is not responsible for any misuse or illegal activities involving this tool.

---
