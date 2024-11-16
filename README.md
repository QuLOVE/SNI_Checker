# SNI connection tester

The **SNI connection tester** is a Python-based tool for analyzing and gathering detailed information about an SNI (Server Name Indication) host. It performs a variety of tests, including DNS resolution, TCP connection testing, HTTPS request validation, SSL certificate analysis, and website metadata extraction.

## Features

- **TCP connection test**: Checks if a TCP connection can be established to the host on port 443.
- **DNS lookup**: Resolves the domain to its IP address and fetches DNS `A` records.
- **SSL certificate analysis**: Fetches and logs details about the SSL/TLS certificate, including issuer and validity.
- **HTTP request analysis**: Logs HTTP request and response headers.
- **Website metadata extraction**: Retrieves and logs the page title, meta description, and content length.
- **Detailed logging**: All test results are logged to a `log.txt` file for later reference.

## Requirements

- Python 3.6+
- Python packages:
  - `requests`
  - `colorama`
  - `beautifulsoup4`
  - `dnspython`

## Installation

1. Clone or download this repository.
2. Install the required dependencies using `pip`:
   ```bash
   pip install requests colorama beautifulsoup4 dnspython
