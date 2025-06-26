import requests
import logging
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse

logger = logging.getLogger(__name__)

class SyncSQLiScanner:
    def __init__(self, add_finding_callback, global_headers=None, global_cookies=None):
        self.add_finding_callback = add_finding_callback
        self.global_headers = global_headers if global_headers else {}
        self.global_cookies = global_cookies if global_cookies else {}

    def scan(self, base_url, payloads=None, test_params=None):
        """
        Performs basic synchronous SQL Injection checks.
        :param base_url: The base URL to test. Can include query parameters.
        :param payloads: List of SQLi payloads.
        :param test_params: List of parameter names to inject into if not in URL already.
        """
        if payloads is None:
            payloads = ["' OR '1'='1", "' OR '1'='1' -- ", "' OR 1=1 -- -", "\" OR \"1\"=\"1", "' OR 'x'='x"]
        if test_params is None:
            test_params = ["id", "cat", "category", "item", "page", "name", "search", "query", "p", "prod"]

        logger.info(f"[*] (SyncSQLiScanner) Starting Basic SQL Injection check on: {base_url}")

        parsed_url = urlparse(base_url)
        original_query_dict = parse_qs(parsed_url.query, keep_blank_values=True)

        # Scenario 1: Test existing parameters in the URL
        if original_query_dict:
            for param_name in original_query_dict.keys():
                for payload in payloads:
                    # Create a copy of original params to modify one param at a time
                    current_params_dict = {k: v[:] for k, v in original_query_dict.items()} # Deep copy lists
                    current_params_dict[param_name] = [original_query_dict[param_name][0] + payload] # Append payload to first value

                    new_query_string = urlencode(current_params_dict, doseq=True)
                    vuln_url = urlunparse(parsed_url._replace(query=new_query_string))
                    self._perform_sqli_request(vuln_url, payload, param_name, "existing parameter")

        # Scenario 2: Test common parameters by appending them
        base_url_no_query = urlunparse(parsed_url._replace(query=''))
        for param_name in test_params:
            # Only test if this common param is not already in the original URL's query
            if param_name not in original_query_dict:
                for payload in payloads:
                    # Append the new test param
                    current_params_dict = {k: v[:] for k, v in original_query_dict.items()}
                    current_params_dict[param_name] = [payload]

                    new_query_string = urlencode(current_params_dict, doseq=True)
                    vuln_url = urlunparse(parsed_url._replace(query=new_query_string)) # uses original path + new query
                    self._perform_sqli_request(vuln_url, payload, param_name, "common parameter")

        logger.info(f"(SyncSQLiScanner) Basic SQL Injection check completed for {base_url}")

    def _perform_sqli_request(self, vuln_url, payload, param_name, test_type):
        try:
            # Use global headers and cookies for the request
            response = requests.get(
                vuln_url,
                headers=self.global_headers,
                cookies=self.global_cookies,
                timeout=10,
                verify=False,
                allow_redirects=True
            )
            response_text = response.text.lower()
            error_indicators = [
                "sql syntax", "mysql", "unclosed quotation mark",
                "odbc", "ora-", "you have an error in your sql syntax",
                "syntax error", "pg_query", "jet database engine error",
                "sqlite_exec", "unexpected end of command"
            ]
            if any(indicator in response_text for indicator in error_indicators):
                self.add_finding_callback(
                    "SQL Injection (Basic)",
                    vuln_url,
                    f"Payload: '{payload}' in param '{param_name}' (tested as {test_type}) triggered potential SQL error.",
                    severity="High"
                )
            else:
                logger.info(f"[-] (SyncSQLiScanner) No obvious SQL Injection at: {vuln_url} with payload '{payload}' on param '{param_name}'.")
        except requests.exceptions.RequestException as e:
            logger.error(f"(SyncSQLiScanner) Error during basic SQL Injection check for {vuln_url}: {e}")
        except Exception as e:
            logger.error(f"(SyncSQLiScanner) Unexpected error during basic SQL Injection check for {vuln_url}: {e}")

# Example usage:
if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)

    def example_add_finding(vulnerability_type, url, details, severity):
        print(f"[+] FOUND: {vulnerability_type} at {url} - {details} ({severity})")

    scanner = SyncSQLiScanner(add_finding_callback=example_add_finding)
    # Test with a known vulnerable URL if possible, e.g., from DVWA or testphp.vulnweb.com
    # scanner.scan("http://testphp.vulnweb.com/listproducts.php?cat=1")
    # scanner.scan("http://testphp.vulnweb.com/artists.php?artist=1")
    # scanner.scan("http://testphp.vulnweb.com/search.php?test=query") # Test with a non-vulnerable one
    # scanner.scan("https://example.com/product?id=123") # Test existing param
    # scanner.scan("https://example.com/search") # Test common params
    logger.info("SQLi scanner module example run finished.")
    pass
