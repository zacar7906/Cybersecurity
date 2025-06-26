import requests
import logging
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse
from html import escape

logger = logging.getLogger(__name__)

class SyncXSSScanner:
    def __init__(self, add_finding_callback, global_headers=None, global_cookies=None):
        self.add_finding_callback = add_finding_callback
        self.global_headers = global_headers if global_headers else {}
        self.global_cookies = global_cookies if global_cookies else {}

    def scan(self, base_url, payloads=None, test_params=None):
        """
        Performs basic synchronous Reflected XSS checks.
        :param base_url: The base URL to test. Can include query parameters.
        :param payloads: List of XSS payloads.
        :param test_params: List of parameter names to inject into if not in URL already.
        """
        if payloads is None:
            payloads = [
                "<script>alert('XSSbyBBP')</script>",
                "<img src=x onerror=alert('XSSbyBBP')>",
                "javascript:alert('XSSbyBBP')", # Often blocked by modern browsers if reflected as is
                "<body onload=alert('XSSbyBBP')>", # Needs to be in a specific context
                "'\"--><script>alert('XSSbyBBP')</script>",
                "<svg/onload=alert('XSSbyBBP')>",
                "<details/open/ontoggle=alert('XSSbyBBP')>"
            ]
        if test_params is None:
            test_params = ["q", "s", "search", "query", "keyword", "name", "param", "input", "term", "redirect"]

        logger.info(f"[*] (SyncXSSScanner) Starting Basic XSS check on: {base_url}")

        parsed_url = urlparse(base_url)
        original_query_dict = parse_qs(parsed_url.query, keep_blank_values=True)

        # Scenario 1: Test existing parameters
        if original_query_dict:
            for param_name in original_query_dict.keys():
                original_value = original_query_dict[param_name][0] if original_query_dict[param_name] else ""
                for payload in payloads:
                    current_params_dict = {k: v[:] for k, v in original_query_dict.items()}
                    # Test by replacing the original value with payload
                    current_params_dict[param_name] = [payload]

                    new_query_string = urlencode(current_params_dict, doseq=True)
                    vuln_url = urlunparse(parsed_url._replace(query=new_query_string))
                    self._perform_xss_request(vuln_url, payload, param_name, "existing parameter")

                    # Test by appending payload to original value (if any)
                    if original_value:
                        current_params_dict[param_name] = [original_value + payload]
                        new_query_string = urlencode(current_params_dict, doseq=True)
                        vuln_url_appended = urlunparse(parsed_url._replace(query=new_query_string))
                        self._perform_xss_request(vuln_url_appended, payload, param_name, "existing parameter (appended)")


        # Scenario 2: Test common parameters by appending them
        base_url_no_query = urlunparse(parsed_url._replace(query=''))
        for param_name in test_params:
            if param_name not in original_query_dict: # Only if not already tested
                for payload in payloads:
                    current_params_dict = {k: v[:] for k, v in original_query_dict.items()}
                    current_params_dict[param_name] = [payload]

                    new_query_string = urlencode(current_params_dict, doseq=True)
                    vuln_url = urlunparse(parsed_url._replace(query=new_query_string))
                    self._perform_xss_request(vuln_url, payload, param_name, "common parameter")

        logger.info(f"(SyncXSSScanner) Basic XSS check completed for {base_url}")

    def _perform_xss_request(self, vuln_url, payload, param_name, test_type):
        try:
            response = requests.get(
                vuln_url,
                headers=self.global_headers,
                cookies=self.global_cookies,
                timeout=10,
                verify=False,
                allow_redirects=True
            )
            # Basic check: Does the raw payload appear in the response?
            # This is a naive check and can lead to FPs/FNs.
            # More advanced checks would involve parsing HTML, checking contexts,
            # or even using a headless browser for DOM XSS.

            # Check for direct reflection of the payload
            if payload in response.text:
                self.add_finding_callback(
                    "XSS (Reflected - Basic)",
                    vuln_url,
                    f"Payload: '{escape(payload)}' directly reflected in response body. Param '{param_name}' (tested as {test_type}). Manual verification needed.",
                    severity="Medium"
                )
            # Check for HTML-escaped reflection (less likely to be XSS but good to note)
            elif escape(payload) in response.text:
                 logger.info(f"[-] (SyncXSSScanner) Payload '{escape(payload)}' found HTML-escaped in response from {vuln_url}.")
            else:
                logger.info(f"[-] (SyncXSSScanner) No obvious XSS reflection at: {vuln_url} with payload '{escape(payload)}' on param '{param_name}'.")

        except requests.exceptions.RequestException as e:
            logger.error(f"(SyncXSSScanner) Error during basic XSS check for {vuln_url}: {e}")
        except Exception as e:
            logger.error(f"(SyncXSSScanner) Unexpected error during basic XSS check for {vuln_url}: {e}")

# Example usage:
if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)

    def example_add_finding(vulnerability_type, url, details, severity):
        print(f"[+] FOUND: {vulnerability_type} at {url} - {details} ({severity})")

    scanner = SyncXSSScanner(add_finding_callback=example_add_finding)
    # Test with a known vulnerable URL if possible
    # scanner.scan("http://testphp.vulnweb.com/search.php?test=query")
    # scanner.scan("http://testphp.vulnweb.com/guestbook.php") # Might have stored XSS, this basic scanner checks reflected
    # scanner.scan("https://xss-game.appspot.com/level1/frame?query=") # Example from XSS game
    logger.info("XSS scanner module example run finished.")
    pass
