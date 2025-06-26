import asyncio
import aiohttp
import logging
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse

logger = logging.getLogger(__name__)

class AsyncOpenRedirectScanner:
    def __init__(self, add_finding_callback):
        self.add_finding_callback = add_finding_callback

    async def scan(self, http_session, base_url, params_to_test=None, redirect_payloads=None):
        """
        Checks for Asynchronous Open Redirect vulnerabilities.
        :param http_session: The aiohttp client session.
        :param base_url: The base URL of the target.
        :param params_to_test: List of parameter names to test for open redirect.
        :param redirect_payloads: List of URLs to attempt redirection to.
        """
        if params_to_test is None:
            params_to_test = ["redirect", "url", "next", "goto", "dest", "returnTo", "continue", "rurl"]
        if redirect_payloads is None:
            # Payloads should ideally be domains you control or well-known benign sites for testing.
            # Avoid using "evil.com" directly in real tests if it's a live domain.
            # Using placeholders or domains known for testing is better.
            redirect_payloads = [
                "https://example.com", # Benign, well-known site
                "http://example.com",
                "//example.com",
                "https://www.google.com", # Another benign site
                "/exploit.example.com/poc.html", # Path-based redirect attempt to an external-like path
                "https://bing.com" # Another benign site for variety
            ]

        logger.info(f"[*] (OpenRedirectScanner) Starting Open Redirect check on: {base_url} for params: {params_to_test}")

        tasks = []
        for param in params_to_test:
            for payload in redirect_payloads:
                tasks.append(self._check_single_open_redirect(http_session, base_url, param, payload))

        await asyncio.gather(*tasks, return_exceptions=True)

    async def _check_single_open_redirect(self, http_session, base_url, param_name, evil_url_payload):
        parsed_url = urlparse(base_url)
        original_query_params = parse_qs(parsed_url.query)

        current_params = original_query_params.copy()
        current_params[param_name] = [evil_url_payload]

        new_query_string = urlencode(current_params, doseq=True)
        test_url = urlunparse(parsed_url._replace(query=new_query_string))

        try:
            # allow_redirects=False is crucial here
            async with http_session.get(test_url, timeout=15, allow_redirects=False) as response:
                if response.status in [301, 302, 303, 307, 308]: # Common redirect statuses
                    location_header = response.headers.get('Location', '')
                    if not location_header:
                        logger.info(f"[-] (OpenRedirectScanner) Redirect status {response.status} but no Location header at: {test_url}")
                        return

                    parsed_location = urlparse(location_header)
                    # Normalize the evil_url_payload to have a scheme for comparison if it's schemeless (e.g. //example.com)
                    normalized_evil_payload = evil_url_payload
                    if normalized_evil_payload.startswith("//"):
                        normalized_evil_payload = "http:" + normalized_evil_payload # Assume http for comparison, could be https

                    parsed_evil_payload_netloc = urlparse(normalized_evil_payload).netloc

                    # Check if the Location header's netloc matches the evil payload's netloc,
                    # or if the location header starts directly with a schemeless evil payload (e.g. //example.com)
                    # or a full evil payload.
                    if (parsed_location.netloc and parsed_evil_payload_netloc and parsed_location.netloc == parsed_evil_payload_netloc) or \
                       (evil_url_payload.startswith("//") and location_header.startswith(evil_url_payload)) or \
                       (location_header.startswith(evil_url_payload) and urlparse(evil_url_payload).scheme != ''):
                        await self.add_finding_callback("Open Redirect", test_url, f"Redirected to {location_header} with payload {evil_url_payload}", severity="Medium")
                    else:
                        logger.info(f"[-] (OpenRedirectScanner) Redirect at: {test_url} to {location_header}, but not to payload's domain '{parsed_evil_payload_netloc}'.")
                else:
                    logger.info(f"[-] (OpenRedirectScanner) No Open Redirect response status at: {test_url} (Status: {response.status})")
        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            logger.error(f"(OpenRedirectScanner) Error during Open Redirect check for {test_url}: {e}")
        except Exception as e:
            logger.error(f"(OpenRedirectScanner) Unexpected error during Open Redirect check for {test_url}: {e}")

# Example usage
if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)

    async def example_add_finding(vulnerability_type, url, details, severity):
        print(f"[+] FOUND: {vulnerability_type} at {url} - {details} ({severity})")

    async def main():
        async with aiohttp.ClientSession() as session:
            scanner = AsyncOpenRedirectScanner(add_finding_callback=example_add_finding)
            # Test with a URL known to have open redirect, or a placeholder.
            # Ensure you have permission before testing on live sites.
            # await scanner.scan(session, "http://testphp.vulnweb.com/redirect.php") # Fictitious redirect page
            # await scanner.scan(session, "https://example.com/login?returnTo=https://example.com/dashboard") # Test with existing param
            logger.info("Open Redirect scanner module example run finished.")

    # asyncio.run(main()) # Commented out
    pass
