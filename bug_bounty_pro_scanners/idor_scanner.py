import asyncio
import aiohttp
import logging
from urllib.parse import urljoin

logger = logging.getLogger(__name__)

class AsyncIDORScanner:
    def __init__(self, add_finding_callback):
        self.add_finding_callback = add_finding_callback

    async def scan(self, http_session, base_url, resource_path="user/profile", user_ids=None):
        """
        Checks for Insecure Direct Object References (IDOR) vulnerabilities.
        :param http_session: The aiohttp client session.
        :param base_url: The base URL of the target.
        :param resource_path: The resource path pattern to test (e.g., 'user/profile', 'api/orders').
        :param user_ids: A list of user IDs to test. Defaults to a common list.
        """
        if user_ids is None:
            user_ids = [1, 2, 3, 4, 5, 100, 101, 1000]  # Default user IDs

        temp_base_url = base_url if base_url.endswith('/') else base_url + '/'
        # urljoin should handle joining temp_base_url (e.g. http://example.com/app/)
        # with resource_path (e.g. users, api/data) correctly.
        # If resource_path is absolute (starts with /), it might replace parts of temp_base_url's path.
        # Assuming resource_path is relative for now.
        target_url_base_for_idor = urljoin(temp_base_url, resource_path)

        if not target_url_base_for_idor.endswith('/'):
            target_url_base_for_idor += '/'

        logger.info(f"[*] (IDORScanner) Starting IDOR check on base: {target_url_base_for_idor} for user IDs: {user_ids}")

        tasks = []
        for user_id in user_ids:
            vuln_url = urljoin(target_url_base_for_idor, str(user_id))
            tasks.append(self._check_single_idor_url(http_session, vuln_url, user_id))

        await asyncio.gather(*tasks, return_exceptions=True)

    async def _check_single_idor_url(self, http_session, vuln_url, user_id):
        try:
            async with http_session.get(vuln_url, timeout=15, allow_redirects=True) as response:
                response_text = await response.text()
                # Basic check, can be made more sophisticated (e.g., checking for user-specific content)
                if response.status == 200 and (
                    f"user_id: {user_id}" in response_text.lower() or
                    f"userid: {user_id}" in response_text.lower() or
                    f"user: {user_id}" in response_text.lower() or
                    "private profile" in response_text.lower() or
                    "confidential data" in response_text.lower() # More generic
                ):
                    await self.add_finding_callback("IDOR", vuln_url, f"Accessed user {user_id}'s potential data. Status: {response.status}. Review manually.", severity="High")
                else:
                    logger.info(f"[-] (IDORScanner) No obvious IDOR at: {vuln_url} (Status: {response.status})")
        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            logger.error(f"(IDORScanner) Error during IDOR check for {vuln_url}: {e}")
        except Exception as e:
            logger.error(f"(IDORScanner) Unexpected error during IDOR check for {vuln_url}: {e}")

# Example of how it might be used (for testing this module standalone)
if __name__ == '__main__':
    # This is placeholder for actual logging and async setup
    logging.basicConfig(level=logging.INFO)

    async def example_add_finding(vulnerability_type, url, details, severity):
        print(f"[+] FOUND: {vulnerability_type} at {url} - {details} ({severity})")

    async def main():
        async with aiohttp.ClientSession() as session:
            idor_scanner = AsyncIDORScanner(add_finding_callback=example_add_finding)
            # Test with a dummy URL, replace with a real target that might have IDORs for actual testing
            # e.g., a locally running vulnerable app.
            # For public sites, ensure you have permission.
            # await idor_scanner.scan(session, "http://testphp.vulnweb.com", resource_path="users")
            # await idor_scanner.scan(session, "https://jsonplaceholder.typicode.com", resource_path="users")
            # await idor_scanner.scan(session, "https_example_vuln_site_com", resource_path="api/user_info")
            logger.info("IDOR scanner module example run finished.")

    # asyncio.run(main()) # Commented out to prevent execution when imported
    pass
