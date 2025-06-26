import subprocess
import logging
import os
import time
import re
import asyncio
import aiohttp
import requests
import json
from argparse import ArgumentParser, ArgumentDefaultsHelpFormatter
from urllib.parse import urlparse, urljoin

# Standardized Logging Configuration
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - [%(module)s:%(lineno)d] - %(message)s',
    handlers=[
        logging.FileHandler("bugbounty_scan.log", mode='w'), # Overwrite log each run
        logging.StreamHandler()
    ]
)
# Main script logger
logger = logging.getLogger(__name__)

DEFAULT_CONFIG_FILE = "config.json"

# Import scanner modules
from bug_bounty_pro_scanners.idor_scanner import AsyncIDORScanner
from bug_bounty_pro_scanners.command_injection_scanner import AsyncCommandInjectionScanner
from bug_bounty_pro_scanners.open_redirect_scanner import AsyncOpenRedirectScanner
from bug_bounty_pro_scanners.sqli_scanner import SyncSQLiScanner
from bug_bounty_pro_scanners.xss_scanner import SyncXSSScanner
from bug_bounty_pro_scanners.lfi_scanner import SyncLFIScanner
from bug_bounty_pro_scanners.external_tool_scanner import ExternalToolScanner


class BugBountyProScanner:
    def __init__(self, base_url, cli_args=None, config=None):
        self.base_url = self._validate_and_normalize_url(base_url)
        self.base_domain = urlparse(self.base_url).netloc
        self.results = []
        self.args = cli_args if cli_args else {}
        self.config = config if config else {}

        # Determine effective settings: CLI > Config > Default
        self.user_agent = self.args.get("user_agent") or self.config.get("default_user_agent", "BugBountyPro/1.0")

        cli_intensity = self.args.get("scan_intensity")
        if cli_intensity:
            self.scan_intensity = cli_intensity
        else:
            self.scan_intensity = self.config.get("default_scan_intensity", "full")

        # Parse auth related options (CLI overrides config)
        self.auth_cookies_str = self.args.get("cookies") or self.config.get("default_cookies_str")
        self.auth_cookie_file = self.args.get("cookie_file") or self.config.get("default_cookie_file")
        self.auth_headers_str = self.args.get("headers") or self.config.get("default_headers_str")

        self.parsed_cookies = self._parse_cookies(self.auth_cookies_str, self.auth_cookie_file)
        self.parsed_headers = self._parse_headers(self.auth_headers_str)

        logger.info(f"Effective User-Agent: {self.user_agent}")
        logger.info(f"Effective Scan Intensity: {self.scan_intensity}")
        if self.parsed_cookies:
            # Avoid logging sensitive cookie values directly in real scenarios unless debugging
            logger.info(f"Using Cookies: { {k: v[:10] + '...' if len(v) > 10 else v for k,v in self.parsed_cookies.items()} }")
        if self.parsed_headers:
            log_headers = {k: (v[:10] + "..." if k.lower() == "authorization" and len(v) > 15 else v) for k,v in self.parsed_headers.items()}
            logger.info(f"Using Custom Headers: {log_headers}")

        report_json_cli = self.args.get("output_json")
        self.report_json_file = report_json_cli if report_json_cli is not None else self.config.get("default_output_json")

        report_html_cli = self.args.get("output_html")
        self.report_html_file = report_html_cli if report_html_cli is not None else self.config.get("default_output_html")

        tool_paths = self.config.get("external_tool_paths", {})

        # Instantiate scanner modules
        # Modules that make HTTP requests will need access to auth details or a pre-configured session
        self.idor_scanner = AsyncIDORScanner(add_finding_callback=self._add_finding_async)
        self.cmd_injection_scanner = AsyncCommandInjectionScanner(add_finding_callback=self._add_finding_async)
        self.open_redirect_scanner = AsyncOpenRedirectScanner(add_finding_callback=self._add_finding_async)

        # For sync scanners, we can pass auth details directly or a configured requests.Session
        self.sqli_scanner = SyncSQLiScanner(add_finding_callback=self._add_finding_sync, global_headers=self.parsed_headers, global_cookies=self.parsed_cookies)
        self.xss_scanner = SyncXSSScanner(add_finding_callback=self._add_finding_sync, global_headers=self.parsed_headers, global_cookies=self.parsed_cookies)
        self.lfi_scanner = SyncLFIScanner(add_finding_callback=self._add_finding_sync, global_headers=self.parsed_headers, global_cookies=self.parsed_cookies)

        self.external_tool_scanner = ExternalToolScanner(
            add_finding_callback=self._add_finding_sync,
            tool_paths=tool_paths
        )

    def _validate_and_normalize_url(self, url):
        if not isinstance(url, str):
            logger.error(f"URL must be a string. Received type: {type(url)}")
            raise ValueError("URL must be a string.")

        if not url.startswith(("http://", "https://")):
            logger.warning(f"URL '{url}' does not have a scheme. Prepending 'https://'.")
            url = "https://" + url

        parsed_url = urlparse(url)
        if not parsed_url.netloc:
            logger.error(f"Invalid URL: '{url}'. Netloc (domain) is missing.")
            raise ValueError(f"Invalid URL: '{url}'. Missing domain.")

        if not re.match(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', url):
            logger.error(f"URL format validation failed for: {url}")
            raise ValueError(f"URL format is invalid: {url}")

        logger.info(f"Validated and normalized URL: {url}")
        return url

    def _parse_cookies(self, cookie_str, cookie_file_path):
        cookies = {}
        if cookie_str:
            try:
                for item in cookie_str.split(';'):
                    item = item.strip()
                    if not item: continue
                    name, value = item.split('=', 1)
                    cookies[name.strip()] = value.strip()
            except ValueError:
                logger.error(f"Invalid cookie string format: '{cookie_str}'. Expected 'name=value;name2=value2'.")

        if cookie_file_path:
            if not os.path.exists(cookie_file_path):
                logger.warning(f"Cookie file specified but not found: {cookie_file_path}")
            else:
                try:
                    with open(cookie_file_path, 'r') as f:
                        for line in f:
                            line = line.strip()
                            if not line or line.startswith('#'): continue
                            if '=' in line: # Simple Name=Value
                                try:
                                    name, value = line.split('=', 1)
                                    cookies[name.strip()] = value.strip()
                                    continue
                                except ValueError: pass # Try Netscape next
                            parts = line.split('\t') # Netscape format
                            if len(parts) == 7:
                                cookies[parts[5].strip()] = parts[6].strip()
                            elif '=' not in line :
                                 logger.warning(f"Skipping unknown cookie format line in file {cookie_file_path}: {line}")
                except IOError as e:
                    logger.error(f"Could not read cookie file {cookie_file_path}: {e}")
                except Exception as e:
                    logger.error(f"Error parsing cookie file {cookie_file_path}: {e}")
        return cookies or None

    def _parse_headers(self, header_str):
        headers = {}
        if header_str:
            try:
                for item in header_str.split(';'):
                    item = item.strip()
                    if not item: continue
                    name, value = item.split(':', 1)
                    headers[name.strip()] = value.strip()
            except ValueError:
                 logger.error(f"Invalid header string format: '{header_str}'. Expected 'HeaderName: Value;HeaderName2: Value2'.")
        return headers or None

    def _add_finding_sync(self, vulnerability_type, url, details, severity="Medium"):
        finding = {"vulnerability": vulnerability_type, "url": url, "details": details, "severity": severity, "timestamp": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())}
        self.results.append(finding)
        logger.info(f"[+] VULN FOUND (SYNC): {vulnerability_type} at {url} - Details: {details}")

    async def _add_finding_async(self, vulnerability_type, url, details, severity="Medium"):
        finding = {"vulnerability": vulnerability_type, "url": url, "details": details, "severity": severity, "timestamp": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())}
        self.results.append(finding)
        logger.info(f"[+] VULN FOUND (ASYNC): {vulnerability_type} at {url} - Details: {details}")

    async def scan_async_vulnerabilities(self, session): # session is now pre-configured with auth
        logger.info("--- Starting Asynchronous Vulnerability Scans ---")
        tasks = []

        idor_paths_to_scan = self.config.get("idor_common_paths", ["users", "api/profile"])
        for path in idor_paths_to_scan:
            tasks.append(self.idor_scanner.scan(session, self.base_url, resource_path=path))

        cmd_inj_params = self.config.get("cmd_injection_params")
        tasks.append(self.cmd_injection_scanner.scan(session, self.base_url, params_to_test=cmd_inj_params))

        open_redirect_params = self.config.get("open_redirect_params")
        tasks.append(self.open_redirect_scanner.scan(session, self.base_url, params_to_test=open_redirect_params))

        await asyncio.gather(*tasks, return_exceptions=True)
        logger.info("--- Asynchronous Vulnerability Scans Completed ---")

    def scan_sync_vulnerabilities(self): # Sync scanners now get auth details in their __init__
        logger.info("--- Starting Synchronous Vulnerability Scans ---")
        sqli_test_params = self.config.get("sqli_test_params")
        self.sqli_scanner.scan(self.base_url, test_params=sqli_test_params)

        xss_test_params = self.config.get("xss_test_params")
        self.xss_scanner.scan(self.base_url, test_params=xss_test_params)

        lfi_test_params = self.config.get("lfi_test_params")
        self.lfi_scanner.scan(self.base_url, test_params=lfi_test_params)
        logger.info("--- Synchronous Vulnerability Scans Completed ---")

    def run_external_tools(self):
        logger.info("--- Starting External Tool Integrations ---")
        parsed_url = urlparse(self.base_url)
        host = parsed_url.hostname

        if not host:
            logger.error(f"Could not derive hostname from base_url: {self.base_url} for Nmap/Subfinder.")
            return

        def get_tool_options(tool_name_cli, tool_name_config):
            cli_opts_str = self.args.get(tool_name_cli)
            if cli_opts_str is not None:
                return cli_opts_str.split() if cli_opts_str else []
            return self.config.get(tool_name_config, [])

        nmap_opts_list = get_tool_options("nmap_options", "default_nmap_options")
        self.external_tool_scanner.run_nmap(host, custom_options=nmap_opts_list)

        subfinder_opts_list = get_tool_options("subfinder_options", "default_subfinder_options")
        self.external_tool_scanner.run_subfinder(host, custom_options=subfinder_opts_list)

        nuclei_opts_list = get_tool_options("nuclei_options", "default_nuclei_options")
        # Nuclei might need cookies/headers passed as command line args if not handled by its own session management
        # For now, not passing them directly to nuclei CLI wrapper.
        self.external_tool_scanner.run_nuclei(self.base_url, custom_options=nuclei_opts_list)

        sqlmap_opts_list = get_tool_options("sqlmap_options", "default_sqlmap_options")
        # SQLMap can use --cookie and --headers options
        if self.parsed_cookies:
            cookie_str_for_sqlmap = "; ".join([f"{k}={v}" for k,v in self.parsed_cookies.items()])
            sqlmap_opts_list.extend(["--cookie", cookie_str_for_sqlmap])
        if self.parsed_headers:
            headers_for_sqlmap = ["--headers=" + "; ".join([f"{k}: {v}" for k,v in self.parsed_headers.items()])] # SQLMap expects single string for headers
            sqlmap_opts_list.extend(headers_for_sqlmap)

        self.external_tool_scanner.run_sqlmap(self.base_url, custom_options=sqlmap_opts_list)

        xsser_opts_list = get_tool_options("xsser_options", "default_xsser_options")
        # XSSer can also use --cookie
        if self.parsed_cookies:
             xsser_opts_list.extend(["--cookie", ";".join([f"{k}={v}" for k,v in self.parsed_cookies.items()])])
        self.external_tool_scanner.run_xsser(self.base_url, custom_options=xsser_opts_list)

        logger.info("--- External Tool Integrations Completed ---")

    async def full_scan_orchestrator(self):
        logger.info(f"Starting full scan for: {self.base_url} with User-Agent: {self.user_agent}")
        start_time = time.time()

        # Prepare headers for aiohttp session, including User-Agent and custom auth headers
        # User-Agent is primary, then add other custom headers
        effective_aio_headers = {'User-Agent': self.user_agent}
        if self.parsed_headers:
            effective_aio_headers.update(self.parsed_headers)

        if self.scan_intensity in ["full", "internal", "light"]:
            self.scan_sync_vulnerabilities() # Sync scanners use self.parsed_cookies/headers internally now

            connector = aiohttp.TCPConnector(ssl=False)
            async with aiohttp.ClientSession(
                connector=connector,
                headers=effective_aio_headers, # Pass combined headers
                cookies=self.parsed_cookies    # Pass parsed cookies
            ) as session:
                await self.scan_async_vulnerabilities(session)

        if self.scan_intensity == "full":
            self.run_external_tools() # External tools will get auth details via CLI options if they support it
        else:
            logger.info(f"Skipping external tool scans based on scan intensity: '{self.scan_intensity}'.")

        elapsed_time = time.time() - start_time
        logger.info(f"Full scan completed in {elapsed_time:.2f} seconds.")
        self.report_findings(json_output_file=self.report_json_file, html_output_file=self.report_html_file)

    def full_scan(self):
        asyncio.run(self.full_scan_orchestrator())

    def _generate_json_report(self, filename):
        logger.info(f"Generating JSON report: {filename}")
        try:
            report_data = {
                "scan_target": self.base_url,
                "scan_timestamp": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
                "scan_intensity": self.scan_intensity,
                "user_agent": self.user_agent,
                "findings_count": len(self.results),
                "findings": self.results
            }
            with open(filename, 'w') as f:
                json.dump(report_data, f, indent=4)
            logger.info(f"JSON report saved to {filename}")
        except IOError as e:
            logger.error(f"Failed to write JSON report to {filename}: {e}")
        except Exception as e:
            logger.error(f"An unexpected error occurred while generating JSON report: {e}")

    def _generate_html_report(self, filename):
        logger.info(f"Generating HTML report: {filename}")
        try:
            from html import escape
            scan_time = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
            html_content = f"""
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>BugBountyPro Scan Report for {escape(self.base_url)}</title>
                <style>
                    body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 0; background-color: #f9f9f9; color: #333; font-size: 16px; line-height: 1.6; }}
                    .container {{ width: 90%; max-width: 1200px; margin: 20px auto; background-color: #fff; padding: 25px; border-radius: 8px; box-shadow: 0 4px 15px rgba(0,0,0,0.1); }}
                    h1 {{ color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 15px; margin-bottom: 25px; text-align: center; }}
                    h2 {{ color: #3498db; margin-top: 30px; border-bottom: 1px solid #eee; padding-bottom:10px;}}
                    table {{ width: 100%; border-collapse: collapse; margin-top: 20px; box-shadow: 0 2px 3px rgba(0,0,0,0.05); }}
                    th, td {{ border: 1px solid #e0e0e0; padding: 12px 15px; text-align: left; vertical-align: top; }}
                    th {{ background-color: #3498db; color: white; font-weight: bold; text-transform: uppercase; letter-spacing: 0.5px; }}
                    tr:nth-child(even) {{ background-color: #f7f9fc; }}
                    tr:hover {{ background-color: #eef7ff; }}
                    .severity-Critical {{ background-color: #ffebee; color: #c62828; font-weight: bold; }}
                    .severity-High {{ background-color: #fff3e0; color: #ef6c00; font-weight: bold; }}
                    .severity-Medium {{ background-color: #fffde7; color: #fbc02d; }}
                    .severity-Low {{ background-color: #e3f2fd; color: #1565c0; }}
                    .severity-Info {{ background-color: #f5f5f5; color: #546e7a; }}
                    .details-column {{ max-width: 400px; word-wrap: break-word; }}
                    .url-column {{ max-width: 300px; word-wrap: break-word; }}
                    a {{ color: #2980b9; text-decoration: none; }}
                    a:hover {{ text-decoration: underline; }}
                    .scan-summary p {{ font-size: 1.1em; margin-bottom: 8px; }}
                </style>
            </head>
            <body>
                <div class="container">
                    <h1>BugBountyPro Scan Report</h1>
                    <div class="scan-summary">
                        <p><strong>Target:</strong> {escape(self.base_url)}</p>
                        <p><strong>Scan Date:</strong> {escape(scan_time)}</p>
                        <p><strong>Scan Intensity:</strong> {escape(self.scan_intensity)}</p>
                        <p><strong>User-Agent:</strong> {escape(self.user_agent)}</p>
                        <p><strong>Total Findings:</strong> {len(self.results)}</p>
                    </div>
            """

            if not self.results:
                html_content += "<h2>No vulnerabilities found in this scan.</h2>"
            else:
                html_content += "<h2>Vulnerability Findings</h2>"
                html_content += "<table><thead><tr><th>Severity</th><th>Type</th><th class='url-column'>URL</th><th class='details-column'>Details</th><th>Timestamp (UTC)</th><th>Remediation</th></tr></thead><tbody>"

                severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
                sorted_findings = sorted(self.results, key=lambda x: severity_order.get(x.get('severity', 'Info'), 5))

                for finding in sorted_findings:
                    vuln_type = escape(finding.get('vulnerability', 'N/A'))
                    url = escape(finding.get('url', 'N/A'))
                    details = escape(finding.get('details', 'N/A')).replace('\n', '<br>')
                    severity = escape(finding.get('severity', 'Info'))
                    timestamp = escape(finding.get('timestamp', 'N/A'))
                    remediation = "Refer to OWASP guidelines and specific vulnerability documentation."

                    html_content += f"""
                    <tr>
                        <td class="severity-{severity}">{severity}</td>
                        <td>{vuln_type}</td>
                        <td class="url-column"><a href="{url}" target="_blank" rel="noopener noreferrer">{url}</a></td>
                        <td class="details-column">{details}</td>
                        <td>{timestamp}</td>
                        <td>{remediation}</td>
                    </tr>
                    """
                html_content += "</tbody></table>"

            html_content += "</div></body></html>"

            with open(filename, 'w', encoding='utf-8') as f:
                f.write(html_content)
            logger.info(f"HTML report saved to {filename}")
        except ImportError:
            logger.error("Could not import 'html' module for HTML escaping.")
        except IOError as e:
            logger.error(f"Failed to write HTML report to {filename}: {e}")
        except Exception as e:
            logger.error(f"An unexpected error occurred while generating HTML report: {e}")

    def report_findings(self, json_output_file=None, html_output_file=None):
        logger.info("\n--- Scan Report (Console) ---")
        if not self.results:
            logger.info("No vulnerabilities found in this scan.")
        else:
            logger.info(f"Found {len(self.results)} potential vulnerabilities:")
            severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
            sorted_findings_console = sorted(self.results, key=lambda x: severity_order.get(x.get('severity', 'Info'), 5))
            for finding in sorted_findings_console:
                logger.info(
                    f"  Severity: {finding.get('severity', 'N/A')}\n"
                    f"  Type: {finding.get('vulnerability', 'N/A')}\n"
                    f"  URL: {finding.get('url', 'N/A')}\n"
                    f"  Details: {finding.get('details', 'N/A')}\n"
                    f"  Timestamp: {finding.get('timestamp', 'N/A')}\n"
                    f"  --------------------"
                )

        if json_output_file:
            self._generate_json_report(json_output_file)

        if html_output_file:
            self._generate_html_report(html_output_file)

if __name__ == "__main__":
    parser = ArgumentParser(description="BugBountyPro - Advanced Vulnerability Scanner",
                            formatter_class=ArgumentDefaultsHelpFormatter)
    parser.add_argument("url", help="Target URL for the vulnerability scan")
    parser.add_argument("--config", default=DEFAULT_CONFIG_FILE, help="Path to configuration JSON file")
    parser.add_argument("--output-json", help="Filename for JSON report output (overrides config)")
    parser.add_argument("--output-html", help="Filename for HTML report output (overrides config)")
    parser.add_argument("--user-agent", help="Custom User-Agent string for scans (overrides config)")
    parser.add_argument(
        "--scan-intensity",
        choices=["light", "internal", "full"],
        default=None, # Default is handled by config or scanner's internal default
        help="Scan intensity: 'light' (fast internal checks), 'internal' (all internal checks), 'full' (all checks including external tools)"
    )
    parser.add_argument("--sqlmap-options", help="Custom options for SQLMap, space-separated (e.g., \"--level=5 --risk=3\") (overrides config)")
    parser.add_argument("--xsser-options", help="Custom options for XSSer, space-separated (overrides config)")
    parser.add_argument("--nmap-options", help="Custom options for Nmap, space-separated (e.g., \"-p 1-65535 -A\") (overrides config)")
    parser.add_argument("--subfinder-options", help="Custom options for Subfinder, space-separated (e.g., \"-all -silent\") (overrides config)")
    parser.add_argument("--nuclei-options", help="Custom options for Nuclei, space-separated (e.g., \"-tags cve,rce\") (overrides config)")

    parser.add_argument(
        "--cookies",
        help="Cookies to use for requests (e.g., \"sessionid=abc;user=def\")",
        default=None
    )
    parser.add_argument(
        "--cookie-file",
        help="Path to a file containing cookies (one 'Name=Value' per line or Netscape format)",
        default=None
    )
    parser.add_argument(
        "--headers",
        help="Custom headers to include in requests (e.g., \"Authorization: Bearer xyz;X-Custom: abc\")",
        default=None
    )

    cli_args_dict = vars(parser.parse_args())

    loaded_config = {}
    config_file_path = cli_args_dict.get("config")

    if os.path.exists(config_file_path):
        try:
            with open(config_file_path, 'r') as f:
                loaded_config = json.load(f)
            logger.info(f"Loaded configuration from {config_file_path}")
        except json.JSONDecodeError as e:
            logger.error(f"Error decoding JSON from config file {config_file_path}: {e}. Proceeding with defaults/CLI args.")
        except IOError as e:
            logger.warning(f"Could not read config file {config_file_path}: {e}. Proceeding with defaults/CLI args.")
    else:
        if config_file_path != DEFAULT_CONFIG_FILE:
             logger.warning(f"Specified config file {config_file_path} was not found. Using defaults and CLI arguments.")
        else:
            logger.info(f"Default config file {DEFAULT_CONFIG_FILE} not found. Using defaults and CLI arguments.")

    try:
        scanner = BugBountyProScanner(cli_args_dict["url"], cli_args=cli_args_dict, config=loaded_config)
        scanner.full_scan()
    except ValueError as ve:
        logger.error(f"Configuration Error: {ve}")
    except Exception as e:
        logger.critical(f"A critical error occurred: {e}", exc_info=True)

# Example Usage:
# python BugBountyPro.py https://public-firing-range.appspot.com --output-json report.json --output-html report.html
# python BugBountyPro.py http://testphp.vulnweb.com --config my_config.json --scan-intensity light
# python BugBountyPro.py http://example.com --cookies "session=123;user=admin"
# Needs sqlmap and xsser in PATH to run external tools
# Example vulnerable sites for testing:
# - http://testphp.vulnweb.com/ (SQLi, XSS, LFI)
# - https://public-firing-range.appspot.com (various, good for XSS, Open Redirect)
# - OWASP Juice Shop (run locally: docker run -d -p 3000:3000 bkimminich/juice-shop)
#   then scan: python BugBountyPro.py http://localhost:3000
#
# Remember to get permission before scanning any target you do not own.
# This script is for educational purposes.
print("BugBountyPro script execution finished.")
