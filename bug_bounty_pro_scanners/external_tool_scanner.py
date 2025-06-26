import subprocess
import logging
import os
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

class ExternalToolScanner:
    def __init__(self, add_finding_callback, tool_paths=None): # Added tool_paths
        self.add_finding_callback = add_finding_callback
        self.tool_paths = tool_paths if tool_paths else {}

        # Ensure log directories exist
        for log_dir in ['./logs/sqlmap', './logs/xsser', './logs/nmap', './logs/nuclei', './logs/subfinder']:
            if not os.path.exists(log_dir):
                try:
                    os.makedirs(log_dir)
                except OSError as e:
                    logger.error(f"Failed to create log directory {log_dir}: {e}")

    def _get_tool_path(self, tool_name):
        # Fetches tool path from config, defaults to tool_name (assuming it's in PATH)
        return self.tool_paths.get(tool_name, tool_name)

    def run_sqlmap(self, target_url, custom_options=None):
        logger.info(f"[*] (ExternalToolScanner) Attempting to run sqlmap on: {target_url}")
        if custom_options is None:
            custom_options = []

        sqlmap_exe = self._get_tool_path("sqlmap")

        try:
            # Default base command parts that can be overridden or extended
            default_opts_map = {
                "--batch": True, "--random-agent": True, "--level": "1", "--risk": "1",
                "--technique": "B", "--output-dir": "./logs/sqlmap", "--ignore-proxy": True, "--threads": "1"
            }

            final_command = [sqlmap_exe, "-u", target_url]

            # Apply custom options first, then fill in defaults if not specified
            # This allows custom options like "--level=5" to override default "--level=1"
            # This is a simplified merge; complex args might need more robust parsing
            user_specified_keys = set()
            for opt_str in custom_options: # e.g., "--level=5" or "--batch" (if user wants to ensure it)
                key = opt_str.split('=',1)[0]
                user_specified_keys.add(key)
                final_command.append(opt_str)

            for key, val in default_opts_map.items():
                if key not in user_specified_keys and (key+"=") not in user_specified_keys : # check for key and key=
                    # Check if any part of custom_options starts with key (e.g. custom has --level=X, default is --level)
                    already_customized = False
                    for cust_opt in custom_options:
                        if cust_opt.startswith(key):
                            already_customized = True
                            break
                    if not already_customized:
                        if isinstance(val, bool) and val: # It's a flag meant to be present
                            final_command.append(key)
                        elif not isinstance(val, bool): # It's an option with a default value
                            final_command.extend([key, val])

            # Remove potential duplicates from simplified merge (keeping last instance)
            # Not strictly necessary with current logic but good for robustness if logic changes
            seen_opts = set()
            deduped_command = []
            for item in reversed(final_command):
                opt_key = item.split('=',1)[0]
                if opt_key.startswith('-'):
                    if opt_key not in seen_opts:
                        deduped_command.insert(0, item)
                        seen_opts.add(opt_key)
                    # if it's a value for an option, it should have been added with its key
                else: # it's a value or the executable name
                    deduped_command.insert(0, item)
            final_command = deduped_command


            logger.info(f"(ExternalToolScanner) Executing sqlmap command: {' '.join(final_command)}")
            result = subprocess.run(final_command, capture_output=True, text=True, check=False, timeout=300)

            parsed_target_url = urlparse(target_url)
            hostname_for_log = parsed_target_url.hostname
            log_file_path = os.path.join("./logs/sqlmap", hostname_for_log, "log") if hostname_for_log else ""

            if result.returncode == 0:
                logger.info(f"[+] (ExternalToolScanner) sqlmap completed successfully for: {target_url}. Check logs in ./logs/sqlmap.")
                if "identified the following injection point(s)" in result.stdout.lower() or \
                   (log_file_path and os.path.exists(log_file_path) and "identified the following injection point(s)" in open(log_file_path, 'r', encoding='utf-8', errors='ignore').read().lower()):
                    self.add_finding_callback("SQL Injection (sqlmap)", target_url, f"sqlmap identified potential SQLi. Details in sqlmap logs: {log_file_path}", severity="Critical")
                elif "all tested parameters appear to be not injectable" in result.stdout.lower():
                     logger.info(f"[-] (ExternalToolScanner) sqlmap reported no vulnerabilities for {target_url}")
            else:
                logger.warning(f"[-] (ExternalToolScanner) sqlmap for {target_url} finished with return code {result.returncode}.")
                logger.debug(f"(ExternalToolScanner) sqlmap stdout for {target_url}:\n{result.stdout}")
                logger.debug(f"(ExternalToolScanner) sqlmap stderr for {target_url}:\n{result.stderr}")

        except subprocess.TimeoutExpired:
            logger.error(f"(ExternalToolScanner) sqlmap timed out for {target_url}.")
            self.add_finding_callback("Tool Execution Issue", target_url, "sqlmap scan timed out.", severity="Info")
        except FileNotFoundError:
            logger.error(f"(ExternalToolScanner) {sqlmap_exe} command not found. Please ensure it's installed and in your PATH or configured in tool_paths.")
            self.add_finding_callback("Tool Configuration Error", target_url, f"{sqlmap_exe} command not found.", severity="Warning")
        except Exception as e:
            logger.error(f"(ExternalToolScanner) Unexpected error running sqlmap on {target_url}: {e}")
            self.add_finding_callback("Tool Execution Issue", target_url, f"Error running sqlmap: {e}", severity="Info")

    def run_xsser(self, target_url, custom_options=None):
        logger.info(f"[*] (ExternalToolScanner) Attempting to run XSSer on: {target_url}")
        if custom_options is None:
            custom_options = []

        xsser_exe = self._get_tool_path("xsser")

        try:
            default_opts = ["--auto", "--crawl=0", "-s"]
            final_command = [xsser_exe, "-u", target_url] + default_opts + custom_options # Simple append, custom can override if xsser handles it
            # Basic deduplication by converting to dict and back for flags/options
            # More robust merging might be needed if complex overrides are common.
            temp_opts = {}
            for opt in default_opts + custom_options:
                if '=' in opt:
                    key = opt.split('=',1)[0]
                    temp_opts[key] = opt
                else:
                    temp_opts[opt] = True # Flag

            final_command = [xsser_exe, "-u", target_url]
            for k,v in temp_opts.items():
                if isinstance(v, bool) and v: final_command.append(k)
                elif not isinstance(v,bool): final_command.append(v)


            logger.info(f"(ExternalToolScanner) Executing XSSer command: {' '.join(final_command)}")
            result = subprocess.run(final_command, capture_output=True, text=True, check=False, timeout=300)

            if "TOP XSS VULNERABILITIES" in result.stdout or \
               "POC XSS" in result.stdout or \
               "Found XSS" in result.stdout.lower():
                logger.info(f"[+] (ExternalToolScanner) XSSer completed for: {target_url} and found potential XSS.")
                self.add_finding_callback("XSS (XSSer)", target_url, "XSSer reported potential XSS. Manual verification needed. Check XSSer logs/output.", severity="Medium")
            else:
                logger.info(f"[-] (ExternalToolScanner) XSSer for {target_url} did not report obvious XSS or failed (Code: {result.returncode}).")
                logger.debug(f"(ExternalToolScanner) XSSer stdout for {target_url}:\n{result.stdout}")
                logger.debug(f"(ExternalToolScanner) XSSer stderr for {target_url}:\n{result.stderr}")

        except subprocess.TimeoutExpired:
            logger.error(f"(ExternalToolScanner) XSSer timed out for {target_url}.")
            self.add_finding_callback("Tool Execution Issue", target_url, "XSSer scan timed out.", severity="Info")
        except FileNotFoundError:
            logger.error(f"(ExternalToolScanner) {xsser_exe} command not found. Please ensure it's installed and in your PATH or configured in tool_paths.")
            self.add_finding_callback("Tool Configuration Error", target_url, f"{xsser_exe} command not found.", severity="Warning")
        except Exception as e:
            logger.error(f"(ExternalToolScanner) Unexpected error running XSSer on {target_url}: {e}")
            self.add_finding_callback("Tool Execution Issue", target_url, f"Error running xsser: {e}", severity="Info")

    def run_nmap(self, target_host, custom_options=None):
        logger.info(f"[*] (ExternalToolScanner) Attempting to run Nmap on: {target_host}")
        if custom_options is None:
            custom_options = []

        nmap_exe = self._get_tool_path("nmap")
        output_file = os.path.join("./logs/nmap", f"{target_host.replace('/', '_')}_nmap.txt")

        try:
            default_opts = ["-sV", "-T4", "--open"]
            # Nmap command structure: nmap [Scan Type(s)] [Options] {target specification}
            # Custom options might include scan types or other options.
            # Simple append: nmap <default_opts> <custom_opts> <target> -oN <output_file>
            # This might not be ideal if custom_opts are meant to replace defaults.

            # A slightly better merge:
            command_parts = [nmap_exe]
            # Add unique options from defaults and custom_options, custom taking precedence for conflicting *types* if parsed
            # For now, just combine and let Nmap handle/error on bad combinations.
            combined_opts = default_opts + custom_options

            # Remove duplicates by converting to a set and back (order might change for non-essential flags)
            # More controlled merging would be needed for complex option overrides.
            # command_parts.extend(list(set(combined_opts)))
            # For now, simple concatenation is likely fine as Nmap handles repeated compatible flags.
            command_parts.extend(combined_opts)

            command_parts.extend([target_host, "-oN", output_file])

            final_command = [item for item in command_parts if item] # Remove empty strings if any

            logger.info(f"(ExternalToolScanner) Executing Nmap command: {' '.join(final_command)}")
            result = subprocess.run(final_command, capture_output=True, text=True, check=False, timeout=600)

            if result.returncode == 0:
                logger.info(f"[+] (ExternalToolScanner) Nmap scan completed for: {target_host}. Output saved to {output_file}")
                open_ports_services = []
                for line in result.stdout.splitlines():
                    if "/tcp" in line and "open" in line: # Basic parsing
                        parts = line.split()
                        port_protocol = parts[0]
                        service = parts[2] if len(parts) > 2 else "unknown"
                        open_ports_services.append(f"{port_protocol} ({service})")
                if open_ports_services:
                    self.add_finding_callback("Nmap Scan Info", target_host, f"Open ports/services: {', '.join(open_ports_services)}. Full report: {output_file}", severity="Info")
                else:
                     logger.info(f"[-] (ExternalToolScanner) Nmap scan for {target_host} found no open ports matching filter or scan was empty.")
            else:
                logger.warning(f"[-] (ExternalToolScanner) Nmap scan for {target_host} finished with return code {result.returncode}.")
                logger.debug(f"(ExternalToolScanner) Nmap stdout for {target_host}:\n{result.stdout}")
                logger.debug(f"(ExternalToolScanner) Nmap stderr for {target_host}:\n{result.stderr}")

        except subprocess.TimeoutExpired:
            logger.error(f"(ExternalToolScanner) Nmap scan timed out for {target_host}.")
            self.add_finding_callback("Tool Execution Issue", target_host, f"Nmap scan timed out. Report (if any): {output_file}", severity="Info")
        except FileNotFoundError:
            logger.error(f"(ExternalToolScanner) {nmap_exe} command not found. Please ensure it's installed and in your PATH or configured in tool_paths.")
            self.add_finding_callback("Tool Configuration Error", target_host, f"{nmap_exe} command not found.", severity="Warning")
        except Exception as e:
            logger.error(f"(ExternalToolScanner) Unexpected error running Nmap on {target_host}: {e}")
            self.add_finding_callback("Tool Execution Issue", target_host, f"Error running Nmap: {e}. Report (if any): {output_file}", severity="Info")

    def run_subfinder(self, target_domain, custom_options=None):
        logger.info(f"[*] (ExternalToolScanner) Attempting to run Subfinder on: {target_domain}")
        if custom_options is None:
            custom_options = []

        subfinder_exe = self._get_tool_path("subfinder")
        output_file = os.path.join("./logs/subfinder", f"{target_domain}_subdomains.txt")

        try:
            # Subfinder: subfinder -d <domain> <custom_opts> -o <output_file>
            command = [subfinder_exe, "-d", target_domain] + custom_options + ["-o", output_file]

            logger.info(f"(ExternalToolScanner) Executing Subfinder command: {' '.join(command)}")
            result = subprocess.run(command, capture_output=True, text=True, check=False, timeout=300)

            if result.returncode == 0:
                logger.info(f"[+] (ExternalToolScanner) Subfinder scan completed for: {target_domain}. Output saved to {output_file}")
                subdomains_found = []
                if os.path.exists(output_file):
                    with open(output_file, 'r') as f:
                        subdomains_found = [line.strip() for line in f if line.strip()]

                if subdomains_found:
                    self.add_finding_callback("Subdomain Enumeration (Subfinder)", target_domain, f"Found {len(subdomains_found)} subdomains. List in {output_file}", severity="Info")
                else: # Successful run but no subdomains found
                    logger.info(f"[-] (ExternalToolScanner) Subfinder found no subdomains for {target_domain} (output file might be empty or tool reported none).")
            else: # Non-zero return code
                # Check stderr for common "no subdomains" messages if not using -silent
                if "no subdomains found" in result.stderr.lower() or (result.stdout and "no subdomains found" in result.stdout.lower()):
                     logger.info(f"[-] (ExternalToolScanner) Subfinder reported no subdomains for {target_domain} (via stderr/stdout).")
                else: # Other error
                    logger.warning(f"[-] (ExternalToolScanner) Subfinder for {target_domain} finished with return code {result.returncode}.")
                    logger.debug(f"(ExternalToolScanner) Subfinder stdout for {target_domain}:\n{result.stdout}")
                    logger.debug(f"(ExternalToolScanner) Subfinder stderr for {target_domain}:\n{result.stderr}")

        except subprocess.TimeoutExpired:
            logger.error(f"(ExternalToolScanner) Subfinder scan timed out for {target_domain}.")
            self.add_finding_callback("Tool Execution Issue", target_domain, f"Subfinder scan timed out. Report (if any): {output_file}", severity="Info")
        except FileNotFoundError:
            logger.error(f"(ExternalToolScanner) {subfinder_exe} command not found. Please ensure it's installed and in your PATH or configured in tool_paths.")
            self.add_finding_callback("Tool Configuration Error", target_domain, f"{subfinder_exe} command not found.", severity="Warning")
        except Exception as e:
            logger.error(f"(ExternalToolScanner) Unexpected error running Subfinder on {target_domain}: {e}")
            self.add_finding_callback("Tool Execution Issue", target_domain, f"Error running Subfinder: {e}. Report (if any): {output_file}", severity="Info")

    def run_nuclei(self, target_url, custom_options=None):
        target_host = urlparse(target_url).netloc
        logger.info(f"[*] (ExternalToolScanner) Attempting to run Nuclei on: {target_url}")
        if custom_options is None:
            custom_options = []

        nuclei_exe = self._get_tool_path("nuclei")
        # Sanitize target_host for filename (e.g. if it contained port)
        safe_target_host_fn = target_host.replace(':','_') if target_host else "unknown_host"
        output_file = os.path.join("./logs/nuclei", f"{safe_target_host_fn}_nuclei_report.json")

        try:
            default_opts = ["-severity", "critical,high,medium"] # Sensible default severity filter
            # Nuclei: nuclei <custom_opts> -u <target_url> -json -o <output_file>
            # Custom options should come before -u for some, after for others (like -t)
            # For simplicity, prepending custom options to a base set of output + target flags.
            command = [nuclei_exe] + custom_options + ["-u", target_url, "-json", "-o", output_file]
            # A simple way to ensure critical flags like -json, -o are present and last if not in custom_options
            # This needs a more robust CLI construction if complex overrides are needed.
            # For now, the above simple concatenation should work for many cases.
            # Ensure no duplicate -o or -json if user provides them in custom_options. This simple model doesn't handle that.

            logger.info(f"(ExternalToolScanner) Executing Nuclei command: {' '.join(command)}")
            result = subprocess.run(command, capture_output=True, text=True, check=False, timeout=900)

            if result.returncode == 0:
                logger.info(f"[+] (ExternalToolScanner) Nuclei scan completed for: {target_url}. Output saved to {output_file}")
                findings_count = 0
                if os.path.exists(output_file):
                    with open(output_file, 'r', encoding='utf-8', errors='ignore') as f_out:
                        content = f_out.read().strip()
                        if len(content) > 2:
                            findings_count = len(content.splitlines())

                if findings_count > 0:
                    self.add_finding_callback("Vulnerability Scan (Nuclei)", target_url, f"Nuclei found {findings_count} potential issues. Report: {output_file}", severity="Medium")
                else:
                    logger.info(f"[-] (ExternalToolScanner) Nuclei scan for {target_url} reported no issues or output file is empty.")
            else: # Non-zero return code might still have findings or indicate errors
                logger.warning(f"[-] (ExternalToolScanner) Nuclei for {target_url} finished with return code {result.returncode}.")
                logger.debug(f"(ExternalToolScanner) Nuclei stdout for {target_url}:\n{result.stdout}")
                logger.debug(f"(ExternalToolScanner) Nuclei stderr for {target_url}:\n{result.stderr}")
                # Check if output file still has content
                if os.path.exists(output_file) and os.path.getsize(output_file) > 2: # Greater than empty JSON list "[]"
                     self.add_finding_callback("Vulnerability Scan (Nuclei - Check Logs)", target_url, f"Nuclei exited with code {result.returncode} but an output file was generated. Review {output_file} and stderr.", severity="Info")


        except subprocess.TimeoutExpired:
            logger.error(f"(ExternalToolScanner) Nuclei scan timed out for {target_url}.")
            self.add_finding_callback("Tool Execution Issue", target_url, f"Nuclei scan timed out. Report (if any): {output_file}", severity="Info")
        except FileNotFoundError:
            logger.error(f"(ExternalToolScanner) {nuclei_exe} command not found. Please ensure it's installed and in your PATH or configured in tool_paths.")
            self.add_finding_callback("Tool Configuration Error", target_url, f"{nuclei_exe} command not found.", severity="Warning")
        except Exception as e:
            logger.error(f"(ExternalToolScanner) Unexpected error running Nuclei on {target_url}: {e}")
            self.add_finding_callback("Tool Execution Issue", target_url, f"Error running Nuclei: {e}. Report (if any): {output_file}", severity="Info")


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)

    def example_add_finding(vulnerability_type, url, details, severity):
        print(f"[+] FOUND: {vulnerability_type} at {url} - {details} ({severity})")

    # Create dummy log dirs for standalone test
    # This is now handled in __init__ but good for standalone test if needed
    for log_dir in ['./logs/sqlmap', './logs/xsser', './logs/nmap', './logs/nuclei', './logs/subfinder']:
        if not os.path.exists(log_dir): os.makedirs(log_dir)

    # Example tool_paths for testing if tools are not in default PATH
    example_tool_paths = {
        # "sqlmap": "/opt/sqlmap/sqlmap.py",
        # "nmap": "/usr/local/bin/nmap"
    }
    ext_scanner = ExternalToolScanner(add_finding_callback=example_add_finding, tool_paths=example_tool_paths)

    test_domain = "scanme.nmap.org"
    test_url_for_tools = "http://scanme.nmap.org"

    # logger.info(f"Testing Nmap on {test_domain}")
    # ext_scanner.run_nmap(test_domain) # Uses default options in scanner
    # ext_scanner.run_nmap(test_domain, custom_options=["-F", "--top-ports", "20"]) # Fast scan, top 20

    # logger.info(f"Testing Subfinder on {test_domain}")
    # ext_scanner.run_subfinder(test_domain, custom_options=["-silent"])

    # logger.info(f"Testing Nuclei on {test_url_for_tools}")
    # ext_scanner.run_nuclei(test_url_for_tools, custom_options=["-tags", "tech,misc"]) # Test specific tags

    # logger.info(f"Testing SQLmap on a specific path (example only, use vulnerable target)")
    # ext_scanner.run_sqlmap("http://testphp.vulnweb.com/listproducts.php?cat=1", custom_options=["--dbms=mysql"])

    logger.info("External tool scanner module example run finished.")
    pass
