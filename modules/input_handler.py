#!/usr/bin/env python3
"""
Input Handler module for SQLFuzzer
"""

from urllib.parse import urlparse


class InputHandler:
    def __init__(self):
        """Initialize the input handler"""
        pass

    def validate_url(self, url):
        """
        Validate the provided URL

        Args:
            url (str): URL to validate

        Returns:
            bool: True if URL is valid, False otherwise
        """
        try:
            parsed = urlparse(url)
            if not all([parsed.scheme, parsed.netloc]):
                print(
                    "[!] Error: Invalid URL format. Please use format: http(s)://example.com/path?param=value")
                return False
            return True
        except Exception as e:
            print(f"[!] Error parsing URL: {e}")
            return False

    def validate_post_data(self, method, post_data):
        """
        Validate POST data if method is POST

        Args:
            method (str): HTTP method (GET or POST)
            post_data (str): POST data to validate

        Returns:
            bool: True if POST data is valid or not needed, False otherwise
        """
        if method.upper() == 'POST' and not post_data:
            print("[!] Error: POST method requires data. Use -d/--data parameter.")
            return False
        return True

    def parse_arguments(self):
        """
        Parse command line arguments

        Returns:
            argparse.Namespace: Parsed arguments
        """
        import argparse

        parser = argparse.ArgumentParser(
            description="SQLFuzzer - A MySQL SQL Injection fuzzing tool")

        parser.add_argument("-u", "--url", required=True,
                            help="Target URL (e.g., http://example.com/page.php?id=1)")
        parser.add_argument("-m", "--method", default="GET", choices=["GET", "POST"],
                            help="HTTP method (GET or POST, default: GET)")
        parser.add_argument("-d", "--post-data",
                            help="POST data (e.g., 'id=1&name=test' or '{\"id\":1}')")
        parser.add_argument("-dt", "--data-type", choices=["form", "json"], default="form",
                            help="POST data type (form or json, default: form)")
        parser.add_argument("-v", "--verbose", action="store_true",
                            help="Verbose output")
        parser.add_argument("-o", "--output",
                            help="Save results to file")
        parser.add_argument("-a", "--user-agent", default="SQLFuzzer/1.0",
                            help="Custom User-Agent (default: SQLFuzzer/1.0)")
        parser.add_argument("-c", "--cookies",
                            help="Cookies to include with HTTP requests")
        parser.add_argument("-mp", "--max-payloads", type=int,
                            help="Maximum number of payloads to test")
        parser.add_argument("-T", "--technique", choices=["error", "boolean", "time", "union"],
                            help="Specific SQL injection technique to test")

        return parser.parse_args()
