#!/usr/bin/env python3
"""
Request Handler module for the SQL Injection Fuzzer
"""

import time
import requests
from requests.exceptions import RequestException, Timeout


class RequestHandler:
    def __init__(self, user_agent=None, cookies=None):
        self.session = requests.Session()

        # Set user agent
        if user_agent:
            self.session.headers.update({'User-Agent': user_agent})
        else:
            self.session.headers.update({'User-Agent': 'SQLFuzzer/1.0'})

        # Set cookies
        if cookies:
            if isinstance(cookies, str):
                # Parse cookie string (format: name1=value1; name2=value2)
                cookie_dict = {}
                for cookie in cookies.split(';'):
                    if '=' in cookie:
                        name, value = cookie.strip().split('=', 1)
                        cookie_dict[name] = value
                self.session.cookies.update(cookie_dict)
            elif isinstance(cookies, dict):
                self.session.cookies.update(cookies)

    def send_request(self, url, method='GET', data=None, headers=None):
        """
        Send an HTTP request to the target URL

        Args:
            url (str): Target URL
            method (str, optional): HTTP method (GET or POST)
            data (dict, optional): Form data for POST requests
            headers (dict, optional): Additional headers

        Returns:
            tuple: (response object, request time in seconds) or (None, None) on error
        """
        try:
            start_time = time.time()

            if method.upper() == 'GET':
                response = self.session.get(
                    url,
                    headers=headers
                )
            elif method.upper() == 'POST':
                response = self.session.post(
                    url,
                    data=data,
                    headers=headers
                )
            else:
                print(f"[!] Unsupported HTTP method: {method}")
                return None, None

            request_time = time.time() - start_time

            return response, request_time

        except Timeout:
            print(f"[!] Request timed out: {url}")
            return None, 5  # Default timeout value for time-based detection
        except RequestException as e:
            print(f"[!] Request error: {e}")
            return None, None
        except Exception as e:
            print(f"[!] Unexpected error: {e}")
            return None, None

    def get_baseline_response(self, url, method='GET', data=None, headers=None):
        """
        Get a baseline response for the target URL
        This is useful for boolean-based detection

        Args:
            url (str): Target URL
            method (str, optional): HTTP method (GET or POST)
            data (dict, optional): Form data for POST requests
            headers (dict, optional): Additional headers

        Returns:
            requests.Response: Baseline response
        """
        response, _ = self.send_request(url, method, data, headers)
        return response

    def check_connection(self, url):
        """
        Check if the target is reachable

        Args:
            url (str): Target URL

        Returns:
            bool: True if target is reachable, False otherwise
        """
        try:
            response = self.send_request(url)
            return response is not None and response.status_code < 500
        except Exception:
            return False
