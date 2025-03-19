#!/usr/bin/env python3
"""
URL Parser module for the SQL Injection Fuzzer
"""

from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import json


class URLParser:
    def parse(self, url):
        """
        Parse a URL and extract its components and parameters

        Args:
            url (str): The URL to parse

        Returns:
            dict: A dictionary containing URL components and parameters
        """
        result = {
            'original_url': url,
            'parameters': {}
        }

        try:
            # Parse URL components
            parsed_url = urlparse(url)

            # Parse query parameters
            if parsed_url.query:
                query_params = parse_qs(parsed_url.query)
                # Convert values from lists to single values
                for param, values in query_params.items():
                    result['parameters'][param] = values[0] if values else ''

        except Exception as e:
            print(f"[!] Error parsing URL: {e}")

        return result

    def parse_post_data(self, data):
        """
        Parse POST data and extract parameters

        Args:
            data (str): POST data string or JSON string

        Returns:
            dict: A dictionary containing POST parameters
        """
        parameters = {}

        try:
            # Try to parse as JSON first
            if data.startswith('{') and data.endswith('}'):
                try:
                    json_data = json.loads(data)
                    return json_data
                except json.JSONDecodeError:
                    pass

            # Try to parse as form data (name1=value1&name2=value2)
            parts = data.split('&')
            for part in parts:
                if '=' in part:
                    name, value = part.split('=', 1)
                    parameters[name] = value

        except Exception as e:
            print(f"[!] Error parsing POST data: {e}")

        return parameters

    def inject_payload(self, url, param_name, payload):
        """
        Inject a payload into a specific parameter of a URL

        Args:
            url (str): The original URL
            param_name (str): The parameter to inject the payload into
            payload (str): The SQL injection payload

        Returns:
            str: The URL with the injected payload
        """
        try:
            # Parse the URL
            parsed_url = urlparse(url)

            # Get existing parameters
            query_params = parse_qs(parsed_url.query)

            # Make a copy of the parameters with single values
            params = {k: v[0] if v else '' for k, v in query_params.items()}

            # Replace the target parameter with the payload
            params[param_name] = payload

            # Rebuild the query string, preserving SQL special characters
            new_query = urlencode(params, safe="*()'-=")

            # Reconstruct the URL with the new query string
            url_parts = list(parsed_url)
            url_parts[4] = new_query

            return urlunparse(url_parts)

        except Exception as e:
            print(f"[!] Error injecting payload: {e}")
            return url

    def inject_payload_to_post_data(self, data, param_name, payload, format_type='form'):
        """
        Inject a payload into a specific parameter of POST data

        Args:
            data (str or dict): The original POST data
            param_name (str): The parameter to inject the payload into
            payload (str): The SQL injection payload
            format_type (str): 'form' or 'json'

        Returns:
            str or dict: The modified POST data with the injected payload
        """
        try:
            if isinstance(data, str):
                # Parse the data first
                if format_type == 'json':
                    try:
                        post_data = json.loads(data)
                    except json.JSONDecodeError:
                        post_data = self.parse_post_data(data)
                else:
                    post_data = self.parse_post_data(data)
            else:
                post_data = data.copy()  # Make a copy if it's already a dict

            # Inject the payload
            post_data[param_name] = payload

            # Return in the appropriate format
            if format_type == 'json':
                return json.dumps(post_data)
            else:
                # Convert dictionary to form data string
                return '&'.join([f"{k}={v}" for k, v in post_data.items()])

        except Exception as e:
            print(f"[!] Error injecting payload to POST data: {e}")
            return data

    def extract_base_url(self, url):
        """
        Extract the base URL (scheme + netloc + path) without query parameters

        Args:
            url (str): The URL to extract from

        Returns:
            str: The base URL
        """
        try:
            parsed_url = urlparse(url)
            url_parts = list(parsed_url)
            url_parts[4] = ''  # empty query string
            url_parts[5] = ''  # empty fragment

            return urlunparse(url_parts)

        except Exception as e:
            print(f"[!] Error extracting base URL: {e}")
            return url
