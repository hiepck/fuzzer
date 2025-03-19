#!/usr/bin/env python3
"""
Response Analyzer module for the SQL Injection Fuzzer
"""

import re
import time


class ResponseAnalyzer:
    def __init__(self, verbose=False):
        self.verbose = verbose
        self.baseline_responses = {}

        # Initialize patterns for common SQL error messages (MySQL specific)
        self._init_patterns()

    def _init_patterns(self):
        """Initialize regex patterns for SQL error detection"""

        # MySQL error patterns
        self.mysql_error_patterns = [
            r"SQL syntax.*MySQL",
            r"Warning.*mysql_.*",
            r"valid MySQL result",
            r"MySqlClient\.",
            r"MySQL Query fail.*",
            r"SQL syntax.*MariaDB server",
            r"Unknown column '[^']+' in 'field list'",
            r"MySqlClient\.",
            r"com\.mysql\.jdbc\.exceptions",
            r"Unclosed quotation mark after the character string",
            r"Syntax error or access violation:",
            r"mysql_fetch_array\(\)",
            r"YOU HAVE AN ERROR IN YOUR SQL SYNTAX",
            r"DATABASE\.MYSQL\.DRIVER",
            r"supplied argument is not a valid MySQL",
            r"javax\.el\.ELException: The identifier \[mysql\]"
        ]

        # Generic database error patterns
        self.generic_error_patterns = [
            r"DB Error",
            r"SQL Error",
            r"SQL syntax.*",
            r"Warning.*SQL.*",
            r"Warning.*syntax.*",
            r"Warning.*for user '.*'",
            r"ORA-[0-9][0-9][0-9][0-9]",
            r"Microsoft OLE DB Provider for SQL Server error",
            r"ODBC.*Driver",
            r"Error.*\bODBC\b.*Driver",
            r"Exception.*java\.sql\.SQLException",
            r"Unclosed quotation mark after the character string",
            r"quoted string not properly terminated",
            r"Syntax error.*in query expression",
            r"Data type mismatch"
        ]

        # Union select patterns (for detecting successful UNION-based injections)
        self.union_select_patterns = [
            r"\b\d+\b\s*,\s*\b\d+\b",           # For simple numeric columns like "1, 2, 3"
            r"[0-9]+ rows in set",              # MySQL rows message
            r"appears more than once in the SELECT list",
        ]

        # Error-based extraction patterns from payloads.py
        self.error_extraction_patterns = [
            r"XPATH syntax error: '~([^~]+)~'",
            r"Duplicate entry '([^']+)' for key",
            r"BIGINT UNSIGNED value is out of range.*'~([^~]+)~'",
            r"Injected~\(([^)]+)\)~END",
            r"XPATH syntax error: '\(~([^~]+)~\)'",
            r"Duplicate entry '\(~([^~]+)~\)' for key"
        ]

    def analyze(self, response, payload, request_time=None):
        """
        Analyze response to detect potential SQL injection vulnerabilities

        Args:
            response (requests.Response): HTTP response object
            payload (str): The SQL injection payload that was used
            request_time (float, optional): Time taken for the request (for time-based detection)

        Returns:
            dict: Analysis result containing vulnerability status and details
        """
        result = {
            'vulnerable': False,
            'details': '',
            'type': None
        }

        # Check if response is valid
        if not response or not hasattr(response, 'text'):
            return result

        # Store original response info
        status_code = response.status_code
        response_text = response.text
        content_length = len(response_text)

        # 1. Check for error-based injection
        if self._check_sql_errors(response_text):
            result['vulnerable'] = True
            result['type'] = 'error-based'
            result['details'] = 'SQL error detected in response'

            # Try to extract data from error messages (more advanced)
            extracted_data = self._extract_data_from_errors(response_text)
            if extracted_data:
                result['details'] += f". Extracted data: {extracted_data}"

            return result

        # 2. Check for UNION-based injections
        if 'UNION SELECT' in payload.upper() and self._check_union_select(response_text):
            result['vulnerable'] = True
            result['type'] = 'union-based'
            result['details'] = 'Possible UNION SELECT injection detected'
            return result

        # 3. Check for time-based injections
        if ('SLEEP' in payload.upper() or 'BENCHMARK' in payload.upper() or 'DELAY' in payload.upper()) and request_time:
            # Check if the request took significantly longer than usual
            sleep_time = 0
            if "SLEEP(" in payload.upper():
                sleep_match = re.search(
                    r"SLEEP\((\d+)\)", payload, re.IGNORECASE)
                if sleep_match:
                    sleep_time = int(sleep_match.group(1))
            elif "BENCHMARK" in payload.upper():
                # For BENCHMARK, we'll just check if it took longer than 2 seconds
                sleep_time = 2

            if sleep_time > 0 and request_time > sleep_time * 0.8:
                result['vulnerable'] = True
                result['type'] = 'time-based'
                result['details'] = f'Time-based injection detected. Request took {request_time:.2f}s'
                return result

        # 4. Store parameter baseline for boolean-based detection
        param_name = self._extract_param_from_payload(payload)
        if param_name and param_name not in self.baseline_responses:
            self.baseline_responses[param_name] = {
                'content_length': content_length,
                'status_code': status_code,
                # Use part of response to avoid memory issues
                'response_text_hash': hash(response_text[:1000])
            }

        # 5. Check for boolean-based injections
        if param_name and param_name in self.baseline_responses:
            boolean_patterns = ["AND 1=1", "OR 1=1", "AND 1=0", "OR 1=0"]

            # Check if this is a boolean test
            is_boolean_test = False
            for pattern in boolean_patterns:
                if pattern in payload.upper():
                    is_boolean_test = True
                    break

            if is_boolean_test:
                baseline = self.baseline_responses[param_name]

                # Check for significant differences based on the logical condition
                condition_true = "1=1" in payload
                condition_false = "1=0" in payload

                # For true conditions with AND, or false conditions with OR, response should be similar to baseline
                # For false conditions with AND, or true conditions with OR, response should differ from baseline
                expected_different = (condition_false and "AND" in payload) or (
                    condition_true and "OR" in payload)

                # Compare with baseline
                content_diff = abs(content_length - baseline['content_length'])
                status_changed = status_code != baseline['status_code']
                response_hash_different = hash(
                    response_text[:1000]) != baseline['response_text_hash']

                is_different = (
                    content_diff > 20) or status_changed or response_hash_different

                # If the actual difference matches our expectation based on the logical condition
                if is_different == expected_different:
                    result['vulnerable'] = True
                    result['type'] = 'boolean-based'
                    result['details'] = 'Boolean-based injection detected. '

                    if content_diff > 20:
                        result['details'] += f'Content length difference: {content_diff} bytes. '
                    if status_changed:
                        result['details'] += f'Status code changed: {baseline["status_code"]} -> {status_code}. '

                    return result

        return result

    def _extract_param_from_payload(self, payload):
        """Try to extract the parameter name from the payload context"""
        # This is a simplified approach - in a real tool, we'd need to track which parameter each payload was applied to
        return None  # The actual implementation would depend on how payloads are tracked with parameters

    def _extract_data_from_errors(self, response_text):
        """
        Extract data leaked in error messages

        Args:
            response_text (str): Response body text

        Returns:
            str: Extracted data or None
        """
        for pattern in self.error_extraction_patterns:
            match = re.search(pattern, response_text, re.IGNORECASE)
            if match:
                return match.group(1)
        return None

    def _check_sql_errors(self, response_text):
        """
        Check for SQL error messages in response

        Args:
            response_text (str): Response body text

        Returns:
            bool: True if SQL errors detected, False otherwise
        """
        # Check MySQL specific errors
        for pattern in self.mysql_error_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                return True

        # Check generic SQL errors
        for pattern in self.generic_error_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                return True

        return False

    def _check_union_select(self, response_text):
        """
        Check for successful UNION SELECT injection markers

        Args:
            response_text (str): Response body text

        Returns:
            bool: True if UNION SELECT markers detected, False otherwise
        """
        for pattern in self.union_select_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                return True

        return False

    def compare_responses(self, baseline_response, test_response):
        """
        Compare two responses to detect differences that might indicate a vulnerability

        Args:
            baseline_response (requests.Response): Baseline response (original request)
            test_response (requests.Response): Test response (with payload)

        Returns:
            dict: Comparison results
        """
        if not baseline_response or not test_response:
            return {'different': False, 'details': 'Invalid responses for comparison'}

        comparison = {
            'different': False,
            'status_code_changed': False,
            'content_length_diff': 0,
            'details': ''
        }

        # Compare status codes
        if baseline_response.status_code != test_response.status_code:
            comparison['different'] = True
            comparison['status_code_changed'] = True
            comparison['details'] += f"Status code changed: {baseline_response.status_code} -> {test_response.status_code}. "

        # Compare content length
        baseline_length = len(baseline_response.text)
        test_length = len(test_response.text)
        comparison['content_length_diff'] = test_length - baseline_length

        # If content length differs significantly, flag it
        if abs(comparison['content_length_diff']) > 50:
            comparison['different'] = True
            comparison['details'] += f"Content length difference: {comparison['content_length_diff']} characters. "

        # If no specific details were added but differences were detected
        if comparison['different'] and not comparison['details']:
            comparison['details'] = "Responses differ but no specific details identified."

        return comparison

    def set_baseline(self, param_name, response):
        """
        Set a baseline response for a parameter for boolean-based detection

        Args:
            param_name (str): Parameter name
            response (requests.Response): Baseline response
        """
        if not response or not hasattr(response, 'text'):
            return

        self.baseline_responses[param_name] = {
            'content_length': len(response.text),
            'status_code': response.status_code,
            'response_text_hash': hash(response.text[:1000])
        }
