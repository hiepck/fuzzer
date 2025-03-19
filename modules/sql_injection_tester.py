#!/usr/bin/env python3
"""
SQL Injection Tester module for SQLFuzzer
"""


class SQLInjectionTester:
    def __init__(self, url_parser, request_handler, response_analyzer, payload_generator, verbose=False):
        self.url_parser = url_parser
        self.request_handler = request_handler
        self.response_analyzer = response_analyzer
        self.payload_generator = payload_generator
        self.verbose = verbose
        self.vulnerabilities = []

    def get_baseline_responses(self, params_info, url, method='GET', post_data=None, data_type='form'):
        """
        Get baseline responses for each parameter for boolean-based detection

        Args:
            params_info (dict): Dictionary containing parameters information
            url (str): Target URL
            method (str): HTTP method
            post_data (str): POST data (if applicable)
            data_type (str): POST data type (if applicable)
        """
        print("[*] Gathering baseline responses for parameters...")

        for param_name in params_info['parameters']:
            original_value = params_info['parameters'][param_name]

            if method.upper() == 'GET':
                baseline_url = self.url_parser.inject_payload(
                    url, param_name, original_value)
                baseline_response = self.request_handler.get_baseline_response(
                    baseline_url)
            else:  # POST
                # For POST, the base URL remains the same, but we modify the data
                baseline_data = self.url_parser.inject_payload_to_post_data(
                    post_data, param_name, original_value, data_type)
                baseline_response = self.request_handler.get_baseline_response(
                    url, method='POST', data=baseline_data)

            if baseline_response:
                self.response_analyzer.set_baseline(
                    param_name, baseline_response)

    def prepare_payloads(self, technique=None):
        """
        Prepare payloads based on selected technique

        Args:
            technique (str, optional): Specific technique to test

        Returns:
            dict or list: Prepared payloads
        """
        if technique == 'error':
            payloads = self.payload_generator.generate_error_based_payloads()
            print(
                f"[*] Loaded {len(payloads)} error-based SQL injection payloads")
            return payloads
        elif technique == 'boolean':
            payloads = self.payload_generator.generate_boolean_based_payloads()
            print(
                f"[*] Loaded {len(payloads)} boolean-based SQL injection payloads")
            return payloads
        elif technique == 'time':
            payloads = self.payload_generator.generate_time_based_payloads()
            print(
                f"[*] Loaded {len(payloads)} time-based SQL injection payloads")
            return payloads
        elif technique == 'union':
            payloads = self.payload_generator.generate_union_based_payloads()
            print(
                f"[*] Loaded {len(payloads)} union-based SQL injection payloads")
            return payloads
        else:
            # Use all payloads but organize them by type for efficient testing
            payloads = {
                'error': self.payload_generator.generate_error_based_payloads(),
                'boolean': self.payload_generator.generate_boolean_based_payloads(),
                'time': self.payload_generator.generate_time_based_payloads(),
                'union': self.payload_generator.generate_union_based_payloads()
            }
            total_payloads = sum(len(p) for p in payloads.values())
            print(f"[*] Loaded {total_payloads} SQL injection payloads")
            return payloads

    def test_parameters(self, params_info, payloads, url, method='GET', post_data=None, data_type='form', technique=None):
        """
        Test each parameter with appropriate payloads

        Args:
            params_info (dict): Dictionary containing parameters information
            payloads (dict or list): Payloads to test
            url (str): Target URL
            method (str): HTTP method
            post_data (str): POST data (if applicable)
            data_type (str): POST data type (if applicable)
            technique (str): Specific technique to test
        """
        for param_name in params_info['parameters']:
            print(f"\n[*] Testing parameter: {param_name}")

            # If specific technique is selected, test only that
            if technique:
                if self._test_parameter_with_payloads(param_name, payloads, url, method, post_data, data_type):
                    break
            else:
                # Test each technique in order of efficiency
                for tech in ['error', 'boolean', 'union', 'time']:
                    print(f"[*] Trying {tech}-based injection...")
                    if self._test_parameter_with_payloads(param_name, payloads[tech], url, method, post_data, data_type):
                        break

                # If vulnerability found in current parameter, check if we need to continue
                if self.vulnerabilities and self._has_vulnerability_for_param(param_name):
                    if len(set(v['parameter'] for v in self.vulnerabilities)) >= len(params_info['parameters']):
                        print(
                            "[*] Found vulnerabilities in all parameters. Stopping tests.")
                        break

    def _has_vulnerability_for_param(self, param_name):
        """
        Check if a vulnerability was found for a specific parameter

        Args:
            param_name (str): Parameter name to check

        Returns:
            bool: True if vulnerability was found, False otherwise
        """
        return any(v['parameter'] == param_name for v in self.vulnerabilities)

    def _test_parameter_with_payloads(self, param_name, payloads, url, method='GET', post_data=None, data_type='form'):
        """
        Test a parameter with a list of payloads

        Args:
            param_name (str): Parameter name to test
            payloads (list): List of payloads to try
            url (str): Target URL
            method (str): HTTP method
            post_data (str): POST data (if applicable)
            data_type (str): POST data type (if applicable)

        Returns:
            bool: True if vulnerability found, False otherwise
        """
        if not payloads:
            return False

        total_payloads = len(payloads)
        for i, payload in enumerate(payloads, 1):
            if self.verbose:
                print(f"[*] Testing payload {i}/{total_payloads}: {payload}")

            if method.upper() == 'GET':
                # Create test URL with injected payload
                test_url = self.url_parser.inject_payload(
                    url, param_name, payload)
                # Send request and measure time
                response, request_time = self.request_handler.send_request(
                    test_url)
                display_url = test_url
            else:  # POST
                # Inject payload into POST data
                test_data = self.url_parser.inject_payload_to_post_data(
                    post_data, param_name, payload, data_type)
                # Send POST request
                response, request_time = self.request_handler.send_request(
                    url, method='POST', data=test_data)
                display_url = f"{url} (POST: {param_name}={payload})"

            if not response:
                continue

            # Analyze response
            result = self.response_analyzer.analyze(
                response, payload, request_time)
            if result['vulnerable']:
                self._record_vulnerability(
                    param_name, payload, display_url, result)
                return True

        return False

    def _record_vulnerability(self, param_name, payload, test_url, result):
        """
        Record a found vulnerability

        Args:
            param_name (str): Vulnerable parameter name
            payload (str): Successful payload
            test_url (str): URL or representation of the request
            result (dict): Analysis result
        """
        vuln = {
            'parameter': param_name,
            'payload': payload,
            'url': test_url,
            'details': result['details'],
            'type': result.get('type', 'unknown')
        }
        self.vulnerabilities.append(vuln)
        print(f"[+] SQL injection ({vuln['type']}) found!")
        print(f"    Parameter: {param_name}")
        print(f"    Payload: {payload}")
        print(f"    URL: {test_url}")
        print(f"    Details: {result['details']}")
        print(
            f"[+] Vulnerability found in parameter '{param_name}'. Stopping tests for this parameter.")

    def print_summary(self, output_file=None):
        """
        Print summary of found vulnerabilities

        Args:
            output_file (str, optional): Path to output file
        """
        if self.vulnerabilities:
            print(
                f"\n[+] Found {len(self.vulnerabilities)} SQL injection vulnerabilities")

            # Print vulnerabilities by type
            vuln_types = {}
            for vuln in self.vulnerabilities:
                vuln_type = vuln.get('type', 'unknown')
                if vuln_type not in vuln_types:
                    vuln_types[vuln_type] = 0
                vuln_types[vuln_type] += 1

            print("\n[*] Vulnerabilities by type:")
            for vuln_type, count in vuln_types.items():
                print(f"    {vuln_type}: {count}")

            if output_file:
                self._save_results(output_file)
        else:
            print("\n[-] No SQL injection vulnerabilities found")

    def _save_results(self, output_file):
        """
        Save results to output file

        Args:
            output_file (str): Path to output file
        """
        import datetime
        try:
            with open(output_file, 'w') as f:
                f.write(f"SQL Injection Fuzzing Results\n")
                f.write(
                    f"Date: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")

                for i, vuln in enumerate(self.vulnerabilities, 1):
                    f.write(f"Vulnerability #{i}:\n")
                    f.write(f"  Type: {vuln.get('type', 'unknown')}\n")
                    f.write(f"  Parameter: {vuln['parameter']}\n")
                    f.write(f"  Payload: {vuln['payload']}\n")
                    f.write(f"  URL: {vuln['url']}\n")
                    f.write(f"  Details: {vuln['details']}\n\n")

            print(f"[*] Results saved to {output_file}")
        except Exception as e:
            print(f"[!] Error saving results: {e}")
