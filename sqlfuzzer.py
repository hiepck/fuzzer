#!/usr/bin/env python3
"""
SQLFuzzer - A MySQL SQL Injection fuzzing tool
"""

import sys
from modules.url_parser import URLParser
from modules.payload_generator import PayloadGenerator
from modules.request_handler import RequestHandler
from modules.response_analyzer import ResponseAnalyzer
from modules.sql_injection_tester import SQLInjectionTester
from modules.input_handler import InputHandler


class SQLFuzzer:
    def __init__(self):
        # Initialize input handler
        self.input_handler = InputHandler()
        # Parse command line arguments
        self.args = self.input_handler.parse_arguments()

        # Initialize modules
        self.url_parser = URLParser()
        self.payload_generator = PayloadGenerator()
        self.request_handler = RequestHandler(
            user_agent=self.args.user_agent,
            cookies=self.args.cookies
        )
        self.response_analyzer = ResponseAnalyzer(verbose=self.args.verbose)

        # Initialize SQL injection tester
        self.sql_injection_tester = SQLInjectionTester(
            self.url_parser,
            self.request_handler,
            self.response_analyzer,
            self.payload_generator,
            verbose=self.args.verbose
        )

    def run(self):
        """Main execution flow of the fuzzer"""
        # Validate inputs
        if not self.input_handler.validate_url(self.args.url):
            return False

        if not self.input_handler.validate_post_data(self.args.method, self.args.post_data):
            return False

        # Display information about the test
        print(f"[*] Starting SQL injection fuzzing on: {self.args.url}")
        print(f"[*] Method: {self.args.method}")

        if self.args.method.upper() == 'POST':
            print(f"[*] POST data type: {self.args.data_type}")

        if self.args.technique:
            print(f"[*] Testing technique: {self.args.technique}")

        # Parse URL or POST data to extract parameters
        if self.args.method.upper() == 'GET':
            params_info = self.url_parser.parse(self.args.url)
            if not params_info['parameters']:
                print(
                    "[!] No parameters found in the URL. SQL injection testing requires parameters.")
                return False
        else:  # POST
            params_info = {
                'parameters': self.url_parser.parse_post_data(self.args.post_data)}
            if not params_info['parameters']:
                print(
                    "[!] No parameters found in the POST data. SQL injection testing requires parameters.")
                return False

        print(
            f"[*] Found {len(params_info['parameters'])} parameter(s) to test")

        # Get baseline responses for boolean-based detection
        self.sql_injection_tester.get_baseline_responses(
            params_info,
            self.args.url,
            self.args.method,
            self.args.post_data,
            self.args.data_type
        )

        # Prepare payloads based on selected technique
        payloads = self.sql_injection_tester.prepare_payloads(
            self.args.technique)

        # Test each parameter with appropriate payloads
        self.sql_injection_tester.test_parameters(
            params_info,
            payloads,
            self.args.url,
            self.args.method,
            self.args.post_data,
            self.args.data_type,
            self.args.technique
        )

        # Print summary of results
        self.sql_injection_tester.print_summary(self.args.output)

        return True


def main():
    try:
        fuzzer = SQLFuzzer()
        fuzzer.run()
    except KeyboardInterrupt:
        print("\n[!] User interrupted the process")
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] An error occurred: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
