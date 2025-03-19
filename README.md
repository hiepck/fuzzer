# SQLFuzzer

A MySQL SQL injection fuzzing and detection tool, using advanced payloads from the `payloads.py` file.

This tool can detect various types of SQL injection vulnerabilities:

- Error-based SQL injection
- Boolean-based blind SQL injection
- Time-based blind SQL injection
- Union-based SQL injection

## Features

- Multiple SQL injection detection techniques
- Advanced payload generation based on MySQL specific syntax
- Support for both GET and POST requests
- JSON and form data support for POST requests
- Detection of different vulnerability types
- Detailed vulnerability reporting
- Ability to focus on specific SQL injection techniques
- Modular architecture for easy maintenance and extension

## Requirements

- Python 3.6+
- Required Python packages:
  - requests

## Installation

1. Clone the repository:

```
git clone https://github.com/yourusername/sqlfuzzer.git
cd sqlfuzzer
```

2. Install required packages:

```
pip install -r requirements.txt
```

## Project Structure

The tool has been organized into modules for better maintainability:

```
sqlfuzzer/
├── sqlfuzzer.py              # Main entry point
├── modules/
│   ├── __init__.py           # Package initialization
│   ├── input_handler.py      # Command-line argument handling
│   ├── payload_generator.py  # SQL injection payload generation
│   ├── payloads.py           # Raw SQL injection payloads
│   ├── request_handler.py    # HTTP request handling
│   ├── response_analyzer.py  # Response analysis
│   ├── sql_injection_tester.py # SQL injection testing logic
│   └── url_parser.py         # URL and parameter parsing
└── requirements.txt          # Package dependencies
```

## Usage

Basic GET request testing:

```
python sqlfuzzer.py -u "http://target.com/page.php?id=1"
```

Testing with POST request:

```
python sqlfuzzer.py -u "http://target.com/login.php" -m POST -d "username=admin&password=test"
```

Testing with JSON POST data:

```
python sqlfuzzer.py -u "http://api.target.com/users" -m POST -d '{"id":1,"name":"test"}' -dt json
```

Advanced usage:

```
python sqlfuzzer.py -u "http://target.com/page.php?id=1" -T error -o results.txt -v
```

### Command-line Options

```
  -h, --help            Show this help message and exit
  -u URL, --url URL     Target URL (e.g., http://example.com/page.php?id=1)
  -m METHOD, --method METHOD
                        HTTP method (GET or POST, default: GET)
  -d POST_DATA, --post-data POST_DATA
                        POST data (e.g., 'id=1&name=test' or '{"id":1}')
  -dt DATA_TYPE, --data-type DATA_TYPE
                        POST data type (form or json, default: form)
  -v, --verbose         Verbose output
  -o OUTPUT, --output OUTPUT
                        Save results to file
  -a USER_AGENT, --user-agent USER_AGENT
                        Custom User-Agent (default: SQLFuzzer/1.0)
  -c COOKIES, --cookies COOKIES
                        Cookies to include with HTTP requests
  -mp MAX_PAYLOADS, --max-payloads MAX_PAYLOADS
                        Maximum number of payloads to test
  -T TECHNIQUE, --technique TECHNIQUE
                        Specific SQL injection technique to test (error, boolean, time, union)
```

## SQL Injection Techniques

### Error-based

Tests for SQL injection vulnerabilities that produce database error messages. These errors can often reveal information about the database structure or data.

```
python sqlfuzzer.py -u "http://target.com/page.php?id=1" -T error
```

### Boolean-based Blind

Tests for SQL injection vulnerabilities where the application behaves differently based on whether the injected SQL condition is true or false.

```
python sqlfuzzer.py -u "http://target.com/page.php?id=1" -T boolean
```

### Time-based Blind

Tests for SQL injection vulnerabilities by injecting SQL that causes a time delay when executed. Useful when no visible output is available.

```
python sqlfuzzer.py -u "http://target.com/page.php?id=1" -T time
```

### Union-based

Tests for SQL injection vulnerabilities that can be exploited using the UNION operator to combine results with a custom SELECT statement.

```
python sqlfuzzer.py -u "http://target.com/page.php?id=1" -T union
```

## Examples

Test for all types of SQL injection vulnerabilities with GET:

```
python sqlfuzzer.py -u "http://vulnerable-site.com/index.php?id=1" -v
```

Test for vulnerabilities in POST form:

```
python sqlfuzzer.py -u "http://vulnerable-site.com/login.php" -m POST -d "username=admin&password=test" -v
```

Test for vulnerabilities in POST JSON API:

```
python sqlfuzzer.py -u "http://api.vulnerable.com/user" -m POST -d '{"id":1}' -dt json -T error
```

Test with a limited number of payloads:

```
python sqlfuzzer.py -u "http://vulnerable-site.com/index.php?id=1" -mp 100
```

Test with custom cookies:

```
python sqlfuzzer.py -u "http://vulnerable-site.com/index.php?id=1" -c "PHPSESSID=1234abcd; auth=true"
```

## Extending the Tool

### Adding New SQL Injection Techniques

To add a new SQL injection technique:

1. Add new payloads to `modules/payloads.py`
2. Implement payload generation in `modules/payload_generator.py`
3. Add detection logic in `modules/response_analyzer.py`
4. Update the `prepare_payloads` method in `modules/sql_injection_tester.py`

### Adding Support for New HTTP Features

To add support for new HTTP features:

1. Update the argument parser in `modules/input_handler.py`
2. Implement the feature in `modules/request_handler.py`
3. Update the main `SQLFuzzer` class in `sqlfuzzer.py` to pass the new features to the appropriate modules

## License

[MIT License](LICENSE)

## Disclaimer

This tool is for educational and ethical testing purposes only. Always obtain proper authorization before testing for vulnerabilities.
