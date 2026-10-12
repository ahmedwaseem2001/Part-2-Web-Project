# Education Portal — Web Security Practical

## Project Overview
This project is a local educational web application developed to demonstrate common web security vulnerabilities and their mitigations. It includes vulnerable and safe versions for comparison.

## Technologies
- Python
- Flask
- SQLite
- HTML
- JavaScript
- Git

## Security Topics Demonstrated
- **Reflected XSS:** User-supplied search input is rendered in the page.
- **Stored XSS:** Submitted comments are displayed in the portal.
- **DOM-Based XSS:** URL hash input is handled by client-side JavaScript.
- **CSRF:** A separate local attacker page demonstrates cross-origin form submission.
- **SQL Injection:** Vulnerable and parameterized login queries are compared.

## Safe Practices Demonstrated
- Jinja template autoescaping
- `textContent` instead of unsafe DOM HTML insertion
- CSRF token validation
- Parameterized SQL queries
- Input validation

## Run Locally
1. Install Python 3.11 or a compatible version.
2. Install Flask in your virtual environment.
3. Run the application:

   `python app.py`

4. Open `http://127.0.0.1:5000`.
5. Use `/vulnerable` and `/safe` to compare the two versions.

## Local Lab Warning
This project is for educational testing on localhost with dummy data only. Do not expose the vulnerable application or Flask debug server to the public internet. The vulnerable routes intentionally contain unsafe behavior and must not be used in production.
