import smtplib
import re
import dns.resolver
from typing import Optional
import logging
import sys

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('email_check_results.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

def extract_domain(email: str) -> str:
    """Extract domain from email address."""
    return email.lower().split('@')[-1]

def get_mx_records(domain: str) -> Optional[str]:
    """Get the primary MX record for a domain."""
    try:
        answers = dns.resolver.resolve(domain, 'MX')
        # Return the highest priority MX record
        return str(answers[0].exchange)
    except Exception as e:
        logger.error(f"Failed to resolve MX records for {domain}: {str(e)}")
        return None

def check_email_exists(email: str) -> bool:
    """Check if an email address exists using SMTP RCPT TO."""
    domain = extract_domain(email)
    mx_host = get_mx_records(domain)
    if not mx_host:
        logger.warning(f"No MX records found for {domain}")
        return False
    
    try:
        with smtplib.SMTP(mx_host, 25, timeout=10) as server:
            server.helo()
            server.mail('test@nonexistent.com')  # Dummy sender
            code, _ = server.rcpt(email)
            if code in (250, 251):
                logger.info(f"Email {email} exists")
                return True
            else:
                logger.warning(f"Email {email} does not exist or server rejected probe (code: {code})")
                return False
    except smtplib.SMTPException as e:
        logger.error(f"SMTP error checking {email}: {str(e)}")
        return False
    except Exception as e:
        logger.error(f"Unexpected error checking {email}: {str(e)}")
        return False

def parse_email(line: str) -> Optional[str]:
    """Parse an email address from a line."""
    line = line.strip()
    if not line:
        return None
    # Basic email validation
    match = re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', line)
    if match:
        return line
    logger.warning(f"Invalid email format: {line}")
    return None

def save_email(email: str, is_valid: bool) -> None:
    """Save an email to the appropriate file based on its validity."""
    file_name = 'valid_emails.txt' if is_valid else 'invalid_emails.txt'
    with open(file_name, 'a', encoding='utf-8') as f:
        f.write(f"{email}\n")

def process_email_file(file_path: str) -> None:
    """Process the email file and check all emails sequentially."""
    # Clear output files before starting
    open('valid_emails.txt', 'w').close()
    open('invalid_emails.txt', 'w').close()

    with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
        emails = [parse_email(line) for line in file]
        emails = [email for email in emails if email]

    logger.info(f"Loaded {len(emails)} emails for checking")

    valid_count = 0
    invalid_count = 0

    for email in emails:
        try:
            is_valid = check_email_exists(email)
            save_email(email, is_valid)
            if is_valid:
                valid_count += 1
            else:
                invalid_count += 1
            logger.info(f"Processed {email}: {'Valid' if is_valid else 'Invalid'}")
        except Exception as e:
            logger.error(f"Error processing {email}: {str(e)}")
            save_email(email, False)
            invalid_count += 1

    logger.info(f"Checking complete. Valid: {valid_count}, Invalid: {invalid_count}")

def main():
    """Main function to run the email existence checker."""
    import argparse
    parser = argparse.ArgumentParser(description="Check if email addresses exist.")
    parser.add_argument('file_path', help="Path to the file containing email addresses")
    args = parser.parse_args()

    process_email_file(args.file_path)

if __name__ == "__main__":
    main()
