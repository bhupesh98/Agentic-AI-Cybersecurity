#!/usr/bin/env python3
"""
OpenAI API Key Verification Script
Purpose: Verify that OpenAI API key is properly configured and working
"""

import os
import sys
from pathlib import Path
from dotenv import load_dotenv

# Add color support for terminal output


class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    BOLD = '\033[1m'
    END = '\033[0m'


def print_success(message):
    print(f"{Colors.GREEN}✓{Colors.END} {message}")


def print_error(message):
    print(f"{Colors.RED}✗{Colors.END} {message}")


def print_warning(message):
    print(f"{Colors.YELLOW}⚠{Colors.END} {message}")


def print_info(message):
    print(f"{Colors.BLUE}ℹ{Colors.END} {message}")


def print_header(message):
    print(f"\n{Colors.BOLD}{'='*60}{Colors.END}")
    print(f"{Colors.BOLD}{message}{Colors.END}")
    print(f"{Colors.BOLD}{'='*60}{Colors.END}\n")


def main():
    print_header("OpenAI API Key Verification")

    # Step 1: Check if .env file exists
    project_root = Path(__file__).parent.parent
    env_path = project_root / '.env'

    print_info(f"Checking for .env file at: {env_path}")

    if not env_path.exists():
        print_error(".env file not found!")
        print_info("Please create a .env file in the project root with:")
        print("   OPENAI_API_KEY=sk-...")
        sys.exit(1)

    print_success(".env file found")

    # Step 2: Load environment variables
    print_info("Loading environment variables...")
    load_dotenv(env_path)

    api_key = os.getenv('OPENAI_API_KEY')

    if not api_key:
        print_error("OPENAI_API_KEY not found in .env file!")
        print_info("Please add the following line to your .env file:")
        print("   OPENAI_API_KEY=sk-...")
        sys.exit(1)

    print_success("OPENAI_API_KEY loaded from .env")

    # Step 3: Validate API key format
    print_info("Validating API key format...")

    if not api_key.startswith('sk-'):
        print_error("Invalid API key format!")
        print_info("OpenAI API keys should start with 'sk-'")
        sys.exit(1)

    # Mask the key for security
    masked_key = f"{api_key[:10]}...{api_key[-4:]}"
    print_success(f"API key format valid: {masked_key}")

    # Step 4: Test API connection
    print_info("Testing API connection...")

    try:
        from openai import OpenAI

        client = OpenAI(api_key=api_key)

        # Make a minimal API call (cheapest possible request)
        print_info("Making test API call (this will cost ~$0.0001)...")

        response = client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "user", "content": "Say 'API connection successful' in exactly those words."}
            ],
            max_tokens=10,
            temperature=0
        )

        # Extract response
        message = response.choices[0].message.content.strip()

        print_success("API call successful!")
        print_info(f"Response: {message}")

        # Show usage stats
        usage = response.usage
        print_info(
            f"Tokens used: {usage.total_tokens} (prompt: {usage.prompt_tokens}, completion: {usage.completion_tokens})")
        print_info(f"Estimated cost: ~$0.0001")

    except ImportError:
        print_error("OpenAI Python package not installed!")
        print_info("Install it with: pip install openai --break-system-packages")
        sys.exit(1)

    except Exception as e:
        print_error(f"API call failed: {str(e)}")

        # Provide helpful error messages
        error_str = str(e).lower()

        if 'invalid' in error_str or 'incorrect' in error_str:
            print_warning("Your API key appears to be invalid.")
            print_info("Please check:")
            print("   1. Copy the FULL key from OpenAI dashboard")
            print("   2. No extra spaces or quotes in .env file")
            print("   3. Key format: OPENAI_API_KEY=sk-...")

        elif 'quota' in error_str or 'billing' in error_str:
            print_warning("API key is valid but billing issue detected.")
            print_info("Please check:")
            print("   1. Your OpenAI account has available credits")
            print("   2. Billing is set up: https://platform.openai.com/account/billing")

        elif 'rate' in error_str or 'limit' in error_str:
            print_warning("Rate limit reached.")
            print_info("Wait a moment and try again.")

        elif 'connection' in error_str or 'network' in error_str:
            print_warning("Network connection issue.")
            print_info("Check your internet connection.")

        else:
            print_info("Full error details:")
            print(f"   {e}")

        sys.exit(1)

    # Step 5: Success summary
    print_header("Verification Complete!")

    print_success("✓ .env file exists")
    print_success("✓ OPENAI_API_KEY loaded")
    print_success("✓ API key format valid")
    print_success("✓ API connection working")

    print(f"\n{Colors.GREEN}{Colors.BOLD}Your OpenAI API key is properly configured!{Colors.END}\n")
    print_info("You can now use OpenAI API in your project.")


if __name__ == "__main__":
    main()
