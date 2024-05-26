# SecurePassGuard

SecurePassGuard is a Python tool for generating strong passwords and checking password strength. It provides functionality to generate random passwords of custom length with various character types and also evaluates the strength of a given password based on multiple criteria.

## Features

- Password Generation: Generate random passwords with customizable length and character types.
- Password Strength Check: Evaluate the strength of a password based on length, character variety, common patterns, repeated characters, and dictionary words.
- Interactive CLI Interface: Simple and interactive command-line interface for easy usage.
- Password Strength Score: Provides a numerical score indicating the strength of the password.
- Recommendations: Offers recommendations based on the strength of the password.

## Installation

1. Clone the repository:

   ```
   git clone https://github.com/KoushikReddyB/SecurePassGuard.git
   ```

2. Navigate to the project directory:

   ```
   cd SecurePassGuard
   ```

3. Install the colorama:

   ```
   pip install colorama
   ```

4. Run the main script:

   ```
   python SPG.py
   ```

## Usage

1. Generate Password:

   - Choose the option to generate a password.
   - Specify the desired length and character types (lowercase, uppercase, digits, special characters).
   - Optionally, allow or disallow sequence patterns in the password.
   - SecurePassGuard will generate a password and display it along with its strength evaluation.

2. Check Password Strength:

   - Select the option to check the strength of a password.
   - Enter the password you want to evaluate.
   - SecurePassGuard will analyze the password and provide a strength assessment along with a numerical score and recommendations.

## Contributing

Contributions are welcome! Feel free to open an issue or submit a pull request for any enhancements or bug fixes.

## License

This project is licensed under the MIT License - see the [LICENSE](#license) file for details.
