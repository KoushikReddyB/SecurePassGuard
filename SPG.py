import re
import random
import string
from colorama import Fore, Style

class SecurePassGuard:
    def __init__(self):
        self.criteria = [
            (self.length_check, "Password must be at least 4 characters long."),
            (self.uppercase_check, "Password must contain at least one uppercase letter."),
            (self.lowercase_check, "Password must contain at least one lowercase letter."),
            (self.digit_check, "Password must contain at least one digit."),
            (self.special_char_check, "Password must contain at least one special character."),
            (self.common_patterns_check, "Password must not contain common patterns or sequences."),
            (self.repeated_char_check, "Password must not contain repeated characters."),
            (self.dictionary_word_check, "Password must not contain dictionary words."),
        ]
        
        self.common_patterns = [
            r'(.)\1{2,}',  # Repeated characters
            r'\b(\w+)\b\s+\1\b',  # Repeated words
            r'4321|5432|6543|7654|8765|9876|0987|1098',  # Reversed sequential digits
            r'zyxwv|yxwvu|xwvut|wvuts|vutsr|utsrq|tsrqp|srqpo|rqpon|qponm|ponml|onmlk|nmlkj|mlkji|lkjih|kjihg|jihgf|ihgfe|hgfed|gfedc|fedcb|edcba',  # Reversed sequential lowercase letters
            r'1234|2345|3456|4567|5678|6789|7890|8901',  # Sequential digits
            r'ZYXWV|YXWVU|XWVUT|WVUTS|VUTSR|UTSRQ|TSRQP|SRQPO|RQPO|QPONM|PONML|ONMLK|NMLKJ|MLKJI|LKJIH|KJIHG|JIHGF|IHGFE|HGFED|GFEDC|FEDCB|EDCBA',  # Reversed sequential uppercase letters
            r'POIUYTREWQ|LKJHGFDSA|MNBVCXZ',  # Reversed keyboard patterns
            r'password|123456|12345678|abc123|qwerty|monkey|letmein|dragon|111111|baseball|iloveyou|trustno1|1234567|sunshine|master|welcome|shadow|ashley|football|jesus|michael|ninja|mustang|password1',  # Common weak passwords
            r'\b\d{1,2}/\d{1,2}/\d{2,4}\b|\b\d{2,4}-\d{1,2}-\d{1,2}\b',  # Dates in various formats
            r'\b\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b',  # Common phone number formats
            r'\b\d{4}[-.\s]?\d{4}[-.\s]?\d{4}[-.\s]?\d{4}\b',  # Credit card number formats
            r'\b0x[0-9A-Fa-f]{2,}\b',  # Hexadecimal numbers
            r'\b[M|D|C|L|X|V|I]+\b',  # Roman numerals
            r'([!@#$%^&*()_+={}\[\]:;"\'<>,.?/\\|`~\-])\1{2,}',  # Repeated symbols
            r'\b[01]{8,}\b',  # Long binary sequences
            r'abcdef|bcdefg|cdefgh|defghi|efghij|fghijk|ghijkl|hijklm|ijklmn|jklmno|klmnop|lmnopq|mnopqr|nopqrs|opqrst|pqrstu|qrstuv|rstuvw|stuvwx|tuvwxy|uvwxyz',  # Sequential lowercase letters
            r'ABCDEFGHIJKLMNOPQRSTUVWXYZ',  # Sequential uppercase letters
            r'QWERTYUIOP|ASDFGHJKL|ZXCVBNM',  # Keyboard patterns
        ]
        
        self.dictionary_words = {
            "password", "123456", "12345678", "123456789", "qwerty", "abc123",
            "monkey", "letmein", "dragon", "111111", "baseball",
            "iloveyou", "trustno1", "1234567", "sunshine", "master", "welcome",
            "shadow", "ashley", "football", "jesus", "michael", "ninja",
            "mustang", "password1", "password123", "hello123", "welcome123",
            "qwerty123", "admin", "login", "welcome1", "password1234", "123123",
            "1234", "12345", "password12345", "superman", "batman", "charlie",
            "access", "test", "passw0rd", "hello", "123456a", "1qaz2wsx",
            "qazwsx", "qwertyuiop", "password!", "iloveyou1", "welcome1234",
            "letmein1", "qwerty12345", "monkey123", "football123", "dragon123",
            "baseball123", "iloveyou123", "trustno1!", "admin123", "admin1234",
            "welcome12345", "password123!", "p@ssw0rd", "welcome123!", "1234567890",
            "123456789", "12345678910", "welcome@123", "letmein123", "iloveyou1234",
            "mustang123", "ninja123", "michael123", "jesus123", "123qwe", "qwe123",
            "123abc", "abc1234", "1234abcd", "abcd1234", "123abc!", "abc123!",
            "12345abc", "abc12345", "123!@#", "!@#123", "pass", "secret",
            "adminadmin", "root", "password12", "password123",
            "qwerty1234", "letmein1234", "welcome1234", "football1234",
            "password123456", "123456789a", "adminadmin123", "root123",
            "password12345!", "iloveyou12345", "qwerty123456", "monkey1234",
            "passw0rd123", "hello1234", "football12345", "dragon1234",
            "baseball1234", "michael1234", "password123!", "superman123",
            "1234567890a", "1234567a", "admin12345", "password12345678",
            "adminadmin1", "letmein12345", "abc12345!", "test123",
            "qwerty123456789", "password1234!", "welcome123456",
            "iloveyou123!", "123qwe123", "passw0rd1", "mustang1234",
            "dragon12345", "shadow123", "baseball1", "football1",
            "qwertyuiop123", "adminadmin12", "password1234567",
            "sunshine123", "michael12345", "12345678910a", "trustno123",
            "monkey12345", "1234qwer", "qazwsx123", "123456aa", "1234567aa",
            "password12345a", "admin1234!", "12345qwert", "football123!",
            "dragon123!", "baseball123!", "michael123!", "trustno1!!",
            "1234567890abc", "1234567890qwe", "sunshine12345", "admin123456",
            "adminadmin12345", "123456789123", "qwerty123abc", "monkey123!",
            "password12345abc", "superman1234", "1234567890qaz", "letmein12",
            "adminadmin1234", "root1234", "password123abc", "password123abc!",
            "1234567890qwert", "1234567890qwerty", "1234567890qweasd",
            "password1234567890", "password1234567890!", "sunshine1234",
            "mustang12345", "michael123abc", "password123abc123",
            "password1234567!", "123456789123456789", "password12345678910",
            "password1234567890a", "password123456789a!", "qwerty12345",
            "12345678901234567890", "password123qwe", "qwerty12345!",
            "password123qwerty", "adminadmin123456", "letmein123abc",
            "trustno12345", "qwerty1234567890", "password12345qwe",
            "password123456qwe", "1234567890123456789", "123456789012345",
            "1234567890123456", "12345678901234567", "123456789012345678",
            "password123456789abc", "password1234567890qwe", "password123456789qwerty",
            "password1234567890qwerty", "password1234567890qweasd",
            "password1234567890qazwsx", "password1234567890qwe123",
            "password1234567890qwe!@#", "password1234567890qweasd!",
            "password1234567890qazwsx!", "password1234567890qwe123!",
            "password1234567890qwe!@#123", "password1234567890qweasd!@#",
            "password1234567890qazwsx!@#", "password1234567890qwe123!@#",
            "password1234567890qwe!@#1234", "password1234567890qweasd!@#1234",
            "password1234567890qazwsx!@#1234", "password1234567890qwe123!@#1234",
            "password1234567890qwe!@#12345", "password1234567890qweasd!@#12345",
            "password1234567890qazwsx!@#12345", "password1234567890qwe123!@#12345",
            "password1234567890qwe!@#123456", "password1234567890qweasd!@#123456",
            "password1234567890qazwsx!@#123456", "password1234567890qwe123!@#123456",
            "password1234567890qwe!@#1234567", "password1234567890qweasd!@#1234567",
            "password1234567890qazwsx!@#1234567", "password1234567890qwe123!@#1234567",
            "password1234567890qwe!@#12345678", "password1234567890qweasd!@#12345678",
            "password1234567890qazwsx!@#12345678", "password1234567890qwe123!@#12345678",
            "password1234567890qwe!@#123456789", "password1234567890qweasd!@#123456789",
            "password1234567890qazwsx!@#123456789", "password1234567890qwe123!@#123456789",
            "password1234567890qwe!@#1234567890", "password1234567890qweasd!@#1234567890",
            "password1234567890qazwsx!@#1234567890", "password1234567890qwe123!@#1234567890"
        }

    def length_check(self, password):
        return len(password) >= 4

    def uppercase_check(self, password):
        return bool(re.search(r'[A-Z]', password))

    def lowercase_check(self, password):
        return bool(re.search(r'[a-z]', password))

    def digit_check(self, password):
        return bool(re.search(r'\d', password))

    def special_char_check(self, password):
        return bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password))

    def common_patterns_check(self, password):
        for pattern in self.common_patterns:
            if re.search(pattern, password):
                return False
        return True

    def repeated_char_check(self, password):
        return not bool(re.search(r'(.)\1\1', password))

    def dictionary_word_check(self, password):
        return not any(word in password.lower() for word in self.dictionary_words)

    def check_password(self, password):
        results = {}
        for check, message in self.criteria:
            if not check(password):
                results[check.__name__] = message
        return results

    def password_strength(self, password):
        results = self.check_password(password)
        score = self.calculate_score(password)
        if not results:
            strength_message = f"{Fore.GREEN}Password is strong.{Style.RESET_ALL}"
        else:
            strength_message = f"{Fore.RED}Password is weak. Issues:\n" + "\n".join(results.values()) + Style.RESET_ALL
        
        recommendation = self.get_recommendation(score)

        return f"{strength_message}\nPassword Score: {score}\n{recommendation}"

    def calculate_score(self, password):
        length_score = min(len(password) * 2, 30)
        variety_score = sum(bool(re.search(pat, password)) * 10 for pat in [r'[A-Z]', r'[a-z]', r'\d', r'[!@#$%^&*(),.?":{}|<>]'])
        common_pattern_penalty = -15 if not self.common_patterns_check(password) else 0
        repeated_char_penalty = -5 if not self.repeated_char_check(password) else 0
        dictionary_word_penalty = -20 if not self.dictionary_word_check(password) else 0
        
        return max(length_score + variety_score + common_pattern_penalty + repeated_char_penalty + dictionary_word_penalty, 0)

    def generate_password(self, length=8, lowercase=True, uppercase=True, digits=True, special_chars=True, allow_sequence=False):
        if length < 5:
            raise ValueError("Password length must be at least 5 characters.")
        
        characters = ""
        if lowercase:
            characters += string.ascii_lowercase
        if uppercase:
            characters += string.ascii_uppercase
        if digits:
            characters += string.digits
        if special_chars:
            characters += string.punctuation

        if not characters:
            raise ValueError("At least one character type should be selected.")

        password = ''.join(random.choice(characters) for _ in range(length))

        if not allow_sequence:
            for pattern in self.common_patterns:
                while re.search(pattern, password):
                    password = ''.join(random.choice(characters) for _ in range(length))

        return password

    def get_recommendation(self, score):
        if score >= 60:
            return f"{Fore.GREEN}Your password is very strong. Keep up the good work!{Style.RESET_ALL}"
        elif score >= 40:
            return f"{Fore.YELLOW}Your password is fairly strong but can be improved.{Style.RESET_ALL}"
        elif score >= 20:
            return f"{Fore.RED}Your password is weak. Consider making it stronger.{Style.RESET_ALL}"
        else:
            return f"{Fore.RED}Your password is very weak. You should change it immediately.{Style.RESET_ALL}"

def main():
    spg = SecurePassGuard()
    
    while True:
        print("\nSecurePassGuard Menu")
        print("1. Generate password")
        print("2. Check password strength")
        print("3. Exit")
        
        choice = input("Enter your choice: ")
        
        if choice == '1':
            length = input("Length of the password [default: 8]: ") or '8'
            if int(length) < 5:
                print(f"{Fore.RED}Password length must be at least 5 characters.{Style.RESET_ALL}")
                continue
            
            lowercase = input("Should it have lowercase (y/n) [default: y]: ").strip().lower() or 'y'
            uppercase = input("Should it have uppercase (y/n) [default: y]: ").strip().lower() or 'y'
            digits = input("Should it have digits (y/n) [default: y]: ").strip().lower() or 'y'
            special_chars = input("Should it have special characters (y/n) [default: y]: ").strip().lower() or 'y'
            allow_sequence = input("Should it allow sequence (y/n) [default: n]: ").strip().lower() or 'n'

            length = int(length)
            lowercase = lowercase == 'y'
            uppercase = uppercase == 'y'
            digits = digits == 'y'
            special_chars = special_chars == 'y'
            allow_sequence = allow_sequence == 'n'
            
            try:
                password = spg.generate_password(length, lowercase, uppercase, digits, special_chars, allow_sequence)
                print(f"\nGenerated Password: {Fore.GREEN}{password}{Style.RESET_ALL}")
                print(spg.password_strength(password))
            except ValueError as e:
                print(f"{Fore.RED}{e}{Style.RESET_ALL}")
        
        elif choice == '2':
            password = input("Enter the password to check: ")
            print(spg.password_strength(password))
        
        elif choice == '3':
            print("Exiting SecurePassGuard. Goodbye!")
            break
        
        else:
            print(f"{Fore.RED}Invalid choice. Please select again.{Style.RESET_ALL}")

if __name__ == "__main__":
    main()
