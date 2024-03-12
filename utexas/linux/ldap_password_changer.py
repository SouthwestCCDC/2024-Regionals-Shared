import base64
import hashlib
import os
import subprocess
import shlex
import random
import string
import argparse

class LDAPPasswordChanger:
    def __init__(self, manager_dn: str, manager_password: str, domain: str):
        self.manager_dn = manager_dn
        self.manager_password = manager_password
        self.domain = domain
        self.temp_password_filename = 'ldap_password_changer_admin_password.txt'
        with open(self.temp_password_filename, 'w') as f:
            f.write(manager_password)
        self.allowed_characters = string.ascii_letters + string.digits + '!@#$%^&*()_+-=[]{}|;:,.<>?'

    def generate_password_hash(self, password: str) -> str:
        salt = os.urandom(4)
        h = hashlib.sha1(password.encode('utf-8')+salt).digest()
        return '{SSHA}' + base64.b64encode(h+salt).decode('utf-8')
    
    def change_password(self, user_dn: str, new_password: str) -> None:
        change_command = f'ldappasswd -x -D "{self.manager_dn}" -y {self.temp_password_filename} -s {new_password} "{user_dn}"'
        subprocess.run(shlex.split(change_command))
    
    def change_password_ldif(self, user_dn: str, new_password: str) -> str:
        new_password_hash = self.generate_password_hash(new_password)
        ldif = f"""
dn: {user_dn}
changetype: modify
replace: userPassword
userPassword: {new_password_hash}
"""
        return ldif
    
    def find_all_users(self) -> list[str]:
        search_command = f'ldapsearch -x -LLL -b "ou=users,{self.domain}" "(objectclass=posixAccount)" | grep "dn: "'
        raw_out = subprocess.check_output(shlex.split(search_command)).decode('utf-8').split()
        users = [x for x in raw_out if x != 'dn:']
        return users
    
    def load_word_list(self) -> list[str]:
        f = open('words.txt', 'r')
        self.words = f.readlines()
        f.close()

    def generate_passphrase(self, length: int) -> str:
        if not hasattr(self, 'words'):
            self.load_word_list()
        word_list = (x.strip() for x in random.sample(self.words, length))
        return 'Ut-'+('-'.join((x.upper() if random.random() > 0.5 else x) for x in word_list))
    
    def generate_password(self, length: int) -> str:
        return ''.join(random.choice(self.allowed_characters) for i in range(length))
    
    def generate_user_passwords(self, users: list[str], length: int, password: bool = False) -> dict[str, str]:
        user_passwords = {}
        for user in users:
            if password:
                user_passwords[user] = self.generate_password(length)
            else:
                user_passwords[user] = self.generate_passphrase(length)
        return user_passwords
    
    def change_all_passwords(self, output_file: str, length: int, password: bool = False) -> None:
        users = self.find_all_users()
        user_passwords = self.generate_user_passwords(users, length, password=password)
        modify_ldif = ''
        with open(output_file, 'w') as f:
            for user in users:
                password = user_passwords[user]
                modify_ldif += self.change_password_ldif(user, password)
                f.write(f'{user},{password}\n')
        with open('modify.ldif', 'w') as f:
            f.write(modify_ldif)
        subprocess.run(shlex.split(f'ldapmodify -x -D "{self.manager_dn}" -y {self.temp_password_filename} -f modify.ldif'))
        os.remove('modify.ldif')

    def remove_temp_password_file(self) -> None:
        os.remove(self.temp_password_filename)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Change all user passwords in an LDAP directory')
    parser.add_argument('-n', '--manager_dn', required=True, help='The DN of the manager account (required)')
    parser.add_argument('-p', '--manager_password', required=True, help='The password of the manager account (required)')
    parser.add_argument('-d', '--domain', required=True, help='The domain of the LDAP directory (required)')
    parser.add_argument('-o', '--output_file', default='passwords.txt', help='The file to write the new passwords to')
    parser.add_argument('-l', '--length', default=5, type=int, help='The length of the new passwords')
    parser.add_argument('--password', action='store_true', help='Use this flag to generate random passwords instead of passphrases')
    args = parser.parse_args()

    password_changer = LDAPPasswordChanger(args.manager_dn, args.manager_password, args.domain)
    password_changer.change_all_passwords(args.output_file, args.length, password=args.password)
    password_changer.remove_temp_password_file()