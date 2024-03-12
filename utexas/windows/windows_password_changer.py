import subprocess, shlex, string, random


class WindowsPasswordChanger:
    def __init__(self):
        self.allowed_characters = string.ascii_letters + string.digits + '!@#$%^&*()_+-=[]{}|;:,.<>?'
        f = open('words.txt', 'r')
        self.words = f.readlines()
        f.close()
    
    def generate_password(self, length: int) -> str:
        return ''.join(random.choice(self.allowed_characters) for i in range(length))

    def generate_passphrase(self, length: int) -> str:
        word_list = (x.strip() for x in random.sample(self.words, length))
        return 'Ut'+('-'.join((x.upper() if random.random() > 0.5 else x) for x in word_list))

    def change_password(self, user: str, password: str) -> None:
        # print(f'net user {user} {password}')
        subprocess.run(shlex.split(f'net user {user} {password}'), check=True)

    def change_all_ad_user_passwords(self, length: int) -> dict[str, str]:
        users = self.get_ad_users()
        user_passwords = {}
        for user in users:
            password = self.generate_passphrase(length)
            self.change_ad_user_password(user, password)
            user_passwords[user] = password
        return user_passwords

    def change_ad_user_password(self, username: str, password: str) -> None:
        cmd_str = f'Get-ADUser -Identity "{username}" | Set-ADAccountPassword -NewPassword (ConvertTo-SecureString -AsPlainText "{password}" -Force)'
        print(cmd_str)
        # subprocess.run(shlex.split(cmd_str), check=True)

    def get_local_users(self) -> list[str]:
        raw_out = subprocess.check_output(['net','user']).decode('utf-8')
        s_index = raw_out.index('--\r\n')
        e_index = raw_out.index('The command completed successfully.\r\n')
        users = raw_out[s_index+4:e_index].split()
        return users
    
    def get_ad_users(self) -> list[str]:
        raw_out = subprocess.check_output(shlex.split('powershell -command "Get-ADUser -Filter *"')).decode('utf-8')
        return [x.split()[2] for x in raw_out.split('\n') if x.startswith('SamAccountName')]

    def check_user_enabled(self, user: str) -> bool:
        raw_out = subprocess.check_output(shlex.split(f'net user {user}')).decode('utf-8')
        raw_out = raw_out[raw_out.index('Account active'):].split()
        return raw_out[2] == 'Yes'
    
    def change_local_user_passwords(self, length: int) -> dict[str, str]:
        users = self.get_local_users()
        user_passwords = {}
        for user in users:
            if self.check_user_enabled(user):
                password = self.generate_passphrase(length)
                self.change_password(user, password)
                user_passwords[user] = password
        return user_passwords
    
    def write_passwords_to_file(self, user_passwords: dict[str, str], filename: str) -> None:
        with open(filename, 'w') as f:
            for user, password in user_passwords.items():
                f.write(f'{user},{password}\n')




if __name__ == '__main__':
    windows_password_changer = WindowsPasswordChanger()
    # ad_password_data = windows_password_changer.change_all_ad_user_passwords(4)
    # windows_password_changer.write_passwords_to_file(ad_password_data, 'ad_passwords.txt')

    local_password_data = windows_password_changer.change_local_user_passwords(4)
    windows_password_changer.write_passwords_to_file(local_password_data, 'changed_passwords.txt')
    subprocess.run(shlex.split('notepad changed_passwords.txt'))
