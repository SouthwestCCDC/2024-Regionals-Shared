import csv

def generate_ldif(row: str) -> str:
    parts = row.split(',')
    return f"""
"""

def process_csv(input_file: str, output_file: str) -> None:
    with open(output_file, 'w') as f:
        with open(input_file) as csvfile:
            spamreader = csv.reader(csvfile)
            for row in spamreader:
                f.write(generate_ldif(row))


if __name__ == '__main__':
    process_csv('input.txt', 'ldifout.txt')