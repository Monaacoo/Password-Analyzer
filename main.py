import string
import time
import json
import bcrypt

#Baixar Rockyou Invoke-WebRequest -Uri "https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt" -OutFile "rockyou.txt"
ROCKYOU_LIST = "rockyou.txt"

def analyse_password(password):
    score = 0

    if len(password) >= 8:
        score += 1
    if any(c.islower() for c in password):
        score += 1
    if any(c.isupper() for c in password):
        score += 1
    if any(c.isdigit() for c in password):
        score += 1
    if any(c in string.punctuation for c in password):
        score += 1

    if score <= 2:
        strenght = "Fraca"
    elif score <= 4:
        strenght = "Media"
    else:
        strenght = "Forte"
    
    return strenght, score

def detect(password):
    patterns = []

    sequences = ["1234", "abcd", "qwerty"]
    for seq in sequences:
        if seq in password.lower():
            patterns.append(f"Detected Sequence: {seq}")
    if password.isdigit():
        patterns.append("Just numbers in password")
    return patterns

def estimated_crack_time(password):
    charset_size = 0

    if any(c.islower() for c in password):
        charset_size += 26
    if any(c.isupper() for c in password):
        charset_size += 26
    if any(c.isdigit() for c in password):
        charset_size += 10
    if any(c in string.punctuation for c in password):
        charset_size += 32
    
    combinations = charset_size ** len(password)
    per_second = 1_000_000
    seconds = combinations / per_second

    return seconds

def hash_password(password):
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode(),salt)
    return hashed

def brute_force(hash_value):

    try:
        with open(ROCKYOU_LIST, "r", encoding="utf-8", errors="ignore") as file:
            for line in file:
                guess = line.strip()

                if bcrypt.checkpw(guess.encode(),hash_value):
                    print(f"Senha: {guess}")
                    return guess
    except FileNotFoundError:
        print(f"WordList não encontrada")

    print(f"Não encontrada")
    return  None

def json_report(password, strenght, score, patterns, crack_time, found):
    report = {
        "password": password,
        "strenght": strenght,
        "score": score,
        "patterns": patterns,
        "estimated_crack_time_second": crack_time,
        "found_in_rockyou": found
    }
    with open("report.json", "w") as f:
        json.dump(report, f, indent=4)
    print("Relatorio gerado em report.json")

if __name__ == "__main__":
    password = input("Digite a senha: ")
    strenght, score = analyse_password(password)
    crack_time = estimated_crack_time(password)
    patterns = detect(password)

    print(f"Força: {strenght} ({score}/5)")
    print(f"Tempo estimado: {round(crack_time,2)} seg")

    if patterns:
        print(f"Padrões encontrados: ")
        for p in patterns:
            print("-", p)

    hashed = hash_password(password)
    found = brute_force(hashed)
    json_report(password,strenght, score, patterns, crack_time, found)