import sqlite3
from werkzeug.security import generate_password_hash
from datetime import date

conn = sqlite3.connect('vacations.db')
c = conn.cursor()

c.execute('''CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    full_name TEXT NOT NULL,
    login TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    is_admin INTEGER DEFAULT 0
)''')

c.execute('''CREATE TABLE IF NOT EXISTS vacations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    year INTEGER NOT NULL,
    week_num INTEGER NOT NULL CHECK (week_num BETWEEN 1 AND 52),
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE(year, week_num)
)''')

c.execute("INSERT OR IGNORE INTO users (full_name, login, password_hash, is_admin) VALUES (?, ?, ?, ?)",
          ("Кучерова София Владимировна", "admin", generate_password_hash("admin123"), 1))

employees = [
    ("Иванов Иван Иванович", "ivanov", "pass123"),
    ("Петров Петр Петрович", "petrov", "pass123"),
    ("Сидоров Сергей Сергеевич", "sidorov", "pass123"),
    ("Козлов Константин Константинович", "kozlov", "pass123"),
]

first_names = ["Александр", "Дмитрий", "Елена", "Мария", "Николай", "Ольга", "Павел", "Юлия"]
last_names = ["Соколов", "Кузнецов", "Лебедев", "Зайцев", "Быков", "Макаров", "Новиков", "Смирнов"]

for i in range(len(employees), 105):
    first = first_names[i % len(first_names)]
    last = last_names[i % len(last_names)]
    full_name = f"{first} {last}ович"
    login = f"user{i+1}"
    employees.append((full_name, login, "pass123"))

for full_name, login, pwd in employees:
    pwd_hash = generate_password_hash(pwd)
    c.execute("INSERT OR IGNORE INTO users (full_name, login, password_hash, is_admin) VALUES (?, ?, ?, 0)",
              (full_name, login, pwd_hash))

conn.commit()

sample_vacations = [
    (1, 2025, 5), (1, 2025, 12),
    (2, 2025, 20), (2, 2025, 28),
    (3, 2025, 35),
    (4, 2025, 42),
]

for user_id, year, week_num in sample_vacations:
    c.execute("INSERT OR IGNORE INTO vacations (user_id, year, week_num) VALUES (?, ?, ?)",
              (user_id, year, week_num))

conn.commit()
c.close()
conn.close()

print("init database!")
