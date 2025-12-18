import sqlite3
from werkzeug.security import generate_password_hash
import random

DB_NAME = "vacations.db"

conn = sqlite3.connect(DB_NAME)
conn.row_factory = sqlite3.Row
c = conn.cursor()

c.execute("DROP TABLE IF EXISTS vacations")
c.execute("DROP TABLE IF EXISTS users")

c.execute("""
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    full_name TEXT NOT NULL,
    login TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    is_admin INTEGER DEFAULT 0
)
""")

c.execute("""
CREATE TABLE vacations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    year INTEGER NOT NULL,
    week_num INTEGER NOT NULL CHECK (week_num BETWEEN 1 AND 52),
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE(year, week_num)
)
""")

base_users = [
    ("Кучерова София Владимировна", "admin",   "admin123", 1),
    ("Иванов Иван Иванович",        "ivanov",  "pass123",  0),
    ("Петров Петр Петрович",        "petrov",  "pass123",  0),
    ("Сидоров Сергей Сергеевич",    "sidorov", "pass123",  0),
    ("Козлов Константин Константинович", "kozlov", "pass123", 0),
    ("Смирнова Анна Александровна", "smirnova","pass123",  0),
    ("Васильев Дмитрий Дмитриевич", "vasiliev","pass123",  0),
    ("Морозова Екатерина Евгеньевна","morozova","pass123", 0),
    ("Новиков Алексей Александрович","novikov","pass123",  0),
    ("Федоров Михаил Михайлович",   "fedorov", "pass123",  0),
]

for full_name, login, pwd, is_admin in base_users:
    pwd_hash = generate_password_hash(pwd)
    c.execute(
        "INSERT INTO users (full_name, login, password_hash, is_admin) VALUES (?, ?, ?, ?)",
        (full_name, login, pwd_hash, is_admin)
    )

target_users = 105
current = len(base_users)

r_first = [
    "Александр", "Дмитрий", "Елена", "Мария",
    "Николай", "Ольга", "Павел", "Юлия",
    "Виктор", "Анна", "Светлана", "Денис",
    "Сергей", "Екатерина"
]
r_last = [
    "Соколов", "Кузнецов", "Лебедев", "Зайцев",
    "Быков", "Макаров", "Новиков", "Смирнов",
    "Волков", "Морозов", "Петров", "Васильев"
]
r_middle = [
    "Александрович", "Дмитриевич", "Сергеевич",
    "Константинович", "Петрович", "Николаевич",
    "Владимирович"
]
latin_bases = ["alex", "dmitry", "elena", "maria", "nik", "olga", "pavel", "yulia",
               "sergey", "sveta", "denis", "vika", "katya", "yana"]

password_patterns = ["pass2023", "pwd2024", "secret25", "login123", "user456", "test789"]

while current < target_users:
    first = random.choice(r_first)
    last = random.choice(r_last)
    middle = random.choice(r_middle)
    full_name = f"{last} {first} {middle}"

    latin_base = random.choice(latin_bases)
    login = f"{latin_base}{current:03d}"
    pwd = random.choice(password_patterns) + str(current)

    pwd_hash = generate_password_hash(pwd)
    try:
        c.execute(
            "INSERT INTO users (full_name, login, password_hash, is_admin) VALUES (?, ?, ?, 0)",
            (full_name, login, pwd_hash)
        )
        current += 1
    except sqlite3.IntegrityError:
        continue


conn.commit()

vacations_2023 = [
    (1, 2023, 8), (1, 2023, 15),
    (2, 2023, 22), (2, 2023, 30),
    (3, 2023, 40),
    (4, 2023, 3),  (4, 2023, 47),
]

vacations_2024 = [
    (5, 2024, 10), (5, 2024, 18),
    (6, 2024, 25), (6, 2024, 33),
    (7, 2024, 45),
]

vacations_2025 = [
    (1, 2025, 5),  (1, 2025, 12),
    (2, 2025, 20), (2, 2025, 28),
    (3, 2025, 35),
    (4, 2025, 42),
]

for user_id, year, week in vacations_2023 + vacations_2024 + vacations_2025:
    try:
        c.execute(
            "INSERT INTO vacations (user_id, year, week_num) VALUES (?, ?, ?)",
            (user_id, year, week)
        )
    except sqlite3.IntegrityError:
        pass

conn.commit()

print("init database!")

conn.close()
