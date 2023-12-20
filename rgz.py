from werkzeug.security import check_password_hash, generate_password_hash
from flask import Blueprint, redirect, render_template, request, session, jsonify
import psycopg2
from datetime import datetime

rgz = Blueprint("rgz", __name__)


ADMIN_USER_ID = 1


# Функции подключения и закрытия базы данных
def dbConnect():
    conn = psycopg2.connect(
        host="127.0.0.1",
        database="rgz",
        user="vladislav_knowledge_base",
        password="123"
    )
    return conn

def dbClose(cursor, connection):
    # Закрытие курсора и соединения с базой данных
    cursor.close()
    connection.close()

# Функция для проверки разрешений пользователя
def user_has_permission_to_create_article(user_id):
    # Подключение к базе данных
    conn = dbConnect()
    cur = conn.cursor()

    try:
        # Проверка существования пользователя с указанным ID
        cur.execute("SELECT id FROM users WHERE id = %s", (user_id,)) #Это сам SQL-запрос. В данном случае, он выбирает id из таблицы users, где значение id равно заданному значению, переданному через параметр.
        result = cur.fetchone() #извлекает одну строку из результата запроса.
        return result is not None #указывает, что у пользователя есть права на создание статьи.
    finally:
        # Закрытие курсора и соединения с базой данных
        dbClose(cur, conn)

@rgz.route("/")
def slesh():
    return redirect('/rgz', code=302)


@rgz.route("/rgz")
def main():
    # Проверка аутентификации пользователя
    user_is_authenticated = 'user_id' in session
#Эта строка создает переменную user_is_authenticated, которая проверяет, есть ли ключ "user_id" в объекте сеанса (session). Если этот ключ присутствует, то считается, что пользователь аутентифицирован.
    current_user = {"username": "Гость"}
#Создается словарь current_user, представляющий информацию о текущем пользователе. В данном случае, устанавливается значение "Гость
    if user_is_authenticated:
        # Если пользователь аутентифицирован, установить его имя пользователя
        current_user["username"] = session["username"]

    # Отображение главной страницы
    return render_template("index.html", user_is_authenticated=user_is_authenticated, current_user=current_user)

@rgz.route('/rgz/register', methods=["GET", "POST"]) #Эта строка указывает на создание обработчика маршрута для пути
def registerPage(): #является обработчиком для данного маршрута
    errors = []
#Если метод запроса - GET, то отображается страница регистрации с формой. Переменная errors передается в шаблон для отображения возможных ошибок.
    if request.method == "GET":
        # Отображение страницы регистрации при GET-запросе
        return render_template("register.html", errors=errors)

    # Получение данных формы при POST-запросе
    #Если метод запроса - POST, то извлекаются данные формы из запроса. Это делается с использованием объекта request
    username = request.form.get("username")
    password = request.form.get("password")

    if not (username and password):
        # Проверка наличия заполненных полей
        errors.append("Пожалуйста, заполните все поля")
        return render_template("register.html", errors=errors)
#Проверяется, заполнены ли оба поля формы (имя пользователя и пароль). Если нет, то добавляется соответствующее сообщение об ошибке
    # Хеширование пароля
    hashPassword = generate_password_hash(password)
#Пароль хешируется с использованием функции generate_password_hash из Flask. Это обеспечивает безопасное хранение пароля в базе данных.
    # Подключение к базе данных
    conn = dbConnect()
    cur = conn.cursor()
#Устанавливается соединение с базой данных и создается курсор. Затем выполняется запрос на проверку уникальности имени пользователя и, если проверка проходит успешно, происходит вставка нового пользователя в базу данных
    cur.execute(f"SELECT username FROM users WHERE username = %s;", (username,))

    if cur.fetchone() is not None:
        # Проверка уникальности имени пользователя
        errors.append("Пользователь с данным именем уже существует")
        conn.close()
        cur.close()
        return render_template("register.html", errors=errors)
#Если имя пользователя уже существует в базе данных, то добавляется сообщение об ошибке, и соединение с базой данных закрывается.
    cur.execute("INSERT INTO users (username, password) VALUES (%s, %s);", (username, hashPassword))
    conn.commit()
    conn.close()
    cur.close()
#Если проверки пройдены успешно, то транзакция фиксируется, и соединение с базой данных закрывается.
    # Перенаправление на страницу логина после успешной регистрации
    return redirect("/rgz/logins")

@rgz.route('/rgz/logins', methods=["GET", "POST"])
def loginPage():#является обработчиком для данного маршрута
    errors = []
#Если метод запроса - GET, то отображается страница входа с формой. Переменная errors передается в шаблон для отображения возможных ошибок.
    if request.method == "GET":
        # Отображение страницы логина при GET-запросе
        return render_template("login.html", errors=errors)

    # Получение данных формы при POST-запросе
    username = request.form.get("username")
    password = request.form.get("password")
#Если метод запроса - POST, то извлекаются данные формы из запроса. Это делается с использованием объекта request из Flask.
    if not (username or password):
        # Проверка наличия заполненных полей
        errors.append("Пожалуйста, заполните все поля")#используется для добавления элемента в конец списка
        return render_template("login.html", errors=errors)
#Проверяется, заполнены ли оба поля формы (имя пользователя и пароль). Если нет, то добавляется соответствующее сообщение об ошибке
    with dbConnect() as conn, conn.cursor() as cur:
#Используется конструкция with для обеспечения правильного закрытия соединения и курсора даже в случае возникновения исключения.
        try:
            # Проверка правильности логина и пароля
            cur.execute("SELECT id, password FROM users WHERE username = %s", (username,))
            result = cur.fetchone()
#Выполняется SQL-запрос для выбора id и password из таблицы users, где username соответствует введенному имени пользователя.
            if result is None:
                errors.append("Неправильный логин или пароль")
                return render_template("login.html", errors=errors)
#Если результат запроса равен None, это означает, что в базе данных не был найден пользователь с введенным именем (username). В таком случае, добавляется сообщение об ошибке в список errors
            userID, hashPassword = result
#Если результат запроса не равен None, значит, был найден пользователь с введенным именем. Далее извлекаются данные пользователя: userID и хешированный пароль (hashPassword).
 
#Затем проверяется введенный пароль с хешированным паролем в базе данных с использованием функции check_password_hash из Flask. Если пароль верен, то аутентификация считается успешной.
            if check_password_hash(hashPassword, password):
                # Успешная аутентификация
                session['user_id'] = userID
                session['username'] = username
                return redirect("/rgz")
            else:
                errors.append("Неправильный логин или пароль")
                return render_template("login.html", errors=errors)
#В случае возникновения исключения при выполнении запроса к базе данных, добавляется сообщение об ошибке в список errors. Это может произойти, например, если произошла ошибка в самом SQL-запросе или при взаимодействии с базой данных.
        except Exception as e:
            errors.append(f"Ошибка при выполнении запроса: {str(e)}")
            return render_template("login.html", errors=errors)
#В случае возникновения исключения, ошибка перехватывается, и выполняется код в блоке except. В данном коде добавляется сообщение об ошибке (включающее текст самой ошибки str(e)) в список 
@rgz.route('/rgz/logout')
def logout():
    # Выход пользователя из системы
    #Здесь используется метод pop() для удаления значений из сеанса. В данном случае, удаляются ключи 'user_id' и 'username'. Если ключи не существуют в сеансе, метод pop() возвращает None.
    session.pop('user_id', None)
    session.pop('username', None)
    return redirect("/rgz/logins")


# Маршрут для отображения списка пользователей (только для админа или авторизованного пользователя)
@rgz.route("/rgz/users")
def show_users():
    if 'user_id' not in session:
        # Перенаправление на страницу авторизации, если пользователь не авторизован
        return redirect('/rgz/logins')

    user_id = session['user_id']
    is_admin = session.get('user_id') == ADMIN_USER_ID

    if user_has_permission_to_create_article(user_id):
        conn = dbConnect()
        cur = conn.cursor()

        try:
            # Получение списка пользователей (исключая текущего пользователя)
            cur.execute("SELECT * FROM users WHERE id != %s;", (user_id,))
            result = cur.fetchall()

            return render_template("users.html", users=result, is_admin=is_admin)
        finally:
            dbClose(cur, conn)

    else:
        # Перенаправление на домашнюю страницу, если у пользователя нет прав
        return redirect('/rgz')

# Маршрут для редактирования пользователя (только для админа)
@rgz.route("/rgz/users/edit/<int:user_id>", methods=["GET", "POST"])
def edit_user(user_id):
    if 'user_id' not in session or session['user_id'] != ADMIN_USER_ID:
        # Перенаправление на страницу авторизации, если пользователь не админ
        return redirect('/rgz/logins')

    conn = dbConnect()
    cur = conn.cursor()

    try:
        if request.method == "GET":
            # Отображение формы редактирования пользователя при GET-запросе
            cur.execute("SELECT id, username FROM users WHERE id = %s;", (user_id,))
            user = cur.fetchone()
            return render_template("edit_user.html", user=user)
        elif request.method == "POST":
            # Обработка формы редактирования при POST-запросе
            new_username = request.form.get("new_username")
            cur.execute("UPDATE users SET username = %s WHERE id = %s;", (new_username, user_id))
            conn.commit()
            return redirect('/rgz/users')
    finally:
        dbClose(cur, conn)

# Маршрут для отправки сообщения (POST-запрос)
@rgz.route("/rgz/send_message/<int:recipient_id>", methods=["POST"])
def send_message(recipient_id):
    if 'user_id' not in session:
        # Перенаправление на страницу авторизации, если пользователь не авторизован
        return redirect('/rgz/logins')

    current_user_id = session['user_id']

    if current_user_id != recipient_id:
        conn = dbConnect()
        cur = conn.cursor()

        try:
            message_text = request.form.get("user_comment")

            if message_text:
                # Вставка нового сообщения в базу данных
                cur.execute("INSERT INTO message (user_id, sender_id, recipient_id, message_text) VALUES (%s, %s, %s, %s);", (recipient_id, current_user_id, recipient_id, message_text))
                conn.commit()

        finally:
            dbClose(cur, conn)

    return redirect('/rgz/users')

# Маршрут для удаления сообщений (POST-запрос)
@rgz.route("/rgz/delete_messages/<int:recipient_id>", methods=["POST"])
def delete_messages(recipient_id):
    if 'user_id' not in session:
        # Перенаправление на страницу авторизации, если пользователь не авторизован
        return redirect('/rgz/logins')

    current_user_id = session['user_id']

    conn = dbConnect()
    cur = conn.cursor()

    try:
        # Удаление отправленных сообщений
        cur.execute("DELETE FROM message WHERE sender_id = %s AND recipient_id = %s;", (current_user_id, recipient_id))

        # Удаление принятых сообщений
        cur.execute("DELETE FROM message WHERE sender_id = %s AND user_id = %s;", (recipient_id, current_user_id))

        conn.commit()
    finally:
        dbClose(cur, conn)

    return redirect('/rgz/users')

# Маршрут для отображения сообщений пользователя
@rgz.route("/rgz/massege")
def massege():
    if 'user_id' not in session:
        # Перенаправление на страницу авторизации, если пользователь не авторизован
        return redirect('/rgz/logins')

    user_id = session['user_id']

    conn = dbConnect()
    cur = conn.cursor()

    try:
        # Получение входящих сообщений для текущего пользователя с именами отправителей
        cur.execute("""
            SELECT m.id, u.username, m.message_text
            FROM message m
            JOIN users u ON m.sender_id = u.id
            WHERE m.recipient_id = %s;
        """, (user_id,))
        messages = cur.fetchall()

        return render_template("massege.html", messages=messages)
    finally:
        dbClose(cur, conn)

# Маршрут для удаления сообщения (GET-запрос)
@rgz.route("/rgz/delete_message/<int:message_id>")
def delete_message(message_id):
    if 'user_id' not in session:
        # Перенаправление на страницу авторизации, если пользователь не авторизован
        return redirect('/rgz/logins')

    user_id = session['user_id']

    conn = dbConnect()
    cur = conn.cursor()

    try:
        # Проверка, принадлежит ли сообщение текущему пользователю
        cur.execute("SELECT id FROM message WHERE id = %s AND recipient_id = %s;", (message_id, user_id))
        result = cur.fetchone()

        if result:
            # Удаление сообщения
            cur.execute("DELETE FROM message WHERE id = %s;", (message_id,))
            conn.commit()

    finally:
        dbClose(cur, conn)

    return redirect('/rgz/massege')

# Маршрут для удаления пользователя (только для админа)
@rgz.route("/rgz/users/delete/<int:user_id>")
def delete_user(user_id):
    if 'user_id' not in session or session['user_id'] != ADMIN_USER_ID:
        # Перенаправление на страницу авторизации, если пользователь не админ
        return redirect('/rgz/logins')

    conn = dbConnect()
    cur = conn.cursor()

    try:
        # Удаление пользователя
        cur.execute("DELETE FROM users WHERE id = %s;", (user_id,))
        conn.commit()
    finally:
        dbClose(cur, conn)

    return redirect('/rgz/users')