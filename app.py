from flask import Flask, render_template, request, redirect, url_for, flash, session, send_file, jsonify, render_template_string
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta
from io import BytesIO
from reportlab.lib.pagesizes import letter, A5
from reportlab.pdfgen import canvas
from reportlab.lib.utils import simpleSplit
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib import colors
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import mm
from functools import wraps, lru_cache
import os
import shutil
import zipfile

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-change-this'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///shop.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_POOL_SIZE'] = 10
app.config['SQLALCHEMY_POOL_RECYCLE'] = 3600
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_pre_ping': True,
    'pool_size': 10,
    'max_overflow': 20
}
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

# Путь к базе данных (в папке instance)
DATABASE_PATH = os.path.join('instance', 'shop.db')

db = SQLAlchemy(app)

# Создаем папку для загрузок
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Кастомный фильтр для безопасной работы со строками
@app.template_filter('safe_string')
def safe_string_filter(value):
    """Возвращает пустую строку если значение None"""
    return value if value is not None else ''

# Фильтр для замены слешей
@app.template_filter('replace_slashes')
def replace_slashes_filter(value):
    """Безопасная замена обратных слешей на прямые"""
    if value is None:
        return ''
    return str(value).replace('\\', '/')

# ==============================
# 🗄️ Модели базы данных
# ==============================

class User(db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='user', index=True)
    last_active = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    orders = db.relationship('Order', backref='user', lazy='select')

class Product(db.Model):
    __tablename__ = 'product'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False, index=True)
    price = db.Column(db.Float, nullable=False)
    image = db.Column(db.String(200))
    is_archived = db.Column(db.Boolean, default=False, index=True)
    order_items = db.relationship('OrderItem', backref='product', lazy='select', cascade='all, delete-orphan')

class Order(db.Model):
    __tablename__ = 'order'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    status = db.Column(db.String(20), default='pending', index=True)
    kurs = db.Column(db.Float, nullable=False, default=12200.0)
    items = db.relationship('OrderItem', backref='order', lazy='select', cascade='all, delete-orphan')

class OrderItem(db.Model):
    __tablename__ = 'order_item'
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey('order.id'), nullable=False, index=True)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False, index=True)
    quantity = db.Column(db.Integer, default=1)

class Banner(db.Model):
    __tablename__ = 'banner'
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)

class Setting(db.Model):
    __tablename__ = 'setting'
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(50), unique=True, nullable=False, index=True)
    value = db.Column(db.Text, nullable=True)

# ==============================
# 🚀 Кэширование настроек
# ==============================

_settings_cache = {}
_cache_timestamp = None
CACHE_TTL = 300  # 5 минут

def get_setting(key, default=None):
    """Получение настройки с кэшированием"""
    global _settings_cache, _cache_timestamp
    
    now = datetime.utcnow()
    if _cache_timestamp is None or (now - _cache_timestamp).total_seconds() > CACHE_TTL:
        # Обновляем кэш
        settings = Setting.query.all()
        _settings_cache = {s.key: s.value for s in settings}
        _cache_timestamp = now
    
    return _settings_cache.get(key, default)

def invalidate_settings_cache():
    """Сброс кэша настроек"""
    global _cache_timestamp
    _cache_timestamp = None

def get_kurs():
    """Получение курса с кэшированием"""
    try:
        return float(get_setting('kurs', '12200'))
    except:
        return 12200.0

def round_price(value):
    """Округление до ближайших 100 сум"""
    return round(value / 100) * 100

# ==============================
# 🔒 Декораторы
# ==============================

def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if 'user_id' not in session:
            flash('Пожалуйста, войдите в систему', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return wrapper

def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        if session.get('role') != 'admin':  # Используем кэшированную роль из сессии
            flash('Доступ запрещен', 'danger')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return wrapper

# ==============================
# 🏠 Основные маршруты
# ==============================

@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    kurs = get_kurs()
    banners = Banner.query.all()
    products = Product.query.filter_by(is_archived=False).all()

    for p in products:
        p.price_uzs = round_price(p.price * kurs)

    return render_template('index.html', products=products, banners=banners)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        
        if not username or not password:
            flash('Заполните все поля', 'danger')
            return redirect(url_for('register'))
        
        if User.query.filter_by(username=username).first():
            flash('Пользователь уже существует', 'danger')
            return redirect(url_for('register'))
        
        user = User(username=username, password=generate_password_hash(password))
        db.session.add(user)
        db.session.commit()
        flash('Регистрация успешна!', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['username'] = user.username
            session['role'] = user.role
            flash('Вход выполнен успешно!', 'success')
            
            if user.role == 'admin':
                return redirect(url_for('admin_dashboard'))
            return redirect(url_for('index'))
        
        flash('Неверный логин или пароль', 'danger')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Вы вышли из системы', 'info')
    return redirect(url_for('index'))

# ==============================
# 🛒 Корзина
# ==============================

@app.route('/cart')
@login_required
def cart():
    kurs = get_kurs()
    cart_items = session.get('cart', {})
    
    if not cart_items:
        return render_template('cart.html', products=[], total=0)
    
    # Оптимизация: один запрос вместо множества
    product_ids = [int(pid) for pid in cart_items.keys()]
    products_dict = {p.id: p for p in Product.query.filter(Product.id.in_(product_ids)).all()}
    
    products = []
    total = 0

    for product_id, quantity in cart_items.items():
        product = products_dict.get(int(product_id))
        if product:
            price_uzs = round_price(product.price * kurs)
            products.append({'product': product, 'quantity': quantity, 'price_uzs': price_uzs})
            total += price_uzs * quantity

    return render_template('cart.html', products=products, total=total)

@app.route('/add_to_cart/<int:product_id>')
def add_to_cart(product_id):
    quantity = int(request.args.get('quantity', 1))
    if 'cart' not in session:
        session['cart'] = {}
    session['cart'][str(product_id)] = session['cart'].get(str(product_id), 0) + quantity
    session.modified = True
    return jsonify(success=True, cart_count=sum(session['cart'].values()))

@app.route('/remove_from_cart/<int:product_id>')
@login_required
def remove_from_cart(product_id):
    cart = session.get('cart', {})
    product_id_str = str(product_id)
    
    if product_id_str in cart:
        del cart[product_id_str]
        session['cart'] = cart
        flash('Товар удален из корзины', 'info')
    
    return redirect(url_for('cart'))

@app.route('/checkout')
@login_required
def checkout():
    cart = session.get('cart', {})
    if not cart:
        flash('Корзина пуста', 'warning')
        return redirect(url_for('cart'))
    
    try:
        order = Order(user_id=session['user_id'], kurs=get_kurs())
        db.session.add(order)
        db.session.flush()
        
        # Массовое добавление элементов заказа
        order_items = [
            OrderItem(order_id=order.id, product_id=int(product_id), quantity=quantity)
            for product_id, quantity in cart.items()
        ]
        db.session.bulk_save_objects(order_items)
        db.session.commit()
        
        session['cart'] = {}
        flash('Заказ успешно оформлен!', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Ошибка при оформлении заказа', 'danger')
    
    return redirect(url_for('profile'))

# ==============================
# 👤 Профиль
# ==============================

@app.route('/profile')
@login_required
def profile():
    user = User.query.get(session['user_id'])
    # Получаем последние 50 заказов с сортировкой
    orders = Order.query.filter_by(user_id=user.id).order_by(Order.created_at.desc()).limit(50).all()
    return render_template('profile.html', user=user, orders=orders)

# ==============================
# 👨‍💼 Админ-панель
# ==============================

@app.route('/admin')
@admin_required
def admin_dashboard():
    # Оптимизация: используем count() вместо загрузки всех данных
    total_users = db.session.query(db.func.count(User.id)).scalar()
    total_products = db.session.query(db.func.count(Product.id)).scalar()
    total_orders = db.session.query(db.func.count(Order.id)).scalar()
    
    # Онлайн пользователи за последние 5 минут
    threshold = datetime.utcnow() - timedelta(minutes=5)
    online_users = db.session.query(db.func.count(User.id)).filter(User.last_active >= threshold).scalar()

    return render_template(
        'admin/dashboard.html',
        total_users=total_users,
        total_products=total_products,
        total_orders=total_orders,
        online_users=online_users
    )

@app.route('/admin/users')
@admin_required
def admin_users():
    users = User.query.order_by(User.id.desc()).all()
    return render_template('admin/users.html', users=users)

@app.route('/admin/add_user', methods=['POST'])
@admin_required
def add_user():
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '').strip()
    role = request.form.get('role', 'user')
    
    if User.query.filter_by(username=username).first():
        flash('Пользователь уже существует', 'danger')
        return redirect(url_for('admin_users'))
    
    user = User(username=username, password=generate_password_hash(password), role=role)
    db.session.add(user)
    db.session.commit()
    flash('Пользователь добавлен', 'success')
    return redirect(url_for('admin_users'))

@app.route('/admin/edit_user/<int:user_id>', methods=['POST'])
@admin_required
def edit_user(user_id):
    user = User.query.get_or_404(user_id)
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '').strip()
    
    if username and username != user.username:
        if User.query.filter_by(username=username).first():
            flash('Логин уже занят', 'danger')
            return redirect(url_for('admin_users'))
        user.username = username
    
    if password:
        user.password = generate_password_hash(password)
    
    db.session.commit()
    flash('Данные пользователя обновлены', 'success')
    return redirect(url_for('admin_users'))

# ==============================
# 📦 Товары
# ==============================

@app.route('/admin/products')
@admin_required
def admin_products():
    products = Product.query.order_by(Product.id.desc()).all()
    # Убедимся что у всех товаров есть значение image (даже если None)
    for product in products:
        if product.image is None:
            product.image = ''
    return render_template('admin/products.html', products=products)

@app.route('/admin/add_product', methods=['POST'])
@admin_required
def add_product():
    name = request.form.get('name', '').strip()
    price = request.form.get('price', '0')
    image = request.files.get('image')
    
    if not name:
        flash('Введите название товара', 'danger')
        return redirect(url_for('admin_products'))
    
    try:
        price = float(price)
    except:
        flash('Неверная цена', 'danger')
        return redirect(url_for('admin_products'))
    
    image_path = ''  # По умолчанию пустая строка вместо None
    if image and image.filename:
        filename = secure_filename(image.filename)
        image_path = os.path.join('uploads', filename)
        full_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        image.save(full_path)
    
    product = Product(name=name, price=price, image=image_path if image_path else None)
    db.session.add(product)
    db.session.commit()
    flash('Товар добавлен', 'success')
    return redirect(url_for('admin_products'))

@app.route('/admin/edit_product/<int:product_id>', methods=['POST'])
@admin_required
def edit_product(product_id):
    product = Product.query.get_or_404(product_id)
    name = request.form.get('name', '').strip()
    price = request.form.get('price')
    image = request.files.get('image')

    if name:
        product.name = name
    if price:
        try:
            product.price = float(price)
        except:
            flash('Неверная цена', 'danger')
            return redirect(url_for('admin_products'))

    if image and image.filename:
        filename = secure_filename(image.filename)
        image_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        image.save(image_path)
        product.image = os.path.join('uploads', filename)

    db.session.commit()
    flash('Товар обновлен успешно', 'success')
    return redirect(url_for('admin_products'))

@app.route('/admin/delete_product/<int:product_id>')
@admin_required
def delete_product(product_id):
    product = Product.query.get_or_404(product_id)
    
    # Проверяем, есть ли заказы с этим товаром
    orders_count = OrderItem.query.filter_by(product_id=product_id).count()
    
    if orders_count > 0:
        # Вместо удаления автоматически архивируем
        product.is_archived = True
        db.session.commit()
        flash(f'Товар нельзя удалить (используется в {orders_count} заказах), поэтому он был перемещен в архив.', 'warning')
        return redirect(url_for('admin_products'))
    
    # Удаляем изображение если есть
    if product.image:
        try:
            image_path = os.path.join(app.config['UPLOAD_FOLDER'], os.path.basename(product.image))
            if os.path.exists(image_path):
                os.remove(image_path)
        except:
            pass
    
    db.session.delete(product)
    db.session.commit()
    flash('Товар успешно удален', 'success')
    return redirect(url_for('admin_products'))

@app.route('/admin/archive_product/<int:product_id>')
@admin_required
def archive_product(product_id):
    product = Product.query.get_or_404(product_id)
    product.is_archived = True
    db.session.commit()
    flash('Товар перенесен в архив', 'info')
    return redirect(url_for('admin_products'))

@app.route('/admin/unarchive_product/<int:product_id>')
@admin_required
def unarchive_product(product_id):
    product = Product.query.get_or_404(product_id)
    product.is_archived = False
    db.session.commit()
    flash('Товар восстановлен', 'success')
    return redirect(url_for('admin_products'))

# ==============================
# 📋 Заказы
# ==============================

@app.route('/admin/orders')
@admin_required
def admin_orders():
    # Оптимизация: используем joinedload для предзагрузки связанных данных
    orders = Order.query.options(
        db.joinedload(Order.user),
        db.joinedload(Order.items).joinedload(OrderItem.product)
    ).order_by(Order.created_at.desc()).limit(100).all()
    
    kurs = get_kurs()
    return render_template('admin/orders.html', orders=orders, kurs=kurs)

@app.route('/admin/update_order/<int:order_id>/<status>')
@admin_required
def update_order(order_id, status):
    if status not in ['confirmed', 'cancelled', 'pending']:
        flash('Неверный статус', 'danger')
        return redirect(url_for('admin_orders'))
    
    order = Order.query.get_or_404(order_id)
    order.status = status
    db.session.commit()
    flash('Статус заказа обновлен', 'success')
    return redirect(url_for('admin_orders'))

@app.route('/admin/print_order/<int:order_id>')
@admin_required
def print_order(order_id):
    order = Order.query.options(
        db.joinedload(Order.user),
        db.joinedload(Order.items).joinedload(OrderItem.product)
    ).get_or_404(order_id)

    kurs = order.kurs or get_kurs()
    total = 0
    items_data = []
    
    for item in order.items:
        price_uzs = round_price(item.product.price * kurs)
        summa = round_price(price_uzs * item.quantity)
        total += summa
        items_data.append({
            'name': item.product.name,
            'quantity': item.quantity,
            'price': price_uzs,
            'summa': summa
        })

    izoh = get_setting('izoh', "Yukingizni tekshirib oling, 3 kundan so'ng javob berilmaydi!")

    html_template = """
    <!DOCTYPE html>
    <html lang="uz">
    <head>
        <meta charset="UTF-8">
        <title>Chek №{{ order.id }}</title>
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
        <style>
            @page { size: A5 portrait; margin: 8mm; }
            body { font-family: "DejaVu Sans", sans-serif; font-size: 11px; color: #111; background: #f9fafb; margin: 0; padding: 0; }
            .container { width: 100%; background: #fff; box-shadow: 0 0 6px rgba(0,0,0,0.1); border-radius: 6px; padding: 12px 16px; box-sizing: border-box; }
            .header { text-align: center; font-weight: 800; font-size: 14px; color: #1e293b; margin-bottom: 2px; letter-spacing: 0.3px; }
            .sub-header { text-align: center; font-size: 10.5px; color: #6b7280; margin-bottom: 8px; }
            .divider { border-bottom: 1px dashed #d1d5db; margin: 8px 0; }
            .info { font-size: 11px; line-height: 1.5; margin-bottom: 6px; color: #111827; }
            .info i { color: #2563eb; width: 14px; text-align: center; margin-right: 4px; }
            table { width: 100%; border-collapse: collapse; margin-top: 5px; font-size: 10.5px; }
            th, td { border: 1px solid #e5e7eb; padding: 4px 3px; text-align: center; }
            th { background: #f3f4f6; font-weight: 700; color: #1e293b; }
            td:nth-child(2) { text-align: left; }
            .total { margin-top: 10px; text-align: right; font-weight: bold; border-top: 1px solid #9ca3af; padding-top: 6px; font-size: 11.5px; }
            .total i { color: #16a34a; margin-right: 4px; }
            .footer { margin-top: 10px; font-size: 10.5px; border-top: 1px dashed #ccc; padding-top: 6px; line-height: 1.4; color: #111827; }
            .footer i { color: #2563eb; margin-right: 4px; }
            .note { margin-top: 6px; text-align: center; font-size: 9.8px; color: #555; }
            @media print { body { background: #fff; } .container { box-shadow: none; border-radius: 0; } }
        </style>
    </head>
    <body onload="window.print()">
        <div class="container">
            <div class="header"><i class="fa-solid fa-store text-primary"></i> Строй Март 0111</div>
            <div class="sub-header">
                <i class="fa-solid fa-phone"></i> +998 88 202 0111 &nbsp;&nbsp; 
                <i class="fa-solid fa-coins"></i> Kurs: {{ "{:,.0f}".format(kurs) }}
            </div>
            <div class="divider"></div>
            <div class="info">
                <p><i class="fa-solid fa-user"></i> <b>Mijoz:</b> {{ order.user.username }}</p>
                <p><i class="fa-solid fa-receipt"></i> <b>Chek №:</b> {{ order.id }}</p>
                <p><i class="fa-solid fa-calendar-days"></i> <b>Sana:</b> {{ order.created_at.strftime('%d.%m.%Y %H:%M:%S') }}</p>
            </div>
            <table>
                <thead>
                    <tr>
                        <th>№</th>
                        <th>Mahsulot nomi</th>
                        <th>Miqdor</th>
                        <th>Birlik</th>
                        <th>Narx</th>
                        <th>Summa</th>
                    </tr>
                </thead>
                <tbody>
                    {% for item in items %}
                    <tr>
                        <td>{{ loop.index }}</td>
                        <td>{{ item.name }}</td>
                        <td>{{ item.quantity }}</td>
                        <td>Дона</td>
                        <td>{{ "{:,.0f}".format(item.price) }}</td>
                        <td>{{ "{:,.0f}".format(item.summa) }}</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
            <div class="total">
                <i class="fa-solid fa-wallet"></i> Jami: {{ "{:,.0f}".format(total) }} UZS<br>
                <i class="fa-solid fa-money-bill-wave"></i> To'lov: {{ "{:,.0f}".format(total) }} UZS
            </div>
            <div class="footer">
                <p><i class="fa-solid fa-pen-to-square"></i> <b>Izoh:</b> {{ izoh }}</p>
                <p><i class="fa-solid fa-mobile-screen"></i> Buyurtma mobil ilovadan yuborilgan</p>
            </div>
            <div class="note">
                <i class="fa-solid fa-heart text-danger"></i> Rahmat xaridingiz uchun!
            </div>
        </div>
    </body>
    </html>
    """

    return render_template_string(html_template, order=order, total=total, izoh=izoh, items=items_data, kurs=kurs)

@app.route('/admin/view_order_pdf/<int:order_id>')
@admin_required
def view_order_pdf(order_id):
    order = Order.query.options(
        db.joinedload(Order.user),
        db.joinedload(Order.items).joinedload(OrderItem.product)
    ).get_or_404(order_id)

    font_path = os.path.join("static", "fonts", "DejaVuSans.ttf")
    if os.path.exists(font_path):
        pdfmetrics.registerFont(TTFont("DejaVuSans", font_path))

    buffer = BytesIO()
    pdf = SimpleDocTemplate(
        buffer, pagesize=A5,
        rightMargin=10*mm, leftMargin=10*mm,
        topMargin=10*mm, bottomMargin=10*mm
    )

    styles = getSampleStyleSheet()
    normal = styles["Normal"]
    title = styles["Title"]
    elements = []

    elements.append(Paragraph("<b>ЧЕК ЗАКАЗА</b>", title))
    elements.append(Spacer(1, 6))
    elements.append(Paragraph(f"Дата: {order.created_at.strftime('%d.%m.%Y %H:%M')}", normal))
    elements.append(Paragraph(f"Заказ № <b>{order.id}</b>", normal))
    elements.append(Paragraph(f"Покупатель: <b>{order.user.username}</b>", normal))
    elements.append(Spacer(1, 10))

    data = [["Наименование", "Кол-во", "Цена", "Сумма"]]
    total = 0
    for item in order.items:
        subtotal = item.product.price * item.quantity
        data.append([
            item.product.name,
            str(item.quantity),
            f"{item.product.price:,.0f} UZS",
            f"{subtotal:,.0f} UZS"
        ])
        total += subtotal

    table = Table(data, colWidths=[60*mm, 15*mm, 25*mm, 30*mm])
    table.setStyle(TableStyle([
        ("FONT", (0, 0), (-1, -1), "DejaVuSans", 9),
        ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.black),
        ("ALIGN", (1, 1), (-1, -1), "CENTER"),
        ("ALIGN", (0, 0), (0, -1), "LEFT"),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
    ]))
    elements.append(table)
    elements.append(Spacer(1, 10))
    elements.append(Paragraph(f"<b>ИТОГО:</b> {total:,.0f} UZS", styles["Heading3"]))
    elements.append(Spacer(1, 20))
    elements.append(Paragraph("<b>Спасибо за покупку!</b>", normal))
    elements.append(Spacer(1, 5))
    elements.append(Paragraph("Ждём вас снова!", normal))

    pdf.build(elements)
    buffer.seek(0)
    return send_file(buffer, mimetype='application/pdf',
                     as_attachment=False,
                     download_name=f"order_{order.id}.pdf")

# ==============================
# 🎨 Баннеры
# ==============================

@app.route('/admin/banners')
@admin_required
def admin_banners():
    banners = Banner.query.all()
    return render_template('admin/banners.html', banners=banners)

@app.route('/admin/add_banner', methods=['POST'])
@admin_required
def add_banner():
    file = request.files.get('banner')
    if file and file.filename:
        os.makedirs('static/banners', exist_ok=True)
        filename = secure_filename(file.filename)
        path = os.path.join('static/banners', filename)
        file.save(path)

        new_banner = Banner(filename=filename)
        db.session.add(new_banner)
        db.session.commit()
        flash('Баннер добавлен', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/delete_banner/<int:banner_id>', methods=['POST'])
@admin_required
def delete_banner(banner_id):
    banner = Banner.query.get_or_404(banner_id)
    try:
        os.remove(os.path.join('static/banners', banner.filename))
    except:
        pass
    db.session.delete(banner)
    db.session.commit()
    flash('Баннер удален', 'success')
    return redirect(url_for('admin_dashboard'))

# ==============================
# ⚙️ Настройки
# ==============================

@app.route('/admin/settings', methods=['GET', 'POST'])
@admin_required
def admin_settings():
    if request.method == 'POST':
        new_izoh = request.form.get('izoh', '').strip()
        new_kurs = request.form.get('kurs', '').strip()

        # Izoh
        izoh_setting = Setting.query.filter_by(key='izoh').first()
        if izoh_setting:
            izoh_setting.value = new_izoh
        else:
            db.session.add(Setting(key='izoh', value=new_izoh))

        # Kurs
        try:
            kurs_value = float(new_kurs.replace(',', '.'))
        except:
            kurs_value = 12200.0
        
        kurs_setting = Setting.query.filter_by(key='kurs').first()
        if kurs_setting:
            kurs_setting.value = str(kurs_value)
        else:
            db.session.add(Setting(key='kurs', value=str(kurs_value)))

        db.session.commit()
        invalidate_settings_cache()  # Сбрасываем кэш
        flash('Настройки успешно обновлены!', 'success')
        return redirect(url_for('admin_settings'))

    izoh = get_setting('izoh', "Yukingizni tekshirib oling, 3 kundan so'ng javob berilmaydi!")
    kurs = get_setting('kurs', "12200")

    return render_template('admin/settings.html', izoh=izoh, kurs=kurs, now=datetime.utcnow())

# ==============================
# 💾 Резервное копирование БД
# ==============================

@app.route('/admin/backup')
@admin_required
def backup_database():
    """Скачивание резервной копии базы данных с файлами"""
    backup_dir = None
    zip_path = None
    
    try:
        # КРИТИЧНО: Закрываем все соединения с БД
        db.session.commit()
        db.session.remove()
        db.engine.dispose()
        
        # Небольшая пауза для освобождения файла
        import time
        time.sleep(0.5)
        
        # Создаем временную папку для бэкапа
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_dir = os.path.join('temp_backup', timestamp)
        os.makedirs(backup_dir, exist_ok=True)
        
        print(f"\n{'='*60}")
        print(f"🚀 Начинаем создание резервной копии...")
        print(f"{'='*60}")
        
        # 1. Копируем базу данных из папки instance
        db_source = DATABASE_PATH  # instance/shop.db
        db_dest = os.path.join(backup_dir, 'shop.db')
        
        if os.path.exists(db_source):
            print(f"📂 Найдена база данных: {db_source}")
            print(f"   Размер: {os.path.getsize(db_source)} байт")
            
            # Используем shutil.copy2 для сохранения метаданных
            shutil.copy2(db_source, db_dest)
            
            if os.path.exists(db_dest):
                print(f"✅ База данных скопирована: {db_dest}")
                print(f"   Размер копии: {os.path.getsize(db_dest)} байт")
            else:
                raise Exception("❌ Копия базы данных не создана!")
        else:
            raise Exception(f"❌ База данных не найдена: {db_source}")
        
        # 2. Копируем папку с загрузками (изображения товаров)
        if os.path.exists(app.config['UPLOAD_FOLDER']):
            uploads_backup = os.path.join(backup_dir, 'uploads')
            shutil.copytree(app.config['UPLOAD_FOLDER'], uploads_backup, dirs_exist_ok=True)
            files_count = len(os.listdir(uploads_backup))
            print(f"✅ Загрузки скопированы: {files_count} файлов")
        else:
            print(f"⚠️  Папка uploads не найдена, пропускаем")
        
        # 3. Копируем папку с баннерами
        if os.path.exists('static/banners'):
            banners_backup = os.path.join(backup_dir, 'banners')
            shutil.copytree('static/banners', banners_backup, dirs_exist_ok=True)
            banners_count = len(os.listdir(banners_backup))
            print(f"✅ Баннеры скопированы: {banners_count} файлов")
        else:
            print(f"⚠️  Папка banners не найдена, пропускаем")
        
        # 4. Создаем ZIP архив
        zip_filename = f'backup_{timestamp}.zip'
        zip_path = os.path.join('temp_backup', zip_filename)
        
        print(f"\n📦 Создаем ZIP архив: {zip_filename}")
        
        with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            # Добавляем все файлы из backup_dir в корень архива
            for root, dirs, files in os.walk(backup_dir):
                for file in files:
                    file_path = os.path.join(root, file)
                    # Путь в архиве будет относительно backup_dir
                    arcname = os.path.relpath(file_path, backup_dir)
                    zipf.write(file_path, arcname)
                    file_size = os.path.getsize(file_path)
                    print(f"   ➕ {arcname} ({file_size} байт)")
        
        # Проверяем что ZIP создан
        if not os.path.exists(zip_path):
            raise Exception("❌ ZIP файл не был создан!")
        
        zip_size = os.path.getsize(zip_path)
        print(f"\n✅ ZIP архив создан успешно!")
        print(f"   Размер архива: {zip_size} байт ({zip_size/1024:.2f} KB)")
        
        # Проверяем содержимое ZIP
        print(f"\n📋 Содержимое архива:")
        with zipfile.ZipFile(zip_path, 'r') as zipf:
            for info in zipf.filelist:
                print(f"   ✓ {info.filename} ({info.file_size} байт)")
        
        print(f"{'='*60}\n")
        
        # Читаем файл в память
        with open(zip_path, 'rb') as f:
            zip_data = BytesIO(f.read())
        
        zip_data.seek(0)
        
        # Очищаем временные файлы
        try:
            if backup_dir and os.path.exists(backup_dir):
                shutil.rmtree(backup_dir)
            if zip_path and os.path.exists(zip_path):
                os.remove(zip_path)
            print("🧹 Временные файлы очищены")
        except Exception as cleanup_error:
            print(f"⚠️  Ошибка при очистке: {cleanup_error}")
        
        # Отправляем файл пользователю
        return send_file(
            zip_data,
            mimetype='application/zip',
            as_attachment=True,
            download_name=zip_filename
        )
        
    except Exception as e:
        error_msg = f'Ошибка при создании резервной копии: {str(e)}'
        print(f"\n❌ {error_msg}\n")
        
        # Очищаем в случае ошибки
        try:
            if backup_dir and os.path.exists(backup_dir):
                shutil.rmtree(backup_dir)
            if zip_path and os.path.exists(zip_path):
                os.remove(zip_path)
        except:
            pass
        
        flash(error_msg, 'danger')
        return redirect(url_for('admin_settings'))


@app.route('/admin/restore', methods=['POST'])
@admin_required
def restore_database():
    """Восстановление базы данных из резервной копии"""
    if 'backup_file' not in request.files:
        flash('Файл не выбран', 'danger')
        return redirect(url_for('admin_settings'))
    
    file = request.files['backup_file']
    
    if file.filename == '':
        flash('Файл не выбран', 'danger')
        return redirect(url_for('admin_settings'))
    
    if not file.filename.endswith('.zip'):
        flash('Неверный формат файла. Требуется ZIP архив', 'danger')
        return redirect(url_for('admin_settings'))
    
    restore_dir = None
    
    try:
        print(f"\n{'='*60}")
        print(f"🔄 Начинаем восстановление из резервной копии...")
        print(f"{'='*60}")
        
        # Создаем временную папку для распаковки
        restore_dir = os.path.join('temp_restore')
        os.makedirs(restore_dir, exist_ok=True)
        
        # Сохраняем загруженный файл
        zip_path = os.path.join(restore_dir, 'backup.zip')
        file.save(zip_path)
        print(f"✅ ZIP файл загружен: {os.path.getsize(zip_path)} байт")
        
        # Проверяем содержимое ZIP
        print(f"\n📋 Содержимое загруженного архива:")
        with zipfile.ZipFile(zip_path, 'r') as zipf:
            file_list = zipf.namelist()
            for filename in file_list:
                print(f"   ✓ {filename}")
            
            # Проверяем наличие shop.db
            if 'shop.db' not in file_list:
                raise Exception("❌ В архиве не найдена база данных shop.db!")
        
        # Распаковываем архив
        print(f"\n📦 Распаковываем архив...")
        with zipfile.ZipFile(zip_path, 'r') as zipf:
            zipf.extractall(restore_dir)
        print(f"✅ Архив распакован в: {restore_dir}")
        
        # КРИТИЧНО: Закрываем все соединения с БД
        print(f"\n🔒 Закрываем соединения с базой данных...")
        db.session.commit()
        db.session.remove()
        db.engine.dispose()
        
        # Небольшая пауза для освобождения файлов
        import time
        time.sleep(0.5)
        
        # Восстанавливаем базу данных в папку instance
        restored_db = os.path.join(restore_dir, 'shop.db')
        if os.path.exists(restored_db):
            print(f"\n💾 Восстанавливаем базу данных...")
            
            # Создаем папку instance если её нет
            os.makedirs('instance', exist_ok=True)
            
            # Создаем резервную копию текущей БД
            if os.path.exists(DATABASE_PATH):
                backup_name = f'instance/shop.db.backup_{datetime.now().strftime("%Y%m%d_%H%M%S")}'
                shutil.copy2(DATABASE_PATH, backup_name)
                print(f"✅ Создана резервная копия: {backup_name}")
            
            # Заменяем базу данных
            shutil.copy2(restored_db, DATABASE_PATH)
            new_size = os.path.getsize(DATABASE_PATH)
            print(f"✅ База данных восстановлена! Размер: {new_size} байт")
            print(f"   Путь: {DATABASE_PATH}")
        else:
            raise Exception(f"❌ В архиве не найдена база данных: shop.db")
        
        # Восстанавливаем файлы загрузок
        restored_uploads = os.path.join(restore_dir, 'uploads')
        if os.path.exists(restored_uploads):
            print(f"\n📁 Восстанавливаем файлы загрузок...")
            if os.path.exists(app.config['UPLOAD_FOLDER']):
                shutil.rmtree(app.config['UPLOAD_FOLDER'])
            shutil.copytree(restored_uploads, app.config['UPLOAD_FOLDER'])
            files_count = len(os.listdir(app.config['UPLOAD_FOLDER']))
            print(f"✅ Восстановлено файлов: {files_count}")
        else:
            print(f"⚠️  Папка uploads не найдена в архиве")
        
        # Восстанавливаем баннеры
        restored_banners = os.path.join(restore_dir, 'banners')
        if os.path.exists(restored_banners):
            print(f"\n🎨 Восстанавливаем баннеры...")
            banners_dir = 'static/banners'
            if os.path.exists(banners_dir):
                shutil.rmtree(banners_dir)
            shutil.copytree(restored_banners, banners_dir)
            banners_count = len(os.listdir(banners_dir))
            print(f"✅ Восстановлено баннеров: {banners_count}")
        else:
            print(f"⚠️  Папка banners не найдена в архиве")
        
        # Сбрасываем кэш настроек
        invalidate_settings_cache()
        
        print(f"\n✅ Восстановление завершено успешно!")
        print(f"{'='*60}\n")
        
        # Очищаем временные файлы
        try:
            if restore_dir and os.path.exists(restore_dir):
                shutil.rmtree(restore_dir)
            print("🧹 Временные файлы очищены")
        except Exception as cleanup_error:
            print(f"⚠️  Ошибка при очистке: {cleanup_error}")
        
        # Очищаем сессию и перенаправляем на логин
        session.clear()
        flash('✅ База данных успешно восстановлена! Войдите заново.', 'success')
        return redirect(url_for('login'))
        
    except Exception as e:
        error_msg = f'Ошибка при восстановлении: {str(e)}'
        print(f"\n❌ {error_msg}\n")
        
        # Очищаем временные файлы в случае ошибки
        try:
            if restore_dir and os.path.exists(restore_dir):
                shutil.rmtree(restore_dir)
        except:
            pass
        
        flash(error_msg, 'danger')
        return redirect(url_for('admin_settings'))

# ==============================
# 🔄 Обновление активности
# ==============================

@app.before_request
def update_last_active():
    """Оптимизированное обновление активности пользователя"""
    if 'user_id' not in session:
        return

    # Игнорируем статические файлы
    if request.endpoint and (request.endpoint.startswith('static') or request.path.startswith('/static/')):
        return

    # Проверяем время последнего обновления в сессии
    last_update = session.get('_last_activity_update')
    now = datetime.utcnow()
    
    # Обновляем только раз в 60 секунд
    if last_update:
        try:
            last_update_time = datetime.fromisoformat(last_update)
            if (now - last_update_time).total_seconds() < 60:
                return
        except:
            pass

    try:
        # Используем update вместо загрузки объекта
        db.session.query(User).filter_by(id=session['user_id']).update({
            'last_active': now
        })
        db.session.commit()
        session['_last_activity_update'] = now.isoformat()
    except:
        db.session.rollback()

# ==============================
# 🚀 Инициализация
# ==============================

with app.app_context():
    db.create_all()
    
    # Создаем админа по умолчанию
    admin = User.query.filter_by(username='admin').first()
    if not admin:
        admin = User(
            username='admin',
            password=generate_password_hash('admin123'),
            role='admin'
        )
        db.session.add(admin)
        db.session.commit()

# ==============================
# 🎯 Запуск приложения
# ==============================

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=False, port=8080, threaded=True)