from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField, FloatField, IntegerField, FileField
from wtforms.validators import DataRequired, Email, EqualTo, ValidationError
from flask_migrate import Migrate
from flask_mail import Mail, Message
import stripe
from functools import wraps
from forms import RegistrationForm, LoginForm, ProductForm
import stripe
import os
from PIL import Image
import io


app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///vendor_wholesaler.db'
app.config['MAIL_SERVER'] = 'smtp.example.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'your_email@example.com'
app.config['MAIL_PASSWORD'] = 'your_email_password'
app.config['STRIPE_PUBLIC_KEY'] = 'your_stripe_public_key'
app.config['STRIPE_SECRET_KEY'] = 'your_stripe_secret_key'
app.config['UPLOAD_FOLDER'] = os.path.join(app.root_path, 'static', 'product_images')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max-limit

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

db = SQLAlchemy(app)
migrate = Migrate(app, db)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
mail = Mail(app)
stripe.api_key = app.config['STRIPE_SECRET_KEY']


# Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    is_wholesaler = db.Column(db.Boolean, default=False)
    products = db.relationship('Product', backref='wholesaler', lazy=True)
    orders = db.relationship('Order', backref='vendor', lazy=True)

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    price = db.Column(db.Float, nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    wholesaler_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    orders = db.relationship('Order', backref='product', lazy=True)
    image_filename = db.Column(db.String(255))  # Make sure this line is present

class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    vendor_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    status = db.Column(db.String(20), default='Pending')
    delivery_method = db.Column(db.String(20), default='Pickup')

class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    is_active = db.Column(db.Boolean, default=True)

# Forms
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    is_wholesaler = BooleanField('Register as Wholesaler')
    submit = SubmitField('Sign Up')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')

class ProductForm(FlaskForm):
    name = StringField('Product Name', validators=[DataRequired()])
    description = StringField('Description', validators=[DataRequired()])
    price = FloatField('Price', validators=[DataRequired()])
    quantity = IntegerField('Quantity', validators=[DataRequired()])
    image = FileField('Product Image')
    submit = SubmitField('Add Product')

def save_product_image(image_file):
    if image_file:
        filename = secure_filename(image_file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        image_file.save(file_path)
        return filename
    return None

# Helper functions
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def wholesaler_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_wholesaler:
            flash('This page is only accessible to wholesalers.', 'warning')
            return redirect(url_for('home'))
        return f(*args, **kwargs)
    return decorated_function

def send_notification_email(user, product):
    msg = Message('Product Now Available',
                  sender='noreply@example.com',
                  recipients=[user.email])
    msg.body = f'The product {product.name} is now available.'
    mail.send(msg)

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def save_product_image(image_file):
    if image_file and allowed_file(image_file.filename):
        filename = secure_filename(image_file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        image_file.save(file_path)
        return filename
    return None

def resize_image(image_file, size=(300, 300)):
    img = Image.open(image_file)
    img.thumbnail(size)
    img_io = io.BytesIO()
    img.save(img_io, 'JPEG', quality=85)
    img_io.seek(0)
    return img_io


# Routes
@app.route('/')
def home():
    return render_template('home.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data)
        user = User(username=form.username.data, email=form.email.data, password_hash=hashed_password, is_wholesaler=form.is_wholesaler.data)
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created! You are now able to log in', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.is_wholesaler:
        products = Product.query.filter_by(wholesaler_id=current_user.id).all()
        orders = Order.query.join(Product).filter(Product.wholesaler_id == current_user.id).all()
    else:
        products = Product.query.all()
        orders = Order.query.filter_by(vendor_id=current_user.id).all()
    return render_template('dashboard.html', products=products, orders=orders)

@app.route('/products')
@login_required
def products():
    page = request.args.get('page', 1, type=int)
    products = Product.query.paginate(page=page, per_page=10)
    return render_template('products.html', products=products)

@app.route('/place_order/<int:product_id>', methods=['POST'])
@login_required
def place_order(product_id):
    product = Product.query.get_or_404(product_id)
    if product.quantity > 0:
        order = Order(vendor_id=current_user.id, product_id=product_id, quantity=1)
        product.quantity -= 1
        db.session.add(order)
        db.session.commit()
        flash('Order placed successfully!', 'success')
    else:
        flash('Product is out of stock!', 'danger')
    return redirect(url_for('products'))

@app.route('/search')
@login_required
def search():
    query = request.args.get('query')
    products = Product.query.filter(Product.name.contains(query) | Product.description.contains(query)).all()
    return render_template('search_results.html', products=products, query=query)

@app.route('/notify/<int:product_id>')
@login_required
def notify(product_id):
    notification = Notification(user_id=current_user.id, product_id=product_id)
    db.session.add(notification)
    db.session.commit()
    flash('You will be notified when this product becomes available.', 'success')
    return redirect(url_for('products'))

@app.route('/checkout/<int:order_id>', methods=['GET', 'POST'])
@login_required
def checkout(order_id):
    order = Order.query.get_or_404(order_id)
    if request.method == 'POST':
        try:
            customer = stripe.Customer.create(email=current_user.email, source=request.form['stripeToken'])
            charge = stripe.Charge.create(
                customer=customer.id,
                amount=int(order.product.price * 100),  # Amount in cents
                currency='usd',
                description=f'Order {order.id}'
            )
            order.status = 'Paid'
            db.session.commit()
            flash('Payment successful!', 'success')
            return redirect(url_for('dashboard'))
        except stripe.error.CardError as e:
            flash('Payment failed. Please try again.', 'danger')
    return render_template('checkout.html', order=order, key=app.config['STRIPE_PUBLIC_KEY'])

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and check_password_hash(user.password_hash, form.password.data):
            login_user(user, remember=form.remember.data)
            flash('Logged in successfully.', 'success')
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('dashboard'))
        else:
            flash('Invalid email or password.', 'danger')
    return render_template('login.html', form=form)

@app.route('/add_product', methods=['GET', 'POST'])
@login_required
@wholesaler_required
def add_product():
    form = ProductForm()
    if form.validate_on_submit():
        try:
            image_filename = None
            if form.image.data:
                image = resize_image(form.image.data)
                image_filename = secure_filename(form.image.data.filename)
                image_path = os.path.join(app.config['UPLOAD_FOLDER'], image_filename)
                with open(image_path, 'wb') as f:
                    f.write(image.getvalue())
            
            new_product = Product(
                name=form.name.data,
                description=form.description.data,
                price=form.price.data,
                quantity=form.quantity.data,
                wholesaler_id=current_user.id,
                image_filename=image_filename
            )
            db.session.add(new_product)
            db.session.commit()
            flash('Product added successfully.', 'success')
            return redirect(url_for('dashboard'))
        except Exception as e:
            db.session.rollback()
            flash(f'An error occurred while adding the product: {str(e)}', 'danger')
    return render_template('add_product.html', form=form)


@app.route('/edit_product/<int:product_id>', methods=['GET', 'POST'])
@login_required
@wholesaler_required
def edit_product(product_id):
    product = Product.query.get_or_404(product_id)
    if product.wholesaler_id != current_user.id:
        abort(403)
    
    form = ProductForm(obj=product)
    if form.validate_on_submit():
        try:
            form.populate_obj(product)
            if form.image.data:
                image = resize_image(form.image.data)
                if product.image_filename:
                    old_image_path = os.path.join(app.config['UPLOAD_FOLDER'], product.image_filename)
                    if os.path.exists(old_image_path):
                        os.remove(old_image_path)
                image_filename = secure_filename(form.image.data.filename)
                image_path = os.path.join(app.config['UPLOAD_FOLDER'], image_filename)
                with open(image_path, 'wb') as f:
                    f.write(image.getvalue())
                product.image_filename = image_filename
            db.session.commit()
            flash('Product updated successfully.', 'success')
            return redirect(url_for('dashboard'))
        except Exception as e:
            db.session.rollback()
            flash(f'An error occurred while updating the product: {str(e)}', 'danger')
    return render_template('edit_product.html', form=form, product=product)

@app.route('/complete_order/<int:order_id>', methods=['POST'])
@login_required
@wholesaler_required
def complete_order(order_id):
    order = Order.query.get_or_404(order_id)
    if order.product.wholesaler_id != current_user.id:
        flash('You do not have permission to complete this order.', 'danger')
        return redirect(url_for('dashboard'))
    
    order.status = 'Completed'
    db.session.commit()
    flash('Order completed successfully.', 'success')
    return redirect(url_for('dashboard'))

@app.route('/remove_product/<int:product_id>', methods=['POST'])
@login_required
@wholesaler_required
def remove_product(product_id):
    product = Product.query.get_or_404(product_id)
    if product.wholesaler_id != current_user.id:
        abort(403)
    
    # Check if there are any orders associated with this product
    associated_orders = Order.query.filter_by(product_id=product_id).all()
    
    if associated_orders:
        # Option 1: Prevent deletion if there are associated orders
        #flash('Cannot remove product. There are existing orders for this product.', 'danger')
        #return redirect(url_for('dashboard'))
        
        # Option 2 (Alternative): Delete associated orders
        for order in associated_orders:
            db.session.delete(order)

    try:
        # Delete the product image if it exists
        if product.image_filename:
            image_path = os.path.join(app.config['UPLOAD_FOLDER'], product.image_filename)
            if os.path.exists(image_path):
                os.remove(image_path)
        
        db.session.delete(product)
        db.session.commit()
        flash('Product removed successfully.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'An error occurred while removing the product: {str(e)}', 'danger')
    
    return redirect(url_for('dashboard'))

if __name__ == '__main__':
    app.run(debug=True)