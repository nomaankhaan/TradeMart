from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from wtforms import StringField, PasswordField, BooleanField, SubmitField, FloatField, IntegerField, FileField
from flask_wtf import FlaskForm
from wtforms.validators import DataRequired
# Initialize the db here to avoid circular import
db = SQLAlchemy()

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False, unique=True)
    email = db.Column(db.String(150), nullable=False, unique=True)
    password_hash = db.Column(db.String(256), nullable=False)
    is_wholesaler = db.Column(db.Boolean, default=False)

    def __repr__(self):
        return f'<User {self.username}>'

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    price = db.Column(db.Float, nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    wholesaler_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    orders = db.relationship('Order', backref='product', lazy=True)
    image_filename = db.Column(db.String(255))  # Make sure this line is present


    def __repr__(self):
        return f'<Product {self.name}>'

class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    vendor_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'))
    quantity = db.Column(db.Integer, nullable=False)

    def __repr__(self):
        return f'<Order {self.id}>'

class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'))

    def __repr__(self):
        return f'<Notification {self.id}>'
    
class ProductForm(FlaskForm):
    name = StringField('Product Name', validators=[DataRequired()])
    description = StringField('Description', validators=[DataRequired()])
    price = FloatField('Price', validators=[DataRequired()])
    quantity = IntegerField('Quantity', validators=[DataRequired()])
    image = FileField('Product Image')
    submit = SubmitField('Add Product')
