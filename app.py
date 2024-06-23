import pandas as pd
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask.views import MethodView
import jwt
import datetime
import hashlib
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = 'xcv' # will store it in env file
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///shopify.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# 1. Database Connection and Table Creation
class Product(db.Model):
    __tablename__ = 'product'
    product_id = db.Column(db.Integer, primary_key=True)
    product_name = db.Column(db.String(100))
    category = db.Column(db.String(50))
    price = db.Column(db.Float)
    quantity_sold = db.Column(db.Integer)
    rating = db.Column(db.Float)
    review_count = db.Column(db.Integer)

class User(db.Model):
    __tablename__ = 'user'
    user_id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)

db.create_all()

# 2. Data Upload
def upload_data(csv_file):
    df = pd.read_csv(csv_file)
    df.to_sql(name='product', con=db.engine, if_exists='replace', index=False)

# 3. Login and Sign-Up System
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.args.get('token')
        if not token:
            return jsonify({'message': 'Token is missing!'}), 403
        try:
            jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        except:
            return jsonify({'message': 'Token is invalid!'}), 403
        return f(*args, **kwargs)
    return decorated

class SignUpAPI(MethodView):
    def post(self):
        data = request.get_json()
        username = data['username']
        password = hashlib.sha256(data['password'].encode()).hexdigest()
        new_user = User(username=username, password=password)
        db.session.add(new_user)
        db.session.commit()
        return jsonify({'message': 'User created successfully'}), 201

class LoginAPI(MethodView):
    def post(self):
        data = request.get_json()
        username = data['username']
        password = hashlib.sha256(data['password'].encode()).hexdigest()
        user = User.query.filter_by(username=username, password=password).first()
        if user:
            token = jwt.encode({'user': username, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'])
            return jsonify({'token': token})
        else:
            return jsonify({'message': 'Invalid credentials'}), 401

# 4. Data Cleaning
def clean_data(df):
    df['price'].fillna(df['price'].median(), inplace=True)
    df['quantity_sold'].fillna(df['quantity_sold'].median(), inplace=True)
    df['rating'] = df.groupby('category')['rating'].transform(lambda x: x.fillna(x.mean()))
    df['price'] = pd.to_numeric(df['price'], errors='coerce')
    df['quantity_sold'] = pd.to_numeric(df['quantity_sold'], errors='coerce')
    df['rating'] = pd.to_numeric(df['rating'], errors='coerce')
    return df

# 5. Data Transformation
def transform_data(df):
    average_rating = df['rating'].mean()
    df['weighted_rating'] = (df['rating'] * df['review_count'] + average_rating * 10) / (df['review_count'] + 10)
    return df

# 6. Data Analysis
def analyze_data():
    df = pd.read_sql_table('product', con=db.engine)
    total_revenue = df.groupby('category').apply(lambda x: (x['price'] * x['quantity_sold']).sum()).reset_index()
    total_revenue.columns = ['category', 'total_revenue']
    top_products = df.sort_values('weighted_rating', ascending=False).groupby('category').first().reset_index()
    top_products = top_products[['category', 'product_name', 'quantity_sold']]
    top_products.columns = ['category', 'top_product', 'top_product_quantity_sold']
    summary = pd.merge(total_revenue, top_products, on='category')
    return summary

class ReportAPI(MethodView):
    @token_required
    def get(self):
        summary = analyze_data()
        return summary.to_csv(index=False)

# Registering the routes with the class-based views
signup_view = SignUpAPI.as_view('signup_api')
login_view = LoginAPI.as_view('login_api')
report_view = ReportAPI.as_view('report_api')

app.add_url_rule('/signup', view_func=signup_view, methods=['POST'])
app.add_url_rule('/login', view_func=login_view, methods=['POST'])
app.add_url_rule('/report', view_func=report_view, methods=['GET'])

# Initialization
if __name__ == '__main__':
    #upload_data('sample_products.csv')
    app.run(debug=True)
