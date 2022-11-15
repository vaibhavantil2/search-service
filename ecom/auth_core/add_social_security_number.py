




from flask_login import(
  login_user,
  logout_user,
  login_required,
  current_user
)
from .models import User, Accounts, Messages
from flask import(
  Blueprint,
  render_template, 
  redirect,
  g,
  url_for,
  request, 
  session,
  flash
)
from werkzeug.security import(
  generate_password_hash,
  check_password_hash
)
from . import db, main
import onetimepass
import pyqrcode
from io import BytesIO


auth = Blueprint('auth', __name__)

@auth.route('/logout')
@login_required
def logout():
  from .models import User
  try:
    logout_user()
    flash('Logout successful!')
  except:
    flash('logout error')  
  return redirect(url_for('main.index'))

@auth.route('/signup', methods=['POST'])
def signup():
  if current_user.is_authenticated:
    return redirect(urL_for('index'))

  social_security_number = str(request.form.get('social_security_number'))
  email = str(request.form.get('email'))
  name = str(request.form.get('given_name')) + ' ' + str(request.form.get('surname'))
  address = str(request.form.get('Street_Address'))
  post_code = str(request.form.get('post_code'))
  phone_number = str(request.form.get('phone_number'))
  password1 = request.form.get('password1')
  password2 = request.form.get('password2')

  if password1 == password2:
    password = password1
  else:
    flash('Password entires must match')
    return redirect(url_for('auth.signup'))
  
  if (len(password) <=12) or (len(password)>64):
    flash('Password too weak, choose a minimum of 12 characters and maximum of 64')
    return redirect(url_for('auth.signup'))

  mail = User.query.filter_by(email=email).first()
  if mail:
    flash('Email address already exists')
    return redirect(url_for('auth.signup'))
  elif len(email) >=256:
    flash('Email too long')
    return redirect(url_for('auth.signup'))

  if (len(address)<=0 or len(address)>=256):
    flash ('None or too long address')
    return redirect(url_for('auth.signup'))
  
  if (len(post_code)!=4):
    flash ('Post code is 4 digits')
    return redirect(url_for('auth.signup'))

  if (len(name) <=0 or len(name)>=500):
    flash ('Name is too long')
    return redirect(url_for('auth.signup'))

  identity = User.query.filter_by(social_security_number=social_security_number).first()
  if identity:
    flash('Social security number already registered')
    return redirect(url_for('auth.signup'))

  from .nexhaiFunctions import security_id_check
  check = security_id_check(str(social_security_number))
  if check == False:
    flash('Invalid social security number')
    return redirect(url_for('auth.signup'))
  
  new_user = User(
    social_security_number=social_security_number,
    email = email,
    password=generate_password_hash(password, method='sha256'),
    name=name,
    phone_number=phone_number,
    address = address,
    post_code = post_code, 
  )

  new_account_exp = int
  new_account_sav = int
  while (new_account_exp == new_account_sav):
    number = Accounts.acc_num_gen()
    for i in range(1,len(number)-1):
      new_account_exp = Accounts.query.filter_by(acc_num_exp = int(number[i])).first()
      new_account_exp = Accounts.query.filter_by(acc_num_sav = int(number[i])).first()
      if new_account_exp is None:
        new_account_exp = int(number[i])
      new_account_sav = Accounts.query.filter_by(acc_num_exp = int(number[i+1])).first()
      new_account_sav = Accounts.query.filter_by(acc_num_sav = int(number[i+1])).first()
      if new_account_sav is None:
        new_account_sav = int(number[i+1])

  new_acc = Accounts(
    social_security_number = social_security_number,
    acc_num_exp = new_account_exp,
    acc_num_exp_bal=10000,
    acc_num_sav = new_account_sav,
    acc_num_sav_bal=10000,
  )
  new_msg = Messages(
    social_security_number = social_security_number,
  )

  db.session.add(new_user)
  db.session.add(new_acc)
  db.session.commit()
  session['social_security_number'] = social_security_number
  
  return redirect(url_for('auth.two_factor_setup'))

@auth.route('/two_factor_setup')
def two_factor_setup():
  if 'social_security_number' not in session:
    return redirect(url_for('main.index'))
  user = User.query.filter_by(social_security_number=session['social_security_number']).first()
  if user is None:
    return redirect(url_for('main.index'))
  token = request.form.get('token')
  return render_template('two_factor_setup.html'), 200, {
    'Cache-Control': 'no-cache, no-store, must-revalidate',
    'Pragma': 'no-cache',
    'Expires': '0'}

@auth.route('/qrcode')
def qrcode():
  if 'social_security_number' not in session:
    return redirect(url_for('main.index'))
  user = User.query.filter_by(social_security_number=session['social_security_number']).first()
  if user is None:
    return redirect(url_for('main.index'))
  
  url = pyqrcode.create(user.get_totp_uri())
  stream = BytesIO()
  url.svg(stream, scale=5)
  return stream.getvalue(), 200, {
        'Content-Type': 'image/svg+xml',
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Pragma': 'no-cache',
        'Expires': '0'}

@auth.route('/validate', methods=['POST'])
def validate():
  token = request.form.get('token')
  user = User.query.filter_by(social_security_number=session['social_security_number']).first()
  if not user.verify_totp(token):
    flash('invalid token, re-register again')
    User.query.filter_by(social_security_number = user.social_security_number).delete()
    Messages.query.filter_by(social_security_number = Messages.social_security_number).delete()
    Accounts.query.filter_by(social_security_number = Accounts.social_security_number).delete()
    db.session.commit()
    return redirect(url_for('auth.signup'))
  user.validated = True
  flash('validation successful')
  db.session.commit()
  return redirect(url_for('main.login'))

@auth.route('/login', methods=['POST'])
def login():
  social_security_number = request.form.get('social_security_number')
  token = request.form.get('token')
  user = User.query.filter_by(social_security_number = social_security_number).first()
  
  if not user:
    flash('invalid input')
    return redirect(url_for('auth.login'))
  elif not user.verify_totp(token):
    flash('invalid input')
    return redirect(url_for('auth.login'))
  elif user.validated==False:
    flash('unvalidated or locked account, contact support')
    return redirect(url_for('auth.login'))

  session['social_security_number'] = user.social_security_number
  
  return redirect(url_for('auth.login_psw'))
  
@auth.route('/login_psw', methods=['POST'])
def login_psw():
  social_security_number = session['social_security_number']
  del session['social_security_number']
  user = User.query.filter_by(social_security_number = social_security_number).first()

  password = request.form.get('password')
  if not check_password_hash(user.password, password):
    user.attempts -= 1
    db.session.commit()
    if user.attempts == 1:
      flash('This is your final attempt before your account will be locked')
    elif user.attempts <= 0:
      flash('Your account is locked')
      user.validated=False
    db.session.commit()
    flash('Invalid entries')
    return redirect(url_for('auth.login'))

  login_user(user)
  user.attemps = 5
  db.session.commit()
  return redirect(url_for('main.profile'))

@auth.route('/accounts', methods=['POST'])
@login_required
def accounts():
  user = current_user
  user = User.query.filter_by(social_security_number=user.social_security_number).first()
  acc = Accounts.query.filter_by(social_security_number = user.social_security_number).first()
  password = request.form.get('password')
  if not check_password_hash(user.password, password):
    flash('Access denied')
    return redirect(url_for('auth.accounts'))
  token = request.form.get('token')
  if not user.verify_totp(token):
    flash('Access denied')
    return redirect(url_for('auth.accounts'))
  return render_template('transfer.html', user=user, acc = acc)
  
 
@auth.route('/transfer', methods=['POST'])
@login_required
def transfer():
  user = current_user 
  acc = Accounts.query.filter_by(social_security_number = user.social_security_number).first()
  acc_from = int(request.form.get('trans_from'))
  acc_to = int(request.form.get('trans_to'))
  amount = int(request.form.get('amount'))
  Accounts.transfer(acc_from, acc_to, amount)
  return redirect(url_for('auth.accounts'))


@auth.route('/inbox', methods=['POST'])
@login_required
def inbox_read():
  user = current_user
  message = db.session.query(user.social_security_number, Messages.content_title).all()
  for i in range(len(message)):
    message[i] = str(message[i]).replace("('", "").replace("',)", "")
  user = User.query.filter_by(social_security_number = user.social_security_number).first()

  password = request.form.get('password')
  if not check_password_hash(user.password, password):
    flash('Access denied')
    return redirect(url_for('main.messages'))
  token = request.form.get('token')
  if not user.verify_totp(token):
    flash('Access denied')
    return redirect(url_for('main.messages'))
  return render_template('inbox.html', user = current_user, message = message)


@auth.route('/messages', methods=['POST'])
@login_required
def messages():
  user = current_user
  message = Messages.query.filter(user.social_security_number==Messages.social_security_number).all()
  message_id = message
  msg = request.form.get('message')
  if (len(str(msg)) > 1024):
    flash('ERROR: message too long')
    return render_template('inbox.html', user=user, message=message)
  if (len(str(msg)) < 10):
    flash('ERROR: message too short')
    return render_template('inbox.html', user=user, message=message)
  content_title = request.form.get('message_recipient')
  content = msg 
  social_security_number = user.social_security_number

  new_message = Messages(
    social_security_number = social_security_number,
    content_title = str(content_title),
    content = content,
  )
  flash('Message sent')
  db.session.add(new_message)
  db.session.commit()

  return render_template('messages.html', user = user)
