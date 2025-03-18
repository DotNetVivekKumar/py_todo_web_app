from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
import json
import os
import hashlib
from flask_dance.contrib.google import make_google_blueprint, google
from flask_dance.contrib.facebook import make_facebook_blueprint, facebook
from flask_dance.contrib.github import make_github_blueprint, github
from flask_dance.consumer import oauth_authorized
from flask_dance.consumer.storage.session import SessionStorage
import secrets

# Add these lines to allow OAuth over HTTP (for development only)
import os
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
os.environ['OAUTHLIB_RELAX_TOKEN_SCOPE'] = '1'

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Required for flash messages and sessions
app.config["GOOGLE_OAUTH_CLIENT_ID"] = "your-google-client-id"
app.config["GOOGLE_OAUTH_CLIENT_SECRET"] = "your-google-client-secret"
app.config["FACEBOOK_OAUTH_CLIENT_ID"] = "your-facebook-client-id"
app.config["FACEBOOK_OAUTH_CLIENT_SECRET"] = "your-facebook-client-secret"
app.config["GITHUB_OAUTH_CLIENT_ID"] = "your-github-client-id"
app.config["GITHUB_OAUTH_CLIENT_SECRET"] = "your-github-client-secret"

# Create OAuth blueprints
google_bp = make_google_blueprint(scope=["profile", "email"], storage=SessionStorage())
facebook_bp = make_facebook_blueprint(scope=["email"], storage=SessionStorage())
github_bp = make_github_blueprint(storage=SessionStorage())

# Register blueprints
app.register_blueprint(google_bp, url_prefix="/login/google")
app.register_blueprint(facebook_bp, url_prefix="/login/facebook")
app.register_blueprint(github_bp, url_prefix="/login/github")

@app.template_global()
def enumerate(iterable, start=0):
    return __builtins__['enumerate'](iterable, start)

class User:
    def __init__(self):
        self.users_file = "users.json"
        self.users = self.load_users()
    
    def load_users(self):
        """Load users from a JSON file if it exists."""
        if os.path.exists(self.users_file):
            try:
                with open(self.users_file, 'r') as f:
                    return json.load(f)
            except json.JSONDecodeError:
                return self.create_default_users()
        else:
            return self.create_default_users()
    
    def create_default_users(self):
        """Create a default user for testing."""
        # Create a default user with username: admin, password: password123
        users = {
            "admin": {
                "password_hash": self.hash_password("password123"),
                "auth_type": "local"
            }
        }
        self.save_users(users)
        return users
    
    def save_users(self, users=None):
        """Save users to a JSON file."""
        if users is None:
            users = self.users
        with open(self.users_file, 'w') as f:
            json.dump(users, f)
    
    def hash_password(self, password):
        """Create a salted hash of the password."""
        salt = "todoappsalt"
        salted = password + salt
        return hashlib.sha256(salted.encode()).hexdigest()
    
    def authenticate(self, username, password):
        """Authenticate a user."""
        if username in self.users and self.users[username].get("auth_type") == "local":
            stored_hash = self.users[username]["password_hash"]
            if self.hash_password(password) == stored_hash:
                return True
        return False
    
    def register(self, username, password, auth_type="local"):
        """Register a new user."""
        if username in self.users:
            return False
        
        if auth_type == "local":
            self.users[username] = {
                "password_hash": self.hash_password(password),
                "auth_type": auth_type
            }
        else:
            # For social logins, we don't store a password
            self.users[username] = {
                "auth_type": auth_type
            }
        
        self.save_users()
        return True
    
    def get_or_create_social_user(self, email, auth_type):
        """Get or create a user from social login."""
        # Use email as username for social logins
        username = f"{auth_type}_{email}"
        
        if username not in self.users:
            # Create a new user with social auth type
            self.register(username, None, auth_type=auth_type)
        
        return username

class TodoList:
    def __init__(self, username):
        self.tasks = []
        self.filename = f"tasks_{username}.json"
        self.load_tasks()
    
    def add_task(self, task):
        """Add a new task to the to-do list."""
        self.tasks.append({"task": task, "completed": False})
        self.save_tasks()
        return True
    
    def list_tasks(self):
        """Return all tasks in the to-do list."""
        return self.tasks
    
    def remove_task(self, task_index):
        """Remove a task from the to-do list by its index."""
        if 0 <= task_index < len(self.tasks):
            removed_task = self.tasks.pop(task_index)
            self.save_tasks()
            return removed_task
        return None
    
    def mark_completed(self, task_index):
        """Mark a task as completed by its index."""
        if 0 <= task_index < len(self.tasks):
            self.tasks[task_index]["completed"] = True
            self.save_tasks()
            return True
        return False
    
    def save_tasks(self):
        """Save tasks to a JSON file."""
        with open(self.filename, 'w') as f:
            json.dump(self.tasks, f)
    
    def load_tasks(self):
        """Load tasks from a JSON file if it exists."""
        if os.path.exists(self.filename):
            try:
                with open(self.filename, 'r') as f:
                    self.tasks = json.load(f)
            except json.JSONDecodeError:
                self.tasks = []
        else:
            self.tasks = []

# Create a global instance of User
user_manager = User()

# Helper function to get the todo list for the current user
def get_todo_list():
    if 'username' in session:
        return TodoList(session['username'])
    return None

@app.route('/')
def index():
    """Redirect to login page if not logged in, otherwise show the to-do list."""
    if 'username' not in session:
        return redirect(url_for('login'))
    
    todo_list = get_todo_list()
    tasks = todo_list.list_tasks()
    return render_template('index.html', tasks=tasks, username=session['username'])

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Handle user login."""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if user_manager.authenticate(username, password):
            session['username'] = username
            flash('Login successful!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password!', 'error')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    """Handle user logout."""
    session.pop('username', None)
    flash('You have been logged out!', 'success')
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    """Handle user registration."""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        if not username or not password:
            flash('Username and password are required!', 'error')
        elif password != confirm_password:
            flash('Passwords do not match!', 'error')
        elif user_manager.register(username, password):
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('login'))
        else:
            flash('Username already exists!', 'error')
    
    return render_template('register.html')

@app.route('/add', methods=['POST'])
def add():
    """Add a new task to the to-do list."""
    if 'username' not in session:
        return redirect(url_for('login'))
    
    task = request.form.get('task')
    if task:
        todo_list = get_todo_list()
        todo_list.add_task(task)
        flash('Task added successfully!', 'success')
    else:
        flash('Task cannot be empty!', 'error')
    return redirect(url_for('index'))

@app.route('/remove/<int:task_id>', methods=['POST'])
def remove(task_id):
    """Remove a task from the to-do list."""
    if 'username' not in session:
        return redirect(url_for('login'))
    
    todo_list = get_todo_list()
    if todo_list.remove_task(task_id):
        flash('Task removed successfully!', 'success')
    else:
        flash('Failed to remove task!', 'error')
    return redirect(url_for('index'))

@app.route('/complete/<int:task_id>', methods=['POST'])
def complete(task_id):
    """Mark a task as completed."""
    if 'username' not in session:
        return redirect(url_for('login'))
    
    todo_list = get_todo_list()
    if todo_list.mark_completed(task_id):
        flash('Task marked as completed!', 'success')
    else:
        flash('Failed to mark task as completed!', 'error')
    return redirect(url_for('index'))

@app.route("/login/google")
def google_login():
    """Initiate Google OAuth login."""
    if not google.authorized:
        return redirect(url_for("google.login"))
    return redirect(url_for("index"))

@app.route("/login/google/authorized")
def google_authorized():
    """Handle Google OAuth callback."""
    if not google.authorized:
        flash('Failed to log in with Google.', 'error')
        return redirect(url_for('login'))
    
    resp = google.get("/oauth2/v1/userinfo")
    if resp.ok:
        email = resp.json()["email"]
        username = user_manager.get_or_create_social_user(email, "google")
        session['username'] = username
        flash('Logged in successfully with Google!', 'success')
        return redirect(url_for('index'))
    
    flash('Failed to get user info from Google.', 'error')
    return redirect(url_for('login'))

@app.route("/login/facebook")
def facebook_login():
    """Initiate Facebook OAuth login."""
    if not facebook.authorized:
        return redirect(url_for("facebook.login"))
    return redirect(url_for("index"))

@app.route("/login/facebook/authorized")
def facebook_authorized():
    """Handle Facebook OAuth callback."""
    if not facebook.authorized:
        flash('Failed to log in with Facebook.', 'error')
        return redirect(url_for('login'))
    
    resp = facebook.get("/me?fields=email")
    if resp.ok:
        email = resp.json().get("email")
        if email:
            username = user_manager.get_or_create_social_user(email, "facebook")
            session['username'] = username
            flash('Logged in successfully with Facebook!', 'success')
            return redirect(url_for('index'))
    
    flash('Failed to get user info from Facebook.', 'error')
    return redirect(url_for('login'))

@app.route("/login/github")
def github_login():
    """Initiate GitHub OAuth login."""
    if not github.authorized:
        return redirect(url_for("github.login"))
    return redirect(url_for("index"))

@app.route("/login/github/authorized")
def github_authorized():
    """Handle GitHub OAuth callback."""
    if not github.authorized:
        flash('Failed to log in with GitHub.', 'error')
        return redirect(url_for('login'))
    
    resp = github.get("/user")
    if resp.ok:
        username = resp.json()["login"]
        username = user_manager.get_or_create_social_user(username, "github")
        session['username'] = username
        flash('Logged in successfully with GitHub!', 'success')
        return redirect(url_for('index'))
    
    flash('Failed to get user info from GitHub.', 'error')
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
