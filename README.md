# To-Do List Web Application

A web-based version of the to-do list application built with Flask.

## Features

- Add new tasks to your to-do list
- List all tasks with their completion status
- Remove tasks from the list
- Mark tasks as completed
- Modern and responsive web interface
- Data persistence using JSON file storage

## Requirements

- Python 3.6 or higher
- Flask 2.3.3
- Werkzeug 2.3.7
- Jinja2 3.1.2

## Installation

1. Make sure you have Python installed on your system
2. Navigate to the directory containing the application
3. Install the required dependencies:

```
pip install -r requirements.txt
```

## How to Run

1. Navigate to the application directory
2. Run the application using:

```
python app.py
```

3. Open your web browser and go to `http://127.0.0.1:5000/`

## Usage

The web application provides an intuitive interface:

1. **Add a new task** - Enter a task in the input field and click "Add Task"
2. **View all tasks** - All tasks are displayed on the main page
3. **Mark a task as completed** - Click the "Complete" button next to a task
4. **Remove a task** - Click the "Remove" button next to a task

## Data Storage

Your tasks are automatically saved to a file named `tasks.json` in the application directory. This ensures that your tasks persist between application runs.