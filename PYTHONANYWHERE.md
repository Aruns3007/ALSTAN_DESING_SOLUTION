# PythonAnywhere Deployment Guide

This project is already close to PythonAnywhere-ready:

- `wsgi.py` exposes `application`
- `requirements.txt` lists the app dependencies
- `db.py` uses a file-based SQLite database in the project folder

## 1. Upload or clone the repo

On PythonAnywhere, place the project in a folder such as:

```text
/home/<your-username>/alstan-project
```

You can either:

- clone the GitHub repo with `git clone`, or
- upload the project files from the Files tab

If you want to keep the current data, make sure `alstandesign.db` is included too.

## 2. Create a virtualenv

Open a Bash console on PythonAnywhere and run:

```bash
mkvirtualenv --python=python3.13 alstan-venv
```

If your account uses a different supported Python version, use that version instead.

Then install the project dependencies:

```bash
pip install -r requirements.txt
```

## 3. Configure the web app

In the PythonAnywhere Web tab:

1. Add a new web app
2. Choose Manual configuration
3. Select the same Python version you used for the virtualenv
4. Set the virtualenv path to your environment, for example:

```text
/home/<your-username>/.virtualenvs/alstan-venv
```

## 4. Update the WSGI file

Open the WSGI config file from the Web tab and make it point to this project:

```python
import sys

path = "/home/<your-username>/alstan-project"
if path not in sys.path:
    sys.path.insert(0, path)

from wsgi import application
```

If you prefer to import directly from `app.py`, this also works:

```python
import sys

path = "/home/<your-username>/alstan-project"
if path not in sys.path:
    sys.path.insert(0, path)

from app import app as application
```

## 5. Configure static files

PythonAnywhere can serve the static folder directly. Add a static mapping in the Web tab:

- URL: `/static/`
- Directory: `/home/<your-username>/alstan-project/static/`

If you have other folders like images or videos that need to be public, add similar mappings for them.

## 6. Reload the app

After saving the WSGI file and static mapping:

1. Reload the web app
2. Open the error log if something fails
3. Check that the database file is readable and in the expected project folder

## 7. Important notes

- PythonAnywhere recommends virtualenvs for uploaded Flask apps.
- PythonAnywhere can run SQLite, but they note it is better for testing than heavy production use.
- Do not rely on `app.run()` on PythonAnywhere. The web app must start through WSGI.
- Because this project uses `__file__`-based paths in `db.py`, it should work correctly as long as the whole project folder stays together.

## 8. Recommended environment variables

If you want to tighten the deployment, set these in the PythonAnywhere WSGI/environment config:

- `FLASK_SECRET_KEY`
- `JWT_SECRET_KEY`

If you do not set them, the app will fall back to the current default values in code.

