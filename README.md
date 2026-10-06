# Password Generator

A web app for generating secure passwords and passphrases. Built with Python and Flask.

## Features

- Generate passwords or passphrases
- Copy generated results
- View password generation history
- Store vault data locally

## Run the project

1. Install Python.
2. Open a terminal in the project folder.
3. Install Flask:

   ```powershell
   pip install flask
   ```

4. Start the app:

   ```powershell
   python app.py
   ```

5. Open [http://127.0.0.1:5000](http://127.0.0.1:5000) in your browser.

## Project files

- `app.py` — Flask application
- `index.html` — web interface
- `vault.db` — local vault database
- `vault.key` — local encryption key

## Keep vault files private

Do not upload `vault.db` or `vault.key
