# Alstandesign

Flask-based project for the Alstandesign site.

## Run locally

```bash
python app.py
```

## Notes

- The project currently uses Flask templates and static assets.
- Netlify is best suited for static front-end hosting, so a separate backend hosting option may be needed for the Flask app.
- Security and authentication helpers are split into `security.py`, `auth.py`, and `db.py` so they are easier to review and explain separately.
