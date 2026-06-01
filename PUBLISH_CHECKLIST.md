# Publish Checklist

## GitHub Readiness

- [ ] `.env` is not committed.
- [ ] `database/*.db` is not committed.
- [ ] `logs/` is not committed.
- [ ] `__pycache__/` folders are not committed.
- [ ] `.pytest_cache/` is not committed.
- [ ] Virtual environment folders are not committed.
- [ ] `.env.example` is committed with placeholders.
- [ ] `README.md` is complete and accurate.
- [ ] `LICENSE` is present.
- [ ] `CONTRIBUTING.md` is present.
- [ ] `CHANGELOG.md` is present.
- [ ] `RELEASE_NOTES.md` is present.
- [ ] GitHub Actions workflow is present.

## Functional Verification

- [ ] Dependencies install using `pip install -r requirements.txt`.
- [ ] Database initializes using `python scripts/seed_admin.py`.
- [ ] IDS model trains using `python ml/train_model.py`.
- [ ] App starts using `python run.py`.
- [ ] Login page opens at `http://127.0.0.1:5000/login`.
- [ ] Admin dashboard opens after admin login.
- [ ] IDS prediction page returns `Normal` and `Attack`.
- [ ] CSV exports download successfully.
- [ ] Tests pass using `python -m unittest discover -s tests -p "test_*.py"`.

## Submission ZIP Checklist

- [ ] Source code files.
- [ ] `README.md`.
- [ ] `requirements.txt`.
- [ ] `.env.example`.
- [ ] `docs/` academic documentation.
- [ ] `screenshots/` with final screenshots.
- [ ] PPT file, if generated separately.
- [ ] Project report PDF or DOCX, if generated separately.
- [ ] Do not include `.env`.
- [ ] Do not include database files.
- [ ] Do not include logs.
- [ ] Do not include cache folders.
- [ ] Do not include virtual environment.

## Suggested ZIP Name

```text
AI_SIEM_IDS_BTech_Project_Submission.zip
```
