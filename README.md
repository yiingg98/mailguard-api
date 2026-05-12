# MailGuard API

Professional email validation API with DNS checks, disposable detection, MX verification, and bulk validation.

## Endpoints

| Endpoint | Method | Description |
|---|---|---|
| `/email/validate` | GET | Full single email validation |
| `/email/bulk-validate` | POST | Validate up to 50 emails at once |
| `/email/mx-check` | GET | Check MX records for a domain |
| `/email/domain-check` | GET | Full domain reputation check |

## What it checks

- Email format validity
- Domain existence (DNS A/AAAA records)
- MX record verification
- Disposable/temporary email detection (500+ known domains)
- Role-based email detection (admin@, info@, support@, etc.)
- Quality score 0-100
- Risk level: low / medium / high

## Quick Start

```bash
pip install -r requirements.txt
uvicorn main:app --reload
```

API docs at `http://localhost:8000/docs`

## Example

```
GET /email/validate?email=test@gmail.com
```

```json
{
  "email": "test@gmail.com",
  "is_valid": true,
  "quality_score": 100,
  "risk_level": "low",
  "suggestion": "Safe to use"
}
```
