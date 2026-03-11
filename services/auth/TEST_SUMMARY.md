# Auth Service - Test Summary

## Overview

Comprehensive test suite for authentication service with **98 tests** covering all major functionality.

## Test Breakdown

```
conftest.py (Configuration & Fixtures)
├─ Database fixtures (in-memory SQLite)
├─ Settings fixtures (with RSA key generation)
├─ User factory fixtures
├─ FastAPI TestClient with dependency injection
└─ Mock fixtures for external services

test_security.py (12 tests)
├─ Password hashing (7 tests)
│  ├─ Hash generation & verification
│  ├─ Hash uniqueness (salted)
│  ├─ Case sensitivity
│  └─ Invalid hash handling
├─ JWT creation (5 tests)
│  ├─ Token structure & format
│  ├─ Payload contents (sub, role, iat, exp)
│  ├─ Signature algorithm (RS256)
│  └─ Multiple token distinctness

test_models.py (18 tests)
├─ Model structure (5 tests)
│  ├─ Required columns
│  ├─ Primary key
│  ├─ Indexes
│  └─ Default values
├─ Constraints (6 tests)
│  ├─ Email uniqueness
│  ├─ Nullable validation
│  ├─ Max length constraints
│  └─ required field validation
└─ Query operations (7 tests)
   ├─ Query by email
   ├─ Count users
   └─ Handle missing records

test_schemas.py (20 tests)
├─ SignupRequest validation (10 tests)
│  ├─ Required fields
│  ├─ Email format validation
│  ├─ Password length (10-128 chars)
│  ├─ Special characters
│  └─ Edge cases
├─ LoginRequest validation (6 tests)
│  ├─ Required fields
│  ├─ Email format
│  ├─ Password length (1-128 chars)
│  └─ Empty string handling
└─ TokenResponse (4 tests)
   ├─ Structure & defaults
   ├─ Serialization
   └─ Schema generation

test_keys.py (20 tests)
├─ Key generation (6 tests)
│  ├─ RSA 2048-bit keypair
│  ├─ PEM format validation
│  ├─ Key uniqueness
│  └─ Public/private relationship
├─ Key loading (5 tests)
│  ├─ PEM parsing
│  ├─ Invalid format handling
│  ├─ Type validation
│  └─ Multiple load cycles
└─ Environment integration (9 tests)
   ├─ get_or_generate_keys
   ├─ ENV var loading
   ├─ Custom ENV var names
   └─ Consistency checks

test_api.py (28 tests)
├─ /healthz endpoint (2 tests)
│  ├─ Status response
│  └─ Content-type validation
├─ /.well-known/jwks.json (3 tests)
│  ├─ JWKS format
│  ├─ Key structure
│  └─ Consistency
├─ /signup endpoint (11 tests)
│  ├─ Success case (201)
│  ├─ Duplicate email (409)
│  ├─ Validation failures (422)
│  ├─ Password hashing
│  ├─ Email normalization
│  ├─ Event logging
│  └─ Security aspects
├─ /login endpoint (10 tests)
│  ├─ Success case (200)
│  ├─ Wrong password (401)
│  ├─ Nonexistent user (401)
│  ├─ User enumeration protection
│  ├─ Email case-insensitivity
│  ├─ Event logging
│  └─ Token generation
└─ Request variations (2 tests)
   ├─ Edge cases
   └─ HTTP method validation

TOTAL: 98 tests
```

## Running Tests

```bash
# All tests
poetry run pytest tests/ -v

# Specific file
poetry run pytest tests/test_security.py -v

# With coverage
poetry run pytest tests/ --cov=app

# Specific test
poetry run pytest tests/test_api.py::TestSignupEndpoint::test_signup_success -v
```

## Key Features Tested

### Security
- Argon2-based password hashing
- RS256 JWT signature generation
- RSA 2048-bit keypair generation
- User enumeration protection
- Password strength enforcement
- Email validation

### Database
- Email uniqueness constraint
- ORM model validation
- Query operations
- Transaction handling
- Default values

### API
- Request validation (422 errors)
- Success responses (200, 201)
- Error responses (401, 409)
- CORS/JWKS endpoint
- Event logging integration

### Integration
- Signup → password hashing → token creation
- Login → verification → token generation  
- Email normalization across flows
- Event logging to log service

## Dependency Injection

Tests use FastAPI's dependency injection to:
- Override `get_db` with test database session
- Override settings with test configuration
- Mock external services (log service)
- Inject RSA keys from test settings

## Mocking Strategy

```python
# HTTP requests to external services
mock_send_event  # Mocks log service events

# Database
db_session  # In-memory SQLite per test

# Configuration
test_settings  # Test-specific settings with keys
```

## Database

- **Type**: SQLite (in-memory)
- **Session**: Fresh per test, auto-cleanup
- **Migrations**: Tables created from ORM models
- **Transactions**: Rollback after each test

## Fixtures

| Fixture | Purpose | Scope |
|---------|---------|-------|
| db_engine | SQLite connection | session |
| db_session | ORM session | function |
| test_settings | Configuration | function |
| create_user | User factory | function |
| create_multiple_users | Bulk user creation | function |
| fastapi_client | Test HTTP client | function |
| mock_send_event | Mock log service | function |

## Common Test Patterns

```python
# Test user creation
def test_something(create_user):
    user = create_user(email="test@example.com")
    # Test with user...

# Test API endpoint
def test_api(fastapi_client):
    response = fastapi_client.post("/signup", json={...})
    assert response.status_code == 201

# Test with mocking
def test_event(fastapi_client, mock_send_event):
    response = fastapi_client.post("/signup", json={...})
    mock_send_event.assert_called_once()

# Test database constraints
def test_constraint(db_session):
    user = User(...)
    db_session.add(user)
    with pytest.raises(Exception):
        db_session.commit()
```

## Coverage Goals

| Component | Target | Status |
|-----------|--------|--------|
| security.py | 95%+ | Passed |
| models.py | 90%+ | Passed |
| schemas.py | 95%+ | Passed |
| keys.py | 90%+ | Passed |
| main.py | 92%+ | Passed |
| Overall | 93%+ | Passed |

## Notes

- Tests use mocking to avoid external service dependencies
- Database tests use transactions with rollback
- Email validation uses pydantic's EmailStr
- JWT tests verify RS256 signatures
- Password tests verify Argon2 hashing
