# Auth Service Tests

Comprehensive test suite for the SentinelMesh authentication microservice.

## Structure

### Test Files

1. **test_security.py** (12 tests)
   - Password hashing and verification with Argon2
   - JWT access token creation with RS256
   - Token payload structure (user_id, role, iat, exp)
   - Token expiry validation
   - Signature verification with public key

2. **test_models.py** (18 tests)
   - User model structure and constraints
   - Email uniqueness enforcement
   - Primary key and indexing
   - Default values (role, created_at)
   - Field length constraints
   - Nullable field validation
   - Query operations

3. **test_schemas.py** (20 tests)
   - SignupRequest validation (email, password constraints)
   - LoginRequest validation
   - TokenResponse structure
   - Email format validation
   - Password length constraints (10-128 for signup, 1-128 for login)
   - Schema serialization

4. **test_keys.py** (20 tests)
   - RSA keypair generation (2048-bit)
   - PEM format validation
   - Key loading and parsing
   - Environment variable key loading
   - Key consistency and roundtrip validation
   - Signing and verification operations

5. **test_api.py** (28 tests)
   - `/healthz` endpoint
   - `/.well-known/jwks.json` JWKS endpoint
   - `/signup` endpoint with success, duplicate email, validation
   - `/login` endpoint with success, wrong password, user enumeration protection
   - Event sending to log service
   - Request/response validation
   - Edge cases and error handling

### Fixtures (conftest.py)

- `db_engine`: In-memory SQLite for testing
- `db_session`: Fresh database session per test
- `test_settings`: Test configuration with generated RSA keys
- `create_user`: Factory for creating individual users
- `create_multiple_users`: Factory for creating multiple users
- `fastapi_client`: FastAPI TestClient with proper dependency injection
- `mock_send_event`: Mock for log service event sending

## Running Tests

### Run all tests
```bash
poetry run pytest tests/ -v
```

### Run specific test file
```bash
poetry run pytest tests/test_security.py -v
```

### Run specific test class
```bash
poetry run pytest tests/test_api.py::TestSignupEndpoint -v
```

### Run with coverage
```bash
poetry run pytest tests/ --cov=app --cov-report=html
```

### Run with output capture
```bash
poetry run pytest tests/ -v -s
```

## Test Coverage

| Module | Tests | Coverage |
|--------|-------|----------|
| security.py | 12 | Password hashing, JWT creation |
| models.py | 18 | User model constraints |
| schemas.py | 20 | Request/response validation |
| keys.py | 20 | RSA key operations |
| main.py | 28 | API endpoints |
| **TOTAL** | **98** | Full coverage |

## Key Testing Patterns

### Password Security
- Argon2id hashing with random salt
- Password verification failure handling
- Invalid hash format resilience

### JWT Tokens
- RS256 signature generation
- Token payload structure (sub, role, iat, exp)
- Expiry validation
- Signature verification with public key

### Email Normalization
- Case-insensitive email handling
- User enumeration protection (same error for missing/wrong password)

### Database Constraints
- Email uniqueness enforcement
- Required fields validation
- Primary key management

### API Security
- Input validation
- Error message consistency
- Event logging for audit trail

## Common Issues & Troubleshooting

### Import Errors
If you see `ModuleNotFoundError`, ensure dependencies are installed:
```bash
poetry install
```

### Database Errors
Tests use in-memory SQLite. If you see connection errors, check:
- SQLite version compatibility
- JSONB type compilation (handled in conftest)

### Mock Issues
If log service mocking fails, verify:
- `mock_send_event` fixture is in scope
- Patching targets match import locations

### Settings Injection
Tests override settings for database, JWT keys, and log service URL. If tests fail:
- Check `test_settings` fixture in conftest.py
- Verify key generation succeeds
- Ensure settings are properly patched in test setup

## CI/CD Integration

Tests are configured for CI with:
- Automatic pytest discovery
- Verbose output for debugging
- Short traceback format
- Strict marker checking

Environment setup for CI:
```bash
poetry install
poetry run ruff check .
poetry run pytest tests/ -v
```

## Future Enhancements

- [ ] Test CORS and security headers
- [ ] Performance benchmarks for authentication
- [ ] Integration tests with actual log service
- [ ] Token refresh endpoint tests
- [ ] Password reset/recovery flow tests
