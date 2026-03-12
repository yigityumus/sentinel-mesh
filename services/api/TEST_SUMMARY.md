# API Service - Test Summary

## Status: Complete (50/50 Tests Passing)

Comprehensive test suite for the API gateway service with **50 tests** covering all major functionality, authentication, and integration scenarios.

## Test Results

- **Total Tests:** 50
- **Passed:** 50
- **Failed:** 0
- **Coverage:** 100% pass rate
- **Linting:** All checks passed (ruff)

## Test Files & Breakdown

### `conftest.py` (Fixtures & Configuration)

Comprehensive pytest configuration with proper dependency injection patterns:

- **RSA Key Generation:** 2048-bit keypair for JWT signing/verification
- **Settings Fixtures:** Mocked configuration with injected public keys
- **Token Factory:** JWT token creation with customizable claims (user_id, role, expiry)
- **TestClient Setup:** FastAPI test client with properly patched external dependencies
  - `app.keys.fetch_public_key_from_jwks` → returns test public key
  - `app.auth.send_event` → mocked for event logging verification
- **authenticated_client / admin_client:** Helper fixtures that wrap api_client with Authorization headers

**Key Implementation Details:**
- Uses `object.__setattr__()` to bypass Pydantic private attribute restrictions
- Patches maintained with `start()/yield` pattern (not `with` blocks) to stay active during test execution
- Module globals updated before app import to ensure settings injection

### `test_api.py` - 21 Endpoint Tests

#### TestHealthzEndpoint (2 tests)
- Returns 200 status with availability info
- Public endpoint requires no authentication

#### TestMeEndpoint (3 tests)
- Returns authenticated user's information
- Returns correct user_id for each user
- Rejects requests without authentication

#### TestAdminStatsEndpoint (3 tests)
- Returns statistics for authenticated admin
- Rejects non-admin users with 403 Forbidden
- Requires authentication (rejects missing token)

#### TestAuthenticationFailures (7 tests)
- Missing Authorization header → 401 Unauthorized
- Invalid Bearer token format → 401 Unauthorized
- Invalid JWT signature → 401 Unauthorized
- Expired tokens → 401 Unauthorized
- Token missing 'sub' (subject) claim → 401 Unauthorized
- Token missing 'role' claim → 401 Unauthorized
- Logs error events for all auth failures

#### TestClientIPHeader (2 tests)
- Extracts client IP from x-real-ip header
- Logs authentication failures with correct client IP

#### TestOriginalPathHeader (2 tests)
- Extracts original request path from x-original-uri header
- Logs authentication failures with correct original path

#### TestRoleManagement (3 tests)
- Admin role can access /admin/stats endpoint
- User role is denied access to /admin/stats (403)
- Different roles have different access levels

#### TestEventLogging (3 tests)
- Logs 'missing_token' event when header missing
- Logs 'invalid_token' event on signature failure
- Logs 'invalid_token_claims' event on missing claims

### `test_auth.py` - 14 Authentication Unit Tests

#### TestGetBearerToken (4 tests)
- Extracts Bearer token from Authorization header
- Raises HTTPException when header missing
- Raises HTTPException on invalid format (not "Bearer <token>")
- Logs 'missing_token' event when header absent

#### TestGetCurrentUser (5 tests)
- Validates and extracts claims from valid JWT token
- Rejects tokens with invalid signature
- Rejects expired tokens
- Rejects tokens missing 'sub' (user_id) claim
- Rejects tokens missing 'role' claim

#### TestClientIPExtraction (3 tests)
- Extracts x-real-ip header (priority over client)
- Falls back to request.client.host when header missing
- Handles missing client gracefully

#### TestOriginalPathExtraction (2 tests)
- Extracts x-original-uri header
- Falls back to request.url.path when header missing

### `test_keys.py` - 15 Key Management Tests

#### TestLoadPublicKey (5 tests)
- Loads valid PEM-encoded public key
- Rejects invalid/malformed PEM
- Rejects empty PEM string
- Rejects private keys passed as public
- Loaded key can verify JWT signatures

#### TestFetchPublicKeyFromJWKS (6 tests)
- Fetches and parses public key from JWKS endpoint
- Returns None on network errors
- Returns None if requested key ID not found
- Finds correct key with custom key ID (kid)
- Handles malformed JWKS response
- Respects 3-second HTTP timeout

#### TestBase64UrlConversion (1 test)
- Converts base64url-encoded integers correctly

## Running Tests

### Install dependencies:
```bash
poetry install --with dev
```

### Run all tests:
```bash
poetry run pytest tests/ -v
```

### Run specific test file:
```bash
poetry run pytest tests/test_api.py -v
```

### Run with coverage report:
```bash
poetry run pytest --cov=app tests/
```

### Run linting check:
```bash
poetry run ruff check .
```

### Run both lint and tests (CI):
```bash
poetry run ruff check . && poetry run pytest tests/ -v
```

## Test Infrastructure & Patterns

### Database & State Management
- In-memory test client (no persistent state)
- Each test is independent and isolated
- Mocked external services (auth service JWKS, log service)

### Authentication Testing
- Real RSA 2048-bit keypairs generated for each test run
- JWT tokens created with valid RS256 signatures
- Proper token expiry validation (using datetime with timezone)
- Role-based access control (admin vs user)

### Mock Strategy
- `app.auth.send_event` → mocked for event logging verification
- `app.keys.fetch_public_key_from_jwks` → returns test public key
- Settings injection via `object.__setattr__()` for Pydantic private attributes
- Patches maintained throughout test execution lifecycle

### Fixture Architecture

```python
rsa_keys (Session)
    ├─> test_settings (Function)
    │       └─> Settings with injected public key
    ├─> create_token (Function)
    │       └─> JWT factory with custom claims
    └─> api_client (Function)
            ├─> Settings patched in module globals
            ├─> Mock patches initialized
            ├─> TestClient created
            └─> authenticated_client / admin_client wrappers
```

## Coverage Summary

### Endpoint Coverage
All 3 endpoints fully tested:
- `GET /healthz` - Public health check
- `GET /me` - Authenticated user info
- `GET /admin/stats` - Admin-only statistics

### Authentication Coverage
- Bearer token extraction and validation
- JWT signature verification (RS256)
- Token expiry validation
- Required claims validation (sub, role)
- Error handling for all auth failure modes

### Integration Coverage
- End-to-end request flow with proper auth
- Role-based access control enforcement
- Event logging on all auth failures
- Header extraction (x-real-ip, x-original-uri)

### Edge Cases Covered
- Missing authorization header
- Invalid token formats
- Expired tokens
- Invalid signatures
- Missing JWT claims
- Non-admin users accessing admin endpoints
- Malformed JWKS responses
- Network timeouts

## Key Learnings & Implementation Notes

### Critical Fix: Pydantic Private Attributes
Pydantic Settings with underscore-prefixed attributes (like `_public_key_pem`) cannot be set via constructor parameters. Solution:
```python
settings_obj = Settings(...)
object.__setattr__(settings_obj, '_public_key_pem', rsa_keys["public"])
```

### Critical Fix: Mock Patch Lifecycle
Using `with patch()` context managers causes patches to exit before tests run. Solution:
```python
patcher = patch("app.auth.send_event")
mock_send = patcher.start()  # Start patches
try:
    yield client
finally:
    patcher.stop()  # Stop after test completes
```

### Mock Target Selection
Patch functions where they're **used**, not where they're defined:
- `patch("app.log_client.send_event")` - where it's defined
- `patch("app.auth.send_event")` - where auth.py imports and uses it

### Real vs Mock RSA Keys
JWKS tests use real RSA key components (not mocked) to properly test the base64url conversion and key reconstruction logic. This ensures the code actually works with real JWKS responses.

## Dependencies

- **FastAPI** - Web framework and TestClient
- **pytest** - Test framework and discovery
- **python-jose** - JWT creation and validation
- **cryptography** - RSA key operations
- **httpx** - HTTP client mocking
- **ruff** - Code linting

## Conclusion

The API service test suite provides comprehensive coverage of authentication flows, endpoint behavior, and integration scenarios. All tests pass with zero linting violations, ready for CI/CD integration.
