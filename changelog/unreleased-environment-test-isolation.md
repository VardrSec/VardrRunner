# Tool-environment test isolation

Use a supplied synthetic environment mapping in the allowlist unit test so an
inherited uppercase proxy variable cannot collide with its lowercase fixture.
Production environment filtering, credential isolation and network settings stay
unchanged. Windows-native execution remains the controlled runtime; unattended
Docker managed execution remains disabled and unsupported.
