# ACME HTTPS Setup Guide

## Overview

Owney now includes built-in ACME (Let's Encrypt) support for automated HTTPS certificate provisioning. No manual certificate management needed.

## What Was Built

### New Crate: `owney-acme`
- **ACME v2 client** - Full Let's Encrypt protocol support (acme2 library)
- **DNS-01 challenges** - Automated DNS record creation/deletion
- **Cloudflare support** - Full API integration for DNS updates
- **Route53 support** - AWS Route53 integration for DNS updates  
- **Certificate management** - Generation, renewal, self-signed certs for dev
- **Error handling** - Comprehensive error types and recovery

### Updated Config (`owney-core`)
New `[acme]` section in `mailserver.toml`:

```toml
[acme]
enabled = true
email = "admin@example.com"
dns_provider = "cloudflare"  # or "route53"

# For Cloudflare:
cloudflare_api_token = "your-api-token"
cloudflare_zone_id = "your-zone-id"

# For Route53:
# route53_zone_id = "your-zone-id"  (uses AWS SDK credentials)

staging = false  # true for testing (unlimited rate limits)
```

## Configuration Examples

### Cloudflare Setup

1. **Get API Token**:
   - Login to Cloudflare dashboard
   - Go to Profile → API Tokens
   - Create token with `Zone:DNS:Edit` permission
   - Copy the token

2. **Get Zone ID**:
   - Go to your domain page
   - Right sidebar shows "Zone ID"

3. **Config**:
   ```toml
   [acme]
   enabled = true
   email = "admin@example.com"
   dns_provider = "cloudflare"
   cloudflare_api_token = "v1.0_abc123..."
   cloudflare_zone_id = "1234567890abcdef"
   staging = false
   ```

### AWS Route53 Setup

1. **Create IAM User** with Route53 permissions:
   ```json
   {
     "Version": "2012-10-17",
     "Statement": [
       {
         "Effect": "Allow",
         "Action": [
           "route53:ChangeResourceRecordSets",
           "route53:ListResourceRecordSets"
         ],
         "Resource": "arn:aws:route53:::hostedzone/YOUR_ZONE_ID"
       }
     ]
   }
   ```

2. **Get Zone ID**:
   - AWS Route53 console
   - Click your hosted zone
   - Note the Zone ID

3. **Set AWS Credentials**:
   ```bash
   export AWS_ACCESS_KEY_ID="your-key"
   export AWS_SECRET_ACCESS_KEY="your-secret"
   export AWS_DEFAULT_REGION="us-east-1"
   ```

4. **Config**:
   ```toml
   [acme]
   enabled = true
   email = "admin@example.com"
   dns_provider = "route53"
   route53_zone_id = "Z1234567890ABC"
   staging = false
   ```

## Architecture

### Module Structure

```
owney-acme/
├── src/
│   ├── lib.rs          # Main types (AcmeConfig, CertPaths)
│   ├── acme.rs         # ACME client (request_certificate, renewal checks)
│   ├── error.rs        # Error types (AcmeError)
│   ├── dns.rs          # DnsProvider trait
│   └── provider.rs     # Cloudflare & Route53 implementations
├── Cargo.toml          # Dependencies (acme2, aws-sdk-route53, etc.)
```

### Flow

```
Setup (one-time):
  1. Admin runs: mailserverd setup --with-acme
  2. Prompts for ACME email + DNS provider details
  3. Creates ACME account with Let's Encrypt
  4. Requests certificate for server.hostname
  5. Creates _acme-challenge.hostname DNS record
  6. Waits for DNS propagation (polling Google DNS)
  7. Submits challenge proof to Let's Encrypt
  8. Receives certificate + saves to data_dir/tls/
  9. Deletes DNS record

Server Startup:
  1. Load TLS certs from data_dir/tls/
  2. Bind HTTPS listener on 0.0.0.0:443 (production)
  3. Bind HTTP listener on 0.0.0.0:80 (for HTTP→HTTPS redirects, optional)

Daily Renewal Worker:
  1. Check certificate expiry
  2. If <30 days until expiry, trigger renewal
  3. Same flow as initial request (challenges, DNS updates, etc.)
  4. Replace cert in-place (zero downtime)
```

### Key Classes

#### AcmeClient
```rust
pub struct AcmeClient {
    config: AcmeConfig,
    dns_provider: Box<dyn DnsProvider>,
}

impl AcmeClient {
    pub async fn request_certificate(&self, cert_paths: &CertPaths) -> Result<(), AcmeError>
    pub fn needs_renewal(cert_paths: &CertPaths) -> Result<bool, AcmeError>
    pub async fn self_signed(domains: Vec<String>, cert_paths: &CertPaths) -> Result<(), AcmeError>
}
```

#### DnsProvider Trait
```rust
#[async_trait]
pub trait DnsProvider: Send + Sync {
    async fn create_challenge_record(&self, domain: &str, value: &str) -> Result<(), AcmeError>
    async fn delete_challenge_record(&self, domain: &str, value: &str) -> Result<(), AcmeError>
    async fn wait_for_propagation(&self, domain: &str, value: &str, timeout_secs: u64) -> Result<(), AcmeError>
}
```

#### DNS Providers
```rust
pub struct CloudflareProvider { ... }  // Cloudflare API
pub struct Route53Provider { ... }     // AWS Route53
```

## What Still Needs Integration

This is the foundation. To use it in production:

1. **Setup Command** (`bin/owneyd setup --with-acme`)
   - Prompt for ACME config
   - Call `AcmeClient::request_certificate()`
   - Save certs to data_dir/tls/

2. **Server Integration** (`bin/owneyd serve`)
   - Load TLS certs from data_dir/tls/
   - Bind on 443 with TLS (production) or 8008 (dev)
   - Implement renewal worker in background

3. **HTTPS Server** (owney-api)
   - Use tokio-rustls for TLS
   - Bind to 0.0.0.0:443 in production
   - Redirect HTTP → HTTPS

4. **Renewal Worker**
   - Check expiry daily (via background worker)
   - Renew if <30 days to expiry
   - Hot-reload certs (zero downtime)

## Development vs Production

### Development (HTTP)
```toml
[api]
listen = "127.0.0.1:8008"  # HTTP on 8008, for testing

# No [acme] or [tls] section
# UI accessible via http://localhost:8008
```

### Staging (Let's Encrypt staging, self-signed certs)
```toml
[api]
listen = "0.0.0.0:443"  # HTTPS on 443

[acme]
enabled = true
email = "admin@example.com"
dns_provider = "cloudflare"
cloudflare_api_token = "..."
cloudflare_zone_id = "..."
staging = true  # <-- Use staging for testing
```

### Production (Let's Encrypt production certs)
```toml
[api]
listen = "0.0.0.0:443"  # HTTPS on 443

[acme]
enabled = true
email = "admin@example.com"
dns_provider = "cloudflare"
cloudflare_api_token = "..."
cloudflare_zone_id = "..."
staging = false  # <-- Production certs
```

## Usage Examples

### Requesting a Certificate (Cloudflare)
```rust
use owney_acme::{AcmeClient, AcmeConfig, CloudflareProvider, CertPaths};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = AcmeConfig::new(
        vec!["mail.example.com".to_string()],
        "admin@example.com".to_string(),
        "cloudflare".to_string(),
    );
    
    let dns = Box::new(CloudflareProvider::new(
        "v1.0_abc123...".to_string(),  // API token
        "1234567890abcdef".to_string(), // Zone ID
    ));
    
    let client = AcmeClient::new(config, dns);
    let cert_paths = CertPaths::in_dir(&"/var/lib/mailserver".into());
    
    client.request_certificate(&cert_paths).await?;
    println!("Certificate saved to {:?}", cert_paths.cert);
    
    Ok(())
}
```

### Checking for Renewal
```rust
use owney_acme::{AcmeClient, CertPaths};

let cert_paths = CertPaths::in_dir(&data_dir);

if AcmeClient::needs_renewal(&cert_paths)? {
    println!("Certificate expires in <30 days, renewing...");
    client.request_certificate(&cert_paths).await?;
}
```

### Self-Signed Certs for Dev
```rust
use owney_acme::AcmeClient;

AcmeClient::self_signed(
    vec!["localhost".to_string()],
    &cert_paths,
).await?;
```

## Error Handling

All ACME operations return `Result<T, AcmeError>`:

```rust
pub enum AcmeError {
    AcmeRequest(String),           // ACME protocol error
    DnsProvider(String),           // DNS API error
    ChallengeValidation(String),   // Challenge failed
    Certificate(String),           // Cert generation/parsing
    Io(std::io::Error),            // File I/O
    Http(String),                  // HTTP request error
    Config(String),                // Invalid configuration
    DnsTimeout,                    // DNS propagation timeout
    RateLimit(String),             // Let's Encrypt rate limit
    CertificateNotFound,           // No cert found
}
```

Common issues:

| Error | Cause | Fix |
|-------|-------|-----|
| `DnsTimeout` | DNS not propagating | Check DNS provider API token/zone ID; increase timeout |
| `AcmeRequest` | ACME server error | Check logs; may be rate limited; retry later |
| `DnsProvider` | DNS API failed | Verify credentials, network connectivity |
| `ChallengeValidation` | Challenge rejected | Ensure DNS record created correctly |
| `RateLimit` | Too many requests | Use staging first; wait before retrying |

## Testing

### Staging Environment
Before going production, test with Let's Encrypt staging:

```toml
[acme]
staging = true  # Unlimited rate limits, self-signed certs
```

This lets you validate the full flow without hitting production rate limits.

### Manual Testing
```bash
# Check if renewal needed
curl http://localhost:8008/admin/cert-status

# Trigger renewal manually
curl -X POST http://localhost:8008/admin/renew-cert
```

## Rate Limits (Production)

Let's Encrypt has rate limits:
- **50 certificates per domain per week**
- **5 duplicate certificates per week**
- **5 failures per domain per hour**

For development, use staging (unlimited).

For production, plan renewal timing to avoid hitting limits.

## Next Steps

To integrate this into the server:

1. **Setup command** - Add ACME provisioning to `mailserverd setup`
2. **Server startup** - Load TLS certs and bind HTTPS listener
3. **Renewal worker** - Background task to check/renew daily
4. **HTTP redirects** - Optional HTTP→HTTPS redirects
5. **Monitoring** - Alert if cert renewal fails

## Files Changed

- ✅ **New**: `crates/owney-acme/` - Full ACME implementation
- ✅ **Modified**: `crates/owney-core/Cargo.toml` - Added ACME config section
- ✅ **Modified**: `Cargo.toml` - Added owney-acme to workspace
- ⏳ **TODO**: `bin/owneyd/src/main.rs` - Integrate setup & serve
- ⏳ **TODO**: `crates/owney-api/src/lib.rs` - HTTPS server
- ⏳ **TODO**: `crates/owney-api/src/renewal.rs` - Background renewal worker

## Troubleshooting

### "Certificate not found" on startup
→ Run `mailserverd setup --with-acme` to provision a certificate first

### "DNS propagation timeout"
→ Check that DNS provider credentials are correct
→ Verify the domain is registered and in the correct zone

### "Rate limit exceeded"
→ Use staging (`acme.staging = true`) for testing
→ Wait 1 week before retrying on production

### "Challenge validation failed"
→ Check that DNS record was created (use `dig _acme-challenge.example.com`)
→ Ensure DNS propagation completed before challenge validation

## References

- ACME RFC: https://tools.ietf.org/html/rfc8555
- Let's Encrypt: https://letsencrypt.org/
- Cloudflare API: https://developers.cloudflare.com/api/
- AWS Route53: https://docs.aws.amazon.com/route53/
