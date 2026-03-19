# DuoSSO Cert Tool

PowerShell utility to build, validate, and deploy LDAPS certificate chains for Duo SSO on Windows domain controllers.

## What It Does

- Scans existing LDAPS-capable certificate chains.
- Validates Duo-related certificate compliance (RSA, key size, EKU, key usage, expiry, private key).
- Rebuilds and exports full certificate chain artifacts on each run.
- Backs up certificates before deletion and writes restore instructions.
- Supports:
  - Single DC
  - Multi-DC Primary
  - Multi-DC Secondary
  - Multi-DC Agent

## Repository Contents

- `DuoSSO-CertTool.ps1` - main automation script.
- `DuoSSO-CertTool-Guide.pdf` - usage and operational guide.

## Run

Open PowerShell as Administrator and execute:

```powershell
.\DuoSSO-CertTool.ps1
```

## Notes

- Test in a non-production environment before broad rollout.
- The script writes logs and backup/restore data under its working directories.
- Review script variables and environment-specific values before production use.
