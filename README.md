# DuoSSO Cert Tool

PowerShell utility to discover, validate, issue, deploy, and report on LDAPS certificate chains for Duo SSO on Windows domain controllers.

## Current Capabilities

- Interactive mode selection at startup:
  - `Execution` performs changes.
  - `Report-Only` follows the same control flow without mutating cert stores, registry, services, or remote targets.
- When a usable existing LDAPS chain is found, the tool can package that chain for Duo instead of replacing it.
- When a usable existing LDAPS chain is found and the operator chooses a new chain, the existing certificates are preserved.
- Scans existing LDAPS-capable certificate chains before issuing new certificates.
- Validates Duo-related certificate compliance:
  - RSA key algorithm
  - minimum 2048-bit keys
  - SHA-256 or stronger signature algorithm
  - Server Authentication and Client Authentication EKUs
  - required key usage values
  - non-expired certificate state
  - private key presence for LDAPS use
- Rebuilds and exports full certificate chain artifacts when issuing a new chain.
- Backs up certificates before deletion and records restore instructions.
- Injects certificates into the NTDS certificate store and verifies LDAPS presentation.
- Generates an HTML report for every run.

## Supported Operating Modes

- `Single DC`
  - Creates or deploys the LDAPS chain on the local DC.
  - Upload the generated root PEM to Duo after the run.
- `Multi-DC Primary`
  - Creates a shared root CA and issues a local leaf cert.
  - Export the shared root PFX for secondary DCs at `Certificates\DuoSSO-RootCert-Shared.pfx`.
  - The run summary displays the shared root PFX password to use on secondary DCs.
  - Upload the generated root PEM to Duo once.
- `Multi-DC Secondary`
  - Imports the shared root PFX.
  - Requires the shared root PFX password from the primary run.
  - Issues a local leaf cert for the current DC.
  - Does not require re-uploading the PEM to Duo.
- `Multi-DC Agent`
  - Runs the primary flow locally.
  - Discovers other DCs and attempts remote deployment over WinRM.
  - Passes the shared root PFX password automatically to remote secondary runs.

## Report-Only Behavior

`Report-Only` mode is designed for pre-change validation.

- Prompts remain interactive and use the same decision tree as `Execution` mode.
- Interactive prompts are labeled with `[REPORT-ONLY]`.
- State-changing operations are logged as planned actions and skipped.
- The HTML report is still written so the run can be reviewed and shared.
- The main log file is also written in `Report-Only` mode.
- Output paths are based on the current working directory where the script is launched.

## Existing Chain Decision Flow

When the tool finds an existing usable LDAPS certificate chain, it shows the chain details and prompts the operator to choose one of these paths:

- Package the existing chain for Duo:
  - export the existing chain artifacts
  - generate the PEM file for Duo upload
  - do not wipe or replace the current certificates
- Create a new self-signed chain while preserving the existing certificates:
  - create and export the new chain artifacts
  - generate the new PEM file for Duo upload
  - do not back up, wipe, or remove the current certificates

If no usable existing chain is found, the original rebuild-and-deploy path is used.

## Generated Artifacts

The script writes or plans the following under its working directory:

- `Certificates\`
  - exported root CER / PEM / PFX
  - exported LDAPS CER
  - existing-chain exports when that path is selected
- `Certificates\Backups\`
  - per-run backup folders
  - `RESTORE-INSTRUCTIONS.log` in `Execution` mode
- `DuoSSO-CertTool-Report-<session>.html`
- `DuoSSO-CertTool.log`
  - written in both `Execution` and `Report-Only` modes

## Requirements

- Windows PowerShell with local administrator rights
- Domain controller host for full certificate deployment flows
- `certutil.exe`
- Active Directory tooling available to resolve DC/domain information
- WinRM enabled on target DCs when using `Multi-DC Agent`

The script includes a preflight gate and will exit if the host is not suitable for the selected deployment behavior.

## Repository Contents

- `DuoSSO-CertTool.ps1` - main automation script
- `DuoSSO-CertTool-Guide.html` - maintained source for the operator guide
- `DuoSSO-CertTool-Guide.pdf` - operator guide aligned to the current feature set

## Running The Tool

Open PowerShell as Administrator and execute:

```powershell
.\DuoSSO-CertTool.ps1
```

Non-interactive secondary mode is used by Agent deployments:

```powershell
.\DuoSSO-CertTool.ps1 3 "C:\Path\To\DuoSSO-RootCert-Shared.pfx" "<SharedRootPfxPassword>"
```

## Execution Flow Summary

1. Run preflight validation.
2. Choose `Execution` or `Report-Only`.
3. Choose the operating mode.
4. Scan for an existing usable LDAPS chain.
5. Either deploy the existing chain or back up, wipe, and issue a new chain.
  If a usable existing chain is found, the operator can instead package the existing chain or create a new packaged chain without removing the current certificates.
6. Bind the selected leaf certificate to NTDS.
7. Restart and verify LDAPS in `Execution` mode, or log the planned steps in `Report-Only` mode.
8. Generate the HTML report.

## Safety Notes

- Test in a non-production environment before broad rollout.
- `Report-Only` is the recommended first pass before any production execution.
- Multi-DC deployments should be validated on a lab domain before broad rollout.
- Backup and restore instructions should be retained with the generated report set for change review.
