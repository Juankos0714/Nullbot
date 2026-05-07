<#
.SYNOPSIS
    Creates a self-signed Authenticode certificate for local development signing.

.DESCRIPTION
    Generates a code-signing cert in the current user's certificate store and
    exports a PFX for CI use. DO NOT ship builds signed with this cert — get a
    proper Authenticode cert from DigiCert, Sectigo, or similar for releases.

.EXAMPLE
    # Sign a single file
    .\sign-dev.ps1
    signtool sign /sha1 <thumbprint> /fd SHA256 /t http://timestamp.digicert.com NullBot.exe

.EXAMPLE
    # Use the exported PFX in a CI pipeline
    signtool sign /f dev-cert.pfx /p devonly /fd SHA256 /t http://timestamp.digicert.com NullBot.exe
#>

#Requires -Version 5.1

$ErrorActionPreference = "Stop"

Write-Host "[sign-dev] Generating self-signed Authenticode certificate..." -ForegroundColor Cyan

$cert = New-SelfSignedCertificate `
    -Subject      "CN=NullBot Dev, O=NullBot Contributors, C=US" `
    -Type          CodeSigning `
    -CertStoreLocation "Cert:\CurrentUser\My" `
    -NotAfter     (Get-Date).AddYears(1) `
    -HashAlgorithm SHA256

$thumbprint = $cert.Thumbprint
Write-Host "[sign-dev] Certificate created."
Write-Host "  Subject:     $($cert.Subject)"
Write-Host "  Thumbprint:  $thumbprint"
Write-Host "  Expires:     $($cert.NotAfter)"

# Export PFX for CI (password: devonly — NEVER use for production)
$pfxPath    = Join-Path $PSScriptRoot "dev-cert.pfx"
$pfxPass    = ConvertTo-SecureString "devonly" -AsPlainText -Force
Export-PfxCertificate -Cert "Cert:\CurrentUser\My\$thumbprint" `
                      -FilePath $pfxPath `
                      -Password $pfxPass | Out-Null

Write-Host ""
Write-Host "[sign-dev] PFX exported to: $pfxPath  (password: devonly)"
Write-Host ""
Write-Host "Sign files with signtool:"
Write-Host "  signtool sign /sha1 $thumbprint /fd SHA256 /t http://timestamp.digicert.com <file>"
Write-Host ""
Write-Host "Or with PFX:"
Write-Host "  signtool sign /f `"$pfxPath`" /p devonly /fd SHA256 /t http://timestamp.digicert.com <file>"
Write-Host ""
Write-Host "[sign-dev] Add this thumbprint to your build script and sign:"
Write-Host "  build\bin\nullbot_cli.exe"
Write-Host "  build\bin\nullbot_amsi_provider.dll"
Write-Host "  ui\bin\Release\net8.0-windows\NullBot.exe"
Write-Host "  installer\bin\Release\en-US\NullBot-0.1.0-x64.msi"
