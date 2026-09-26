param(
    [int]$StartupTimeoutSeconds = 180
)

$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$composeBase = Join-Path $repoRoot 'infrastructure/podman/dev-minimal.compose.yaml'
$composeAuth = Join-Path $repoRoot 'infrastructure/podman/keycloak-test.compose.yaml'
$projectName = 'maridauth' + ([Guid]::NewGuid().ToString('N').Substring(0, 12))
$objectRoot = Join-Path ([System.IO.Path]::GetTempPath()) "$projectName-objects"

function Get-FreePort {
    $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
    $listener.Start()
    try { return ([System.Net.IPEndPoint]$listener.LocalEndpoint).Port }
    finally { $listener.Stop() }
}

function Assert-Status($response, [int]$expected, [string]$description) {
    if ([int]$response.StatusCode -ne $expected) {
        throw "$description returned $([int]$response.StatusCode), expected $expected."
    }
}

function Get-TokenClaims([string]$token) {
    $payload = $token.Split('.')[1].Replace('-', '+').Replace('_', '/')
    $payload += '=' * ((4 - $payload.Length % 4) % 4)
    return [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($payload)) | ConvertFrom-Json
}

$dbPort = Get-FreePort
$keycloakPort = Get-FreePort
$apiPort = Get-FreePort
$ownerPassword = [Convert]::ToHexString([System.Security.Cryptography.RandomNumberGenerator]::GetBytes(32)).ToLowerInvariant()
$appPassword = [Convert]::ToHexString([System.Security.Cryptography.RandomNumberGenerator]::GetBytes(32)).ToLowerInvariant()
$workerPassword = [Convert]::ToHexString([System.Security.Cryptography.RandomNumberGenerator]::GetBytes(32)).ToLowerInvariant()
$keycloakPassword = [Convert]::ToHexString([System.Security.Cryptography.RandomNumberGenerator]::GetBytes(32)).ToLowerInvariant()
$clientSecret = [Convert]::ToHexString([System.Security.Cryptography.RandomNumberGenerator]::GetBytes(32)).ToLowerInvariant()
$environmentNames = @(
    'MARID_DB_OWNER_PASSWORD', 'MARID_DB_APP_PASSWORD', 'MARID_DB_WORKER_PASSWORD', 'MARID_KEYCLOAK_ADMIN_PASSWORD',
    'MARID_TEST_CLIENT_SECRET', 'MARID_DB_HOST_PORT', 'MARID_DB_PORT',
    'MARID_KEYCLOAK_HOST_PORT', 'MARID_ADMIN_PASSWORD_STDIN',
    'MARID_OIDC_AUTHORITY', 'MARID_OIDC_AUDIENCE', 'ConnectionStrings__Marid',
    'ASPNETCORE_URLS', 'ASPNETCORE_ENVIRONMENT', 'MARID_OBJECT_ROOT'
)
$previousEnvironment = @{}
foreach ($name in $environmentNames) {
    $previousEnvironment[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
}
$env:MARID_DB_OWNER_PASSWORD = $ownerPassword
$env:MARID_DB_APP_PASSWORD = $appPassword
$env:MARID_DB_WORKER_PASSWORD = $workerPassword
$env:MARID_KEYCLOAK_ADMIN_PASSWORD = $keycloakPassword
$env:MARID_TEST_CLIENT_SECRET = $clientSecret
$env:MARID_DB_HOST_PORT = [string]$dbPort
$env:MARID_DB_PORT = [string]$dbPort
$env:MARID_KEYCLOAK_HOST_PORT = [string]$keycloakPort
$env:MARID_ADMIN_PASSWORD_STDIN = '1'
$env:MARID_OIDC_AUTHORITY = "http://127.0.0.1:$keycloakPort/realms/marid-test"
$env:MARID_OIDC_AUDIENCE = 'marid-api'
$env:ConnectionStrings__Marid = "Host=127.0.0.1;Port=$dbPort;Database=marid;Username=marid_app;Password=$appPassword"
$env:ASPNETCORE_URLS = "http://127.0.0.1:$apiPort"
$env:ASPNETCORE_ENVIRONMENT = 'Development'
$env:MARID_OBJECT_ROOT = $objectRoot
$apiProcess = $null
$started = $false
$stdoutPath = Join-Path ([System.IO.Path]::GetTempPath()) "$projectName-api-out.log"
$stderrPath = Join-Path ([System.IO.Path]::GetTempPath()) "$projectName-api-err.log"

try {
    Push-Location -LiteralPath $repoRoot
    try {
        $started = $true
        docker compose -p $projectName -f $composeBase -f $composeAuth up -d postgres keycloak
        if ($LASTEXITCODE -ne 0) { throw 'Disposable PostgreSQL and Keycloak did not start.' }

        $deadline = (Get-Date).AddSeconds($StartupTimeoutSeconds)
        $databaseReady = $false
        while ((Get-Date) -lt $deadline) {
            docker compose -p $projectName -f $composeBase -f $composeAuth exec -T postgres `
                pg_isready -U marid_owner -d marid *> $null
            if ($LASTEXITCODE -eq 0) { $databaseReady = $true; break }
            Start-Sleep -Seconds 2
        }
        if (-not $databaseReady) { throw 'Disposable PostgreSQL did not become ready.' }
        $ownerPassword | dotnet run --project apps/admin -- migrate
        if ($LASTEXITCODE -ne 0) { throw 'Database migration failed.' }

        $tenantId = '11111111-1111-4111-8111-111111111111'
        $otherTenantId = '22222222-2222-4222-8222-222222222222'
        $seedSql = "INSERT INTO tenants (id,slug,display_name) VALUES ('$tenantId','auth-test','Auth Test'),('$otherTenantId','auth-test-b','Auth Test B'); INSERT INTO tenant_controls (tenant_id,autonomy,kill_mode) VALUES ('$tenantId','OBSERVE','READ_ONLY'),('$otherTenantId','OBSERVE','READ_ONLY'); INSERT INTO incidents (id,tenant_id,title,severity,status) VALUES ('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa','$tenantId','Tenant A secret incident','HIGH','OPEN'); INSERT INTO deployment_domains (id,tenant_id,hostname,verification_token,verification_status,last_verified_at) VALUES ('dddddddd-dddd-4ddd-8ddd-dddddddddddd','$tenantId','soc.example.com','fixture','VERIFIED',now());"
        $evidenceId = 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee'
        $exportId = 'ffffffff-ffff-4fff-8fff-ffffffffffff'
        $artifactId = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'
        $seedSql += " INSERT INTO evidence_objects (id,tenant_id,source,source_event_id,source_at,sensor_identity,content_type,byte_size,object_key,sha256,parser_version,correlation_id,trace_id) VALUES ('$evidenceId','$tenantId','fixture','evt-a',now(),'fixture','text/plain',10,'evidence/$tenantId/fixture.bin',repeat('a',64),'1','fixture','fixture');"
        $seedSql += " INSERT INTO export_jobs (id,tenant_id,period_start,period_end,status,requested_by,idempotency_key,manifest_key,manifest_sha256) VALUES ('$exportId','$tenantId',now()-interval '1 month',now(),'COMPLETED','fixture','fixture-export','exports/$tenantId/fixture/manifest.json',repeat('a',64));"
        $seedSql += " INSERT INTO export_artifacts (id,tenant_id,job_id,name,object_key,byte_size,sha256) VALUES ('$artifactId','$tenantId','$exportId','fixture.ndjson','exports/$tenantId/fixture/data.ndjson',10,repeat('a',64));"
        docker compose -p $projectName -f $composeBase -f $composeAuth exec -T postgres `
            psql -v ON_ERROR_STOP=1 -U marid_owner -d marid -c $seedSql
        if ($LASTEXITCODE -ne 0) { throw 'Authentication test tenant seed failed.' }

        $metadataUrl = "$env:MARID_OIDC_AUTHORITY/.well-known/openid-configuration"
        $keycloakReady = $false
        $deadline = (Get-Date).AddSeconds($StartupTimeoutSeconds)
        while ((Get-Date) -lt $deadline) {
            try {
                $metadata = Invoke-RestMethod -Uri $metadataUrl -TimeoutSec 3
                if ($metadata.issuer -eq $env:MARID_OIDC_AUTHORITY) {
                    $keycloakReady = $true
                    break
                }
            } catch { }
            Start-Sleep -Seconds 3
        }
        if (-not $keycloakReady) { throw 'Disposable Keycloak realm did not become ready.' }
        $tokenResponse = Invoke-RestMethod -Method Post -Uri $metadata.token_endpoint `
            -Body @{ grant_type = 'client_credentials'; client_id = 'marid-test-ingestor'; client_secret = $clientSecret } `
            -ContentType 'application/x-www-form-urlencoded'
        $token = [string]$tokenResponse.access_token
        if (-not $token) { throw 'Keycloak did not issue an access token.' }
        $claims = Get-TokenClaims $token
        if ($claims.tenant_id -ne $tenantId -or $claims.actor_type -ne 'service' -or
            $claims.azp -ne 'marid-test-ingestor' -or
            $claims.aud -notcontains 'marid-api' -or
            @($claims.scope.Split(' ')) -notcontains 'events.ingest') {
            throw 'Keycloak access token is missing required tenant, actor, audience, or scope claims.'
        }
        $noAudienceResponse = Invoke-RestMethod -Method Post -Uri $metadata.token_endpoint `
            -Body @{ grant_type = 'client_credentials'; client_id = 'marid-test-no-audience'; client_secret = $clientSecret } `
            -ContentType 'application/x-www-form-urlencoded'
        $noAudienceToken = [string]$noAudienceResponse.access_token
        if ((Get-TokenClaims $noAudienceToken).aud -contains 'marid-api') {
            throw 'Negative test token unexpectedly includes the API audience.'
        }
        $otherResponse = Invoke-RestMethod -Method Post -Uri $metadata.token_endpoint `
            -Body @{ grant_type = 'client_credentials'; client_id = 'marid-test-other-tenant'; client_secret = $clientSecret } `
            -ContentType 'application/x-www-form-urlencoded'
        $otherToken = [string]$otherResponse.access_token
        $otherClaims = Get-TokenClaims $otherToken
        if ($otherClaims.tenant_id -ne $otherTenantId -or
            @($otherClaims.scope.Split(' ')) -notcontains 'incidents.read' -or
            @($otherClaims.scope.Split(' ')) -notcontains 'deployment.domains.read') {
            throw 'Other-tenant test token lacks expected claims.'
        }

        dotnet restore apps/api/Marid.Api.csproj -p:NuGetAudit=false
        if ($LASTEXITCODE -ne 0) { throw 'API restore failed.' }
        dotnet build apps/api/Marid.Api.csproj -c Release --no-restore -p:NuGetAudit=false
        if ($LASTEXITCODE -ne 0) { throw 'API build failed.' }
        $apiProcess = Start-Process dotnet -ArgumentList @('run', '-c', 'Release', '--no-build', '--no-launch-profile', '--project', 'apps/api') `
            -WorkingDirectory $repoRoot -WindowStyle Hidden -PassThru `
            -RedirectStandardOutput $stdoutPath -RedirectStandardError $stderrPath
        $apiUrl = "http://127.0.0.1:$apiPort"
        $apiReady = $false
        $deadline = (Get-Date).AddSeconds(60)
        while ((Get-Date) -lt $deadline) {
            try {
                $ready = Invoke-WebRequest -Uri "$apiUrl/health/ready" -SkipHttpErrorCheck -TimeoutSec 3
                if ([int]$ready.StatusCode -eq 200) { $apiReady = $true; break }
            } catch { }
            Start-Sleep -Seconds 2
        }
        if (-not $apiReady) { throw 'API did not become ready.' }

        $eventUri = "$apiUrl/v1/events"
        $event = @{
            source = 'keycloak-test'; sourceEventId = "event-$projectName";
            category = 'endpoint'; sourceTimestamp = [DateTimeOffset]::UtcNow.ToString('O');
            sensorIdentity = 'test-sensor'; parserVersion = '1';
            rawEventReference = "raw://$projectName"; entityReferences = @();
            provenance = @{}; confidence = 0.9
        }
        $body = $event | ConvertTo-Json -Depth 5 -Compress
        $unauthenticated = Invoke-WebRequest -Method Post -Uri $eventUri `
            -Body $body -ContentType 'application/json' -SkipHttpErrorCheck
        Assert-Status $unauthenticated 401 'Missing token'
        $wrongAudience = Invoke-WebRequest -Method Post -Uri $eventUri `
            -Headers @{ Authorization = "Bearer $noAudienceToken" } `
            -Body $body -ContentType 'application/json' -SkipHttpErrorCheck
        Assert-Status $wrongAudience 401 'Wrong audience token'
        $headers = @{ Authorization = "Bearer $token" }
        $ungranted = Invoke-WebRequest -Method Post -Uri $eventUri -Headers $headers `
            -Body $body -ContentType 'application/json' -SkipHttpErrorCheck
        Assert-Status $ungranted 403 'Unregistered service identity'

        $expiry = [DateTimeOffset]::UtcNow.AddHours(1).ToString('yyyy-MM-ddTHH:mm:ssZ')
        $ownerPassword | dotnet run --project apps/admin -- grant-role $tenantId `
            ([string]$claims.sub) 'marid-test-ingestor' SERVICE EVENT_INGESTOR $expiry
        if ($LASTEXITCODE -ne 0) { throw 'Service role grant failed.' }
        $created = Invoke-WebRequest -Method Post -Uri $eventUri -Headers $headers `
            -Body $body -ContentType 'application/json' -SkipHttpErrorCheck
        Assert-Status $created 201 'Authorized event ingest'
        $duplicate = Invoke-WebRequest -Method Post -Uri $eventUri -Headers $headers `
            -Body $body -ContentType 'application/json' -SkipHttpErrorCheck
        Assert-Status $duplicate 200 'Idempotent event retry'
        $event.category = 'network'
        $changedBody = $event | ConvertTo-Json -Depth 5 -Compress
        $changed = Invoke-WebRequest -Method Post -Uri $eventUri -Headers $headers `
            -Body $changedBody -ContentType 'application/json' -SkipHttpErrorCheck
        Assert-Status $changed 409 'Conflicting event retry'
        $otherExpiry = [DateTimeOffset]::UtcNow.AddHours(1).ToString('yyyy-MM-ddTHH:mm:ssZ')
        $ownerPassword | dotnet run --project apps/admin -- grant-role $otherTenantId `
            ([string]$otherClaims.sub) 'marid-test-other-tenant' SERVICE AUDITOR $otherExpiry
        if ($LASTEXITCODE -ne 0) { throw 'Other tenant role grant failed.' }
        $otherIncidents = Invoke-WebRequest -Uri "$apiUrl/v1/incidents" `
            -Headers @{ Authorization = "Bearer $otherToken" } -SkipHttpErrorCheck
        Assert-Status $otherIncidents 200 'Other tenant incident list'
        if (@($otherIncidents.Content | ConvertFrom-Json).Count -ne 0) {
            throw 'Other tenant could read Tenant A incident.'
        }
        $otherDomains = Invoke-WebRequest -Uri "$apiUrl/v1/deployment/domains" `
            -Headers @{ Authorization = "Bearer $otherToken" } -SkipHttpErrorCheck
        Assert-Status $otherDomains 200 'Other tenant domain list'
        if (@($otherDomains.Content | ConvertFrom-Json).Count -ne 0) {
            throw 'Other tenant could read Tenant A domain.'
        }
        $missingEvidence = Invoke-WebRequest -Uri "$apiUrl/v1/evidence/$evidenceId" `
            -Headers @{ Authorization = "Bearer $otherToken" } -SkipHttpErrorCheck
        Assert-Status $missingEvidence 404 'Cross-tenant evidence metadata guess'
        $missingEvidenceBytes = Invoke-WebRequest -Uri "$apiUrl/v1/evidence/$evidenceId/content" `
            -Headers @{ Authorization = "Bearer $otherToken" } -SkipHttpErrorCheck
        Assert-Status $missingEvidenceBytes 404 'Cross-tenant evidence download guess'
        $missingExport = Invoke-WebRequest -Uri "$apiUrl/v1/exports/$exportId" `
            -Headers @{ Authorization = "Bearer $otherToken" } -SkipHttpErrorCheck
        Assert-Status $missingExport 404 'Cross-tenant export job guess'
        $missingArtifactList = Invoke-WebRequest -Uri "$apiUrl/v1/exports/$exportId/artifacts" `
            -Headers @{ Authorization = "Bearer $otherToken" } -SkipHttpErrorCheck
        Assert-Status $missingArtifactList 404 'Cross-tenant artifact list guess'
        $otherExports = Invoke-WebRequest -Uri "$apiUrl/v1/exports" `
            -Headers @{ Authorization = "Bearer $otherToken" } -SkipHttpErrorCheck
        Assert-Status $otherExports 200 'Other tenant export list'
        if (@($otherExports.Content | ConvertFrom-Json).Count -ne 0) {
            throw 'Other tenant could enumerate Tenant A exports.'
        }
        $missingManifest = Invoke-WebRequest -Uri "$apiUrl/v1/exports/$exportId/manifest" `
            -Headers @{ Authorization = "Bearer $otherToken" } -SkipHttpErrorCheck
        Assert-Status $missingManifest 404 'Cross-tenant manifest guess'
        $missingArtifact = Invoke-WebRequest -Uri "$apiUrl/v1/exports/$exportId/artifacts/$artifactId" `
            -Headers @{ Authorization = "Bearer $otherToken" } -SkipHttpErrorCheck
        Assert-Status $missingArtifact 404 'Cross-tenant artifact guess'
        $wrongScope = Invoke-WebRequest -Uri "$apiUrl/v1/exports" -Headers $headers `
            -SkipHttpErrorCheck
        Assert-Status $wrongScope 403 'Ingest-only token export access'
        foreach ($path in @("/v1/exports/$exportId", "/v1/exports/$exportId/artifacts",
                           "/v1/exports/$exportId/manifest",
                           "/v1/exports/$exportId/artifacts/$artifactId")) {
            $denied = Invoke-WebRequest -Uri "$apiUrl$path" -Headers $headers -SkipHttpErrorCheck
            Assert-Status $denied 403 "Ingest-only token $path"
        }
        $deniedCreate = Invoke-WebRequest -Method Post -Uri "$apiUrl/v1/exports" `
            -Headers $headers -Body '{}' -ContentType 'application/json' -SkipHttpErrorCheck
        Assert-Status $deniedCreate 403 'Ingest-only token export creation'
        $tlsAllowed = Invoke-WebRequest -Uri "$apiUrl/internal/tls/allow?domain=soc.example.com" `
            -SkipHttpErrorCheck
        Assert-Status $tlsAllowed 200 'Verified TLS issuance lookup'
        $tlsDenied = Invoke-WebRequest -Uri "$apiUrl/internal/tls/allow?domain=unknown.example.com" `
            -SkipHttpErrorCheck
        Assert-Status $tlsDenied 404 'Unverified TLS issuance lookup'
        $ownerPassword | dotnet run --project apps/admin -- revoke-role $tenantId `
            ([string]$claims.sub) 'marid-test-ingestor' EVENT_INGESTOR
        if ($LASTEXITCODE -ne 0) { throw 'Service role revocation failed.' }
        $revoked = Invoke-WebRequest -Method Post -Uri $eventUri -Headers $headers `
            -Body $body -ContentType 'application/json' -SkipHttpErrorCheck
        Assert-Status $revoked 403 'Revoked service identity'
        Write-Output 'Real Keycloak token and HTTP authorization checks passed.'
    } finally {
        Pop-Location
    }
} finally {
    if ($apiProcess) {
        Stop-Process -Id $apiProcess.Id -Force -ErrorAction SilentlyContinue
        $apiProcess.WaitForExit(5000) | Out-Null
    }
    if ($started) {
        docker compose -p $projectName -f $composeBase -f $composeAuth `
            down --volumes --remove-orphans | Out-Null
    }
    foreach ($name in $environmentNames) {
        [Environment]::SetEnvironmentVariable($name, $previousEnvironment[$name], 'Process')
    }
    foreach ($path in @($stdoutPath, $stderrPath)) {
        if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path -Force }
    }
    $resolvedObjectRoot = [System.IO.Path]::GetFullPath($objectRoot)
    $resolvedTempRoot = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath())
    if ((Test-Path -LiteralPath $resolvedObjectRoot) -and
        $resolvedObjectRoot.StartsWith($resolvedTempRoot, [StringComparison]::OrdinalIgnoreCase) -and
        [System.IO.Path]::GetFileName($resolvedObjectRoot) -eq "$projectName-objects") {
        [System.IO.Directory]::Delete($resolvedObjectRoot, $true)
    }
}
