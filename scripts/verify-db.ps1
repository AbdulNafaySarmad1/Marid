param(
    [int]$StartupTimeoutSeconds = 90
)

$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$composePath = Join-Path $repoRoot 'infrastructure/podman/dev-minimal.compose.yaml'
$projectName = 'maridverify' + ([Guid]::NewGuid().ToString('N').Substring(0, 12))
$listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
$listener.Start()
$hostPort = ([System.Net.IPEndPoint]$listener.LocalEndpoint).Port
$listener.Stop()

$ownerPassword = [Convert]::ToBase64String([System.Security.Cryptography.RandomNumberGenerator]::GetBytes(36))
$appPassword = [Convert]::ToBase64String([System.Security.Cryptography.RandomNumberGenerator]::GetBytes(36))
$keycloakPassword = [Convert]::ToBase64String([System.Security.Cryptography.RandomNumberGenerator]::GetBytes(36))
$environmentNames = @(
    'MARID_DB_OWNER_PASSWORD', 'MARID_DB_APP_PASSWORD', 'MARID_KEYCLOAK_ADMIN_PASSWORD',
    'MARID_DB_HOST_PORT', 'MARID_DB_PORT', 'MARID_ADMIN_PASSWORD_STDIN',
    'MARID_TEST_OWNER_PASSWORD', 'MARID_TEST_APP_PASSWORD', 'MARID_TEST_DB_PORT'
)
$previousEnvironment = @{}
foreach ($name in $environmentNames) {
    $previousEnvironment[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
}
$env:MARID_DB_OWNER_PASSWORD = $ownerPassword
$env:MARID_DB_APP_PASSWORD = $appPassword
$env:MARID_KEYCLOAK_ADMIN_PASSWORD = $keycloakPassword
$env:MARID_DB_HOST_PORT = [string]$hostPort
$env:MARID_DB_PORT = [string]$hostPort
$env:MARID_ADMIN_PASSWORD_STDIN = '1'
$env:MARID_TEST_OWNER_PASSWORD = $ownerPassword
$env:MARID_TEST_APP_PASSWORD = $appPassword
$env:MARID_TEST_DB_PORT = [string]$hostPort
$started = $false

try {
    Push-Location -LiteralPath $repoRoot
    try {
        $started = $true
        docker compose -p $projectName -f $composePath up -d postgres
        if ($LASTEXITCODE -ne 0) { throw 'Disposable PostgreSQL did not start.' }

        $ready = $false
        $deadline = (Get-Date).AddSeconds($StartupTimeoutSeconds)
        while ((Get-Date) -lt $deadline) {
            docker compose -p $projectName -f $composePath exec -T postgres `
                pg_isready -U marid_owner -d marid *> $null
            if ($LASTEXITCODE -eq 0) { $ready = $true; break }
            Start-Sleep -Seconds 2
        }
        if (-not $ready) { throw 'Disposable PostgreSQL did not become ready.' }

        $ownerPassword | dotnet run --project apps/admin -- migrate
        if ($LASTEXITCODE -ne 0) { throw 'Migration runner failed.' }
        $ownerPassword | dotnet run --project apps/admin -- migrate
        if ($LASTEXITCODE -ne 0) { throw 'Migration idempotence check failed.' }

        docker compose -p $projectName -f $composePath exec -T postgres `
            psql -v ON_ERROR_STOP=1 -U marid_owner -d marid -f /opt/marid/tests/rls.sql
        if ($LASTEXITCODE -ne 0) { throw 'Tenant isolation SQL checks failed.' }
        docker run --rm --network "${projectName}_default" `
            --mount "type=bind,source=$repoRoot,target=/src" -w /src `
            -e MARID_TEST_OWNER_PASSWORD -e MARID_TEST_APP_PASSWORD `
            -e MARID_TEST_DB_HOST=postgres -e MARID_TEST_DB_PORT=5432 `
            mcr.microsoft.com/dotnet/sdk:10.0 dotnet test `
            tests/integration/Marid.Api.IntegrationTests/Marid.Api.IntegrationTests.csproj `
            -c Release -p:NuGetAudit=false -m:1
        if ($LASTEXITCODE -ne 0) { throw 'Live store integration checks failed.' }
        docker compose -p $projectName -f $composePath exec -T postgres `
            pg_dump -Fc -U marid_owner -d marid -f /tmp/marid-test.backup
        if ($LASTEXITCODE -ne 0) { throw 'Disposable database backup failed.' }
        docker compose -p $projectName -f $composePath exec -T postgres `
            createdb -U marid_owner marid_restore
        if ($LASTEXITCODE -ne 0) { throw 'Disposable restore target creation failed.' }
        docker compose -p $projectName -f $composePath exec -T postgres `
            pg_restore -U marid_owner -d marid_restore /tmp/marid-test.backup
        if ($LASTEXITCODE -ne 0) { throw 'Disposable database restore failed.' }
        $restored = docker compose -p $projectName -f $composePath exec -T postgres `
            psql -At -v ON_ERROR_STOP=1 -U marid_owner -d marid_restore `
            -c 'SELECT (SELECT count(*) FROM schema_migrations) = 4 AND (SELECT count(*) FROM tenants) >= 2 AND (SELECT count(*) FROM security_events) >= 1 AND (SELECT count(*) FROM tenant_role_grants) >= 1;'
        if ($LASTEXITCODE -ne 0 -or ($restored | Out-String).Trim() -ne 't') {
            throw 'Restored database did not contain expected schema and tenant records.'
        }
        Write-Output 'Disposable migrations, RLS, live store, and database restore checks passed.'
    }
    finally {
        Pop-Location
    }
}
finally {
    if ($started) {
        docker compose -p $projectName -f $composePath down --volumes --remove-orphans | Out-Null
    }
    foreach ($name in $environmentNames) {
        [Environment]::SetEnvironmentVariable($name, $previousEnvironment[$name], 'Process')
    }
}
