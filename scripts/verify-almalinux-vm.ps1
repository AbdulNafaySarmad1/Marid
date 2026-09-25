$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$runner = Join-Path $PSScriptRoot 'verify-almalinux-vm.sh'
$bootstrap = Join-Path $PSScriptRoot 'bootstrap.sh'
$containerName = 'marid-vm-' + ([Guid]::NewGuid().ToString('N').Substring(0, 12))

try {
    docker run --rm --name $containerName --memory=2g --cpus=2 `
        --security-opt=no-new-privileges `
        --mount "type=bind,source=$runner,target=/input/verify.sh,readonly" `
        --mount "type=bind,source=$bootstrap,target=/input/bootstrap.sh,readonly" `
        debian:bookworm-slim bash /input/verify.sh
    if ($LASTEXITCODE -ne 0) { throw 'Disposable AlmaLinux VM verification failed.' }
}
finally {
    $matching = docker ps -a --filter "name=^/$containerName$" --format '{{.Names}}'
    if ($LASTEXITCODE -eq 0 -and $matching -eq $containerName) {
        docker rm -f $containerName | Out-Null
    }
}
