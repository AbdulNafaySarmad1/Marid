using System.Security.Cryptography;

namespace Marid.Api;

public interface IObjectStore
{
    bool IsAvailable { get; }
    Task<StoredObject> PutAsync(string key, Func<Stream, CancellationToken, Task> produce,
        CancellationToken ct);
    Task<Stream> OpenVerifiedAsync(string key, string sha256, CancellationToken ct);
    Task DeleteAsync(string key, CancellationToken ct);
}

public sealed record StoredObject(string Key, long ByteSize, string Sha256);

public sealed class FileObjectStore : IObjectStore
{
    private readonly string? root;

    public FileObjectStore(string? configuredRoot)
    {
        if (string.IsNullOrWhiteSpace(configuredRoot)) return;
        if (!Path.IsPathFullyQualified(configuredRoot))
            throw new InvalidOperationException("MARID_OBJECT_ROOT must be an absolute path.");
        root = Path.GetFullPath(configuredRoot);
        Directory.CreateDirectory(root);
    }

    public bool IsAvailable => root is not null;

    public async Task<StoredObject> PutAsync(string key,
        Func<Stream, CancellationToken, Task> produce, CancellationToken ct)
    {
        var path = Resolve(key);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        var temporary = path + ".tmp-" + Guid.NewGuid().ToString("N");
        try
        {
            await using (var output = new FileStream(temporary, FileMode.CreateNew,
                             FileAccess.Write, FileShare.None, 131072,
                             FileOptions.Asynchronous | FileOptions.SequentialScan))
            {
                await produce(output, ct);
                await output.FlushAsync(ct);
                output.Flush(flushToDisk: true);
            }
            var stored = await InspectAsync(key, temporary, ct);
            if (stored.ByteSize == 0) throw new InvalidDataException("Empty objects are not accepted.");
            if (File.Exists(path))
            {
                var existing = await InspectAsync(key, path, ct);
                if (existing != stored)
                    throw new InvalidDataException("An object key already contains different content.");
                return existing;
            }
            File.Move(temporary, path);
            return stored;
        }
        finally
        {
            if (File.Exists(temporary)) File.Delete(temporary);
        }
    }

    public async Task<Stream> OpenVerifiedAsync(string key, string sha256,
        CancellationToken ct)
    {
        var path = Resolve(key);
        var input = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read,
            131072, FileOptions.Asynchronous | FileOptions.SequentialScan);
        try
        {
            var actual = await SHA256.HashDataAsync(input, ct);
            if (!CryptographicOperations.FixedTimeEquals(actual, Convert.FromHexString(sha256)))
                throw new InvalidDataException("Stored object failed SHA-256 verification.");
            input.Position = 0;
            return input;
        }
        catch
        {
            await input.DisposeAsync();
            throw;
        }
    }

    public Task DeleteAsync(string key, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        File.Delete(Resolve(key));
        return Task.CompletedTask;
    }

    private string Resolve(string key)
    {
        if (root is null) throw new InvalidOperationException("MARID_OBJECT_ROOT is not configured.");
        var segments = key.Split('/');
        if (segments.Length < 2 || segments.Any(segment => segment is "" or "." or ".." ||
            segment.Any(c => !char.IsAsciiLetterOrDigit(c) && c is not ('-' or '_' or '.'))))
            throw new ArgumentException("Invalid object key.", nameof(key));
        var path = Path.GetFullPath(Path.Combine([root, .. segments]));
        if (!path.StartsWith(root + Path.DirectorySeparatorChar,
                OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal))
            throw new ArgumentException("Object key escapes the storage root.", nameof(key));
        return path;
    }

    private static async Task<StoredObject> InspectAsync(string key, string path,
        CancellationToken ct)
    {
        await using var input = new FileStream(path, FileMode.Open, FileAccess.Read,
            FileShare.Read, 131072, FileOptions.Asynchronous | FileOptions.SequentialScan);
        var digest = await SHA256.HashDataAsync(input, ct);
        return new StoredObject(key, input.Length, Convert.ToHexString(digest).ToLowerInvariant());
    }
}
