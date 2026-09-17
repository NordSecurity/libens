using System.Diagnostics;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Ens.Tests;

internal sealed record Handshake(
    [property: JsonPropertyName("port")] ushort Port,
    [property: JsonPropertyName("public_key")] string PublicKey,
    [property: JsonPropertyName("root_certificate")] string RootCertificate,
    [property: JsonPropertyName("username")] string? Username,
    [property: JsonPropertyName("password")] string? Password);

internal sealed class StubServer : IDisposable
{
    private const string StubEnvVar = "ENS_STUB";

    private readonly Process process;

    public Handshake Handshake { get; }

    private StubServer(Process process, Handshake handshake)
    {
        this.process = process;
        Handshake = handshake;
    }

    public static StubServer Start(string schema)
    {
        var process = new Process
        {
            StartInfo = new ProcessStartInfo(StubPath(), schema)
            {
                RedirectStandardInput = true,
                RedirectStandardOutput = true,
            },
        };

        process.Start();

        try
        {
            var announcement = process.StandardOutput.ReadLine()
                ?? throw new InvalidOperationException("The stub announced nothing");

            var handshake = JsonSerializer.Deserialize<Handshake>(announcement)
                ?? throw new InvalidOperationException($"Cannot parse the announcement {announcement}");

            return new StubServer(process, handshake);
        }
        catch
        {
            process.Kill(entireProcessTree: true);
            throw;
        }
    }

    public void Notify(int code, string? additionalInfo) =>
        Send(new { command = "notification", code, additional_info = additionalInfo });

    public byte[] PublicKey => Convert.FromBase64String(Handshake.PublicKey);

    public byte[] RootCertificate => Convert.FromBase64String(Handshake.RootCertificate);

    private void Send(object command)
    {
        process.StandardInput.WriteLine(JsonSerializer.Serialize(command));
        process.StandardInput.Flush();
    }

    private static string StubPath()
    {
        var configured = Environment.GetEnvironmentVariable(StubEnvVar);
        if (!string.IsNullOrEmpty(configured))
        {
            return configured;
        }

        var target = Environment.GetEnvironmentVariable("CARGO_TARGET_DIR");
        if (string.IsNullOrEmpty(target))
        {
            target = Path.Combine("..", "..", "..", "..", "..", "target");
        }

        return Path.Combine(target, "debug", "ens-stub");
    }

    public void Dispose()
    {
        process.StandardInput.Close();
        if (!process.WaitForExit(TimeSpan.FromSeconds(10)))
        {
            process.Kill(entireProcessTree: true);
            throw new InvalidOperationException("The stub did not exit");
        }

        if (process.ExitCode != 0)
        {
            throw new InvalidOperationException($"The stub exited with {process.ExitCode}");
        }

        process.Dispose();
    }
}
