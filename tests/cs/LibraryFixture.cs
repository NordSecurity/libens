using uniffi.ens;
using Xunit;

namespace Ens.Tests;

// libens must be initialised once per process, before any other call, and
// deinitialised at the end.
public sealed class LibraryFixture : IDisposable
{
    private const string AppVersion = "cs-tests";

    public LibraryFixture()
    {
        EnsMethods.SetLogCallback(LogLevel.Debug, new ConsoleLogCallback());
        EnsMethods.Init(AppVersion);
    }

    public void Dispose() => EnsMethods.Deinit();

    private sealed class ConsoleLogCallback : LogCallback
    {
        public void Log(LogLevel logLevel, string message) =>
            Console.WriteLine($"[libens:{logLevel}] {message}");
    }
}

[CollectionDefinition(Collection)]
public sealed class LibraryCollection : ICollectionFixture<LibraryFixture>
{
    public const string Collection = "libens";
}
