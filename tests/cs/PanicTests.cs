using uniffi.ens;
using Xunit;

namespace Ens.Tests;

[Collection(LibraryCollection.Collection)]
public class PanicTests
{
    private const string NordLynxSchema = "nordlynx";
    private const int PrivateKeyLen = 32;
    private const int ServerMaintenanceCode = 2;
    private const string CallbackPanicReason = "callback panicked";

    [Fact]
    public void TestExceptionInNotify()
    {
        using var server = StubServer.Start(NordLynxSchema);

        var config = new Config();
        config.SetRootCertificateOverride(server.RootCertificate);

        var callback = new ThrowingRecorder();
        using var connection = EnsMethods.Connect(
            $"127.0.0.1:{server.Handshake.Port}",
            null,
            new Authentication.WithKeys(new Keys(new byte[PrivateKeyLen], server.PublicKey, KeyKind.NordLynx)),
            callback,
            config);

        server.Notify(ServerMaintenanceCode, null);

        Assert.StartsWith(CallbackPanicReason, callback.WaitDisconnect());
    }

    private sealed class ThrowingRecorder : ErrorNotificationCallback
    {
        private readonly NotificationRecorder recorder = new();

        public void Notify(ConnectionErrorNotification notification) =>
            throw new InvalidOperationException("notify failed");

        public void Disconnected(string? reason) => recorder.Disconnected(reason);

        public string? WaitDisconnect() => recorder.WaitDisconnect();
    }
}
