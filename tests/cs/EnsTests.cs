using System.Security.Cryptography;
using uniffi.ens;
using Xunit;

namespace Ens.Tests;

[Collection(LibraryCollection.Collection)]
public class EnsTests
{
    private const string NordLynxSchema = "nordlynx";
    private const string OpenVpnSchema = "openvpn";
    private const int PrivateKeyLen = 32;
    private const int ServerMaintenanceCode = 2;
    private const string MaintenanceInfo = "planned maintenance";
    private const string WrongPassword = "wrong";
    private const string ShutdownReason = "shutdown";

    [Fact]
    public void TestNotificationOverKeyAuthentication()
    {
        using var server = StubServer.Start(NordLynxSchema);

        var callback = new NotificationRecorder();
        using var connection = ConnectToStub(server, new Authentication.WithKeys(
            new Keys(RandomNumberGenerator.GetBytes(PrivateKeyLen), server.PublicKey, KeyKind.NordLynx)), callback);

        server.Notify(ServerMaintenanceCode, MaintenanceInfo);

        var notification = callback.WaitNotification();

        Assert.Equal(new ConnectionErrorNotificationKind.ServerMaintenance(), notification.kind);
        Assert.Equal(MaintenanceInfo, notification.additionalInfo);

        connection.Shutdown();

        Assert.Equal(ShutdownReason, callback.WaitDisconnect());
    }

    [Fact]
    public void TestNotificationOverPasswordAuthentication()
    {
        using var server = StubServer.Start(OpenVpnSchema);

        var callback = new NotificationRecorder();
        using var connection = ConnectToStub(server, new Authentication.WithCredentials(
            new Credentials(server.Handshake.Username!, server.Handshake.Password!, CredentialsKind.OpenVpn)), callback);

        server.Notify(ServerMaintenanceCode, MaintenanceInfo);

        var notification = callback.WaitNotification();

        Assert.Equal(new ConnectionErrorNotificationKind.ServerMaintenance(), notification.kind);
        Assert.Equal(MaintenanceInfo, notification.additionalInfo);

        connection.Shutdown();

        Assert.Equal(ShutdownReason, callback.WaitDisconnect());
    }

    [Fact]
    public void TestAuthenticationRejection()
    {
        using var server = StubServer.Start(OpenVpnSchema);

        var callback = new NotificationRecorder();
        using var connection = ConnectToStub(server, new Authentication.WithCredentials(
            new Credentials(server.Handshake.Username!, WrongPassword, CredentialsKind.OpenVpn)), callback);

        var expected = $"'http://127.0.0.1:{server.Handshake.Port}/' rejected the authentication";

        Assert.Equal(expected, callback.WaitDisconnect());
        Assert.Equal(0, callback.NotificationCount);
    }

    private static Connection ConnectToStub(
        StubServer server, Authentication authentication, ErrorNotificationCallback callback)
    {
        var config = new Config();
        config.SetRootCertificateOverride(server.RootCertificate);

        return EnsMethods.Connect(
            $"127.0.0.1:{server.Handshake.Port}", null, authentication, callback, config);
    }
}
