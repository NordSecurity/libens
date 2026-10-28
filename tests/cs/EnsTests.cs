using System.Security.Cryptography;
using uniffi.ens;
using Xunit;

namespace Ens.Tests;

[Collection(LibraryCollection.Collection)]
public class EnsTests
{
    private const string NordLynxSchema = "nordlynx";
    private const string NordWhisperSchema = "nordwhisper";
    private const string OpenVpnSchema = "openvpn";
    private const int PrivateKeyLen = 32;
    private const int ConnectionLimitReachedCode = 1;
    private const int ServerMaintenanceCode = 2;
    private const int UnauthenticatedCode = 3;
    private const int SupersededCode = 4;
    private const int UnsupportedCipherCode = 5;
    private const int UnknownCode = 99;
    private const string MaintenanceInfo = "planned maintenance";
    private const string MalformedAddress = "not-an-address";
    private const string WrongPassword = "wrong";
    private const string ShutdownReason = "shutdown";
    private const string AuthRejectionReason =
        "persistent error code: 'The request does not have valid authentication credentials', message: \"Incorrect password\"";

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
    public void TestNotificationOverPasswordAuthentication() =>
        ReceiveOverPasswordAuthentication(OpenVpnSchema, CredentialsKind.OpenVpn);

    [Fact]
    public void TestNotificationOverNordWhisperAuthentication() =>
        ReceiveOverPasswordAuthentication(NordWhisperSchema, CredentialsKind.NordWhisper);

    private static void ReceiveOverPasswordAuthentication(string schema, CredentialsKind kind)
    {
        using var server = StubServer.Start(schema);

        var callback = new NotificationRecorder();
        using var connection = ConnectToStub(server, new Authentication.WithCredentials(
            new Credentials(server.Handshake.Username!, server.Handshake.Password!, kind)), callback);

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

        Assert.Equal(AuthRejectionReason, callback.WaitDisconnect());
        Assert.Equal(0, callback.NotificationCount);
    }

    [Fact]
    public void TestNotificationKinds()
    {
        using var server = StubServer.Start(NordLynxSchema);

        var expected = new (int Code, ConnectionErrorNotificationKind Kind)[]
        {
            (ConnectionLimitReachedCode, new ConnectionErrorNotificationKind.ConnectionLimitReached()),
            (ServerMaintenanceCode, new ConnectionErrorNotificationKind.ServerMaintenance()),
            (UnauthenticatedCode, new ConnectionErrorNotificationKind.Unauthenticated()),
            (SupersededCode, new ConnectionErrorNotificationKind.Superseded()),
            (UnsupportedCipherCode, new ConnectionErrorNotificationKind.UnsupportedCipher()),
            (UnknownCode, new ConnectionErrorNotificationKind.Unknown(UnknownCode)),
        };

        var callback = new NotificationRecorder();
        using var connection = ConnectToStub(server, KeyAuthentication(server.PublicKey), callback);

        foreach (var (code, kind) in expected)
        {
            server.Notify(code, null);

            Assert.Equal(kind, callback.WaitNotification().kind);
        }
    }

    [Fact]
    public void TestMalformedAddress()
    {
        Assert.Throws<EnsException.InvalidInput>(() => EnsMethods.Connect(
            MalformedAddress, null, KeyAuthentication(new byte[PrivateKeyLen]), new NotificationRecorder(), new Config()));
    }

    [Fact]
    public void TestLogCallback()
    {
        Assert.True(LibraryFixture.LogCount > 0, "No log message arrived");
    }

    private static Connection ConnectToStub(
        StubServer server,
        Authentication authentication,
        ErrorNotificationCallback callback)
    {
        var config = new Config();
        config.SetRootCertificateOverride(server.RootCertificate);

        return EnsMethods.Connect(
            $"127.0.0.1:{server.Handshake.Port}", null, authentication, callback, config);
    }

    private static Authentication KeyAuthentication(byte[] vpnPublicKey) =>
        new Authentication.WithKeys(
            new Keys(RandomNumberGenerator.GetBytes(PrivateKeyLen), vpnPublicKey, KeyKind.NordLynx));
}
