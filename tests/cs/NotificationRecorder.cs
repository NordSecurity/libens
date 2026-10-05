using System.Collections.Concurrent;
using uniffi.ens;

namespace Ens.Tests;

internal sealed class NotificationRecorder : ErrorNotificationCallback
{
    private static readonly TimeSpan CallbackTimeout = TimeSpan.FromSeconds(10);

    private readonly BlockingCollection<ConnectionErrorNotification> notifications = new();
    private readonly BlockingCollection<string?> disconnects = new();

    public int NotificationCount => notifications.Count;

    public void Notify(ConnectionErrorNotification notification) => notifications.Add(notification);

    public void Disconnected(string? reason) => disconnects.Add(reason);

    public ConnectionErrorNotification WaitNotification() => Take(notifications, "notification");

    public string? WaitDisconnect() => Take(disconnects, "disconnect");

    private static T Take<T>(BlockingCollection<T> queue, string what)
    {
        if (!queue.TryTake(out var item, CallbackTimeout))
        {
            throw new TimeoutException($"No {what} within {CallbackTimeout}");
        }

        return item;
    }
}
