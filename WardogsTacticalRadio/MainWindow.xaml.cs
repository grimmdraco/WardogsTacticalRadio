using System.Windows;
using System.Windows.Input;
using System.Windows.Media;
using WardogsTacticalRadio.Audio;
using WardogsTacticalRadio.Input;
using WardogsTacticalRadio.Models;
using WardogsTacticalRadio.Networking;
using WardogsTacticalRadio.Storage;

namespace WardogsTacticalRadio;

public partial class MainWindow : Window
{
    private AppSettings _settings = new();
    private RadioSessionService? _sessionService;
    private RadioAudioService? _audioService;
    private GlobalPttHotkeys? _hotkeys;
    private const string Version = "v0.1.0-alpha2b";
    private string _selectedTxChannel = "SQD";
    private bool _transmitting;
    private CancellationTokenSource? _rxResetCts;

    public MainWindow()
    {
        InitializeComponent();
        Loaded += MainWindow_Loaded;
        Closing += MainWindow_Closing;
    }

    private async void MainWindow_Loaded(object sender, RoutedEventArgs e)
    {
        _settings = await AppSettingsStore.LoadAsync();
        UserNameText.Text = _settings.UserName;
        CallsignText.Text = _settings.Callsign;
        RoleText.Text = _settings.Role;
        HostEligibleText.Text = _settings.HostEligible ? "● YES" : "● NO";
        HostEligibleText.Foreground = _settings.HostEligible ? (Brush)Application.Current.Resources["Green"] : (Brush)Application.Current.Resources["Red"];
        LocalAddressText.Text = $"{RadioSessionService.GetBestLanAddress()}:{_settings.ListenPort}";
        VersionText.Text = Version;
        PopulateSocialPanels();

        _sessionService = new RadioSessionService(_settings);
        _sessionService.StatusChanged += OnStatusChanged;
        _sessionService.SessionChanged += OnSessionChanged;
        _sessionService.AudioFrameReceived += OnAudioFrameReceived;
        _sessionService.ConnectionLost += OnConnectionLost;

        try
        {
            _audioService = new RadioAudioService();
            _audioService.MicrophoneFrameReady += OnMicrophoneFrameReady;
            _audioService.Start();
            AudioStatusText.Text = "AUDIO: READY";
        }
        catch (Exception ex)
        {
            AudioStatusText.Text = $"AUDIO: ERROR ({ex.Message})";
            AudioStatusText.Foreground = (Brush)Application.Current.Resources["Red"];
        }

        try
        {
            // See GlobalPttHotkeys for why this uses a raw keyboard hook instead of WPF's
            // (focus-scoped) PreviewKeyDown/Up.
            _hotkeys = new GlobalPttHotkeys([Key.F9, Key.F10]);
            _hotkeys.KeyDown += OnHotkeyDown;
            _hotkeys.KeyUp += OnHotkeyUp;
            _hotkeys.Start();
        }
        catch (Exception ex)
        {
            AudioStatusText.Text = $"HOTKEYS: ERROR ({ex.Message}) // USE ON-SCREEN PTT";
            AudioStatusText.Foreground = (Brush)Application.Current.Resources["Red"];
        }

        SelectTxChannel("SQD");
    }

    // Hook callbacks already run on this (UI) thread's message loop, so Dispatcher.Invoke is
    // just defensive here - it's a no-op re-entry, not a cross-thread marshal - kept in case
    // hook installation ever moves off the UI thread.
    private void OnHotkeyDown(Key key)
    {
        Dispatcher.Invoke(() =>
        {
            if (key == Key.F9) { SelectTxChannel("SQD"); BeginTransmit("SQD"); }
            else if (key == Key.F10) { SelectTxChannel("CMD"); BeginTransmit("CMD"); }
        });
    }

    private void OnHotkeyUp(Key key)
    {
        Dispatcher.Invoke(() =>
        {
            if ((key == Key.F9 && _selectedTxChannel == "SQD") || (key == Key.F10 && _selectedTxChannel == "CMD"))
                EndTransmit();
        });
    }

    private void PopulateSocialPanels()
    {
        FriendsList.Items.Clear();
        if (_settings.Friends.Count == 0) FriendsList.Items.Add("No friends saved yet.");
        else foreach (var friend in _settings.Friends) FriendsList.Items.Add($"{friend.Callsign,-12} {friend.Status}");
        ServersList.Items.Clear();
        if (_settings.KnownServers.Count == 0) ServersList.Items.Add("No known servers yet.");
        else foreach (var server in _settings.KnownServers) ServersList.Items.Add($"{(server.Favorite ? "★" : " ")} {server.Name}  {server.Address}");
        RecentList.Items.Clear();
        if (_settings.RecentSessions.Count == 0) RecentList.Items.Add("No recent sessions yet.");
        else foreach (var session in _settings.RecentSessions.OrderByDescending(s => s.LastJoinedUtc).Take(8)) RecentList.Items.Add($"{session.Name}  {session.Address}");
    }

    private async void PrepareInternetHostingButton_Click(object sender, RoutedEventArgs e)
    {
        PrepareInternetHostingButton.IsEnabled = false;
        ConnectivityStatusText.Text = "CHECKING FIREWALL / ROUTER...";
        ConnectivityStatusText.Foreground = (Brush)Application.Current.Resources["Amber"];
        try
        {
            var report = await HostConnectivityService.PrepareAsync(_settings.ListenPort);
            var firewall = report.FirewallRuleReady ? "FIREWALL READY" : "FIREWALL NEEDS ATTENTION";
            var mapping = report.AutomaticPortMappingReady ? "AUTO PORT READY" : "MANUAL ROUTER SETUP MAY BE REQUIRED";
            ConnectivityStatusText.Text = $"{firewall} // {mapping}\nPUBLIC: {report.PublicAddress}:{_settings.ListenPort}\nGATEWAY: {report.GatewayAddress}";
            ConnectivityStatusText.Foreground = report.FirewallRuleReady
                ? (Brush)Application.Current.Resources["Green"]
                : (Brush)Application.Current.Resources["Amber"];
            JoinAddressBox.Text = report.PublicAddress != "Unknown" ? report.PublicAddress : JoinAddressBox.Text;
        }
        catch (Exception ex)
        {
            ConnectivityStatusText.Text = $"CONNECTIVITY CHECK FAILED // {ex.Message}";
            ConnectivityStatusText.Foreground = (Brush)Application.Current.Resources["Red"];
        }
        finally
        {
            PrepareInternetHostingButton.IsEnabled = true;
        }
    }

    private void OpenRouterButton_Click(object sender, RoutedEventArgs e)
    {
        try { HostConnectivityService.OpenRouterPage(); }
        catch (Exception ex)
        {
            ConnectivityStatusText.Text = $"ROUTER PAGE FAILED // {ex.Message}";
            ConnectivityStatusText.Foreground = (Brush)Application.Current.Resources["Red"];
        }
    }

    private async void HostButton_Click(object sender, RoutedEventArgs e)
    {
        if (_sessionService is null) return;
        if (string.IsNullOrEmpty(HostPasswordBox.Password))
        {
            SetStatus("HOST FAILED // A SESSION PASSWORD IS REQUIRED", false);
            return;
        }
        try
        {
            HostButton.IsEnabled = false; JoinButton.IsEnabled = false;
            await _sessionService.HostAsync(HostSessionNameBox.Text, _settings.ListenPort, HostPasswordBox.Password);
            DisconnectButton.IsEnabled = true;
            RememberSession(HostSessionNameBox.Text, $"{RadioSessionService.GetBestLanAddress()}:{_settings.ListenPort}");
        }
        catch (Exception ex) { SetStatus($"HOST FAILED // {ex.Message}", false); HostButton.IsEnabled = true; JoinButton.IsEnabled = true; }
    }

    private async void JoinButton_Click(object sender, RoutedEventArgs e)
    {
        if (_sessionService is null) return;
        try
        {
            HostButton.IsEnabled = false; JoinButton.IsEnabled = false;
            var address = JoinAddressBox.Text.Trim();
            if (string.IsNullOrWhiteSpace(address)) address = "127.0.0.1";
            await _sessionService.JoinAsync(address, _settings.ListenPort, JoinPasswordBox.Password);
            DisconnectButton.IsEnabled = true;
            RememberSession("Joined Radio Net", $"{address}:{_settings.ListenPort}");
        }
        catch (Exception ex) { SetStatus($"JOIN FAILED // {ex.Message}", false); HostButton.IsEnabled = true; JoinButton.IsEnabled = true; }
    }

    private async void DisconnectButton_Click(object sender, RoutedEventArgs e)
    {
        if (_sessionService is null) return;
        DisconnectButton.IsEnabled = false;
        await _sessionService.StopAsync();
        ResetToIdle();
    }

    // Resets the UI to idle after a deliberate disconnect. OnConnectionLost below handles the
    // same "no active session" end state for an unexpected drop, with its own distinct
    // messaging ("LINK LOST" vs a plain idle screen).
    private void ResetToIdle()
    {
        _transmitting = false;
        NetTitleText.Text = "NET: STANDBY";
        RxTxLargeText.Text = "STBY";
        ActiveCallsignText.Text = "NO ACTIVE TRANSMISSION";
        SessionIdText.Text = "NET ID: --------";
        LcdStatusText.Text = "SIG: ----   NET: 0   HOST: NONE";
        LeftStatusText.Text = "● OFFLINE";
        LeftStatusText.Foreground = (Brush)Application.Current.Resources["Amber"];
        TxLamp.Fill = new SolidColorBrush(Color.FromRgb(72, 54, 50));
        RxLamp.Fill = new SolidColorBrush(Color.FromRgb(50, 80, 47));
        HostButton.IsEnabled = true;
        JoinButton.IsEnabled = true;
        DisconnectButton.IsEnabled = false;
        AudioStatusText.Text = "AUDIO: READY // F9 SQD / F10 CMD";
    }

    private void CmdButton_Click(object sender, RoutedEventArgs e) => SelectTxChannel("CMD");
    private void SqdButton_Click(object sender, RoutedEventArgs e) => SelectTxChannel("SQD");

    private void SelectTxChannel(string channel)
    {
        if (channel == "CMD" && !CanUseCommandNet())
        {
            AudioStatusText.Text = "AUDIO: CMD TX REQUIRES LEADERSHIP ROLE";
            return;
        }
        _selectedTxChannel = channel;
        CmdButton.BorderThickness = channel == "CMD" ? new Thickness(3) : new Thickness(1);
        SqdButton.BorderThickness = channel == "SQD" ? new Thickness(3) : new Thickness(1);
        TxChannelText.Text = $"TX NET: {channel}";
    }

    private bool CanUseCommandNet() => _settings.Role.Contains("Leader", StringComparison.OrdinalIgnoreCase) || _settings.Role.Contains("Command", StringComparison.OrdinalIgnoreCase);

    private void PttButton_PreviewMouseLeftButtonDown(object sender, MouseButtonEventArgs e) { BeginTransmit(_selectedTxChannel); PttButton.CaptureMouse(); e.Handled = true; }
    private void PttButton_PreviewMouseLeftButtonUp(object sender, MouseButtonEventArgs e) { EndTransmit(); PttButton.ReleaseMouseCapture(); e.Handled = true; }

    private void BeginTransmit(string channel)
    {
        if (_sessionService?.IsConnected != true) { AudioStatusText.Text = "AUDIO: JOIN OR HOST A NET FIRST"; return; }
        if (channel == "CMD" && !CanUseCommandNet()) return;
        _selectedTxChannel = channel;
        _transmitting = true;
        RxTxLargeText.Text = $"TX {channel}";
        ActiveCallsignText.Text = _settings.Callsign;
        TxLamp.Fill = (Brush)Application.Current.Resources["Red"];
        AudioStatusText.Text = $"TRANSMITTING // {channel}";
    }

    private void EndTransmit()
    {
        if (!_transmitting) return;
        _transmitting = false;
        TxLamp.Fill = new SolidColorBrush(Color.FromRgb(72, 54, 50));
        RestoreSessionDisplay();
        AudioStatusText.Text = $"AUDIO: READY // F9 SQD / F10 CMD";
    }

    private void OnMicrophoneFrameReady(byte[] pcm16)
    {
        if (!_transmitting || _sessionService?.IsConnected != true) return;
        _ = _sessionService.TransmitAudioAsync(_selectedTxChannel, pcm16);
    }

    private void OnAudioFrameReceived(AudioFrame frame)
    {
        if (frame.ChannelId is not ("SQD" or "CMD")) return;
        _audioService?.Play(frame.Pcm16);
        Dispatcher.Invoke(() =>
        {
            if (_transmitting) return;
            RxTxLargeText.Text = $"RX {frame.ChannelId}";
            ActiveCallsignText.Text = frame.SourceCallsign;
            RxLamp.Fill = (Brush)Application.Current.Resources["Green"];
            AudioStatusText.Text = $"RECEIVING // {frame.ChannelId} // {frame.SourceCallsign}";
            _rxResetCts?.Cancel();
            _rxResetCts = new CancellationTokenSource();
            var token = _rxResetCts.Token;
            _ = Task.Run(async () =>
            {
                try { await Task.Delay(350, token); }
                catch { return; }
                Dispatcher.Invoke(() => { if (!_transmitting) { RxLamp.Fill = new SolidColorBrush(Color.FromRgb(50, 80, 47)); RestoreSessionDisplay(); AudioStatusText.Text = "AUDIO: READY // F9 SQD / F10 CMD"; } });
            }, token);
        });
    }

    private void RestoreSessionDisplay()
    {
        var state = _sessionService?.Session;
        if (state is null) { RxTxLargeText.Text = "STBY"; ActiveCallsignText.Text = "NO ACTIVE TRANSMISSION"; return; }
        RxTxLargeText.Text = _sessionService?.IsHosting == true ? "HOST" : "LINK";
        ActiveCallsignText.Text = $"HOST // {state.HostCallsign}";
    }

    private void OnConnectionLost(string reason)
    {
        Dispatcher.Invoke(() =>
        {
            _transmitting = false;
            NetTitleText.Text = "NET: STANDBY";
            RxTxLargeText.Text = "LINK LOST";
            ActiveCallsignText.Text = "HOST UNREACHABLE";
            SessionIdText.Text = "NET ID: --------";
            LcdStatusText.Text = reason;
            LeftStatusText.Text = "● OFFLINE";
            LeftStatusText.Foreground = (Brush)Application.Current.Resources["Amber"];
            TxLamp.Fill = new SolidColorBrush(Color.FromRgb(72, 54, 50));
            RxLamp.Fill = new SolidColorBrush(Color.FromRgb(50, 80, 47));
            HostButton.IsEnabled = true;
            JoinButton.IsEnabled = true;
            DisconnectButton.IsEnabled = false;
            AudioStatusText.Text = "AUDIO: LINK LOST // REJOIN OR HOST A NET";
        });
    }

    private void OnStatusChanged(string status)
    {
        Dispatcher.Invoke(() =>
        {
            if (_sessionService?.Session is not null)
            {
                LeftStatusText.Text = _sessionService.IsHosting ? "● HOSTING" : "● ONLINE";
                LeftStatusText.Foreground = (Brush)Application.Current.Resources["Green"];
                return;
            }
            SetStatus(status, true);
        });
    }

    private void OnSessionChanged(RadioSessionState state)
    {
        Dispatcher.Invoke(() =>
        {
            NetTitleText.Text = $"NET: {state.SessionName.ToUpperInvariant()}";
            if (!_transmitting) RestoreSessionDisplay();
            SessionIdText.Text = $"NET ID: {state.SessionId.ToString()[..8].ToUpperInvariant()}";
            LcdStatusText.Text = $"SIG: GOOD   NET: {state.Peers.Count}   HOST: {state.HostCallsign}";
            LeftStatusText.Text = _sessionService?.IsHosting == true ? "● HOSTING" : "● CONNECTED";
            LeftStatusText.Foreground = (Brush)Application.Current.Resources["Green"];
        });
    }

    private void SetStatus(string status, bool connectedColor)
    {
        LcdStatusText.Text = status.ToUpperInvariant();
        LeftStatusText.Text = connectedColor ? "● ONLINE" : "● ERROR";
        LeftStatusText.Foreground = (Brush)Application.Current.Resources[connectedColor ? "Green" : "Red"];
    }

    private void RememberSession(string name, string address)
    {
        _settings.RecentSessions.RemoveAll(s => string.Equals(s.Address, address, StringComparison.OrdinalIgnoreCase));
        _settings.RecentSessions.Add(new RecentSession { Name = name, Address = address, LastJoinedUtc = DateTime.UtcNow });
        if (_settings.RecentSessions.Count > 20) _settings.RecentSessions = _settings.RecentSessions.OrderByDescending(s => s.LastJoinedUtc).Take(20).ToList();
        PopulateSocialPanels();
        _ = AppSettingsStore.SaveAsync(_settings);
    }

    private async void MainWindow_Closing(object? sender, System.ComponentModel.CancelEventArgs e)
    {
        _rxResetCts?.Cancel();
        _hotkeys?.Dispose();
        _audioService?.Dispose();
        if (_sessionService is not null) await _sessionService.DisposeAsync();
        await AppSettingsStore.SaveAsync(_settings);
    }
}
