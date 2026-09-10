using System.IO;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Security;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Authentication.ExtendedProtection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using WardogsTacticalRadio.Audio;
using WardogsTacticalRadio.Models;

namespace WardogsTacticalRadio.Networking;

// Wire protocol: every connection is TLS (SslStream) carrying newline-delimited JSON
// "envelopes" (see NetworkEnvelope). Before any session/audio traffic is trusted, a peer
// must complete a password-based mutual handshake:
//
//   host -> client : "challenge" { nonce }
//   client -> host : "hello"     { peer info, clientNonce, proof = HMAC(password, hostNonce || channelBinding) }
//   host -> client : "session-ack" { session state, hostProof = HMAC(password, clientNonce || channelBinding) }
//                      (or "auth-failed" if the client's proof didn't check out)
//
// The password itself is never sent - only an HMAC over a nonce is - and that HMAC is
// additionally bound to the TLS channel via GetChannelBindingBytes(). That binding is what
// stops a relay-style MITM (one that terminates TLS itself and presents its own certificate)
// from riding through the password check even though there's no certificate pinning yet:
// each side's channel-binding value depends on which certificate *it* actually saw, so an
// attacker sitting in the middle ends up with two different values on either side of it,
// which makes the HMAC comparison fail. See ValidateServerCertificate for the corresponding
// client-side trust decision.
public sealed class RadioSessionService : IAsyncDisposable
{
    private const int NonceSizeBytes = 32;

    private sealed class PeerConnection
    {
        public required TcpClient Client { get; init; }
        public required SslStream Stream { get; init; }
        public required StreamReader Reader { get; init; }
        public Guid PeerId { get; init; }
    }

    private readonly JsonSerializerOptions _json = new(JsonSerializerDefaults.Web);
    private readonly List<PeerConnection> _connections = new();
    private readonly SemaphoreSlim _sendGate = new(1, 1);
    private TcpListener? _listener;
    private PeerConnection? _upstream;
    private CancellationTokenSource? _cts;
    private X509Certificate2? _hostCertificate;
    private byte[] _passwordKey = Array.Empty<byte>();

    public bool IsHosting { get; private set; }
    public bool IsConnected { get; private set; }
    public RadioSessionState? Session { get; private set; }
    public RadioPeer LocalPeer { get; }

    public event Action<string>? StatusChanged;
    public event Action<RadioSessionState>? SessionChanged;
    public event Action<AudioFrame>? AudioFrameReceived;
    public event Action<string>? ConnectionLost;

    public RadioSessionService(AppSettings settings)
    {
        LocalPeer = new RadioPeer
        {
            UserName = settings.UserName,
            Callsign = settings.Callsign,
            Role = settings.Role,
            HostEligible = settings.HostEligible
        };
    }

    public async Task HostAsync(string sessionName, int port, string password, CancellationToken cancellationToken = default)
    {
        // Secure by default: hosting used to accept any TCP connection with no credential at
        // all, which is what let anyone who found the IP:port join, inject audio, or spoof
        // peers. Requiring a password here (rather than making it optional) closes that gap
        // unconditionally instead of relying on the host remembering to set one.
        if (string.IsNullOrEmpty(password))
            throw new ArgumentException("A session password is required to host a radio net.", nameof(password));

        await StopAsync();
        _passwordKey = Encoding.UTF8.GetBytes(password);
        // A fresh, ephemeral cert per hosting session is enough for TLS confidentiality/integrity;
        // it isn't meant to prove identity on its own (see ValidateServerCertificate) since there's
        // no PKI to issue a "real" one against for a peer-to-peer LAN/internet radio net.
        _hostCertificate = CreateEphemeralServerCertificate();
        _cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        Session = new RadioSessionState
        {
            SessionName = string.IsNullOrWhiteSpace(sessionName) ? "WARDOGS RADIO NET" : sessionName.Trim(),
            HostPeerId = LocalPeer.PeerId,
            HostCallsign = LocalPeer.Callsign,
            Peers = [LocalPeer]
        };

        _listener = new TcpListener(IPAddress.Any, port);
        _listener.Start();
        IsHosting = true;
        IsConnected = true;
        StatusChanged?.Invoke($"HOSTING // {GetBestLanAddress()}:{port} // ENCRYPTED + PASSWORD PROTECTED");
        SessionChanged?.Invoke(Session);
        _ = AcceptLoopAsync(_cts.Token);
    }

    public async Task JoinAsync(string address, int port, string password, CancellationToken cancellationToken = default)
    {
        await StopAsync();
        _passwordKey = Encoding.UTF8.GetBytes(password);
        _cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        var token = _cts.Token;

        var tcpClient = new TcpClient { NoDelay = true };
        StatusChanged?.Invoke($"CONNECTING // {address}:{port}");
        await tcpClient.ConnectAsync(address, port, token);

        SslStream sslStream = new(tcpClient.GetStream(), leaveInnerStreamOpen: false, ValidateServerCertificate);
        try
        {
            await sslStream.AuthenticateAsClientAsync(new SslClientAuthenticationOptions { TargetHost = address }, token);
            StatusChanged?.Invoke("LINK ENCRYPTED // VERIFYING SESSION PASSWORD");

            var reader = new StreamReader(sslStream, Encoding.UTF8, false, 4096, leaveOpen: true);
            // Fail closed rather than falling back to an unbound proof: without a channel
            // binding, the HMAC below would only prove "knows the password", not "knows the
            // password on *this* TLS connection", reopening the relay-MITM gap.
            var channelBinding = GetChannelBindingBytes(sslStream)
                ?? throw new NotSupportedException("This connection did not provide a TLS channel binding; refusing to authenticate to avoid a relay attack.");

            var challengeEnvelope = await ReadEnvelopeAsync(reader, token)
                ?? throw new IOException("Host closed the connection before presenting an authentication challenge.");
            if (challengeEnvelope.Type != "challenge")
                throw new IOException("Host did not present an authentication challenge.");
            var challenge = challengeEnvelope.ReadPayload<ChallengeMessage>()
                ?? throw new IOException("Malformed authentication challenge from host.");
            var hostNonce = Convert.FromBase64String(challenge.Nonce);

            var clientNonce = RandomNumberGenerator.GetBytes(NonceSizeBytes);
            var proof = ComputeProof(_passwordKey, hostNonce, channelBinding);
            var hello = new HelloRequest
            {
                Peer = LocalPeer,
                ClientNonce = Convert.ToBase64String(clientNonce),
                Proof = Convert.ToBase64String(proof)
            };
            await SendAsync(sslStream, NetworkEnvelope.Create("hello", hello), token);

            var ackEnvelope = await ReadEnvelopeAsync(reader, token)
                ?? throw new IOException("Host closed the connection during authentication.");
            if (ackEnvelope.Type == "auth-failed")
            {
                var failure = ackEnvelope.ReadPayload<AuthFailedMessage>();
                throw new UnauthorizedAccessException(failure?.Reason ?? "Incorrect session password.");
            }
            if (ackEnvelope.Type != "session-ack")
                throw new IOException($"Unexpected message from host during authentication: {ackEnvelope.Type}");

            var ack = ackEnvelope.ReadPayload<SessionAck>() ?? throw new IOException("Malformed session response from host.");
            // Mutual auth: the client already proved it knows the password via `proof` above;
            // this checks the reverse, so a rogue "host" that doesn't actually know the
            // password can't feed a joining client a fabricated session/roster.
            var expectedHostProof = ComputeProof(_passwordKey, clientNonce, channelBinding);
            if (!CryptographicOperations.FixedTimeEquals(Convert.FromBase64String(ack.HostProof), expectedHostProof))
                throw new UnauthorizedAccessException("Host failed to prove knowledge of the session password (possible impersonation).");

            var connection = new PeerConnection { Client = tcpClient, Stream = sslStream, Reader = reader, PeerId = LocalPeer.PeerId };
            _upstream = connection;
            IsConnected = true;
            Session = ack.Session;
            SessionChanged?.Invoke(Session);
            StatusChanged?.Invoke($"CONNECTED // NET SYNC // {Session.SessionName}");

            _ = ReceiveLoopAsync(connection, token);
        }
        catch
        {
            try { sslStream.Dispose(); } catch { }
            try { tcpClient.Dispose(); } catch { }
            throw;
        }
    }

    public async Task TransmitAudioAsync(string channelId, byte[] pcm16, CancellationToken cancellationToken = default)
    {
        if (!IsConnected || pcm16.Length == 0) return;
        var frame = new AudioFrame
        {
            SourcePeerId = LocalPeer.PeerId,
            SourceCallsign = LocalPeer.Callsign,
            ChannelId = channelId,
            Pcm16 = pcm16
        };
        var envelope = NetworkEnvelope.Create("audio", frame);

        if (IsHosting)
        {
            await BroadcastAsync(envelope, null, cancellationToken);
        }
        else if (_upstream is { Client.Connected: true } upstream)
        {
            await SendAsync(upstream.Stream, envelope, cancellationToken);
        }
    }

    private async Task AcceptLoopAsync(CancellationToken cancellationToken)
    {
        if (_listener is null) return;
        try
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                var tcpClient = await _listener.AcceptTcpClientAsync(cancellationToken);
                tcpClient.NoDelay = true;
                _ = AuthenticateAndAcceptClientAsync(tcpClient, cancellationToken);
            }
        }
        catch (OperationCanceledException) { }
        catch (Exception ex) { StatusChanged?.Invoke($"HOST ERROR // {ex.Message}"); }
    }

    private async Task AuthenticateAndAcceptClientAsync(TcpClient tcpClient, CancellationToken cancellationToken)
    {
        SslStream? sslStream = null;
        try
        {
            sslStream = new SslStream(tcpClient.GetStream(), leaveInnerStreamOpen: false);
            await sslStream.AuthenticateAsServerAsync(
                new SslServerAuthenticationOptions { ServerCertificate = _hostCertificate, ClientCertificateRequired = false },
                cancellationToken);

            var reader = new StreamReader(sslStream, Encoding.UTF8, false, 4096, leaveOpen: true);
            var channelBinding = GetChannelBindingBytes(sslStream);

            var hostNonce = RandomNumberGenerator.GetBytes(NonceSizeBytes);
            await SendAsync(sslStream, NetworkEnvelope.Create("challenge", new ChallengeMessage { Nonce = Convert.ToBase64String(hostNonce) }), cancellationToken);

            var helloEnvelope = await ReadEnvelopeAsync(reader, cancellationToken);
            if (helloEnvelope is null || helloEnvelope.Type != "hello") { Discard(tcpClient, sslStream); return; }
            var hello = helloEnvelope.ReadPayload<HelloRequest>();
            var clientNonce = TryDecodeBase64(hello?.ClientNonce);
            var providedProof = TryDecodeBase64(hello?.Proof);

            // channelBinding is null here only if this platform/TLS session couldn't produce one;
            // short-circuiting to false (rather than computing the proof without it) means we
            // never silently downgrade to an unbound comparison.
            var authenticated = hello is not null && channelBinding is not null && clientNonce is not null && providedProof is not null
                && CryptographicOperations.FixedTimeEquals(ComputeProof(_passwordKey, hostNonce, channelBinding), providedProof);

            if (!authenticated)
            {
                await SendAsync(sslStream, NetworkEnvelope.Create("auth-failed", new AuthFailedMessage { Reason = "Invalid session password." }), cancellationToken);
                StatusChanged?.Invoke($"AUTH REJECTED // {SafeRemoteEndpoint(tcpClient)}");
                Discard(tcpClient, sslStream);
                return;
            }

            if (Session is null) { Discard(tcpClient, sslStream); return; }

            var peer = hello!.Peer;
            peer.LastHeartbeatUtc = DateTime.UtcNow;
            var connection = new PeerConnection { Client = tcpClient, Stream = sslStream, Reader = reader, PeerId = peer.PeerId };

            // Multiple clients can complete the handshake concurrently, and List<T> isn't
            // thread-safe - without this lock, two peers joining at the same instant could
            // corrupt _connections/Session.Peers or throw a collection-modified exception.
            lock (_connections)
            {
                _connections.Add(connection);
                Session.Peers.RemoveAll(p => p.PeerId == peer.PeerId);
                Session.Peers.Add(peer);
            }

            var hostProof = ComputeProof(_passwordKey, clientNonce!, channelBinding!);
            await SendAsync(sslStream, NetworkEnvelope.Create("session-ack", new SessionAck { Session = Session, HostProof = Convert.ToBase64String(hostProof) }), cancellationToken);
            await BroadcastSessionAsync(cancellationToken, except: connection);
            SessionChanged?.Invoke(Session);
            StatusChanged?.Invoke($"LINKED // {peer.Callsign}");

            await ReceiveLoopAsync(connection, cancellationToken);
        }
        catch (OperationCanceledException)
        {
            Discard(tcpClient, sslStream);
        }
        catch (Exception ex)
        {
            StatusChanged?.Invoke($"HANDSHAKE FAILED // {ex.Message}");
            Discard(tcpClient, sslStream);
        }
    }

    private static void Discard(TcpClient client, SslStream? stream)
    {
        try { stream?.Dispose(); } catch { }
        try { client.Dispose(); } catch { }
    }

    private static string SafeRemoteEndpoint(TcpClient client)
    {
        try { return client.Client.RemoteEndPoint?.ToString() ?? "unknown"; }
        catch { return "unknown"; }
    }

    private async Task ReceiveLoopAsync(PeerConnection connection, CancellationToken cancellationToken)
    {
        var wasUpstream = ReferenceEquals(connection, _upstream);
        try
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                var envelope = await ReadEnvelopeAsync(connection.Reader, cancellationToken);
                if (envelope is null) break;
                await HandleEnvelopeAsync(connection, envelope, cancellationToken);
            }
        }
        catch (OperationCanceledException) { }
        catch (Exception ex)
        {
            if (!cancellationToken.IsCancellationRequested)
                StatusChanged?.Invoke($"LINK LOST // {ex.Message}");
        }
        finally
        {
            if (IsHosting)
            {
                await RemoveDisconnectedClientAsync(connection, cancellationToken);
            }
            else if (wasUpstream && !cancellationToken.IsCancellationRequested)
            {
                _upstream = null;
                IsConnected = false;
                Session = null;
                ConnectionLost?.Invoke("HOST CONNECTION LOST");
                StatusChanged?.Invoke("LINK LOST // HOST UNREACHABLE");
            }

            lock (_connections) _connections.Remove(connection);
            Discard(connection.Client, connection.Stream);
        }
    }

    private async Task RemoveDisconnectedClientAsync(PeerConnection connection, CancellationToken cancellationToken)
    {
        if (Session is null) return;
        bool removed;
        lock (_connections) removed = Session.Peers.RemoveAll(p => p.PeerId == connection.PeerId) > 0;
        if (!removed) return;

        SessionChanged?.Invoke(Session);
        StatusChanged?.Invoke("PEER DISCONNECTED // SESSION UPDATED");
        try { await BroadcastSessionAsync(cancellationToken); } catch { }
    }

    private async Task HandleEnvelopeAsync(PeerConnection source, NetworkEnvelope envelope, CancellationToken cancellationToken)
    {
        switch (envelope.Type)
        {
            // !IsHosting matters: only a client should ever accept a "session" update from its
            // upstream host. Without this guard, any authenticated peer could push a forged
            // "session" envelope to the host and overwrite its own authoritative state.
            case "session" when !IsHosting:
            {
                var state = envelope.ReadPayload<RadioSessionState>();
                if (state is null) return;
                Session = state;
                SessionChanged?.Invoke(state);
                StatusChanged?.Invoke($"NET SYNC // {state.SessionName}");
                break;
            }
            case "audio":
            {
                var frame = envelope.ReadPayload<AudioFrame>();
                if (frame is null || frame.SourcePeerId == LocalPeer.PeerId) return;
                AudioFrameReceived?.Invoke(frame);
                if (IsHosting)
                    await BroadcastAsync(envelope, source, cancellationToken);
                break;
            }
        }
    }

    private async Task BroadcastSessionAsync(CancellationToken cancellationToken, PeerConnection? except = null)
    {
        if (Session is null) return;
        await BroadcastAsync(NetworkEnvelope.Create("session", Session), except, cancellationToken);
    }

    private async Task BroadcastAsync(NetworkEnvelope envelope, PeerConnection? except, CancellationToken cancellationToken)
    {
        List<PeerConnection> snapshot;
        lock (_connections) snapshot = _connections.ToList();
        foreach (var connection in snapshot)
        {
            if (connection == except) continue;
            try { await SendAsync(connection.Stream, envelope, cancellationToken); } catch { }
        }
    }

    private async Task SendAsync(Stream stream, NetworkEnvelope envelope, CancellationToken cancellationToken)
    {
        var json = JsonSerializer.Serialize(envelope, _json) + "\n";
        var bytes = Encoding.UTF8.GetBytes(json);
        await _sendGate.WaitAsync(cancellationToken);
        try
        {
            await stream.WriteAsync(bytes, cancellationToken);
            await stream.FlushAsync(cancellationToken);
        }
        finally { _sendGate.Release(); }
    }

    private async Task<NetworkEnvelope?> ReadEnvelopeAsync(StreamReader reader, CancellationToken cancellationToken)
    {
        var line = await reader.ReadLineAsync(cancellationToken);
        return line is null ? null : JsonSerializer.Deserialize<NetworkEnvelope>(line, _json);
    }

    // There's no PKI to validate the host's certificate against - it's self-signed and
    // regenerated every hosting session - so this deliberately accepts any certificate
    // (trust-on-first-use). That's safe against an on-path relay attacker *only* because
    // ComputeProof binds the password proof to this exact TLS channel via its channel-binding
    // token: a relay that terminates TLS itself and presents a different certificate ends up
    // with a different binding value on each side, which fails the proof check even though
    // each individual TLS handshake succeeded. What this does *not* protect against: nothing
    // here verifies you're connecting to the host you actually intend. If you're given a wrong
    // or spoofed address that happens to run a service using the same password (e.g. it
    // leaked, or is weak/reused), you'll complete a fully valid, non-MITM'd handshake with the
    // wrong host. Closing that gap needs endpoint verification - e.g. confirming a certificate
    // fingerprint out-of-band - which is follow-up work, not implemented here.
    private bool ValidateServerCertificate(object sender, X509Certificate? certificate, X509Chain? chain, SslPolicyErrors sslPolicyErrors)
    {
        if (sslPolicyErrors != SslPolicyErrors.None)
            StatusChanged?.Invoke("LINK ENCRYPTED // HOST CERTIFICATE NOT INDEPENDENTLY VERIFIED (NO PKI) // RELYING ON SESSION PASSWORD");
        return certificate is not null;
    }

    private static X509Certificate2 CreateEphemeralServerCertificate()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest("CN=WardogsTacticalRadio-EphemeralHost", ecdsa, HashAlgorithmName.SHA256);
        var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddDays(2));
        // CreateSelfSigned's cert holds an ephemeral (non-persisted) private key, which
        // SChannel/SslStream can fail to use for TLS server auth on Windows. Exporting and
        // reimporting as PFX forces a key handle SslStream can actually work with.
        return new X509Certificate2(certificate.Export(X509ContentType.Pfx));
    }

    // Returns a value derived from the certificate seen on this specific TLS connection
    // (RFC 5929 "tls-server-end-point"). Both sides land on the same value only when they're
    // really talking to each other with no one splitting the TLS connection in between - see
    // ValidateServerCertificate for why that property matters here.
    private static byte[]? GetChannelBindingBytes(SslStream stream)
    {
        try
        {
            using var binding = stream.TransportContext.GetChannelBinding(ChannelBindingKind.Endpoint);
            if (binding is null || binding.IsInvalid || binding.Size <= 0) return null;
            var bytes = new byte[binding.Size];
            Marshal.Copy(binding.DangerousGetHandle(), bytes, 0, binding.Size);
            return bytes;
        }
        catch
        {
            return null;
        }
    }

    // The password itself never goes on the wire, only this HMAC over a single-use nonce plus
    // the channel binding - so it can't be replayed on a different connection or reused to
    // derive the password.
    private static byte[] ComputeProof(byte[] passwordKey, byte[] nonce, byte[] channelBinding)
    {
        using var hmac = new HMACSHA256(passwordKey);
        var buffer = new byte[nonce.Length + channelBinding.Length];
        Buffer.BlockCopy(nonce, 0, buffer, 0, nonce.Length);
        Buffer.BlockCopy(channelBinding, 0, buffer, nonce.Length, channelBinding.Length);
        return hmac.ComputeHash(buffer);
    }

    private static byte[]? TryDecodeBase64(string? value)
    {
        if (string.IsNullOrEmpty(value)) return null;
        try { return Convert.FromBase64String(value); }
        catch (FormatException) { return null; }
    }

    public async Task StopAsync()
    {
        _cts?.Cancel();
        try { _listener?.Stop(); } catch { }
        try { if (_upstream is not null) Discard(_upstream.Client, _upstream.Stream); } catch { }
        lock (_connections)
        {
            foreach (var connection in _connections) Discard(connection.Client, connection.Stream);
            _connections.Clear();
        }
        _listener = null;
        _upstream = null;
        _cts?.Dispose();
        _cts = null;
        IsHosting = false;
        IsConnected = false;
        Session = null;
        _hostCertificate?.Dispose();
        _hostCertificate = null;
        await Task.CompletedTask;
    }

    public static string GetBestLanAddress()
    {
        try
        {
            foreach (var nic in NetworkInterface.GetAllNetworkInterfaces()
                         .Where(n => n.OperationalStatus == OperationalStatus.Up && n.NetworkInterfaceType != NetworkInterfaceType.Loopback))
            {
                foreach (var ua in nic.GetIPProperties().UnicastAddresses)
                {
                    if (ua.Address.AddressFamily == AddressFamily.InterNetwork && !IPAddress.IsLoopback(ua.Address))
                        return ua.Address.ToString();
                }
            }
        }
        catch { }
        return "127.0.0.1";
    }

    public async ValueTask DisposeAsync()
    {
        await StopAsync();
        _sendGate.Dispose();
    }
}
