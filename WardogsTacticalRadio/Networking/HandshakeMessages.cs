using WardogsTacticalRadio.Models;

namespace WardogsTacticalRadio.Networking;

// See the handshake summary on RadioSessionService for how these fit together. Kept separate
// from RadioPeer/RadioSessionState so auth material (nonces, proofs) never ends up inside the
// session roster that gets broadcast to every peer.

// Host -> connecting client, right after the TLS handshake: a fresh nonce to prove liveness
// and prevent replaying a proof captured on an earlier connection.
public sealed class ChallengeMessage
{
    public string Nonce { get; set; } = string.Empty;
}

// Connecting client -> host, in response to a ChallengeMessage: who they are, plus proof they
// know the session password (see RadioSessionService.ComputeProof) and a nonce of their own
// for the host to prove itself back with in SessionAck.
public sealed class HelloRequest
{
    public RadioPeer Peer { get; set; } = new();
    public string ClientNonce { get; set; } = string.Empty;
    public string Proof { get; set; } = string.Empty;
}

// Host -> newly-authenticated client: the current session state, plus the host's own proof of
// knowing the password (mutual auth - see RadioSessionService.JoinAsync).
public sealed class SessionAck
{
    public RadioSessionState Session { get; set; } = new();
    public string HostProof { get; set; } = string.Empty;
}

// Host -> client when the proof in HelloRequest didn't check out (wrong password, or a proof
// bound to a different TLS channel). Lets the UI show a clear reason instead of just a dropped
// connection.
public sealed class AuthFailedMessage
{
    public string Reason { get; set; } = string.Empty;
}
