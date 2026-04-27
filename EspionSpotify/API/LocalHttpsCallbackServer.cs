using System;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using SpotifyAPI.Web.Auth;

namespace EspionSpotify.API
{
    /// <summary>
    /// A minimal HTTPS TCP server that handles the OAuth 2.0 authorization-code callback from
    /// Spotify when the redirect URI uses the https scheme. It uses an embedded self-signed TLS
    /// certificate for localhost so that HTTPS redirect URIs work without any external setup.
    /// </summary>
    internal sealed class LocalHttpsCallbackServer : IDisposable
    {
        // Self-signed certificate: CN=localhost, SAN=localhost/127.0.0.1, RSA-2048/SHA-256,
        // valid 100 years, TLS server auth EKU. No password on the PFX.
        private static readonly byte[] EmbeddedCertificateBytes = Convert.FromBase64String(
            "MIIJMwIBAzCCCO8GCSqGSIb3DQEHAaCCCOAEggjcMIII2DCCA5cGCSqGSIb3DQEHBqCCA4gw" +
            "ggOEAgEAMIIDfQYJKoZIhvcNAQcBMCQGCiqGSIb3DQEMAQMwFgQQ8Z9N9jGwVrW8NCyhAHrO" +
            "7gICB9CAggNIsnJotPLLllv3mEMl79WY4T7o42m+VZzxKaetmdcx/v1Yb0naz8ofYGT+APvb" +
            "fRfuqiB8hHGcx9em34I3BL9ESz4SJGOLUFIsZNACgL31fMLK7BPXRAMlHh5+iBDC1602Gm1k" +
            "oXUyge90EfZj3c2x5VndsiBiNcxUFvsjxeV1/Acb5GUCGdARtwg+nfTLwHW0WPAoMev16VDV" +
            "KsPYCcd7vf7DO5sEwYhTPNTqXKJlu3NDNbrSg108iZv3kWde/XQQirtBPPlaVc4W//0ixhz+" +
            "trycQvC+ucwaThkU+eu2DckwsB3PKzG82xr+c2OcPQQgAvxfdnFQmSCRKmqR41lCmL7QSNqP" +
            "EJ2CI5Ec4K4bQuobcxd25rV0o5RYHB8s1pWYp9Zpw2y7nPQQLpaQOh1FHz0CTTHEkZjpV4SE" +
            "9S4iMuKstJ+kyWygSj5Nt8Yu3aaU3uHfSMDtyD1ZbpSeRtzKvfjxl+yfOlHMwRD6mOw0HbLL" +
            "NmkjiLZR1ksNI9Mv6Y2RHjwdaJdT58qdPAIKGSw4bINsYKyVaLl7fy8s2+XfimmMGzAFOZl6" +
            "d51ajAcWy4+rfXPdzJEe2rmJyDNzUnmt/PRY7sivStHPiCa/qGy7Mrxft67f4U9hy43Ja+KY" +
            "nVESV6QtOtZzHYypKiOEP/0Czxcl08MzPMi4XEj4e8KpGcFTpxpMosKZOnGT5C9vO44zkk3g" +
            "gNPTIn1DSLDvHhgMbTRrB67DDSnz8aiOKAplHG/J0iWqwmXIsIjNazDDMSkTb/d15xCBihrT" +
            "dTP/y2qSftrWromJrtQsZOda6eBKI0nJSV7BOjqGz4Hwqwve8FO17Kt4zplfLRWZcUFxnGB0" +
            "nIxsVtnoH95gCGrEUU4M3nBdSAC+32xd/468SOkf1BIk9yJ6OVIRA6xjzWYOB57bVYmTxFGp" +
            "HNncss2lBmcCe8LSFkOUfTyOTBXz986ZbACdpNxPZkNSOweX2LnSKcx2OL+F7M6wbCduxEOD" +
            "XoAxuydn3esa5+RM1IoLbG7llAoPHCj5yPhZfz7lW2yfdgFdupL/sB0V8LhcjDlS0McV9w8M" +
            "rKJCu9my3wjpiJYzyfzRKKdb5+repw1eNe51Bgx8RASfhh4z18HAMIIFOQYJKoZIhvcNAQcB" +
            "oIIFKgSCBSYwggUiMIIFHgYLKoZIhvcNAQwKAQKgggT2MIIE8jAkBgoqhkiG9w0BDAEDMBYE" +
            "EI+Cgsayrz0WGJFF1Revo/4CAgfQBIIEyNHnmCGPHi/1xxkZiQLWVV51N6paL8DqYa/90CCV" +
            "Q0RIe019GPJluc+sU+dQEu2uLQQ/lnlmIU6vEwVcDJVEPLdNHSdx7Qt8DtFkN4LSVrQagauB" +
            "Ns0yw70nVuID7mpfoGcUt7EzNrpX6dpoXOjQe9420Vqdhgx3gISxDRu7ybr+FfqPe8derzyW" +
            "FllXxChT/XXbCtzdpPhHUZTDqf392pmF6RQXFfIMm/scuzmgW83nchNRHLh8hYIwAfVIfpEN" +
            "zhKF9pYFpm6UGG9qzoUKM6aJLygE/hhlDPwrsv8CdWznOlO89vQbOemLFXrADUXFZStg4SAp" +
            "Q+pfuuNYjVBgmMtZgd3U7dM1bRbwZaV4JShn1EO2Mu4Ax+PaAxSpbh/7+6TVI23Ykk42a03W" +
            "HmfCQgYpH1FNnNDoLDs2EvW/beT+Kjh+Q/kUpsiaZv/ZdUYwkt2K3DDljPhMt44WMqBZYUud" +
            "wNYSBMSJc9x+0C+g1VLNlnuVJmilFEpd/eMlbmq7SkWZ5/kPxV2Hk7tUxL1Rjr1w5snWArlz" +
            "fXou+BW6r355RQSaiPVhdFbRLTQpUR5FapO5msL4k2+Q8NVYLKKX/QKbVbp+1VtpF/QO/8cw" +
            "/ChLyljYpMHJ8iYCGfLC6xG67ichkqdHNFYa/42jhYj84Rp+6m6Djw8KZGNDfDzapofr+Tqk" +
            "cZa6Rz9Csi02OUYR8cmjZgCISu5Lxjnxo62j8yguqbf6JOPAnK9/5b12ii229Ge+C7Xhelba" +
            "Jd7UmjnBq+mODSHEbfIsf48DE9gdk7yjKtUIraVFRDzzM4mEDznL/WaqMwddeW7G9d9gBfG2" +
            "5rg4Aw080PffCTCslolJlr4BAnYWdFU6sPlbJ9VLhzGk4D+ouhRL1vgIO7KjGrDojnVst9xy" +
            "gg1+n9wOCfYn9+3glWQelIMuY95kKcP3tzgbIvATVf+Acd7gA2qbzXob5cfsnoVKtuvrAsZO" +
            "4gvLmhFA9gsN1C3IwrdROG2p9NFVy8ggcZ1UcUyxBROWn+Lafti8xhH7DPtwL42HRYCZDQYb" +
            "PfaYwytw9ae2sOsrrgjYJbEyE3FY+nDflqjEyBmcXh8I2Iy9IQphEzjX6DkLOrupPQONBaRx" +
            "y9ZKu4rJvCvHXICO3lwF6gDLkJmX/LqRDQeFa7/fWOJB2or0NH/4Olq6dPlkQ+dpDlRKG/0F" +
            "aPnwuF6j5TQCuiB3AcgrHyMWxGnuWXehJtAogA5AQYsJAhT/Ys5DfeAFOxY0y0w/qsvsaOvq" +
            "5URy0nzW/IWsWnGBsDji16QPNjB3rytm2xV931gvcr+7PdQ/l/V7aSQH4Zw7R3Iqx/gZMUJY" +
            "Rqx3GBkzH3u4/lCDY5j4jPHEJ1hZs4JNWFjYhlwbZGNr/lA92FVCyrCOxDoHr+yZwCoIoJzG" +
            "NAxpmgsGLs6M60RBqiEaXRf34V8gQulYLjHVDGItZ2keuNjJTfQaO16jmroC2TS6sZZDzKxa" +
            "VHyA4h64Ozk5lBGPG+e+c3du7msA2Hdfb7VJwgGwcSyzRVB3GVOVd3r3Aq7nc4KfAvDYyjOB" +
            "CP2vHlG17wnZ9F+x+VejIVkXEWu5pwUgRv7/ZIo7e7BGPTl5Z5oq58pHmpYYE2Xz86/ewEIA" +
            "4IVrdIV3QTEVMBMGCSqGSIb3DQEJFTEGBAQBAAAAMDswHzAHBgUrDgMCGgQUw/Mjm6nd1bZb" +
            "yhW4hHdr0V0XOX0EFOmnz/OAczY5gKJs1587sc58qAcLAgIH0A==");

        private readonly int _port;
        private TcpListener _listener;
        private CancellationTokenSource _cts;
        private X509Certificate2 _certificate;
        private bool _disposed;

        public delegate void OnAuthReceived(object sender, AuthorizationCode payload);

        public event OnAuthReceived AuthReceived;

        public LocalHttpsCallbackServer(string redirectUrl)
        {
            _port = new Uri(redirectUrl).Port;
        }

        public void Start()
        {
            if (_disposed) throw new ObjectDisposedException(nameof(LocalHttpsCallbackServer));

            _certificate?.Dispose();
            _cts?.Dispose();
            _certificate = new X509Certificate2(EmbeddedCertificateBytes, (string)null,
                X509KeyStorageFlags.Exportable);
            _cts = new CancellationTokenSource();
            _listener = new TcpListener(IPAddress.Loopback, _port);
            _listener.Start();
            Task.Run(() => AcceptLoopAsync(_cts.Token));
        }

        public void Stop()
        {
            _cts?.Cancel();
            try { _listener?.Stop(); } catch { /* ignore */ }
        }

        private async Task AcceptLoopAsync(CancellationToken ct)
        {
            while (!ct.IsCancellationRequested)
            {
                TcpClient client;
                try
                {
                    client = await _listener.AcceptTcpClientAsync();
                }
                catch (Exception) when (ct.IsCancellationRequested || _disposed)
                {
                    break;
                }
                catch (Exception)
                {
                    continue;
                }

                Task.Run(() => HandleClientAsync(client, ct));
            }
        }

        private async Task HandleClientAsync(TcpClient client, CancellationToken ct)
        {
            using (client)
            using (var sslStream = new SslStream(client.GetStream(), false))
            {
                try
                {
                    await sslStream.AuthenticateAsServerAsync(_certificate);
                }
                catch
                {
                    return;
                }

                try
                {
                    var buffer = new byte[8192];
                    var bytesRead = await sslStream.ReadAsync(buffer, 0, buffer.Length, ct);
                    if (bytesRead <= 0) return;

                    var request = Encoding.UTF8.GetString(buffer, 0, bytesRead);
                    var lines = request.Split(new[] { '\r', '\n' }, 2);
                    if (lines.Length < 1 || string.IsNullOrEmpty(lines[0])) return;

                    var lineParts = lines[0].Split(' ');
                    if (lineParts.Length < 2) return;

                    var path = lineParts[1];
                    var qIndex = path.IndexOf('?');
                    var query = qIndex >= 0 ? path.Substring(qIndex + 1) : string.Empty;

                    var code = GetQueryParam(query, "code");
                    var error = GetQueryParam(query, "error");

                    const string responseHtml =
                        "<html><script type=\"text/javascript\">window.close();" +
                        "</script>OK - This window can be closed now</html>";
                    var responseBody = Encoding.UTF8.GetBytes(responseHtml);
                    var responseHeader = string.Format(
                        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n" +
                        "Content-Length: {0}\r\nConnection: close\r\n\r\n",
                        responseBody.Length);
                    var headerBytes = Encoding.ASCII.GetBytes(responseHeader);

                    await sslStream.WriteAsync(headerBytes, 0, headerBytes.Length, ct);
                    await sslStream.WriteAsync(responseBody, 0, responseBody.Length, ct);
                    await sslStream.FlushAsync(ct);

                    AuthReceived?.Invoke(this, new AuthorizationCode { Code = code, Error = error });
                }
                catch (OperationCanceledException)
                {
                    // Server was stopped; ignore.
                }
                catch
                {
                    // Ignore other connection errors.
                }
            }
        }

        private static string GetQueryParam(string query, string name)
        {
            if (string.IsNullOrEmpty(query)) return null;
            foreach (var pair in query.Split('&'))
            {
                var eq = pair.IndexOf('=');
                if (eq < 0) continue;
                var key = Uri.UnescapeDataString(pair.Substring(0, eq));
                if (string.Equals(key, name, StringComparison.OrdinalIgnoreCase))
                    return Uri.UnescapeDataString(pair.Substring(eq + 1));
            }
            return null;
        }

        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;
            Stop();
            _certificate?.Dispose();
            _cts?.Dispose();
        }
    }
}
