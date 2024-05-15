using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

// Configurazione
var p12FilePath = "/Users/simonerocchi/temp/rentricert/cert.txt"; // Inserisci il percorso del tuo file qui
var p12 = File.ReadAllText(p12FilePath); // Base64 file .p12
var password = "9x8a|q2S"; // Password del file .p12
var cert = new X509Certificate2(Convert.FromBase64String(p12), password, X509KeyStorageFlags.MachineKeySet);
var algo = cert.PublicKey.Oid.FriendlyName == "RSA" ? SecurityAlgorithms.RsaSha256 : cert.PublicKey.Oid.FriendlyName == "ECC" ? SecurityAlgorithms.EcdsaSha256 : throw new InvalidOperationException("Unsupported key algorithm");

var issuer = "01111330526"; // Indicare l'identificativo dell'operatore presente nel subject del certificato
var regId = "ROX6B217T00"; // Indicare l'identificativo del registro

var aud = "rentrigov.demo.api"; // Per produzione rentrigov.api
var baseApi = "https://demoapi.rentri.gov.it"; // Per produzione https://api.rentri.gov.it
var api = $"{baseApi}/dati-registri/operatore/v1.0/{regId}/movimenti";
var jti = Guid.NewGuid().ToString(); // Id del JWT

var jsonData = @"[{""riferimenti"": { ""numero_registrazione"": { ""anno"": 2024, ""progressivo"": 1 } }}]";

// Dati scambiati
var content = new StringContent(jsonData, System.Text.Encoding.UTF8, "application/json");

// ID_AUTH_REST_02
var tokenHandler = new JsonWebTokenHandler();
var tokenDescriptor = new Microsoft.IdentityModel.Tokens.SecurityTokenDescriptor
{
    AdditionalHeaderClaims = new Dictionary<string, object> { { "x5c", new string[] { Convert.ToBase64String(cert.Export(X509ContentType.Cert)) } } },
    Audience = aud,
    Issuer = issuer,
    Claims = new Dictionary<string, object> { { "jti", jti } },
    SigningCredentials = algo == SecurityAlgorithms.RsaSha256 ? new SigningCredentials(new RsaSecurityKey(cert.GetRSAPrivateKey()), algo) : new SigningCredentials(new ECDsaSecurityKey(cert.GetECDsaPrivateKey()), algo)
};
var idAuth = tokenHandler.CreateToken(tokenDescriptor);

// INTEGRITY_REST_01
using var sha256 = SHA256.Create();
var digest = $"SHA-256={Convert.ToBase64String(sha256.ComputeHash(await content.ReadAsByteArrayAsync()))}";

tokenDescriptor.Claims.Add("signed_headers", new Dictionary<string, string>[] {
    new() { { "digest", digest } },
    new() { { "content-type", content.Headers.ContentType?.ToString()! } }
});

var integrity = tokenHandler.CreateToken(tokenDescriptor);

// Client con headers
using var cli = new HttpClient();
cli.DefaultRequestHeaders.Add("Authorization", $"Bearer {idAuth}");
cli.DefaultRequestHeaders.Add("Digest", digest);
cli.DefaultRequestHeaders.Add("Agid-JWT-Signature", integrity);

// Chiamata API
var res = await cli.PostAsync(api, content);
var response = await res.Content.ReadAsStringAsync();
Console.WriteLine(response);