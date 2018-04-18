using Microsoft.Azure.ActiveDirectory.GraphClient;
using Microsoft.IdentityModel.Clients.ActiveDirectory;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.Notifications;
using Microsoft.Owin.Security.OpenIdConnect;
using Owin;
using PocADD.Models;
using System;
using System.Configuration;
using System.Security.Claims;
//using System.IdentityModel.Claims;
using System.Threading.Tasks;
using System.Web;

namespace PocADD
{
    public partial class Startup
    {
        private static string clientId = ConfigurationManager.AppSettings["ida:ClientId"];
        private static string appKey = ConfigurationManager.AppSettings["ida:ClientSecret"];
        private static string aadInstance = ConfigurationManager.AppSettings["ida:AADInstance"];
        private static string tenantId = ConfigurationManager.AppSettings["ida:TenantId"];
        private static string postLogoutRedirectUri = ConfigurationManager.AppSettings["ida:PostLogoutRedirectUri"];

        public static readonly string Authority = aadInstance + tenantId;

        // This is the resource ID of the AAD Graph API.  We'll need this to request a token to call the Graph API.
        string graphResourceId = "https://graph.windows.net";

        public void ConfigureAuth(IAppBuilder app)
        {
            ApplicationDbContext db = new ApplicationDbContext();

            app.SetDefaultSignInAsAuthenticationType(CookieAuthenticationDefaults.AuthenticationType);

            app.UseCookieAuthentication(new CookieAuthenticationOptions());

            app.UseOpenIdConnectAuthentication(new OpenIdConnectAuthenticationOptions
            {
                ClientId = clientId,
                Authority = Authority,
                PostLogoutRedirectUri = postLogoutRedirectUri,

                Notifications = new OpenIdConnectAuthenticationNotifications()
                {
                    AuthorizationCodeReceived = async (context) =>
                    {
                        ClientCredential credential = new ClientCredential(clientId, appKey);
                        string signedInUserID = context.AuthenticationTicket.Identity.FindFirst(ClaimTypes.NameIdentifier).Value;
                        AuthenticationContext authContext = new AuthenticationContext(Authority, new ADALTokenCache(signedInUserID));
                        AuthenticationResult result = await authContext.AcquireTokenByAuthorizationCodeAsync(context.Code,
                            new Uri(HttpContext.Current.Request.Url.GetLeftPart(UriPartial.Path)), credential, graphResourceId);

                        var claims = context.AuthenticationTicket.Identity as System.Security.Claims.ClaimsIdentity;

                        string tenantID = claims.FindFirst("http://schemas.microsoft.com/identity/claims/tenantid").Value;

                        Uri servicePointUri = new Uri(graphResourceId);
                        Uri serviceRoot = new Uri(servicePointUri, tenantID);

                        ActiveDirectoryClient activeDirectoryClient = new ActiveDirectoryClient(serviceRoot, async () => await GetTokenForApplication(claims));

                        // Iterate each Azure Active Directory Group object using Azure Graph API to get the Group Display Name.
                        // Add a new ASP.NET Role to the claims set named using the AAD Group Display Name
                        foreach (Claim claim in claims.FindAll("groups"))
                        {
                            try
                            {
                                String displayName = (await activeDirectoryClient.Groups
                                    .Where(u => u.ObjectId.Equals(claim.Value))
                                    .ExecuteAsync()).CurrentPage[0].DisplayName;

                                claims.AddClaim(new Claim(ClaimTypes.Role.ToString(), displayName));
                            }
                            catch (Exception ex)
                            {// an exception is thrown if a group objectid is not found - ignore  }
                            }
                        }
                    },
                    AuthenticationFailed = (context) =>
                    {
                        context.HandleResponse();
                        context.Response.Redirect("/?errormessage=" + context.Exception.Message);
                        return Task.FromResult(0);
                    }
                }
            });
        }

        public async Task<string> GetTokenForApplication(ClaimsIdentity claims)
        {
            string signedInUserID = claims.FindFirst(ClaimTypes.NameIdentifier).Value;
            string tenantID = claims.FindFirst("http://schemas.microsoft.com/identity/claims/tenantid").Value;
            string userObjectID = claims.FindFirst("http://schemas.microsoft.com/identity/claims/objectidentifier").Value;

            // get a token for the Graph without triggering any user interaction (from the cache, via multi-resource refresh token, etc)
            ClientCredential clientcred = new ClientCredential(clientId, appKey);
            // initialize AuthenticationContext with the token cache of the currently signed in user, as kept in the app's database
            AuthenticationContext authenticationContext = new AuthenticationContext(aadInstance + tenantID, new ADALTokenCache(signedInUserID));
            AuthenticationResult authenticationResult = await authenticationContext.AcquireTokenSilentAsync(graphResourceId, clientcred, new UserIdentifier(userObjectID, UserIdentifierType.UniqueId));
            return authenticationResult.AccessToken;
        }
    }
}
