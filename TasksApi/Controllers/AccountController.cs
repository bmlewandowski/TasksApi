using System;
using System.Collections.Generic;
using System.Data;
using System.Data.SqlClient;
using System.Net.Http;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Threading.Tasks;
using System.Web;
using System.Web.Http;
using System.Web.Http.ModelBinding;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.EntityFramework;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.OAuth;
using Newtonsoft.Json.Linq;
using TasksApi.Models;
using TasksApi.Providers;
using TasksApi.Results;
using System.Linq;

namespace TasksApi.Controllers
{
    [Authorize]
    [RoutePrefix("api/Account")]
    public class AccountController : ApiController
    {
        private const string LocalLoginProvider = "Local";
        private ApplicationUserManager _userManager;

        public AccountController()
        {
        }

        public AccountController(ApplicationUserManager userManager,
            ISecureDataFormat<AuthenticationTicket> accessTokenFormat)
        {
            UserManager = userManager;
            AccessTokenFormat = accessTokenFormat;
        }

        public ApplicationUserManager UserManager
        {
            get
            {
                return _userManager ?? Request.GetOwinContext().GetUserManager<ApplicationUserManager>();
            }
            private set
            {
                _userManager = value;
            }
        }

        public ISecureDataFormat<AuthenticationTicket> AccessTokenFormat { get; private set; }

        // GET api/Account/UserInfo
        [HostAuthentication(DefaultAuthenticationTypes.ExternalBearer)]
        [Route("UserInfo")]
        public UserInfoViewModel GetUserInfo()
        {
            ExternalLoginData externalLogin = ExternalLoginData.FromIdentity(User.Identity as ClaimsIdentity);

            return new UserInfoViewModel
            {
                Email = User.Identity.GetUserName(),
                HasRegistered = externalLogin == null,
                LoginProvider = externalLogin != null ? externalLogin.LoginProvider : null
            };
        }

        // POST api/Account/Logout
        [Route("Logout")]
        public IHttpActionResult Logout()
        {
            Authentication.SignOut(CookieAuthenticationDefaults.AuthenticationType);
            return Ok();
        }

        // GET api/Account/ManageInfo?returnUrl=%2F&generateState=true
        [Route("ManageInfo")]
        public async Task<ManageInfoViewModel> GetManageInfo(string returnUrl, bool generateState = false)
        {
            IdentityUser user = await UserManager.FindByIdAsync(User.Identity.GetUserId());

            if (user == null)
            {
                return null;
            }

            List<UserLoginInfoViewModel> logins = new List<UserLoginInfoViewModel>();

            foreach (IdentityUserLogin linkedAccount in user.Logins)
            {
                logins.Add(new UserLoginInfoViewModel
                {
                    LoginProvider = linkedAccount.LoginProvider,
                    ProviderKey = linkedAccount.ProviderKey
                });
            }

            if (user.PasswordHash != null)
            {
                logins.Add(new UserLoginInfoViewModel
                {
                    LoginProvider = LocalLoginProvider,
                    ProviderKey = user.UserName,
                });
            }

            return new ManageInfoViewModel
            {
                LocalLoginProvider = LocalLoginProvider,
                Email = user.UserName,
                Logins = logins,
                ExternalLoginProviders = GetExternalLogins(returnUrl, generateState)
            };
        }

        // POST api/Account/ChangePassword
        [Route("ChangePassword")]
        public async Task<IHttpActionResult> ChangePassword(ChangePasswordBindingModel model)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            IdentityResult result = await UserManager.ChangePasswordAsync(User.Identity.GetUserId(), model.OldPassword,
                model.NewPassword);

            if (!result.Succeeded)
            {
                return GetErrorResult(result);
            }

            return Ok();
        }

        // POST api/Account/SetPassword
        [Route("SetPassword")]
        public async Task<IHttpActionResult> SetPassword(SetPasswordBindingModel model)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            IdentityResult result = await UserManager.AddPasswordAsync(User.Identity.GetUserId(), model.NewPassword);

            if (!result.Succeeded)
            {
                return GetErrorResult(result);
            }

            return Ok();
        }

        // POST api/Account/AddExternalLogin
        [Route("AddExternalLogin")]
        public async Task<IHttpActionResult> AddExternalLogin(AddExternalLoginBindingModel model)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            Authentication.SignOut(DefaultAuthenticationTypes.ExternalCookie);

            AuthenticationTicket ticket = AccessTokenFormat.Unprotect(model.ExternalAccessToken);

            if (ticket == null || ticket.Identity == null || (ticket.Properties != null
                && ticket.Properties.ExpiresUtc.HasValue
                && ticket.Properties.ExpiresUtc.Value < DateTimeOffset.UtcNow))
            {
                return BadRequest("External login failure.");
            }

            ExternalLoginData externalData = ExternalLoginData.FromIdentity(ticket.Identity);

            if (externalData == null)
            {
                return BadRequest("The external login is already associated with an account.");
            }

            IdentityResult result = await UserManager.AddLoginAsync(User.Identity.GetUserId(),
                new UserLoginInfo(externalData.LoginProvider, externalData.ProviderKey));

            if (!result.Succeeded)
            {
                return GetErrorResult(result);
            }

            return Ok();
        }

        // POST api/Account/RemoveLogin
        [Route("RemoveLogin")]
        public async Task<IHttpActionResult> RemoveLogin(RemoveLoginBindingModel model)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            IdentityResult result;

            if (model.LoginProvider == LocalLoginProvider)
            {
                result = await UserManager.RemovePasswordAsync(User.Identity.GetUserId());
            }
            else
            {
                result = await UserManager.RemoveLoginAsync(User.Identity.GetUserId(),
                    new UserLoginInfo(model.LoginProvider, model.ProviderKey));
            }

            if (!result.Succeeded)
            {
                return GetErrorResult(result);
            }

            return Ok();
        }

        // GET api/Account/ExternalLogin
        [OverrideAuthentication]
        [HostAuthentication(DefaultAuthenticationTypes.ExternalCookie)]
        [AllowAnonymous]
        [Route("ExternalLogin", Name = "ExternalLogin")]
        public async Task<IHttpActionResult> GetExternalLogin(string provider, string error = null)
        {
            if (error != null)
            {
                return Redirect(Url.Content("~/") + "#error=" + Uri.EscapeDataString(error));
            }

            if (!User.Identity.IsAuthenticated)
            {
                return new ChallengeResult(provider, this);
            }

            ExternalLoginData externalLogin = ExternalLoginData.FromIdentity(User.Identity as ClaimsIdentity);

            if (externalLogin == null)
            {
                return InternalServerError();
            }

            if (externalLogin.LoginProvider != provider)
            {
                Authentication.SignOut(DefaultAuthenticationTypes.ExternalCookie);
                return new ChallengeResult(provider, this);
            }

            ApplicationUser user = await UserManager.FindAsync(new UserLoginInfo(externalLogin.LoginProvider,
                externalLogin.ProviderKey));

            bool hasRegistered = user != null;

            if (hasRegistered)
            {
                Authentication.SignOut(DefaultAuthenticationTypes.ExternalCookie);

                ClaimsIdentity oAuthIdentity = await user.GenerateUserIdentityAsync(UserManager,
                   OAuthDefaults.AuthenticationType);
                ClaimsIdentity cookieIdentity = await user.GenerateUserIdentityAsync(UserManager,
                    CookieAuthenticationDefaults.AuthenticationType);

                AuthenticationProperties properties = ApplicationOAuthProvider.CreateProperties(user.UserName);
                Authentication.SignIn(properties, oAuthIdentity, cookieIdentity);
            }
            else
            {
                IEnumerable<Claim> claims = externalLogin.GetClaims();
                ClaimsIdentity identity = new ClaimsIdentity(claims, OAuthDefaults.AuthenticationType);
                Authentication.SignIn(identity);
            }

            return Ok();
        }

        // GET api/Account/ExternalLogins?returnUrl=%2F&generateState=true
        [AllowAnonymous]
        [Route("ExternalLogins")]
        public IEnumerable<ExternalLoginViewModel> GetExternalLogins(string returnUrl, bool generateState = false)
        {
            IEnumerable<AuthenticationDescription> descriptions = Authentication.GetExternalAuthenticationTypes();
            List<ExternalLoginViewModel> logins = new List<ExternalLoginViewModel>();

            string state;

            if (generateState)
            {
                const int strengthInBits = 256;
                state = RandomOAuthStateGenerator.Generate(strengthInBits);
            }
            else
            {
                state = null;
            }

            foreach (AuthenticationDescription description in descriptions)
            {
                ExternalLoginViewModel login = new ExternalLoginViewModel
                {
                    Name = description.Caption,
                    Url = Url.Route("ExternalLogin", new
                    {
                        provider = description.AuthenticationType,
                        response_type = "token",
                        client_id = Startup.PublicClientId,
                        redirect_uri = new Uri(Request.RequestUri, returnUrl).AbsoluteUri,
                        state = state
                    }),
                    State = state
                };
                logins.Add(login);
            }

            return logins;
        }

        // POST api/Account/Registeruser
        /// <summary>
        /// Allows Admin to add User to Organization
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
        [Authorize]
        [Route("Registeruser")]
        public async Task<IHttpActionResult> Registeruser(RegisterUserBindingModel model)
        {

            var claimsIdentity = (ClaimsIdentity)this.RequestContext.Principal.Identity;
            var adminId = claimsIdentity.Claims.FirstOrDefault(x => x.Type == ClaimTypes.NameIdentifier)?.Value;
            SqlConnection con = new SqlConnection();
            con.ConnectionString = System.Configuration.ConfigurationManager.ConnectionStrings["DefaultConnection"].ConnectionString;
            con.Open();

            string sqlgetorgid = "SELECT OrgId FROM OrganizationUsers WHERE UserId = @userId";
            SqlCommand cmdget = new SqlCommand(sqlgetorgid, con);

            cmdget.Parameters.Add("@userId", SqlDbType.VarChar);
            cmdget.Parameters["@userId"].Value = adminId;

            var OrgId = cmdget.ExecuteScalar();

            model.Password = Guid.NewGuid().ToString();
            model.ConfirmPassword = model.Password;


            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            var user = new ApplicationUser() { UserName = model.Email, Email = model.Email };

            IdentityResult result = await UserManager.CreateAsync(user, model.Password);

            var userId = user.Id;

            string sqlinsertorgusr = "INSERT INTO OrganizationUsers (OrgId, UserId, AuthKey01, AuthKey02, AuthKeyExpires) values (@OrgId, @UserId, @Authkey01, @Authkey02, @AuthKeyExpires);SELECT SCOPE_IDENTITY()";

            SqlCommand cmd = new SqlCommand(sqlinsertorgusr, con);

            cmd.Parameters.Add("@OrgId", SqlDbType.Int);
            cmd.Parameters["@OrgId"].Value = OrgId;

            cmd.Parameters.Add("@UserId", SqlDbType.VarChar);
            cmd.Parameters["@UserId"].Value = userId;

            cmd.Parameters.Add("@AuthKey01", SqlDbType.VarChar);
            cmd.Parameters["@AuthKey01"].Value = Guid.NewGuid().ToString();

            cmd.Parameters.Add("@AuthKey02", SqlDbType.VarChar);
            cmd.Parameters["@AuthKey02"].Value = Guid.NewGuid().ToString();

            cmd.Parameters.Add("@AuthKeyExpires", SqlDbType.DateTime2);
            cmd.Parameters["@AuthKeyExpires"].Value = DateTime.Now.AddDays(1);

            var OrgUserId = cmd.ExecuteScalar();

            con.Close();
            con.Dispose();

            if (!result.Succeeded)
            {
                return GetErrorResult(result);
            }

            else
            {
                //Log the user in

                return Ok("User Imported");
            }

        }


        // POST api/Account/Registeradmin
        /// <summary>
        /// Creates Admin of a new Organization
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
        [AllowAnonymous]
        [Route("Registeradmin")]
        public async Task<IHttpActionResult> Registeradmin(RegisterAdminBindingModel model)
        {

            model.Password = Guid.NewGuid().ToString();
            model.ConfirmPassword = model.Password;
            model.Admin = 1;

            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            var user = new ApplicationUser() { UserName = model.Email, Email = model.Email };

            IdentityResult result = await UserManager.CreateAsync(user, model.Password);

            //Creates Organization in Organizations table and creates user as admin in OrganizationUsers table

            var userId = user.Id;
            var organization = model.Organization;

            SqlConnection con = new SqlConnection();
            con.ConnectionString = System.Configuration.ConfigurationManager.ConnectionStrings["DefaultConnection"].ConnectionString;

            string sqlinsertorg = "INSERT INTO Organizations (Name) values (@Name);SELECT SCOPE_IDENTITY()";

            con.Open();
            SqlCommand cmd = new SqlCommand(sqlinsertorg, con);

            cmd.Parameters.Add("@name", SqlDbType.VarChar);
            cmd.Parameters["@name"].Value = organization;

            var OrgId = cmd.ExecuteScalar();

            string sqlinsertorgusr = "INSERT INTO OrganizationUsers (OrgId, UserId, Admin, AuthKey01, AuthKey02, AuthKeyExpires) values (@OrgId, @UserId, @Admin, @Authkey01, @Authkey02, @AuthKeyExpires);SELECT SCOPE_IDENTITY()";

            SqlCommand cmd2 = new SqlCommand(sqlinsertorgusr, con);

            cmd2.Parameters.Add("@OrgId", SqlDbType.Int);
            cmd2.Parameters["@OrgId"].Value = OrgId;

            cmd2.Parameters.Add("@UserId", SqlDbType.VarChar);
            cmd2.Parameters["@UserId"].Value = userId;

            cmd2.Parameters.Add("@Admin", SqlDbType.Int);
            cmd2.Parameters["@Admin"].Value = 1;

            cmd2.Parameters.Add("@AuthKey01", SqlDbType.VarChar);
            cmd2.Parameters["@AuthKey01"].Value = Guid.NewGuid().ToString();

            cmd2.Parameters.Add("@AuthKey02", SqlDbType.VarChar);
            cmd2.Parameters["@AuthKey02"].Value = Guid.NewGuid().ToString();

            cmd2.Parameters.Add("@AuthKeyExpires", SqlDbType.DateTime2);
            cmd2.Parameters["@AuthKeyExpires"].Value = DateTime.Now.AddDays(1);

            var OrgUserId = cmd2.ExecuteScalar();

            con.Close();
            con.Dispose();

            if (!result.Succeeded)
            {
                return GetErrorResult(result);
            }

            else
            {
                //Log the user in
                var tokenExpiration = TimeSpan.FromDays(1);
                ClaimsIdentity identity = new ClaimsIdentity(OAuthDefaults.AuthenticationType);
                identity.AddClaim(new Claim(ClaimTypes.Name, user.UserName));
                identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, userId));
                identity.AddClaim(new Claim("role", "user"));
                var props = new AuthenticationProperties()
                {
                    IssuedUtc = DateTime.UtcNow,
                    ExpiresUtc = DateTime.UtcNow.Add(tokenExpiration),
                };
                var ticket = new AuthenticationTicket(identity, props);
                var accessToken = Startup.OAuthOptions.AccessTokenFormat.Protect(ticket);
                JObject tokenResponse = new JObject(
                new JProperty("userId", userId),
                new JProperty("userName", user.UserName),
                new JProperty("access_token", accessToken),
                new JProperty("token_type", "bearer"),
                new JProperty("expires_in", tokenExpiration.TotalSeconds.ToString()),
                new JProperty(".issued", ticket.Properties.IssuedUtc.GetValueOrDefault().DateTime.ToUniversalTime()),
                new JProperty(".expires", ticket.Properties.ExpiresUtc.GetValueOrDefault().DateTime.ToUniversalTime()));

                return Ok(tokenResponse);
            }

            //return Ok();
        }

        // POST api/Account/Register
        /// <summary>
        /// Standard Register with addition of creating Org and OrgUser and generation Authkeys
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
        [AllowAnonymous]
        [Route("Register")]
        public async Task<IHttpActionResult> Register(RegisterBindingModel model)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            var user = new ApplicationUser() { UserName = model.Email, Email = model.Email };

            IdentityResult result = await UserManager.CreateAsync(user, model.Password);

            // BEGIN CUSTOMIZATION

            //Creates Organization in Organisations table and creates user as admin in OrganizationUsers table

            var userId = user.Id;
            var organization = model.Organization;

            SqlConnection con = new SqlConnection();
            con.ConnectionString = System.Configuration.ConfigurationManager.ConnectionStrings["DefaultConnection"].ConnectionString;

            string sqlinsertorg = "INSERT INTO Organizations (Name) values (@Name);SELECT SCOPE_IDENTITY()";

            con.Open();
            SqlCommand cmd = new SqlCommand(sqlinsertorg, con);

            cmd.Parameters.Add("@name", SqlDbType.VarChar);
            cmd.Parameters["@name"].Value = organization;

            var OrgId = cmd.ExecuteScalar();

            string sqlinsertorgusr = "INSERT INTO OrganizationUsers (OrgId, UserId, Admin, AuthKey01, AuthKey02, AuthKeyExpires) values (@OrgId, @UserId, @Admin, @Authkey01, @Authkey02, @AuthKeyExpires);SELECT SCOPE_IDENTITY()";

            SqlCommand cmd2 = new SqlCommand(sqlinsertorgusr, con);

            cmd2.Parameters.Add("@OrgId", SqlDbType.Int);
            cmd2.Parameters["@OrgId"].Value = OrgId;

            cmd2.Parameters.Add("@UserId", SqlDbType.VarChar);
            cmd2.Parameters["@UserId"].Value = userId;

            cmd2.Parameters.Add("@Admin", SqlDbType.Int);
            cmd2.Parameters["@Admin"].Value = 1;

            cmd2.Parameters.Add("@AuthKey01", SqlDbType.VarChar);
            cmd2.Parameters["@AuthKey01"].Value = Guid.NewGuid().ToString();

            cmd2.Parameters.Add("@AuthKey02", SqlDbType.VarChar);
            cmd2.Parameters["@AuthKey02"].Value = Guid.NewGuid().ToString();

            cmd2.Parameters.Add("@AuthKeyExpires", SqlDbType.DateTime2);
            cmd2.Parameters["@AuthKeyExpires"].Value = DateTime.Now.AddDays(1);

            var OrgUserId = cmd2.ExecuteScalar();

            con.Close();
            con.Dispose();

            // END CUSTOMIZATION

            if (!result.Succeeded)
            {
                return GetErrorResult(result);
            }

            return Ok();
        }

        // POST api/Account/RegisterExternal
        [OverrideAuthentication]
        [HostAuthentication(DefaultAuthenticationTypes.ExternalBearer)]
        [Route("RegisterExternal")]
        public async Task<IHttpActionResult> RegisterExternal(RegisterExternalBindingModel model)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            var info = await Authentication.GetExternalLoginInfoAsync();
            if (info == null)
            {
                return InternalServerError();
            }

            var user = new ApplicationUser() { UserName = model.Email, Email = model.Email };

            IdentityResult result = await UserManager.CreateAsync(user);
            if (!result.Succeeded)
            {
                return GetErrorResult(result);
            }

            result = await UserManager.AddLoginAsync(user.Id, info.Login);
            if (!result.Succeeded)
            {
                return GetErrorResult(result);
            }
            return Ok();
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing && _userManager != null)
            {
                _userManager.Dispose();
                _userManager = null;
            }

            base.Dispose(disposing);
        }

        #region Helpers

        private IAuthenticationManager Authentication
        {
            get { return Request.GetOwinContext().Authentication; }
        }

        private IHttpActionResult GetErrorResult(IdentityResult result)
        {
            if (result == null)
            {
                return InternalServerError();
            }

            if (!result.Succeeded)
            {
                if (result.Errors != null)
                {
                    foreach (string error in result.Errors)
                    {
                        ModelState.AddModelError("", error);
                    }
                }

                if (ModelState.IsValid)
                {
                    // No ModelState errors are available to send, so just return an empty BadRequest.
                    return BadRequest();
                }

                return BadRequest(ModelState);
            }

            return null;
        }

        private class ExternalLoginData
        {
            public string LoginProvider { get; set; }
            public string ProviderKey { get; set; }
            public string UserName { get; set; }

            public IList<Claim> GetClaims()
            {
                IList<Claim> claims = new List<Claim>();
                claims.Add(new Claim(ClaimTypes.NameIdentifier, ProviderKey, null, LoginProvider));

                if (UserName != null)
                {
                    claims.Add(new Claim(ClaimTypes.Name, UserName, null, LoginProvider));
                }

                return claims;
            }

            public static ExternalLoginData FromIdentity(ClaimsIdentity identity)
            {
                if (identity == null)
                {
                    return null;
                }

                Claim providerKeyClaim = identity.FindFirst(ClaimTypes.NameIdentifier);

                if (providerKeyClaim == null || String.IsNullOrEmpty(providerKeyClaim.Issuer)
                    || String.IsNullOrEmpty(providerKeyClaim.Value))
                {
                    return null;
                }

                if (providerKeyClaim.Issuer == ClaimsIdentity.DefaultIssuer)
                {
                    return null;
                }

                return new ExternalLoginData
                {
                    LoginProvider = providerKeyClaim.Issuer,
                    ProviderKey = providerKeyClaim.Value,
                    UserName = identity.FindFirstValue(ClaimTypes.Name)
                };
            }
        }

        private static class RandomOAuthStateGenerator
        {
            private static RandomNumberGenerator _random = new RNGCryptoServiceProvider();

            public static string Generate(int strengthInBits)
            {
                const int bitsPerByte = 8;

                if (strengthInBits % bitsPerByte != 0)
                {
                    throw new ArgumentException("strengthInBits must be evenly divisible by 8.", "strengthInBits");
                }

                int strengthInBytes = strengthInBits / bitsPerByte;

                byte[] data = new byte[strengthInBytes];
                _random.GetBytes(data);
                return HttpServerUtility.UrlTokenEncode(data);
            }
        }

        #endregion
    }
}
