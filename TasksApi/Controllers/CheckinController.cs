using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Claims;
using System.Web.Http;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.OAuth;
using Newtonsoft.Json.Linq;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.EntityFramework;
using System.Data.SqlClient;
using System.Data;
using SendGrid.Helpers.Mail;
using SendGrid;
using System.Threading.Tasks;
using TasksApi.Models;
using TasksApi;

namespace TasksApi.Controllers

{
    public class ReqEmail
    {
        public string Email { get; set; }
    }

    public class KnockKnock
    {
        public string UserId { get; set; }
        public string AuthKey01 { get; set; }
        public string AuthKey02 { get; set; }

    }

    public class CheckInController : ApiController
    {

        // GET: api/checkin/
        [HttpGet]
        public async Task<HttpResponseMessage> SendMail(string link, string sendaddress)
        {
            var apiKey = System.Configuration.ConfigurationManager.AppSettings["SendGridAPIKey"];
            var client = new SendGridClient(apiKey);
            var from = new EmailAddress("Postmoderncode@gmail.com", "SkillResults");
            var to = new EmailAddress(sendaddress, sendaddress);
            var subject = "SkillResults Login ";
            var htmlContent = "<p>The follpowing is a secure link into Skill Results: <a href=\"http://40.87.90.212" + link + "\" title=\"Login\">Login to Skill Results</a></p>";
            var msg = MailHelper.CreateSingleEmail(from, to, subject, "", htmlContent);
            var response = await client.SendEmailAsync(msg);

            HttpResponseMessage response2 = Request.CreateResponse(HttpStatusCode.OK, "Mail Sent");
            return response2;
        }

        // GET: api/checkin/
        [HttpGet]
        //Takes UserId and 2 provided GUIDs as Querystrings and tests that the keys are correct and that        
        //the expiration for the keys hasn't passed and then sends the requester an authentication token.
        public HttpResponseMessage Get([FromUri] KnockKnock value)
        {

            var UserManager = new UserManager<ApplicationUser>(new UserStore<ApplicationUser>(new ApplicationDbContext()));

            SqlConnection con = new SqlConnection();
            con.ConnectionString = System.Configuration.ConfigurationManager.ConnectionStrings["DefaultConnection"].ConnectionString;

            using (con)
            {
                string dbauthkey01 = "";
                string dbauthkey02 = "";
                DateTime dbauthexpires = DateTime.Now;

                SqlCommand command = new SqlCommand("SELECT UserId, AuthKey01, AuthKey02, AuthKeyExpires FROM OrganizationUsers WHERE UserId = '" + value.UserId + "';", con);
                con.Open();

                SqlDataReader reader = command.ExecuteReader();


                if (reader.HasRows)
                {
                    while (reader.Read())
                    {
                        dbauthkey01 = reader.GetString(1);
                        dbauthkey02 = reader.GetString(2);
                        dbauthexpires = reader.GetDateTime(3);
                    }
                }

                else
                {
                    Console.WriteLine("No rows found.");
                    HttpResponseMessage response = Request.CreateResponse(HttpStatusCode.NotFound, "User Not Found");
                    return response;
                }

                reader.Close();

                // Check that the provided GUIDs match the OrganizationUsers keys and that the expiration hasn't passed
                if (dbauthkey01 == value.AuthKey01 && dbauthkey02 == value.AuthKey02 && dbauthexpires > DateTime.Now)
                {

                    con.Close();
                    con.Dispose();

                    //Guid Keys have passed
                    var user = UserManager.FindById(value.UserId);
                    var userId = user.Id;
                    var tokenExpiration = TimeSpan.FromDays(1);
                    ClaimsIdentity identity = new ClaimsIdentity(OAuthDefaults.AuthenticationType);
                    identity.AddClaim(new Claim(ClaimTypes.Name, user.UserName));
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

                    HttpResponseMessage response = Request.CreateResponse(HttpStatusCode.OK, tokenResponse);
                    return response;

                }
                else
                {
                    con.Close();
                    con.Dispose();

                    HttpResponseMessage response = Request.CreateResponse(HttpStatusCode.BadRequest, "Invalid User Key");
                    return response;

                }

            }

        }

        // POST api/checkin/
        [HttpPost]
        //Takes provided email address and if user exists, generates 2 new GUIDS and expiration date and
        //saves them on the organizationuser record while generating a querystring url to be used to login.
        public async Task<HttpResponseMessage> Post([FromBody] ReqEmail reqemail)
        {
            var UserManager = new UserManager<ApplicationUser>(new UserStore<ApplicationUser>(new ApplicationDbContext()));

            if (UserManager.FindByName(reqemail.Email) != null)
            {
                var user = UserManager.FindByName(reqemail.Email);
                var NewAuthKey01 = Guid.NewGuid().ToString();
                var NewAuthKey02 = Guid.NewGuid().ToString();
                var NewAuthKeyExpires = DateTime.Now.AddDays(1);

                //Basic UPDATE method with Parameters
                SqlConnection sqlConn = new SqlConnection(System.Configuration.ConfigurationManager.ConnectionStrings["DefaultConnection"].ConnectionString);
                SqlCommand sqlComm = new SqlCommand();
                sqlComm = sqlConn.CreateCommand();
                sqlComm.CommandText = "UPDATE OrganizationUsers SET AuthKey01=@AuthKey01,AuthKey02=@AuthKey02,AuthKeyExpires = @AuthKeyExpires WHERE UserId=@UserId";

                sqlComm.Parameters.Add("@AuthKey01", SqlDbType.VarChar);
                sqlComm.Parameters["@AuthKey01"].Value = NewAuthKey01;

                sqlComm.Parameters.Add("@AuthKey02", SqlDbType.VarChar);
                sqlComm.Parameters["@AuthKey02"].Value = NewAuthKey02;

                sqlComm.Parameters.Add("@AuthKeyExpires", SqlDbType.DateTime2);
                sqlComm.Parameters["@AuthKeyExpires"].Value = NewAuthKeyExpires;

                sqlComm.Parameters.Add("@UserId", SqlDbType.VarChar);
                sqlComm.Parameters["@UserId"].Value = user.Id;

                sqlConn.Open();
                sqlComm.ExecuteNonQuery();
                sqlConn.Close();

                var tokenResponse = "/auth?UserId=" + user.Id + "&Authkey01=" + NewAuthKey01 + "&Authkey02=" + NewAuthKey02;
                await SendMail(tokenResponse, user.Email);

                HttpResponseMessage response = Request.CreateResponse(HttpStatusCode.OK, tokenResponse);
                return response;
            }

            else
            {

                HttpResponseMessage response = Request.CreateResponse(HttpStatusCode.NotFound, "User Not Found");
                return response;
            }

        }

    }
}
