using System;
using System.Collections.Generic;
using System.Data;
using System.Data.SqlClient;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Claims;
using System.Web.Http;
using Newtonsoft.Json;
using System.Threading.Tasks;
using TasksApi.Models;

namespace TasksApi.Controllers
{
    public class OrganizationUsersController : ApiController
    {

        // GET: api/OrganizationUsers
        /// <summary>
        /// Returns list of Users in the logged in User's Organization
        /// </summary>
        /// <returns></returns>
        [AllowAnonymous]

        public HttpResponseMessage GetAreaCategoriesCustoms()
        {

            var claimsIdentity = (ClaimsIdentity)this.RequestContext.Principal.Identity;
            var userId = claimsIdentity.Claims.FirstOrDefault(x => x.Type == ClaimTypes.NameIdentifier)?.Value;

            List<OrganizationUsers> OrganizationUsers = new List<OrganizationUsers>();

            if (userId != null)
            {
                SqlDataReader reader = null;
                SqlConnection con = new SqlConnection();
                con.ConnectionString = System.Configuration.ConfigurationManager.ConnectionStrings["DefaultConnection"].ConnectionString;

                SqlCommand sqlCmd = new SqlCommand();
                sqlCmd.CommandType = CommandType.Text;
                sqlCmd.Connection = con;
                con.Open();
                sqlCmd.CommandText = "SELECT OrgId FROM OrganizationUsers WHERE UserId = @UserId";

                sqlCmd.Parameters.Add("@UserId", SqlDbType.VarChar);
                sqlCmd.Parameters["@UserId"].Value = userId;

                var OrgId = sqlCmd.ExecuteScalar();


                sqlCmd.CommandText = "SELECT o.OrgId, o.UserId, o.Created, o.Admin, a.UserName FROM OrganizationUsers as o, AspNetUsers as a WHERE o.UserId = a.Id  AND o.OrgId = @OrgId";

                sqlCmd.Parameters.Add("@OrgId", SqlDbType.Int);
                sqlCmd.Parameters["@OrgId"].Value = OrgId;

                reader = sqlCmd.ExecuteReader();

                while (reader.Read())
                {
                    OrganizationUsers f = new OrganizationUsers();
                    f.UserName = (string)reader["UserName"];
                    f.OrgId = (int)reader["OrgId"];
                    f.UserId = (string)reader["UserId"];
                    f.Created = (DateTime)reader["Created"];
                    f.Admin = (int)reader["Admin"];
                    OrganizationUsers.Add(f);
                }

                con.Close();
            }

            HttpResponseMessage response = Request.CreateResponse(HttpStatusCode.OK, OrganizationUsers);
            return response;
        }

    }
}
