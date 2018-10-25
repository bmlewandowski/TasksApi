using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace TasksApi.Models
{

    public class ReqEmail
    {
        public string Email { get; set; }
    }


    public class AccessRequest
    {
        public string UserId { get; set; }
        public string AuthKey01 { get; set; }
        public string AuthKey02 { get; set; }

    }

    public class User
    {
        public string UserId { get; set; } = string.Empty;
        public string Email { get; set; } = string.Empty;
    }

    public partial class OrganizationUsers
    {
        public int Id { get; set; }
        public string UserName { get; set; }
        public int OrgId { get; set; }
        public string UserId { get; set; }
        public System.DateTime Created { get; set; }
        public int Admin { get; set; }

        internal static void Add(OrganizationUsers f)
        {
            throw new NotImplementedException();
        }
    }

}