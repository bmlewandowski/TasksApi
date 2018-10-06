using System;
using System.Collections.Generic;
using System.Data;
using System.Data.Entity;
using System.Data.Entity.Infrastructure;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Claims;
using System.Web.Http;
using System.Web.Http.Description;
using TasksDataAccess;

namespace TasksApi.Controllers
{
    public class TasksController : ApiController
    {
        private TASKSDBEntities db = new TASKSDBEntities();

        // GET: api/Tasks
        [Authorize]
        public IQueryable<Task> GetTasks([FromUri] int listid)
        {
            //return all tasks associated with the tasklist id
            return db.Tasks.Where((p) => p.ListId == listid);
        }

        // GET: api/Tasks/5
        [ResponseType(typeof(Task))]
        public IHttpActionResult GetTask(int id)
        {
            Task task = db.Tasks.Find(id);
            //TODO: Make sure task is accessible for requestor from permissions
            if (task == null)
            {
                return NotFound();
            }

            return Ok(task);
        }

        // PUT: api/Tasks/5
        [ResponseType(typeof(void))]
        public IHttpActionResult PutTask(int id, Task task)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            if (id != task.Id)
            {
                return BadRequest();
            }

            db.Entry(task).State = EntityState.Modified;

            try
            {
                db.SaveChanges();
            }
            catch (DbUpdateConcurrencyException)
            {
                if (!TaskExists(id))
                {
                    return NotFound();
                }
                else
                {
                    throw;
                }
            }

            return StatusCode(HttpStatusCode.NoContent);
        }

        // POST: api/Tasks
        [ResponseType(typeof(Task))]
        public IHttpActionResult PostTask(Task task)
        {

            var claimsIdentity = (ClaimsIdentity)this.RequestContext.Principal.Identity;
            var userId = claimsIdentity.Claims.FirstOrDefault(x => x.Type == ClaimTypes.NameIdentifier)?.Value;
            task.OwnerId = userId;

            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            db.Tasks.Add(task);
            db.SaveChanges();

            return CreatedAtRoute("DefaultApi", new { id = task.Id }, task);

        }

        // DELETE: api/Tasks/5
        [ResponseType(typeof(Task))]
        public IHttpActionResult DeleteTask(int id)
        {

            var claimsIdentity = (ClaimsIdentity)this.RequestContext.Principal.Identity;
            var userId = claimsIdentity.Claims.FirstOrDefault(x => x.Type == ClaimTypes.NameIdentifier)?.Value;

            Task task = db.Tasks.Find(id);

            //make sure task exists and is owned by requester
            if (task == null || task.OwnerId != userId)
            {
                return NotFound();
            }

            db.Tasks.Remove(task);
            db.SaveChanges();

            return Ok(task);
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                db.Dispose();
            }
            base.Dispose(disposing);
        }

        private bool TaskExists(int id)
        {
            return db.Tasks.Count(e => e.Id == id) > 0;
        }
    }
}