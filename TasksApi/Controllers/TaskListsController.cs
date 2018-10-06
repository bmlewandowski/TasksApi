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
    public class TaskListsController : ApiController
    {
        private TASKSDBEntities db = new TASKSDBEntities();

        // GET: api/TaskLists
        [Authorize]
        public IQueryable<TaskList> GetTaskLists()
        {
            //var Name = ClaimsPrincipal.Current.Identity.Name;
            var claimsIdentity = (ClaimsIdentity)this.RequestContext.Principal.Identity;
            var userId = claimsIdentity.Claims.FirstOrDefault(x => x.Type == ClaimTypes.NameIdentifier)?.Value;

            return db.TaskLists.Where((p) => p.OwnerId == userId);
        }

        // GET: api/TaskLists/5
        [Authorize]
        [ResponseType(typeof(TaskList))]
        public IHttpActionResult GetTaskList(int id)
        {
            TaskList taskList = db.TaskLists.Find(id);
            if (taskList == null)
            {
                return NotFound();
            }

            return Ok(taskList);
        }

        // PUT: api/TaskLists/5
        [Authorize]
        [ResponseType(typeof(void))]
        public IHttpActionResult PutTaskList(int id, TaskList taskList)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            if (id != taskList.Id)
            {
                return BadRequest();
            }

            db.Entry(taskList).State = EntityState.Modified;

            try
            {
                db.SaveChanges();
            }
            catch (DbUpdateConcurrencyException)
            {
                if (!TaskListExists(id))
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

        // POST: api/TaskLists
        [Authorize]
        [ResponseType(typeof(TaskList))]
        public IHttpActionResult PostTaskList(TaskList taskList)
        {

            var claimsIdentity = (ClaimsIdentity)this.RequestContext.Principal.Identity;
            var userId = claimsIdentity.Claims.FirstOrDefault(x => x.Type == ClaimTypes.NameIdentifier)?.Value;
            taskList.OwnerId = userId;

            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            db.TaskLists.Add(taskList);
            db.SaveChanges();

            return CreatedAtRoute("DefaultApi", new { id = taskList.Id }, taskList);
        }

        // DELETE: api/TaskLists/5
        [Authorize]
        [ResponseType(typeof(TaskList))]
        public IHttpActionResult DeleteTaskList(int id)
        {
            TaskList taskList = db.TaskLists.Find(id);
            if (taskList == null)
            {
                return NotFound();
            }

            db.TaskLists.Remove(taskList);

            //TODO: Do a loop to delete all tasks included in a tasklist and tasklist members

            db.SaveChanges();

            return Ok(taskList);
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                db.Dispose();
            }
            base.Dispose(disposing);
        }

        private bool TaskListExists(int id)
        {
            return db.TaskLists.Count(e => e.Id == id) > 0;
        }
    }
}