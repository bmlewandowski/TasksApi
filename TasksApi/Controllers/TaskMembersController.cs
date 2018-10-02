using System;
using System.Collections.Generic;
using System.Data;
using System.Data.Entity;
using System.Data.Entity.Infrastructure;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Web.Http;
using System.Web.Http.Description;
using TasksDataAccess;

namespace TasksApi.Controllers
{
    public class TaskMembersController : ApiController
    {
        private TASKSDBEntities db = new TASKSDBEntities();

        // GET: api/TaskMembers
        public IQueryable<TaskMember> GetTaskMembers()
        {
            return db.TaskMembers;
        }

        // GET: api/TaskMembers/5
        [ResponseType(typeof(TaskMember))]
        public IHttpActionResult GetTaskMember(int id)
        {
            TaskMember taskMember = db.TaskMembers.Find(id);
            if (taskMember == null)
            {
                return NotFound();
            }

            return Ok(taskMember);
        }

        // PUT: api/TaskMembers/5
        [ResponseType(typeof(void))]
        public IHttpActionResult PutTaskMember(int id, TaskMember taskMember)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            if (id != taskMember.Id)
            {
                return BadRequest();
            }

            db.Entry(taskMember).State = EntityState.Modified;

            try
            {
                db.SaveChanges();
            }
            catch (DbUpdateConcurrencyException)
            {
                if (!TaskMemberExists(id))
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

        // POST: api/TaskMembers
        [ResponseType(typeof(TaskMember))]
        public IHttpActionResult PostTaskMember(TaskMember taskMember)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            db.TaskMembers.Add(taskMember);
            db.SaveChanges();

            return CreatedAtRoute("DefaultApi", new { id = taskMember.Id }, taskMember);
        }

        // DELETE: api/TaskMembers/5
        [ResponseType(typeof(TaskMember))]
        public IHttpActionResult DeleteTaskMember(int id)
        {
            TaskMember taskMember = db.TaskMembers.Find(id);
            if (taskMember == null)
            {
                return NotFound();
            }

            db.TaskMembers.Remove(taskMember);
            db.SaveChanges();

            return Ok(taskMember);
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                db.Dispose();
            }
            base.Dispose(disposing);
        }

        private bool TaskMemberExists(int id)
        {
            return db.TaskMembers.Count(e => e.Id == id) > 0;
        }
    }
}