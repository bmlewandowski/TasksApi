//------------------------------------------------------------------------------
// <auto-generated>
//     This code was generated from a template.
//
//     Manual changes to this file may cause unexpected behavior in your application.
//     Manual changes to this file will be overwritten if the code is regenerated.
// </auto-generated>
//------------------------------------------------------------------------------

namespace TasksDataAccess
{
    using System;
    using System.Collections.Generic;
    
    public partial class Task
    {
        public int Id { get; set; }
        public string Name { get; set; }
        public bool Complete { get; set; }
        public string OwnerId { get; set; }
        public System.DateTime Created { get; set; }
        public string CompletedBy { get; set; }
        public Nullable<System.DateTime> CompletedOn { get; set; }
    }
}