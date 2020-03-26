using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Identity.API.Models.AccountViewModels
{
    public class LoggedInViewModel
    {
        public LoggedInViewModel(object token ,string username , string email , string ID)
        {
            Token = token;
            Id =ID;
            Username = username;
            Email = email;
        }
        
        public LoggedInViewModel ()
        { }
        public object Token { get; set; }
        public string Id { get; set; }
        public string Username { get; set; }
        public string Email { get; set; }
    }
}
