using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Api.Auth;

namespace Api.Controllers
{
    [Route("api/[controller]")]
    public class ValuesController : Controller
    {
        // GET api/values
        [HttpGet]
        public IEnumerable<string> Get()
        {
            var name = Environment.GetEnvironmentVariable("COMPUTERNAME") ??
                Environment.GetEnvironmentVariable("HOSTNAME") ??
                Environment.MachineName;
            return new[] { $"MachineName={name}" }.Union(Request.Headers.Select(x => $"{x.Key}={x.Value}"));
        }
        // https://docs.microsoft.com/en-us/aspnet/core/migration/1x-to-2x/identity-2x
        [Permission("client_report_api")]
        // GET api/values/5
        [HttpGet("{id}")]
        public string Get(int id)
        {
            return id.ToString();
        }

        // POST api/values
        [HttpPost]
        public void Post([FromBody]string value)
        {
        }

        // PUT api/values/5
        [HttpPut("{id}")]
        public void Put(int id, [FromBody]string value)
        {
        }

        // DELETE api/values/5
        [HttpDelete("{id}")]
        public void Delete(int id)
        {
        }
    }
}
