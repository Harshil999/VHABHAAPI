using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ABHA_HIMS.Application.Dtos
{
    public class EmailVerificationInput
    {
        public string Email { get; set; } = string.Empty; // plain email expected
        public string XToken { get; set; } = string.Empty;
    }
}
