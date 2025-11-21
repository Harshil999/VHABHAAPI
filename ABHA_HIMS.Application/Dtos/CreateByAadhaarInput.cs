using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ABHA_HIMS.Application.Dtos
{
    public class CreateByAadhaarInput
    {
        public string TxnId { get; set; } = string.Empty;
        public string OtpValue { get; set; } = string.Empty; // expected already encrypted
        public string Mobile { get; set; } = string.Empty;
    }
}
