using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ABHA_HIMS.Application.Dtos
{
    public class MobileVerifyInput
    {
        public string TxnId { get; set; } = string.Empty;
        public string Otp { get; set; } = string.Empty; // plain OTP expected (or encrypted string)
    }
}
