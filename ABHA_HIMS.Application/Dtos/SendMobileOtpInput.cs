using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.Json.Serialization;
using System.Threading.Tasks;

namespace ABHA_HIMS.Application.Dtos
{
    public class MobileOtpInput
    {
        public string Mobile { get; set; } = string.Empty; // plain mobile expected (e.g. "9429728770")
        public string? TxnId { get; set; }
    }
}
