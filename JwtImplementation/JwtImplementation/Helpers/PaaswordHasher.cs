using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Server.IIS;
using System.Text;

namespace JwtImplementation.Helpers
{
    public class PaaswordHasher
    {
        public static string HashPassword(string pass)
        {
            if (string.IsNullOrEmpty(pass))
            {
                  return "Null password"; ;
            }
            else
            {
                byte[] storepass = ASCIIEncoding.ASCII.GetBytes(pass);
                string encryptpass = Convert.ToBase64String(storepass);
                return encryptpass;
            }
        }
        public static string DecryptedPass(string pass)
        {
            if (string.IsNullOrEmpty(pass))
            {
                return "Null password";
            }
            byte[] encrypt=Convert.FromBase64String(pass);
            string decrypt = ASCIIEncoding.ASCII.GetString(encrypt);
            return decrypt;

        }
    }
}
