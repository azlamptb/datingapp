using System;
using System.Threading.Tasks;
using DatingApp.API.Models;
using Microsoft.EntityFrameworkCore;

namespace DatingApp.API.Data
{
    public class AuthRepository : IAuthRepository
    {
        private readonly DataContext _context;
        public AuthRepository(DataContext context)
        {
            this._context = context;

        }
        public async Task<User> Login(string username, string passowrd)
        {
            var user = await _context.Users.FirstOrDefaultAsync(x=>x.Username ==username);
            if(user ==null)
               return null;

            if(!VerifyPasswordHash(passowrd, user.PasswordHash, user.PasswordSalt))
               return null;

            return user;
        }

        private bool VerifyPasswordHash(string passowrd, byte[] passwordHash, byte[] passwordSalt)
        {
            using(var hmac = new System.Security.Cryptography.HMACSHA512(passwordSalt))
            {  
               var ComputeHash  = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(passowrd));
               for(int i=0;i<ComputeHash.Length;i++)
               {
                   if(ComputeHash[i]!=passwordHash[i]) return false;
               }
            }
            return true;
            
        }

        public async Task<User> Register(User user, string passowrd)
        {
           byte[] passowrdHash, passowrdsalt;
           CreatePasswordHash(passowrd,out passowrdHash, out passowrdsalt);

           user.PasswordHash = passowrdHash;
           user.PasswordSalt= passowrdsalt;
           await _context.Users.AddAsync(user);
           await _context.SaveChangesAsync();
           return user;
        }

        private void CreatePasswordHash(string passowrd, out byte[] passowrdHash, out byte[] passowrdsalt)
        {
            using(var hmac = new System.Security.Cryptography.HMACSHA512())
            {
                passowrdsalt =hmac.Key;
                passowrdHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(passowrd));
            }
        }

        public async Task<bool> UserExists(string username)
        {
            if(await _context.Users.AnyAsync(x=>x.Username==username))
                return true;
            else
                return false;
        }
    }
}