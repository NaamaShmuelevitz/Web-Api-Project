using Entities;

namespace Repositories
{
    public interface IUsersRepository
    {
        Task<User> GetById(int id);
        Task<User> GetByUserName(string userName);
        Task<User> Register(User user);
        Task<User> UpdateUser(int id, User userToUpdate);
    }
}