using System;
using System.Threading.Tasks;

namespace KeePass
{
    public interface ICredentialProvider
    {
        Task<KeePassCredentials> GetCredentialsAsync(IFile file);
        Boolean SetCredentialsAsync(IFile file, KeePassCredentials credentials);
    }
}
