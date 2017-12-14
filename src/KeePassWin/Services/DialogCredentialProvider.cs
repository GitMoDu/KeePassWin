using KeePass.Win.Views;
using System;
using System.Threading.Tasks;
using Windows.Security.Credentials;

namespace KeePass.Win.Services
{
    public class DialogCredentialProvider : ICredentialProvider
    {
        private readonly Func<IFile, PasswordDialog> _dialogFactory;

        private readonly HelloProvider Hello = new HelloProvider();

        public DialogCredentialProvider(Func<IFile, PasswordDialog> dialogFactory)
        {
            _dialogFactory = dialogFactory;
        }

        public Boolean SetCredentialsAsync(IFile file, KeePassCredentials credentials)
        {
            return Hello.SetCredentialsForFileId(file.Name, null, credentials.Password);
        }

        public async Task<KeePassCredentials> GetCredentialsAsync(IFile file)
        {
            PasswordCredential StoredCredentials = null;
            if (await Hello.IsSupportedAsync())
            {
                StoredCredentials = await Hello.GetCredentialsForFileId(file.Name, null);
            }

            if (StoredCredentials == null)
            {
                var dialog = _dialogFactory(file);
                var model = await dialog.GetModelAsync();

                if (model == null)
                {
                    return default(KeePassCredentials);
                }

                return new KeePassCredentials(model.KeyFile, model.Password);
            }
            else
            {
                StoredCredentials.RetrievePassword();
                return new KeePassCredentials(null, StoredCredentials.Password);
            }
        }
    }
}
