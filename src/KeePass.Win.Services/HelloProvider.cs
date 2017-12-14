using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Windows.Security.Credentials;
using Windows.Security.Credentials.UI;
using Windows.UI.Xaml;

namespace KeePass.Win.Services
{
    public class HelloProvider
    {
        private readonly String HelloStorageTag = Application.Current.GetType().ToString();
        private String DefaultUserName = "HelloUser";

        private PasswordVault _Vault = null;
        private PasswordVault Vault
        {
            get
            {
                if (_Vault == null)
                {
                    _Vault = new PasswordVault();
                }
                return _Vault;
            }
        }

        private void ClearAllKeys()
        {
            IReadOnlyList<PasswordCredential> SymmetricKeys = Vault.RetrieveAll();

            foreach (PasswordCredential symmetricKey in SymmetricKeys)
            {
                Vault.Remove(symmetricKey);
            }
        }

        private String _RequestVerificationMessage = null;
        private String RequestVerificationMessage
        {
            get
            {
                if (_RequestVerificationMessage == null)
                {
                    _RequestVerificationMessage = "Auto login"; //Get localized message.
                }

                return _RequestVerificationMessage;
            }
        }

        public async Task<Boolean> IsSupportedAsync()
        {
            return await KeyCredentialManager.IsSupportedAsync();
        }


        private PasswordCredential GetValueFromLocker(string resourceName, string userName)
        {
            PasswordCredential Credentials = null;

            try
            {
                List<PasswordCredential> CredentialsList = new List<PasswordCredential>();

                IReadOnlyList<PasswordCredential> AllKeys = Vault.RetrieveAll();

                int Count = AllKeys.Count;
                foreach (PasswordCredential item in AllKeys)
                {
                    if (item.Resource.Equals(resourceName))
                    {
                        CredentialsList.Add(item);
                    }
                }

                if (CredentialsList.Count > 0)
                {
                    if (CredentialsList.Count == 1)
                    {
                        Credentials = CredentialsList[0];
                    }
                    else
                    {
                        if (userName != null)
                        {
                            Credentials = Vault.Retrieve(resourceName, userName);
                        }
                        else
                        {
                            Credentials = Vault.Retrieve(resourceName, DefaultUserName);
                        }
                    }
                }
            }
            catch (Exception ex )
            {
                String a = ex.ToString();
            }

            return Credentials;
        }

        private String GetCredentialsTag(String fileId)
        {
            return HelloStorageTag + '/' + fileId;
        }

        public Boolean SetCredentialsForFileId(String fileId, String userName, String value)
        {
            try
            {
                PasswordCredential StoredCredentials = GetValueFromLocker(GetCredentialsTag(fileId), userName);
                if (StoredCredentials != null)
                {
                    Vault.Remove(StoredCredentials);
                }

                PasswordCredential NewCredential = null;

                if (userName != null)
                {
                    NewCredential = new PasswordCredential(GetCredentialsTag(fileId), userName, value);
                }
                else
                {
                    NewCredential = new PasswordCredential(GetCredentialsTag(fileId), DefaultUserName, value);
                }

                Boolean PasswordMatch = false;
                if (NewCredential.Password.Length > 0)
                {
                    Vault.Add(NewCredential);
                    PasswordMatch = true;
                }

                return PasswordMatch;
            }
            catch (Exception)
            {
                //TODO: Log
            }

            return false;
        }
        public async Task<PasswordCredential> GetCredentialsForFileId(String fileId, String userName)
        {
            PasswordCredential Credentials = GetValueFromLocker(GetCredentialsTag(fileId), userName);

            try
            {
                if (Credentials != null && await UserConsentVerifier.RequestVerificationAsync(RequestVerificationMessage) == UserConsentVerificationResult.Verified)
                {
                    Credentials.RetrievePassword();
                    if (Credentials.Password?.Length > 0)
                    {
                        return Credentials;
                    }
                    else
                    {
                        Vault.Remove(Credentials);
                    }
                }
            }
            catch (Exception)
            {
                //TODO: Log
            }

            return null;
        }
    }
}
