﻿using System;
using Windows.ApplicationModel.DataTransfer;

namespace KeePass.Win.Services
{
    public class TimedClipboard : IClipboard
    {
        private readonly TimeSpan _delay;

        public TimedClipboard(TimeSpan delay)
        {
            _delay = delay;
        }

        public void SetText(string text)
        {
            if (text == null)
            {
                return;
            }

            var dp = new DataPackage();

            dp.SetText(text);

            Clipboard.SetContent(dp);

            ClearTextAsync();
        }

        public void ClearTextAsync()
        {
#if FALSE
            Task.Run(async () =>
            {
                await Task.Delay(_delay);

                await CoreApplication.MainView.CoreWindow.Dispatcher.RunAsync(Windows.UI.Core.CoreDispatcherPriority.Low, Clipboard.Clear);
            });
#endif
        }
    }
}