﻿using System;
using System.Diagnostics;
using System.Linq;
using Windows.UI.Xaml;
using Windows.UI.Xaml.Controls;
using Windows.UI.Xaml.Input;

namespace KeePass.Win.Mvvm
{
    public partial class Keyboard
    {
        public static readonly DependencyProperty ShortcutProperty = DependencyProperty.RegisterAttached("Shortcut", typeof(ShortcutName), typeof(Keyboard), new PropertyMetadata(default(ShortcutName)));
        public static readonly DependencyProperty AutoWireProperty = DependencyProperty.RegisterAttached("AutoWire", typeof(bool), typeof(Keyboard), new PropertyMetadata(false, AutoWirePropertyChanged));

        public static void SetShortcut(MenuFlyoutItem attached, ShortcutName value)
        {
            attached.SetValue(ShortcutProperty, value);
        }

        public static void SetAutoWire(FrameworkElement attached, bool value)
        {
            attached.SetValue(AutoWireProperty, value);
        }

        public static ShortcutName GetShortcut(MenuFlyoutItem attached)
        {
            return (ShortcutName)attached.GetValue(ShortcutProperty);
        }

        public static bool GetAutoWire(FrameworkElement attached)
        {
            return (bool)attached.GetValue(AutoWireProperty);
        }

        private static void AutoWirePropertyChanged(DependencyObject d, DependencyPropertyChangedEventArgs args)
        {
            var shortcut = d as FrameworkElement;

            if (shortcut == null)
            {
                return;
            }

            if (!(bool)args.NewValue)
            {
                shortcut.KeyDown -= ShortcutKeyDown;
                return;
            }

            shortcut.KeyDown += ShortcutKeyDown;
            shortcut.Unloaded += (s, _) => (s as FrameworkElement).KeyDown -= ShortcutKeyDown;
        }

        private static void ShortcutKeyDown(object sender, KeyRoutedEventArgs e)
        {
            var content = e.OriginalSource as ContentControl;
            var root = content?.ContentTemplateRoot;

            // If the root is a UserControl (such as the Entry view), grab its content. Otherwise, use the root object itself
            var menu = ((root as UserControl)?.Content ?? root)?.ContextFlyout as MenuFlyout;

            if (menu == null)
            {
                Debug.Assert(true, "No flyout was found with shortcut information");
                return;
            }

            var key = s_keyboardHandler.Value.ProcessKeypress((int)e.Key);

            if (key == ShortcutName.None)
            {
                return;
            }

            if (key == ShortcutName.ShowMenu)
            {
                e.Handled = true;
                menu.ShowAt(content);
                return;
            }

            var item = menu.Items
                .OfType<MenuFlyoutItem>()
                .FirstOrDefault(i => GetShortcut(i) == key) as MenuFlyoutItem;

            if (item == null)
            {
                return;
            }

            var command = item.Command;
            var param = item.CommandParameter;

            if (command?.CanExecute(param) == true)
            {
                command.Execute(param);
            }
        }
    }
}
