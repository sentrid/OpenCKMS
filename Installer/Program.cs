using System;
using System.Windows.Forms;
using WixSharp;
using WixSharp.Forms;

namespace Installer
{
    internal static class Program
    {
        static void Main()
        {
            var project = new ManagedProject("OpenCKMS",
                    new Dir(@"%ProgramFiles%\SentrId\OpenCKMS",
                    new File("Program.cs")),
                    new User("CkmsService")
                    {
                        CanNotChangePassword = false,
                        CreateUser = true,
                        Disabled = false,
                        LogonAsBatchJob = false,
                        LogonAsService = true,
                        FailIfExists = true,
                        Name = "OpenCKMS Service User",
                        //Password = System.Web.Security.Membership.GeneratePassword(20, 10),
                        PasswordExpired = false,
                        PasswordNeverExpires = true,
                        RemoveOnUninstall = true,
                        UpdateIfExists = false,
                        WixIncludeInComponent = false
                    })
            {
                GUID = new Guid("6fe30b47-2577-43ad-9095-1861ba25889b"),
                ManagedUI = ManagedUI.Empty
            };


            //no standard UI dialogs
            project.ManagedUI = ManagedUI.Default;  //all standard UI dialogs

            //custom set of standard UI dialogs
            project.ManagedUI = new ManagedUI();

            project.ManagedUI.InstallDialogs.Add(Dialogs.Welcome)
                                            .Add(Dialogs.Licence)
                                            .Add(Dialogs.SetupType)
                                            .Add(Dialogs.Features)
                                            .Add(Dialogs.InstallDir)
                                            .Add(Dialogs.Progress)
                                            .Add(Dialogs.Exit);

            project.ManagedUI.ModifyDialogs.Add(Dialogs.MaintenanceType)
                                           .Add(Dialogs.Features)
                                           .Add(Dialogs.Progress)
                                           .Add(Dialogs.Exit);

            project.Load += Msi_Load;
            project.BeforeInstall += Msi_BeforeInstall;
            project.AfterInstall += Msi_AfterInstall;

            //project.SourceBaseDir = "<input dir path>";
            //project.OutDir = "<output dir path>";

            

            project.BuildMsi();
        }

        static void Msi_Load(SetupEventArgs e)
        {
            if (!e.IsUISupressed && !e.IsUninstalling)
                MessageBox.Show(e.ToString(), "Load");
        }

        static void Msi_BeforeInstall(SetupEventArgs e)
        {
            if (!e.IsUISupressed && !e.IsUninstalling)
                MessageBox.Show(e.ToString(), "BeforeInstall");
        }

        static void Msi_AfterInstall(SetupEventArgs e)
        {
            if (!e.IsUISupressed && !e.IsUninstalling)
                MessageBox.Show(e.ToString(), "AfterExecute");
        }

        private static string GeneratePassword()
        {

            return "";
        }
    }
}
