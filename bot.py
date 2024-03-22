import discord
import asyncio
import subprocess
import os
import random
import string
import shutil

class DiscordBot:
    def __init__(self, token, guild_id, channel_id):
        self.token = token
        self.guild_id = guild_id
        self.channel_id = channel_id
        self.intents = discord.Intents.default()  # Enable the default intents
        self.client = discord.Client(intents=self.intents)
        self.sent_ips = set()  # Store the set of previously sent IPs

    async def send_notification(self, message):
        guild = self.client.get_guild(self.guild_id)
        if guild:
            channel = guild.get_channel(self.channel_id)
            if channel:
                await channel.send(message)
            else:
                print(f"Error: Channel with ID {self.channel_id} not found in server with ID {self.guild_id}.")
        else:
            print(f"Error: Server with ID {self.guild_id} not found.")

    async def check_flagged_ips(self):
        while True:
            with open('flagged_ips.txt', 'r') as f:
                flagged_ips = set(line.strip() for line in f if line.strip())  # Skip empty lines
            new_ips = flagged_ips - self.sent_ips  # Calculate new IPs
            if new_ips:
                message = "New Flagged IP Addresses:\n"
                await self.send_notification(message)
                self.sent_ips.update(new_ips)  # Update sent_ips with new IPs

                # Check for flooding
                if len(new_ips) >= 5:
                    await self.send_notification("Flood alert! Five or more new IP addresses added in the last check.")

                # Add IP addresses to firewall block list
                for ip in new_ips:
                    subprocess.run(f"netsh advfirewall firewall add rule name=\"Block_{ip}\" dir=in interface=any action=block remoteip={ip}",
                                   shell=True)

                # Rename flagged_ips.txt to a random name and move to logs folder
                new_file_name = ''.join(random.choices(string.ascii_letters + string.digits, k=10)) + '.txt'
                os.rename('flagged_ips.txt', os.path.join('logs', new_file_name))
                open('flagged_ips.txt', 'w').close()  # Create an empty flagged_ips.txt file
            await asyncio.sleep(5)  # Check every minute

    async def on_ready(self):
        print(f'We have logged in as {self.client.user}')
        # Set the bot's activity to "Protecting our Server"
        await self.client.change_presence(activity=discord.Activity(type=discord.ActivityType.watching, name="Protecting our Server"))
        # Start the task to continuously check for flagged IPs
        asyncio.create_task(self.check_flagged_ips())

    async def on_message(self, message):
        # Check if the message is from an allowed user
        allowed_users = [180354849358086155, 1006952793023721484]  # Replace these with your allowed user IDs
        if message.author.id not in allowed_users:
            # Check if the message is a command
            if message.content.startswith('!'):
                await message.channel.send("You are not allowed to send commands.")
            return  # Ignore messages from users not in the allowed list

        if message.content.startswith('!block_ip'):
            ip = message.content.split(' ')[1]
            subprocess.run(f"netsh advfirewall firewall add rule name=\"Block_{ip}\" dir=in interface=any action=block remoteip={ip}",
                           shell=True)
            await message.channel.send(f"IP address {ip} has been added to the firewall block list.")
        elif message.content.startswith('!unblock_ip'):
            ip = message.content.split(' ')[1]
            subprocess.run(f"netsh advfirewall firewall delete rule name=\"Block_{ip}\"", shell=True)
            await message.channel.send(f"IP address {ip} has been removed from the firewall block list.")
        elif message.content == '!about':
            about_message = ("I'm a Discord bot designed to protect your server from flood attacks by monitoring and blocking flagged IP addresses. "
                            "You can say I am a lifesaver. Coded By Rectofen.")
            await message.channel.send(about_message)

    def run(self):
        @self.client.event
        async def on_ready():
            await self.on_ready()

        @self.client.event
        async def on_message(message):
            await self.on_message(message)

        self.client.run(self.token)


# Set your Discord token and channel ID here
TOKEN = 'your_discord_token'
GUILD_ID = your_serverID
CHANNEL_ID = your_channelID

# Create and run the Discord bot
bot = DiscordBot(TOKEN, GUILD_ID, CHANNEL_ID)
bot.run()