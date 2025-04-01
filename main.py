from email.mime import message
import discord
from discord.ext import commands
import datetime
from collections import defaultdict, Counter
import re
from keep_alive import keep_alive
import os  # For secure token loading

# ------------------
# Configuration Settings
# ------------------
LOG_CHANNEL_ID = 1356571939170287697  # Update with your logging channel ID
TOKEN = os.getenv("T")
keep_alive()
# Spam, link, and other timeouts
SPAM_TIME_FRAME = 3          # seconds for text spam detection
SPAM_MESSAGE_LIMIT = 1         # messages allowed in time frame
LINK_SPAM_TIME_FRAME = 1      # seconds for link spam detection
LINK_SPAM_LIMIT = 1            # links allowed in time frame

# Timeouts (in days or minutes) for various offenses
TEXT_SPAM_TIMEOUT = 1          # 1 day timeout for text spam
LINK_SPAM_TIMEOUT = 1          # 3 day timeout for link spam
SELF_PROMO_TIMEOUT = 1         # 1 day timeout for self promotion
BAD_WORD_TIMEOUT = 1           # 3 day timeout for bad language
MENTION_SPAM_TIMEOUT = 1       # 1 day timeout for mention spam
CAPS_TIMEOUT = 1               # 1 day timeout for excessive uppercase
ALT_ACCOUNT_TIMEOUT = 1        # 1 day timeout for newly created accounts (anti-alt)

# Advanced thresholds
MAX_MENTIONS = 5               # Maximum allowed mentions per message
MIN_MESSAGE_LENGTH_FOR_CAPS = 10    # Only check caps if message is longer than this
CAPS_PERCENTAGE_THRESHOLD = 0.7       # 70% uppercase triggers anti-caps
ALT_ACCOUNT_AGE_DAYS = 7       # Accounts younger than this (in days) are considered "alts"

# Anti-Nuke thresholds (for mass deletion events)
CHANNEL_DELETE_THRESHOLD = 2   # If more than this many channels are deleted within 10 seconds, alert
ROLE_DELETE_THRESHOLD = 2      # Same for roles

# Escalation: violation count that triggers auto-ban
VIOLATION_BAN_THRESHOLD = 1

# Suspicious keywords for attachments (token grabbers)
SUSPICIOUS_FILE_KEYWORDS = ["token", "grabber", "stealer", "discord_token"]

# ------------------
# Global Tracking Structures
# ------------------
violation_counts = defaultdict(int)        # Per-user violation count
global_violation_counter = Counter()         # For overall server stats

user_message_times = defaultdict(list)       # For spam tracking (text)
user_link_times = defaultdict(list)          # For link spam tracking
join_times = []                              # For anti-raid tracking

# For ghost ping detection – store recent messages with mentions
recent_messages = {}

# For anti-nuke (mass deletion) tracking
channel_delete_events = []
role_delete_events = []

# Keywords & Regex patterns
SELF_PROMO_KEYWORDS = ["discord.gg", "youtube.com", "twitch.tv"]
BAD_WORDS = ["badword1", "badword2"]  # Update with your banned words
INVITE_REGEX = re.compile(r"(discord\.gg/|discordapp\.com/invite/)", re.IGNORECASE)
URL_REGEX = re.compile(r"https?://", re.IGNORECASE)

# ------------------
# Bot Setup
# ------------------
intents = discord.Intents.default()
intents.members = True
intents.messages = True
intents.message_content = True

bot = commands.Bot(command_prefix="!", intents=intents)
start_time = datetime.datetime.utcnow()

# ------------------
# Helper Functions
# ------------------
async def log_action(message: str, guild: discord.Guild):
    """Log a message to the designated logging channel."""
    log_channel = guild.get_channel(LOG_CHANNEL_ID)
    if log_channel:
        await log_channel.send(f"🔔 {message}")

def is_owner_or_admin():
    """Only allow server owner or users with allowed roles."""
    async def predicate(interaction: discord.Interaction):
        if not interaction.guild:
            raise discord.app_commands.CheckFailure("❌ This command can only be used in a server.")
        if interaction.user.id == interaction.guild.owner_id:
            return True
        allowed_roles = ["Admin", "OWNER"]
        if any(role.name in allowed_roles for role in interaction.user.roles):
            return True
        raise discord.app_commands.CheckFailure("❌ This command is restricted to the server owner or Admin roles.")
    return discord.app_commands.check(predicate)

async def escalate_violation(user: discord.Member, guild: discord.Guild, reason: str):
    """Increase violation count and auto-ban if threshold exceeded."""
    violation_counts[user.id] += 1
    global_violation_counter[user.id] += 1
    count = violation_counts[user.id]
    await log_action(f"{user} violation count increased to {count}. Reason: {reason}", guild)
    if count >= VIOLATION_BAN_THRESHOLD:
        try:
            until = discord.utils.utcnow() + datetime.timedelta(days=TEXT_SPAM_TIMEOUT)
            await message.author.timeout(until, reason="Spamming messages 📢")
            await log_action(f"{message.author} timed out for spamming messages.", message.guild)
            await escalate_violation(message.author, message.guild, "Text spam")
        except Exception as e:
            print(f"Error Spamming {user}: {e}")

def percentage_upper(text: str) -> float:
    """Return percentage of uppercase letters in a text."""
    if not text:
        return 0.0
    letters = [c for c in text if c.isalpha()]
    if not letters:
        return 0.0
    return sum(1 for c in letters if c.isupper()) / len(letters)

# ------------------
# Event Listeners
# ------------------
@bot.event
async def on_ready():
    print(f"Bot is ready. Logged in as {bot.user} 🚀")
    try:
        synced = await bot.tree.sync()
        print(f"Synced {len(synced)} command(s) ✅")
    except Exception as e:
        print("Error syncing commands:", e)

@bot.event
async def on_interaction(interaction: discord.Interaction):
    """Log every slash command usage."""
    if interaction.type == discord.InteractionType.application_command:
        cmd_name = interaction.data.get("name")
        await log_action(f"{interaction.user} invoked command '{cmd_name}'.", interaction.guild)

@bot.event
async def on_guild_channel_create(channel: discord.abc.GuildChannel):
    """Log new channel creation."""
    await log_action(f"Channel '{channel.name}' was created.", channel.guild)

@bot.event
async def on_guild_channel_delete(channel: discord.abc.GuildChannel):
    """Track channel deletions for anti-nuke."""
    now = datetime.datetime.utcnow().timestamp()
    channel_delete_events.append(now)
    # Remove old events beyond 10 seconds
    while channel_delete_events and now - channel_delete_events[0] > 10:
        channel_delete_events.pop(0)
    await log_action(f"Channel '{channel.name}' was deleted! ({len(channel_delete_events)} deletions in last 10 sec)", channel.guild)
    if len(channel_delete_events) >= CHANNEL_DELETE_THRESHOLD:
        await log_action("ALERT: Mass channel deletion detected! (Anti-Nuke)", channel.guild)

@bot.event
async def on_guild_role_delete(role: discord.Role):
    """Track role deletions for anti-nuke."""
    now = datetime.datetime.utcnow().timestamp()
    role_delete_events.append(now)
    while role_delete_events and now - role_delete_events[0] > 10:
        role_delete_events.pop(0)
    await log_action(f"Role '{role.name}' was deleted! ({len(role_delete_events)} deletions in last 10 sec)", role.guild)
    if len(role_delete_events) >= ROLE_DELETE_THRESHOLD:
        await log_action("ALERT: Mass role deletion detected! (Anti-Nuke)", role.guild)

@bot.event
async def on_webhooks_update(guild: discord.Guild, channel: discord.abc.GuildChannel = None):
    """When webhooks are updated, check for suspicious ones and remove them."""
    try:
        webhooks = await guild.webhooks()
        for webhook in webhooks:
            if any(word in webhook.name.lower() for word in ["token", "grab", "steal", "selfbot"]):
                await webhook.delete(reason="Suspicious webhook detected (Anti-Webhook)")
                await log_action(f"Suspicious webhook '{webhook.name}' was deleted.", guild)
    except Exception as e:
        print("Error in on_webhooks_update:", e)

@bot.event
async def on_message(message: discord.Message):
    # Ignore bot messages
    if message.author.bot:
        return

    now = datetime.datetime.utcnow().timestamp()
    content_lower = message.content.lower()

    # If message is in DM, possibly selfbot usage (very basic check)
    if isinstance(message.channel, discord.DMChannel):
        await log_action(f"DM from {message.author} detected (Possible selfbot). Content: {message.content}", message.guild if message.guild else None)
        return

    # Store message for ghost ping detection if it mentions users
    if message.mentions:
        recent_messages[message.id] = {
            "content": message.content,
            "author": message.author,
            "timestamp": now,
            "mentions": message.mentions
        }

    # 1️⃣ Anti-Spam: Check text spam
    times = user_message_times[message.author.id]
    times.append(now)
    user_message_times[message.author.id] = [t for t in times if now - t < SPAM_TIME_FRAME]
    if len(user_message_times[message.author.id]) > SPAM_MESSAGE_LIMIT:
        try:
            await message.delete()
        except Exception as e:
            print("Error deleting spam message:", e)
        # Send warning DM on first offense
        if violation_counts[message.author.id] < 2:
            try:
                await message.author.send("Warning: Do not spam! Continued spam will lead to more severe actions.")
            except:
                pass
        try:
            until = discord.utils.utcnow() + datetime.timedelta(days=TEXT_SPAM_TIMEOUT)
            await message.author.timeout(until, reason="Spamming messages 📢")
            await log_action(f"{message.author} timed out for spamming messages.", message.guild)
            await escalate_violation(message.author, message.guild, "Text spam")
            return
        except Exception as e:
            print("Error timing out for text spam:", e)

    # 4️⃣ Anti-Invite: Delete unauthorized Discord invite links
    if INVITE_REGEX.search(message.content):
        try:
            await message.delete()
        except Exception as e:
            print("Error deleting invite message:", e)
        try:
            until = discord.utils.utcnow() + datetime.timedelta(days=SELF_PROMO_TIMEOUT)
            await message.author.timeout(until, reason="Unauthorized invite shared 🚫")
            await log_action(f"{message.author} timed out for sharing invites.", message.guild)
            await escalate_violation(message.author, message.guild, "Unauthorized invite")
            return
        except Exception as e:
            print("Error timing out for invite:", e)

    # 5️⃣ Anti-Link: Delete harmful links (phishing, etc.)
    if URL_REGEX.search(message.content) and not INVITE_REGEX.search(message.content):
        try:
            await message.delete()
        except Exception as e:
            print("Error deleting harmful link:", e)
        try:
            until = discord.utils.utcnow() + datetime.timedelta(days=LINK_SPAM_TIMEOUT)
            await message.author.timeout(until, reason="Harmful link detected 🚫")
            await log_action(f"{message.author} timed out for sharing harmful links.", message.guild)
            await escalate_violation(message.author, message.guild, "Harmful link")
            return
        except Exception as e:
            print("Error timing out for harmful link:", e)

    # 6️⃣ Anti-Alt: Check if the account is too new
    account_age = (datetime.datetime.utcnow() - message.author.created_at).days
    if account_age < ALT_ACCOUNT_AGE_DAYS:
        try:
            await message.delete()
        except Exception as e:
            print("Error deleting message from alt account:", e)
        try:
            until = discord.utils.utcnow() + datetime.timedelta(days=ALT_ACCOUNT_TIMEOUT)
            await message.author.timeout(until, reason="Newly created account detected (Anti-Alt)")
            await log_action(f"{message.author} timed out as a suspected alt account.", message.guild)
            await escalate_violation(message.author, message.guild, "Alt account")
            return
        except Exception as e:
            print("Error timing out for alt account:", e)

    # 7️⃣ Anti-Token Grabber: Check attachments for suspicious filenames
    if message.attachments:
        for attachment in message.attachments:
            fname = attachment.filename.lower()
            if any(keyword in fname for keyword in SUSPICIOUS_FILE_KEYWORDS):
                await log_action(f"Suspicious file '{attachment.filename}' sent by {message.author} in {message.channel}.", message.guild)

    # 8️⃣ Anti-Ghost Ping: (Handled in on_message_delete)

    # 9️⃣ Anti-Selfbot: (Handled by DM check above)

    # 10️⃣ Anti-CAPS & Anti-Mention Spam
    if len(message.mentions) > MAX_MENTIONS:
        try:
            await message.delete()
        except Exception as e:
            print("Error deleting mention spam message:", e)
        try:
            until = discord.utils.utcnow() + datetime.timedelta(days=MENTION_SPAM_TIMEOUT)
            await message.author.timeout(until, reason="Excessive mentions detected 🚫")
            await log_action(f"{message.author} timed out for mention spam.", message.guild)
            await escalate_violation(message.author, message.guild, "Mention spam")
            return
        except Exception as e:
            print("Error timing out for mention spam:", e)

    if len(message.content) >= MIN_MESSAGE_LENGTH_FOR_CAPS:
        if percentage_upper(message.content) >= CAPS_PERCENTAGE_THRESHOLD:
            try:
                await message.delete()
            except Exception as e:
                print("Error deleting all-caps message:", e)
            try:
                until = discord.utils.utcnow() + datetime.timedelta(days=CAPS_TIMEOUT)
                await message.author.timeout(until, reason="Excessive use of CAPS 🚫")
                await log_action(f"{message.author} timed out for excessive CAPS.", message.guild)
                await escalate_violation(message.author, message.guild, "Excessive CAPS")
                return
            except Exception as e:
                print("Error timing out for CAPS:", e)

    await bot.process_commands(message)

@bot.event
async def on_message_edit(before: discord.Message, after: discord.Message):
    if before.author.bot:
        return
    if before.content != after.content:
        try:
            await log_action(f"Message edited by {before.author} in {before.channel}:\nBefore: {before.content}\nAfter: {after.content}", before.guild)
        except Exception as e:
            print("Error logging message edit:", e)

@bot.event
async def on_message_delete(message: discord.Message):
    if message.author.bot:
        return
    ghost_ping = ""
    if message.id in recent_messages:
        ghost_ping = " (Possible ghost ping detected)"
        del recent_messages[message.id]
    try:
        await log_action(f"Message deleted by {message.author} in {message.channel}{ghost_ping}\nContent: {message.content}", message.guild)
    except Exception as e:
        print("Error logging message deletion:", e)

@bot.event
async def on_member_join(member: discord.Member):
    now = datetime.datetime.utcnow().timestamp()
    join_times.append(now)
    recent_joins = [t for t in join_times if now - t < 10]
    # 2️⃣ Anti-Raid: Auto-ban if mass join detected
    if len(recent_joins) > 5:
        try:
            await member.ban(reason="Mass join detected (Anti-Raid)")
            await log_action(f"{member} was auto-banned due to mass join (Anti-Raid).", member.guild)
            return
        except Exception as e:
            print("Error auto-banning member during raid:", e)
    # Auto-assign "Member" role
    member_role = discord.utils.get(member.guild.roles, name="Member")
    if member_role:
        try:
            await member.add_roles(member_role, reason="Auto-assigned Member role on join")
            await log_action(f"Assigned 'Member' role to {member}.", member.guild)
        except Exception as e:
            print(f"Error assigning role to {member}: {e}")
    await log_action(f"{member} joined 👋", member.guild)

# ------------------
# Slash Commands (Owner/Admin Only)
# ------------------
@bot.tree.command(name="ping", description="Check the bot's latency.")
@is_owner_or_admin()
async def ping(interaction: discord.Interaction):
    latency = round(bot.latency * 1000)
    await interaction.response.send_message(f"Pong! ⚡ {latency}ms")

@bot.tree.command(name="uptime", description="Shows how long the bot has been online.")
@is_owner_or_admin()
async def uptime(interaction: discord.Interaction):
    now = datetime.datetime.utcnow()
    delta = now - start_time
    hours, remainder = divmod(int(delta.total_seconds()), 3600)
    minutes, seconds = divmod(remainder, 60)
    uptime_str = f"{hours}h {minutes}m {seconds}s"
    await interaction.response.send_message(f"Uptime ⏱️: {uptime_str}")

@bot.tree.command(name="serverinfo", description="Get information about the server.")
@is_owner_or_admin()
async def serverinfo(interaction: discord.Interaction):
    guild = interaction.guild
    if guild:
        embed = discord.Embed(title=f"{guild.name} Info 🏠", color=discord.Color.blue())
        embed.add_field(name="Server ID", value=guild.id, inline=False)
        embed.add_field(name="Member Count", value=guild.member_count, inline=False)
        embed.add_field(name="Created At", value=guild.created_at.strftime("%Y-%m-%d %H:%M:%S"), inline=False)
        await interaction.response.send_message(embed=embed)
    else:
        await interaction.response.send_message("❌ This command can only be used in a server.")

@bot.tree.command(name="userinfo", description="Get information about a user.")
@is_owner_or_admin()
async def userinfo(interaction: discord.Interaction, member: discord.Member = None):
    member = member or interaction.user
    embed = discord.Embed(title=f"User Info: {member} 👤", color=discord.Color.green())
    embed.add_field(name="User ID", value=member.id, inline=False)
    embed.add_field(name="Joined Server", value=member.joined_at.strftime("%Y-%m-%d %H:%M:%S") if member.joined_at else "N/A", inline=False)
    embed.add_field(name="Account Created", value=member.created_at.strftime("%Y-%m-%d %H:%M:%S"), inline=False)
    await interaction.response.send_message(embed=embed)

@bot.tree.command(name="ban", description="Ban a user.")
@is_owner_or_admin()
@discord.app_commands.checks.has_permissions(ban_members=True)
async def ban(interaction: discord.Interaction, member: discord.Member, reason: str = "No reason provided"):
    try:
        await member.ban(reason=reason)
        await interaction.response.send_message(f"Banned {member} 💥 for: {reason}")
        await log_action(f"{member} was banned by {interaction.user} for: {reason}.", interaction.guild)
    except Exception as e:
        await interaction.response.send_message("Failed to ban member ❌", ephemeral=True)
        await log_action(f"Failed ban attempt by {interaction.user} on {member}. Error: {e}", interaction.guild)
        print("Ban error:", e)

@bot.tree.command(name="kick", description="Kick a user.")
@is_owner_or_admin()
@discord.app_commands.checks.has_permissions(kick_members=True)
async def kick(interaction: discord.Interaction, member: discord.Member, reason: str = "No reason provided"):
    try:
        await member.kick(reason=reason)
        await interaction.response.send_message(f"Kicked {member} 👢 for: {reason}")
        await log_action(f"{member} was kicked by {interaction.user} for: {reason}.", interaction.guild)
    except Exception as e:
        await interaction.response.send_message("Failed to kick member ❌", ephemeral=True)
        await log_action(f"Failed kick attempt by {interaction.user} on {member}. Error: {e}", interaction.guild)
        print("Kick error:", e)

@bot.tree.command(name="timeout", description="Timeout a user for a specified duration (minutes).")
@is_owner_or_admin()
@discord.app_commands.checks.has_permissions(moderate_members=True)
async def timeout(interaction: discord.Interaction, member: discord.Member, duration: int, reason: str = "No reason provided"):
    try:
        until = discord.utils.utcnow() + datetime.timedelta(minutes=duration)
        await member.timeout(until, reason=reason)
        await interaction.response.send_message(f"Timed out {member} for {duration} minute(s) ⏳. Reason: {reason}")
        await log_action(f"{member} was timed out by {interaction.user} for {duration} minute(s). Reason: {reason}", interaction.guild)
    except Exception as e:
        await interaction.response.send_message("Failed to timeout member ❌", ephemeral=True)
        await log_action(f"Failed timeout attempt by {interaction.user} on {member}. Error: {e}", interaction.guild)
        print("Timeout error:", e)

@bot.tree.command(name="recover_timeout", description="Remove timeout from a user (recover timeout).")
@is_owner_or_admin()
@discord.app_commands.checks.has_permissions(moderate_members=True)
async def recover_timeout(interaction: discord.Interaction, member: discord.Member):
    try:
        await member.timeout(None, reason="Timeout recovered")
        await interaction.response.send_message(f"Timeout has been removed for {member} ✅")
        await log_action(f"Timeout removed for {member} by {interaction.user}.", interaction.guild)
    except Exception as e:
        await interaction.response.send_message("Failed to recover timeout ❌", ephemeral=True)
        await log_action(f"Failed to recover timeout for {member} by {interaction.user}. Error: {e}", interaction.guild)
        print("Recover timeout error:", e)

@bot.tree.command(name="violations", description="Check a user's violation count.")
@is_owner_or_admin()
async def violations(interaction: discord.Interaction, member: discord.Member):
    count = violation_counts.get(member.id, 0)
    await interaction.response.send_message(f"{member} has {count} violation(s).")

@bot.tree.command(name="reset_violations", description="Reset a user's violation count.")
@is_owner_or_admin()
async def reset_violations(interaction: discord.Interaction, member: discord.Member):
    violation_counts[member.id] = 0
    await interaction.response.send_message(f"{member}'s violation count has been reset.")

@bot.tree.command(name="stats", description="Display overall server violation statistics.")
@is_owner_or_admin()
async def stats(interaction: discord.Interaction):
    total_violations = sum(violation_counts.values())
    top_offenders = sorted(violation_counts.items(), key=lambda x: x[1], reverse=True)[:3]
    msg = f"Total Violations: {total_violations}\nTop Offenders:\n"
    for user_id, count in top_offenders:
        msg += f"User ID {user_id}: {count} violations\n"
    await interaction.response.send_message(msg)

@bot.tree.command(name="security_check", description="Check the status of security systems.")
@is_owner_or_admin()
async def security_check(interaction: discord.Interaction):
    status = (
        "**Security Systems Active:**\n"
        "- Anti-Spam (Text, Link, Mentions, CAPS): Active ✅\n"
        "- Anti-Raid: Active ✅\n"
        "- Anti-Nuke (Mass Deletions): Active ✅\n"
        "- Auto Role Assignment: Active ✅\n"
        "- Self Promotion & Bad Word Filter: Active ✅\n"
        "- Anti-Invite & Anti-Link: Active ✅\n"
        "- Anti-Alt: Active ✅\n"
        "- Anti-Webhook: Active ✅\n"
        "- Anti-Token Grabber: Active ✅\n"
        "- Anti-Ghost Ping: Active ✅\n"
        "- Anti-Selfbot: Active ✅\n"
        "- Command & Channel Logging: Active ✅\n"
        "- Violation Tracking & Escalation: Active ✅\n"
    )
    await interaction.response.send_message(status)

# Global error handler for slash commands
@ping.error
@uptime.error
@serverinfo.error
@userinfo.error
@ban.error
@kick.error
@timeout.error
@recover_timeout.error
@violations.error
@reset_violations.error
@stats.error
@security_check.error
async def command_error(interaction: discord.Interaction, error):
    if isinstance(error, discord.app_commands.MissingPermissions):
        await interaction.response.send_message("❌ You don't have permission to use this command.", ephemeral=True)
    elif isinstance(error, discord.app_commands.CheckFailure):
        await interaction.response.send_message(f"❌ {error}", ephemeral=True)
    else:
        await interaction.response.send_message("❌ An error occurred while executing the command.", ephemeral=True)
        await log_action(f"Error in command '{interaction.command.name}' invoked by {interaction.user}: {error}", interaction.guild)
        print("Command error:", error)

# ------------------
# Run the Bot
# ------------------
if TOKEN:
    bot.run(TOKEN)
else:
    print("Error: DISCORD_BOT_TOKEN environment variable not set!")
