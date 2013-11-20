#Install ruby1.9.1 or higher 
#Install ruby's gem manager (rubygems1.9.1 for ubuntu users)
#
#gem install cinch
#
#Run the dtella.py script and launch the DC++ client connect to the hub
#(Address = 127.0.0.1:7314). In the DC++ client chat you will enter the command
#to set a static peer connection port Using the !UDP command. So say you wanted
#to create a static port at 9231 you would enter.
#
#!UDP 9231
#
#Now change the following line to be equal the given port you gave in the !UDP command.
#So say you changed your port to 9231 change the following line to: $dc_port = 9231
$dc_port = 0000

require 'cinch'

# IRC Bot configurations
bot_name = "Remote"
bot_nickname = "MyBot" #Choose your bot's name
irc_server = "cs-club.ca"
irc_port = 6697
use_ssl = true
oper_cmd = Array.new()   # Place oper authentication commands in a file called .oper_cmd "#ucsc",
autojoin_channels = [ "#ucsc", "#vending_machine"]
#autosend_cmd = ["samode #ucsc +o #{bot_nickname}", "samode #vending_machines +o #{bot_nickname}", "samode #vending_machines +sp"]

IP_ADDRESS_REGEX = /[0-9]+[\.][0-9]+[\.][0-9]+[\.][0-9]/
$i = 0

# Create and instantiate the bot, rms, and define the actions that rms takes
# based on different events that occur
bot = Cinch::Bot.new do
  configure do |c|
    c.server = irc_server
    c.port = irc_port
    c.ssl.use = use_ssl
    c.channels = autojoin_channels
    c.realname = bot_name
    c.nick = bot_nickname
    c.user = bot_nickname
  end

  helpers do
    # Get the current IP address of the bot
    def getIp()

    	ipaddress = %x(ifconfig eth0 | grep "inet addr"  | awk -F: '{print $2}' | awk '{print $1}')

      if ipaddress == "" then
        ipaddress = %x(ifconfig wlan0 | grep "inet addr"  | awk -F: '{print $2}' | awk '{print $1}')
      end

	    return ipaddress.chomp
    end
  end



  # On connect become oper then join & setup the specified channels that rms is moderating
  on :connect do |m|
    sleep(10)
    oper_cmd.each() {|cmd| @bot.irc.send(cmd)}
    #autosend_cmd.each() {|cmd| @bot.irc.send(cmd)}
    @users = Hash.new   # hash that stores a list of users on the channels
  end

    # RMS will respond when he is addressed, it's too difficult to add support
  # for him to understand the context and know who to respond to
  on :message, /^#{bot_nickname}[\:,]* (.+)/ do |m, convo|
   		m.reply("#{m.user.nick}, " + getIp() + ":" + $dc_port.to_s)

      puts "my host #{m.user.data}"
      puts "MyIP #{m.user.host.scan(IP_ADDRESS_REGEX)[0]}"
  end

    # Log channel members when they make a channel message
  on :channel do |m|
    unless @users.key?(m.user.nick)
      # Add the new uscs member to the list of channel members and send them a nice
      # introductory/welcome message
		@users[m.user.nick] = [m.user.nick, m.channel, m.message, Time.now.
      		asctime]
     	m.reply("#{m.user.nick}, " + introduction)
    end
  end

end

bot.start