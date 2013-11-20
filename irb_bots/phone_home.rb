require 'cinch'

# IRC Bot configurations
bot_name = "Remote"
bot_nickname = "Josephs_bot"
irc_server = "cs-club.ca"
irc_port = 6697
$dc_port = 9231
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
  	if m.user.realname.match(/Daniel/) || m.user.host.match(/dick@nat023.dc-uoit.net.*/) then
  		if $i == 0 then
  			m.reply("Shitty#{m.user.nick}")
  			$i+=1
  		end
  	elsif
   		m.reply("#{m.user.nick}, " + getIp() + ":" + $dc_port.to_s)

      puts "my host #{m.user.data}"
      puts "MyIP #{m.user.host.scan(IP_ADDRESS_REGEX)[0]}"
	end
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