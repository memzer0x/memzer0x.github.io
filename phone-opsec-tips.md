# Social Media Anonymity Tips and Tricks (from dread)

The guide is about anonymity on social media and the safe use of a mobile phones. It should make it difficult to identify what you do or who you are. There is something for everyone in it.

Thoughts on some applications.

Facebook Messenger: End to end encryption is opt in and only enabled when you start a secret conversation. Secret conversations not available on web app. FB has a history of all secret conversations, you can not delete it. Deleting something on FB doesn't delete anything from their databases or backups.

Telegram: Very popular and allows for huge groups. Desktop application does not have end to end encryption. End to End encryption is only in secret chats. If using a Televend shop to order drugs then you should use the app on Tails and manually PGP encrypt your address.
Set up Telegram on Tails dreadytofatroptsdj6io7l3xptbet6onoyno2yv7jicoxknyazubrad.onion/post/f21e4eada88a77f82008/#c-8f48c2c4c28c5ade43
Make Telegram persistent on Tails dreadytofatroptsdj6io7l3xptbet6onoyno2yv7jicoxknyazubrad.onion/post/6ba79b8708c26aaf2bd9/#c-ffc19b9f565eff160e
Telegram stores are throwing buyer OpSec out of the window. Telegram is what people think is safe and it is the de facto drug app in many countries. Use something else.

Wickr Me: Wickr does not have phone activation and it does not require an email to sign up. It is encrypted by default and it has a self destruct on messages that you can set up. A lot of vendors and other people in the drug trade trust Wickr. wickr.com/security/ Wickr does not hide who you are (IP address) or who you talk to. It is up to you to protect your identity. If the people you talk to fail to protect themselves then that can come back to bite you in the ass. You shouldn't on the same account talk to people you order drugs from, people you sell drugs to and then your real life friends too. All of this should be separate.

WhatsApp: Has end to end encryption. It is Facebook. Facebook wants to gather as much information as possible so they can better advertise to you. Probably not the best choice.

Instagram: Like facebook it is hostile towards Tor. Might be a lucrative place for advertising. It does not have end to end encryption for the chat.

Reddit and Twitter: Hostile towards Tor users. Reddit just doesn't work if you use a Tor exit node. They will shadowban you account. Twitter will lock your account if you use it with Tor and they'll ask for phone verification. These are still important platforms for getting a message out (DarkDotFail on Twitter, DreadAlert on Reddit).

SnapChat: Why do people post shit that incriminates them or you and expect SnapChat to actually delete what they post? SnapChat does not delete anything. It is a good place to advertise drugs.

TikTok, Tinder, Grindr: Might be a good places to advertise drugs, depends how you work them.

Signal: Signal is the most promising of all IM apps. Good security and privacy. Only thing kept in logs is your phone number. Phone number requirement is what is keeping me from recommending it to everyone. You can activate Signal with a temporary number and prevent account getting stolen signal.org/blog/signal-pins/ If you and who you are talking to are willing to go through with buying a phone number then use Signal.

Encrochat & Sky ECC: LE found the servers and pushed an update that broke the encryption and identified the users. Users of the services were hiding among other criminals. The service was not any better than a free solution. It was a giant honeypot and the effects of it will be felt for years. Use something that is widely used by regular people. Information that is critical should be manually PGP encrypted.
All centralized services have useful data to hand over to LE. All of them can be forced to start logging data that they normally don't.

Data that is logged:

1. Contacts and historical contacts on the app
2. Contacts on your phone
3. Contents of messages
4. Encrypted messages
5. Sent files
6. Deleted messages
7. Original EXIF data of sent photos
8. Phone models used with the app
9. Phone IMEI and other uniquely identifying data
9. IP addresses used with the
10. Your phone number
11. Contents or metadata of files on your phone
12. Location data
13. Contents of your SMS messages
14. Your browsing history
15. And more

Number 9 is how the police attaches real names to pseudonyms in IM (instant messaging) applications. Most people also use their real phone number on Telegram/Signal. Those that do have burner phones/numbers have non existent OpSec (operational security) beyond that. They use their burner at their home or at work, at their friends place. They have their burner turned on while their regular phone is turned on like while driving down a highway or in a bar. Sitting in a restaurant, turning off your phone and turning on the burner is not sufficient OpSec either.

When the company does not have to comply with law enforcement the process of identifying a person behind an account is more involved but perfectly doable.
Process looks roughly like this:

1. Identify account you want to investigate.
2. Identify IP addresses of the servers that IM app clients connect to.
3a. Start conversation with account under investigation. Each message the suspect sends to you corresponds with upload traffic from a phone to the server identified in step 2. The timestamps of them sending a message and you receiving a message will correlate. Do this however many times needed and you have a match.
3b. Each message you send will correlate with a download by the suspect's phone. These will be time correlated if the suspect is currently online.
3b. Send a file of known size to suspect. This will stand out among all of the other single message uploads/downloads.
3c. Start a video/voice connection with suspect. This will correspond with a data stream of known duration and size.
3d. If suspect is not talking to you then you can use "message read" notifications that will be uploaded by the suspect or "person is writing a message" notifications that will be downloaded by the suspect. Initiating a voice or video connection request can also be correlated. You sending a message will not work if the person is not currently online but it can be used if you use the "message read" notification on your side and the corresponding download of the message by the suspect.

The more people that the suspect gets to hide in the more data you need to identify the suspect. Of course you try to narrow down the geographic location of the suspect to make this process quicker.


TEMPORARY PHONE NUMBER

This will be used to activate an account. Beware that this number is temporary and you get it for just a few minutes. After that it is gone and you can not get it back. People can use it to steal your account. Some services want to verify you with the phone number again when you log in from a new place (happens if you use Tor), set up a 2FA authentication with those services. Use the Google authenticator app if available. Second option is e-mail authentication. Remember that every process must be done through tor. If you use the service through Tor but used the email without it at any point then you are screwed forever.

1. Set up tails. The DNM Bible is down right now but you can find the offline version here as a PDF dreadytofatroptsdj6io7l3xptbet6onoyno2yv7jicoxknyazubrad.onion/post/40c86816505155c1a0d8
2. Buy Monero. If you need to then buy BTC with Monero (also in the bible). You must send the crypto transactions over Tor.
3. You can buy phone numbers here textverified.com or here 5sim.net or any other service that you'd prefer. They must accept crypto.

You might tie all of your activated accounts together that you activate with purchases with the same account on one of these websites. Same if you make purchases with BTC from the same Bitcoin account, the BTC connection is across websites and their accounts. This depends on the website keeping these logs but you can not assume or trust that they don't. If an account on one of these number selling websites is ever identified as yours then all activations that you do with it in the future will be tied to you.


TOR HOSTILE WEBSITES

This is for completeness sake. I don't know exactly how to do it just that it is possible. You need to route your traffic like this you->tor->proxy->website.

You'll have to buy a proxy server with Monero. Or buy a VPS and configure a proxy yourself. If anyone has a good guide on how to do this then I'd appreciate it.


PHONE IMEI and SIM

All phones have a unique identification number, IMEI. It gets sent when you connect to a cell tower. You can't change IMEI on most phones anymore, you need to develop a custom solution for every phone. Mobile service providers keep track of IMEI numbers. When they saw them, the geographic location and the SIM that was present. IMEI ties together different SIM cards used on a phone. Some people are under the impression that the SIM is important and throwing out or changing the SIM is what saves them. The SIM is tied to your name and it is what enables service providers to bill people.

Some apps on your phone will have access to your IMEI. If the network operator knows the IMEI and through some app an IMEI is identified as belonging to you the suspect then that might lead to an arrest.

If you do not want an IMEI being associated with you then buy your phone with cash in some place that you are not easily identified. NEVER connect to a cell tower. If you make an emergency call then that will broadcast your IMEI. Airplane mode is a software switch, it doesn't actually turn off the antenna. There is no guarantee that your phone will not try to connect to a cell tower even with no SIM in phone. Same goes for airplane mode. 
