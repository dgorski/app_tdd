# app_tdd

TDD Module for Asterisk

The goal of app_tdd is to effectively filter out TDD tones coming in on a channel and publish them to AMI/Stasis.  Additionally, allow AMI/Stasis apps to post messages that will in turn be sent out through the channel as TDD tones.

This allows for centralized TDD processing (rather than requiring TDD/TTY hardware or software at the user endpoint).

app_tdd.c contained here compiles cleanly under asterisk 18.8.0.

Things that work so far:

- the receiver does receive TDD (FSK @ 45.45bps, 50bps support added but untested)
- the transmitter does transmit TDD (as above)
- transmitter and receiver have been tested with real TDD TTY hardware (Ultratec 1140)
- Also tested with a real iPhone RTT (via PSTN)
- AMI events are raised when a TDD message is received
- AMI requests to send TDD on a channel function properly
- CLI requests to send TDD on a channel function properly
- Dialplan application to send TDD on a channel
- TddStop application and manager command to remove existing TDD processing from a channel

Things that still need work:

- received messages should be encoded as they may contain control sequences (\r \n \0 etc)
  - some of this is implemented (\r and \n), need to test/complete
- the send AMI and CLI commands should also use some sort of encoding in order to send supported baudot specials
  - some of this is implemented, (\r and \n) need to test/complete
- fix AMI/ARI events for TddStop (TddStart is properly emitted)

